package ledger

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "math"
    "sort"

    "github.com/jackc/pgx/v5"
)

const (
    currencyLen = 3
    minEntries  = 2
    maxEntries  = 1000
)

const (
    ModeLive = "live"
    ModeTest = "test"
)

var (
    ErrUnbalanced          = errors.New("ledger: entries must sum to zero per currency")
    ErrInvalidTxn          = errors.New("ledger: invalid transaction")
    ErrIdempotencyMismatch = errors.New("ledger: idempotency key reused with a different payload")
)

type Entry struct {
    Account  string
    Currency string
    Amount   int64
}

type Txn struct {
    ID             string
    MerchantID     string
    Mode           string
    IdempotencyKey string
    Entries        []Entry
}

func validCurrency(c string) bool {
    if len(c) != currencyLen {
        return false
    }
    for i := 0; i < len(c); i++ {
        if c[i] < 'A' || c[i] > 'Z' {
            return false
        }
    }
    return true
}

func hashTxn(t Txn) string {
    entries := make([]Entry, len(t.Entries))
    copy(entries, t.Entries)
    sort.Slice(entries, func(i, j int) bool {
        a, b := entries[i], entries[j]
        if a.Account != b.Account {
            return a.Account < b.Account
        }
        if a.Currency != b.Currency {
            return a.Currency < b.Currency
        }
        return a.Amount < b.Amount
    })
    h := sha256.New()
    fmt.Fprintf(h, "%q\n", t.Mode)
    for _, e := range entries {
        fmt.Fprintf(h, "%q|%q|%d\n", e.Account, e.Currency, e.Amount)
    }
    return hex.EncodeToString(h.Sum(nil))
}

func validate(t Txn) error {
    if t.ID == "" || t.MerchantID == "" || t.IdempotencyKey == "" {
        return fmt.Errorf("%w: id, merchant id and idempotency key are required", ErrInvalidTxn)
    }
    if len(t.Entries) < minEntries || len(t.Entries) > maxEntries {
        return fmt.Errorf("%w: entry count must be between %d and %d", ErrInvalidTxn, minEntries, maxEntries)
    }
    if t.Mode != ModeLive && t.Mode != ModeTest {
        return fmt.Errorf("%w: unknown mode %q", ErrInvalidTxn, t.Mode)
    }
    sums := map[string]int64{}
    for _, e := range t.Entries {
        if e.Account == "" || e.Amount == 0 || !validCurrency(e.Currency) {
            return fmt.Errorf("%w: bad entry for account %q", ErrInvalidTxn, e.Account)
        }
        cur := sums[e.Currency]
        if (e.Amount > 0 && cur > math.MaxInt64-e.Amount) || (e.Amount < 0 && cur < math.MinInt64-e.Amount) {
            return fmt.Errorf("%w: amount overflow in %s", ErrInvalidTxn, e.Currency)
        }
        sums[e.Currency] = cur + e.Amount
    }
    for _, sum := range sums {
        if sum != 0 {
            return ErrUnbalanced
        }
    }
    return nil
}

func Post(ctx context.Context, tx pgx.Tx, t Txn) (duplicate bool, err error) {
    if err := validate(t); err != nil {
        return false, err
    }

    hash := hashTxn(t)
    tag, err := tx.Exec(ctx,
        `insert into transactions(id, merchant_id, mode, idempotency_key, request_hash)
         values ($1, $2, $3, $4, $5)
         on conflict (merchant_id, idempotency_key) do nothing`,
        t.ID, t.MerchantID, t.Mode, t.IdempotencyKey, hash,
    )
    if err != nil {
        return false, fmt.Errorf("ledger: insert transaction: %w", err)
    }
    if tag.RowsAffected() == 0 {
        var existing string
        if err := tx.QueryRow(ctx,
            `select request_hash from transactions where merchant_id = $1 and idempotency_key = $2`,
            t.MerchantID, t.IdempotencyKey,
        ).Scan(&existing); err != nil {
            return false, fmt.Errorf("ledger: load existing transaction: %w", err)
        }
        if existing != hash {
            return false, ErrIdempotencyMismatch
        }
        return true, nil
    }

    accounts := make([]string, len(t.Entries))
    currencies := make([]string, len(t.Entries))
    amounts := make([]int64, len(t.Entries))
    for i, e := range t.Entries {
        accounts[i], currencies[i], amounts[i] = e.Account, e.Currency, e.Amount
    }
    if _, err := tx.Exec(ctx,
        `insert into entries(txn_id, account, currency, amount)
         select $1, a, c, m from unnest($2::text[], $3::text[], $4::bigint[]) as u(a, c, m)`,
        t.ID, accounts, currencies, amounts,
    ); err != nil {
        return false, fmt.Errorf("ledger: insert entries: %w", err)
    }
    return false, nil
}