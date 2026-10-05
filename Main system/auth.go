package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

)

const (
	prefixLen    = 12
	touchTimeout = 2 * time.Second
)

var (
	ErrInvalidKey  = errors.New("auth: invalid api key")
	ErrInvalidMode = errors.New("auth: mode must be test or live")

	keyPattern = regexp.MustCompile(fmt.Sprintf(`^sk_(?:test|live)_[A-Za-z0-9_-]{%d}$`, ids.SecretChars))
)

type Principal struct {
	KeyID      string
	MerchantID string
	Mode       string
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func (s *Store) Authenticate(ctx context.Context, header string) (Principal, error) {
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || !keyPattern.MatchString(token) {
		return Principal{}, ErrInvalidKey
	}

	var p Principal
	err := s.pool.QueryRow(ctx,
		`select id, merchant_id, mode from api_keys where key_hash = $1 and revoked_at is null`,
		HashKey(token),
	).Scan(&p.KeyID, &p.MerchantID, &p.Mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrInvalidKey
	}
	if err != nil {
		return Principal{}, err
	}

	go s.touch(p.KeyID)
	return p, nil
}

func (s *Store) touch(keyID string) {
	ctx, cancel := context.WithTimeout(context.Background(), touchTimeout)
	defer cancel()
	_, _ = s.pool.Exec(ctx,
		`update api_keys set last_used_at = now()
		 where id = $1 and (last_used_at is null or last_used_at < now() - interval '1 minute')`,
		keyID,
	)
}

func (s *Store) Create(ctx context.Context, merchantID, mode string) (id, key string, err error) {
	if mode != "test" && mode != "live" {
		return "", "", ErrInvalidMode
	}
	key = ids.Secret("sk_" + mode + "_")
	id = ids.New("key_")
	_, err = s.pool.Exec(ctx,
		`insert into api_keys(id, merchant_id, key_hash, prefix, mode) values ($1, $2, $3, $4, $5)`,
		id, merchantID, HashKey(key), key[:prefixLen], mode,
	)
	if err != nil {
		return "", "", err
	}
	return id, key, nil
}