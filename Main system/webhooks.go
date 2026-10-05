package webhooks

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	TaskType  = "webhook:deliver"
	QueueName = "webhooks"

	ModeLive = "live"
	ModeTest = "test"

	MaxRetries = 6

	secretPrefix = "whsec_"
	secretBytes  = 32
	maxURLLen    = 2048

	maxDrainBytes   = 1 << 16
	deliveryTimeout = 10 * time.Second
	taskTimeout     = 30 * time.Second
	dialTimeout     = 5 * time.Second
	tlsTimeout      = 5 * time.Second
	headerTimeout   = 8 * time.Second
	idleTimeout     = 90 * time.Second
	recordTimeout   = 5 * time.Second
	healthTimeout   = 5 * time.Second
	maxIdleConns    = 100
	maxIdlePerHost  = 4

	sweepGrace    = 30 * time.Second
	sweepLease    = 2 * time.Minute
	sweepInterval = 15 * time.Second
	sweepBatch    = 100

	dedupeRetention          = 24 * time.Hour
	rotationOverlap          = 24 * time.Hour
	disableAfterFailedEvents = 25

	userAgent       = "Webhooks/1.0"
	signatureHeader = "Webhook-Signature"
	eventIDHeader   = "Webhook-Event-Id"

	eventColumns = "id, merchant_id, mode, type, payload, created_at"

	sweepClaimQuery = `update events
		set sweep_claimed_at = now()
		where id in (
			select id from events
			where enqueued_at is null
				and created_at < now() - make_interval(secs => $1)
				and (sweep_claimed_at is null or sweep_claimed_at < now() - make_interval(secs => $2))
			order by created_at
			limit $3
			for update skip locked
		)
		returning ` + eventColumns
)

var (
	backoff = []time.Duration{
		1 * time.Minute,
		5 * time.Minute,
		30 * time.Minute,
		2 * time.Hour,
		6 * time.Hour,
		24 * time.Hour,
	}

	ErrBlockedAddress = errors.New("destination address not allowed")

	errInvalidTarget       = errors.New("invalid delivery target")
	errEndpointUnavailable = errors.New("endpoint unavailable")
	errSecretDecrypt       = errors.New("webhook secret could not be decrypted")

	blockedNets = []*net.IPNet{
		mustCIDR("0.0.0.0/8"),
		mustCIDR("100.64.0.0/10"),
		mustCIDR("192.0.0.0/24"),
		mustCIDR("192.0.2.0/24"),
		mustCIDR("198.18.0.0/15"),
		mustCIDR("198.51.100.0/24"),
		mustCIDR("203.0.113.0/24"),
		mustCIDR("240.0.0.0/4"),
		mustCIDR("100::/64"),
		mustCIDR("64:ff9b::/96"),
		mustCIDR("64:ff9b:1::/48"),
		mustCIDR("2001::/32"),
		mustCIDR("2001:db8::/32"),
		mustCIDR("2002::/16"),
		mustCIDR("fec0::/10"),
	}
)

type Event struct {
	ID         string
	MerchantID string
	Mode       string
	Type       string
	Payload    json.RawMessage
	CreatedAt  time.Time
}

type taskPayload struct {
	EventID    string `json:"event_id"`
	EndpointID string `json:"endpoint_id"`
}

type Observer interface {
	DeliveryFinished(outcome string, status int, elapsed time.Duration)
}

type Notifier interface {
	EndpointDisabled(ctx context.Context, merchantID, endpointID string)
}

type noopObserver struct{}

func (noopObserver) DeliveryFinished(string, int, time.Duration) {}

type noopNotifier struct{}

func (noopNotifier) EndpointDisabled(context.Context, string, string) {}

type SecretBox struct {
	aeads []cipher.AEAD
}

func NewSecretBox(keys ...[]byte) (*SecretBox, error) {
	if len(keys) == 0 {
		return nil, errors.New("webhooks: at least one encryption key is required")
	}
	aeads := make([]cipher.AEAD, 0, len(keys))
	for _, key := range keys {
		if len(key) != 32 {
			return nil, errors.New("webhooks: encryption keys must be 32 bytes")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("webhooks: build cipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("webhooks: build gcm: %w", err)
		}
		aeads = append(aeads, gcm)
	}
	return &SecretBox{aeads: aeads}, nil
}

func (b *SecretBox) Encrypt(secret, endpointID string) ([]byte, error) {
	aead := b.aeads[0]
	nonce := make([]byte, aead.NonceSize())
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, fmt.Errorf("webhooks: read nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, []byte(secret), []byte(endpointID)), nil
}

func (b *SecretBox) Decrypt(blob []byte, endpointID string) (string, error) {
	for _, aead := range b.aeads {
		size := aead.NonceSize()
		if len(blob) < size {
			continue
		}
		plain, err := aead.Open(nil, blob[:size], blob[size:], []byte(endpointID))
		if err == nil {
			return string(plain), nil
		}
	}
	return "", errSecretDecrypt
}

func NewSecret() (string, error) {
	raw := make([]byte, secretBytes)
	if _, err := cryptorand.Read(raw); err != nil {
		return "", fmt.Errorf("webhooks: generate secret: %w", err)
	}
	return secretPrefix + hex.EncodeToString(raw), nil
}

func Body(e Event) ([]byte, error) {
	return json.Marshal(struct {
		ID       string          `json:"id"`
		Type     string          `json:"type"`
		Created  int64           `json:"created"`
		Livemode bool            `json:"livemode"`
		Data     json.RawMessage `json:"data"`
	}{e.ID, e.Type, e.CreatedAt.Unix(), e.Mode == ModeLive, e.Payload})
}

func Sign(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func SignatureHeaderMulti(secrets []string, ts int64, body []byte) string {
	var b strings.Builder
	b.WriteString("t=")
	b.WriteString(strconv.FormatInt(ts, 10))
	for _, secret := range secrets {
		b.WriteString(",v1=")
		b.WriteString(Sign(secret, ts, body))
	}
	return b.String()
}

func SignatureHeader(secret string, ts int64, body []byte) string {
	return SignatureHeaderMulti([]string{secret}, ts, body)
}

func ValidateEndpointURL(raw, mode string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > maxURLLen || u.Hostname() == "" || u.User != nil {
		return errors.New("invalid url")
	}
	httpAllowed := mode == ModeTest && u.Scheme == "http"
	if u.Scheme != "https" && !httpAllowed {
		return errors.New("url must use https")
	}
	return nil
}

func CheckDestination(ctx context.Context, raw string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return errors.New("invalid url")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if isBlocked(ip) {
			return ErrBlockedAddress
		}
		return nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addrs) == 0 {
		return errors.New("hostname does not resolve")
	}
	for _, addr := range addrs {
		if isBlocked(addr.IP) {
			return ErrBlockedAddress
		}
	}
	return nil
}

func InsertEvent(ctx context.Context, tx pgx.Tx, e Event) error {
	if !json.Valid(e.Payload) {
		return errors.New("webhooks: event payload is not valid json")
	}
	_, err := tx.Exec(ctx,
		`insert into events(id, merchant_id, mode, type, payload, created_at)
		 values ($1, $2, $3, $4, $5, $6)`,
		e.ID, e.MerchantID, e.Mode, e.Type, e.Payload, e.CreatedAt,
	)
	return err
}

func ReenableEndpoint(ctx context.Context, pool *pgxpool.Pool, merchantID, endpointID string) error {
	tag, err := pool.Exec(ctx,
		`update webhook_endpoints
		 set active = true, consecutive_failures = 0, disabled_at = null
		 where id = $1 and merchant_id = $2`,
		endpointID, merchantID,
	)
	if err != nil {
		return fmt.Errorf("reenable endpoint: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func RotateSecret(ctx context.Context, pool *pgxpool.Pool, box *SecretBox, merchantID, endpointID string) (string, error) {
	secret, err := NewSecret()
	if err != nil {
		return "", err
	}
	sealed, err := box.Encrypt(secret, endpointID)
	if err != nil {
		return "", err
	}
	tag, err := pool.Exec(ctx,
		`update webhook_endpoints
		 set previous_secret_enc = secret_enc,
		     previous_secret_expires_at = now() + make_interval(secs => $4),
		     secret_enc = $3
		 where id = $1 and merchant_id = $2`,
		endpointID, merchantID, sealed, rotationOverlap.Seconds(),
	)
	if err != nil {
		return "", fmt.Errorf("rotate secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return "", pgx.ErrNoRows
	}
	return secret, nil
}

func RetryDelay(n int, _ error, _ *asynq.Task) time.Duration {
	idx := n
	if idx < 0 {
		idx = 0
	}
	if idx > len(backoff)-1 {
		idx = len(backoff) - 1
	}
	base := backoff[idx]
	return base + time.Duration(mathrand.Int64N(int64(base)/5))
}

type Enqueuer struct {
	pool   *pgxpool.Pool
	client *asynq.Client
}

func NewEnqueuer(pool *pgxpool.Pool, client *asynq.Client) *Enqueuer {
	return &Enqueuer{pool: pool, client: client}
}

func (e *Enqueuer) Enqueue(ctx context.Context, ev Event) error {
	rows, err := e.pool.Query(ctx,
		`select id from webhook_endpoints where merchant_id = $1 and mode = $2 and active`,
		ev.MerchantID, ev.Mode,
	)
	if err != nil {
		return fmt.Errorf("list endpoints: %w", err)
	}
	endpointIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("collect endpoints: %w", err)
	}

	var errs []error
	for _, endpointID := range endpointIDs {
		payload, err := json.Marshal(taskPayload{EventID: ev.ID, EndpointID: endpointID})
		if err != nil {
			errs = append(errs, fmt.Errorf("encode task: %w", err))
			continue
		}
		_, err = e.client.EnqueueContext(ctx,
			asynq.NewTask(TaskType, payload),
			asynq.Queue(QueueName),
			asynq.TaskID(ev.ID+":"+endpointID),
			asynq.MaxRetry(MaxRetries),
			asynq.Timeout(taskTimeout),
			asynq.Retention(dedupeRetention),
		)
		if err != nil && !errors.Is(err, asynq.ErrTaskIDConflict) {
			errs = append(errs, fmt.Errorf("enqueue %s: %w", endpointID, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	_, err = e.pool.Exec(ctx,
		`update events set enqueued_at = now() where id = $1 and enqueued_at is null`,
		ev.ID,
	)
	if err != nil {
		return fmt.Errorf("mark enqueued: %w", err)
	}
	return nil
}

func (e *Enqueuer) Sweep(ctx context.Context) error {
	rows, err := e.pool.Query(ctx, sweepClaimQuery,
		sweepGrace.Seconds(), sweepLease.Seconds(), sweepBatch,
	)
	if err != nil {
		return fmt.Errorf("claim events: %w", err)
	}
	pending, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Event])
	if err != nil {
		return fmt.Errorf("collect events: %w", err)
	}

	var errs []error
	for _, ev := range pending {
		if err := e.Enqueue(ctx, ev); err != nil {
			errs = append(errs, fmt.Errorf("event %s: %w", ev.ID, err))
		}
	}
	if len(pending) > 0 {
		slog.InfoContext(ctx, "webhook sweep finished", "claimed", len(pending), "failed", len(errs))
	}
	return errors.Join(errs...)
}

func (e *Enqueuer) RunSweeper(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.Sweep(ctx); err != nil {
				slog.ErrorContext(ctx, "webhook sweep failed", "err", err)
			}
		}
	}
}

type Handler struct {
	pool     *pgxpool.Pool
	client   *http.Client
	secrets  *SecretBox
	observer Observer
	notifier Notifier
	now      func() time.Time
}

type Option func(*Handler)

func WithObserver(o Observer) Option {
	return func(h *Handler) { h.observer = o }
}

func WithNotifier(n Notifier) Option {
	return func(h *Handler) { h.notifier = n }
}

func WithClock(now func() time.Time) Option {
	return func(h *Handler) { h.now = now }
}

func NewHandler(pool *pgxpool.Pool, client *http.Client, secrets *SecretBox, opts ...Option) *Handler {
	h := &Handler{
		pool:     pool,
		client:   client,
		secrets:  secrets,
		observer: noopObserver{},
		notifier: noopNotifier{},
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

type endpoint struct {
	url     string
	secrets []string
}

func (h *Handler) ProcessTask(ctx context.Context, t *asynq.Task) error {
	var tp taskPayload
	if err := json.Unmarshal(t.Payload(), &tp); err != nil {
		return fmt.Errorf("bad task payload: %w", asynq.SkipRetry)
	}

	ev, err := h.loadEvent(ctx, tp.EventID)
	if err != nil {
		return err
	}
	ep, err := h.loadEndpoint(ctx, ev, tp.EndpointID)
	if err != nil {
		return err
	}
	body, err := Body(ev)
	if err != nil {
		return fmt.Errorf("encode event: %w", asynq.SkipRetry)
	}

	started := h.now()
	status, deliverErr := h.post(ctx, ep.url, ep.secrets, ev.ID, started.Unix(), body)
	elapsed := h.now().Sub(started)

	outcome, message := classify(status, deliverErr)
	retried, ok := asynq.GetRetryCount(ctx)
	if !ok {
		retried = 0
	}
	maxRetry, ok := asynq.GetMaxRetry(ctx)
	if !ok {
		maxRetry = MaxRetries
	}

	detached := context.WithoutCancel(ctx)
	h.record(detached, ev.ID, tp.EndpointID, retried+1, status, message)
	h.observer.DeliveryFinished(outcome, status, elapsed)

	logger := slog.With(
		"event_id", ev.ID,
		"endpoint_id", tp.EndpointID,
		"host", hostOf(ep.url),
		"attempt", retried+1,
		"outcome", outcome,
		"status", status,
		"elapsed_ms", elapsed.Milliseconds(),
	)

	if deliverErr == nil {
		logger.DebugContext(ctx, "webhook delivered")
		h.markHealthy(detached, tp.EndpointID)
		return nil
	}

	permanent := isPermanent(deliverErr)
	logger.WarnContext(ctx, "webhook delivery failed", "permanent", permanent)
	if permanent || retried >= maxRetry {
		h.markFailed(detached, ev.MerchantID, tp.EndpointID)
	}
	if permanent {
		return fmt.Errorf("%s: %w", message, asynq.SkipRetry)
	}
	return errors.New(message)
}

func (h *Handler) loadEvent(ctx context.Context, id string) (Event, error) {
	var ev Event
	err := h.pool.QueryRow(ctx,
		"select "+eventColumns+" from events where id = $1", id,
	).Scan(&ev.ID, &ev.MerchantID, &ev.Mode, &ev.Type, &ev.Payload, &ev.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Event{}, fmt.Errorf("event not found: %w", asynq.SkipRetry)
	}
	if err != nil {
		return Event{}, fmt.Errorf("load event: %w", err)
	}
	return ev, nil
}

func (h *Handler) loadEndpoint(ctx context.Context, ev Event, endpointID string) (endpoint, error) {
	var (
		target          string
		current         []byte
		previous        []byte
		previousExpires *time.Time
		active          bool
	)
	err := h.pool.QueryRow(ctx,
		`select url, secret_enc, previous_secret_enc, previous_secret_expires_at, active
		 from webhook_endpoints
		 where id = $1 and merchant_id = $2 and mode = $3`,
		endpointID, ev.MerchantID, ev.Mode,
	).Scan(&target, &current, &previous, &previousExpires, &active)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !active) {
		return endpoint{}, fmt.Errorf("%w: %w", errEndpointUnavailable, asynq.SkipRetry)
	}
	if err != nil {
		return endpoint{}, fmt.Errorf("load endpoint: %w", err)
	}

	secret, err := h.secrets.Decrypt(current, endpointID)
	if err != nil {
		slog.ErrorContext(ctx, "webhook secret decrypt failed", "endpoint_id", endpointID)
		return endpoint{}, fmt.Errorf("%w: %w", errSecretDecrypt, asynq.SkipRetry)
	}
	secrets := []string{secret}

	if len(previous) > 0 && previousExpires != nil && previousExpires.After(h.now()) {
		old, err := h.secrets.Decrypt(previous, endpointID)
		if err != nil {
			slog.WarnContext(ctx, "previous webhook secret decrypt failed", "endpoint_id", endpointID)
		} else {
			secrets = append(secrets, old)
		}
	}
	return endpoint{url: target, secrets: secrets}, nil
}

func (h *Handler) post(ctx context.Context, target string, secrets []string, eventID string, ts int64, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errInvalidTarget, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set(signatureHeader, SignatureHeaderMulti(secrets, ts, body))
	req.Header.Set(eventIDHeader, eventID)

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return resp.StatusCode, fmt.Errorf("endpoint returned status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func (h *Handler) record(ctx context.Context, eventID, endpointID string, attempt, status int, message string) {
	ctx, cancel := context.WithTimeout(ctx, recordTimeout)
	defer cancel()

	var code *int
	if status != 0 {
		code = &status
	}
	var msg *string
	if message != "" {
		msg = &message
	}
	_, err := h.pool.Exec(ctx,
		`insert into webhook_attempts(event_id, endpoint_id, attempt, status_code, error)
		 values ($1, $2, $3, $4, $5)`,
		eventID, endpointID, attempt, code, msg,
	)
	if err != nil {
		slog.ErrorContext(ctx, "webhook attempt not recorded",
			"event_id", eventID, "endpoint_id", endpointID, "attempt", attempt, "err", err)
	}
}

func (h *Handler) markHealthy(ctx context.Context, endpointID string) {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()

	_, err := h.pool.Exec(ctx,
		`update webhook_endpoints set consecutive_failures = 0
		 where id = $1 and consecutive_failures <> 0`,
		endpointID,
	)
	if err != nil {
		slog.ErrorContext(ctx, "webhook health reset failed", "endpoint_id", endpointID, "err", err)
	}
}

func (h *Handler) markFailed(ctx context.Context, merchantID, endpointID string) {
	dbCtx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()

	var disabled bool
	err := h.pool.QueryRow(dbCtx,
		`update webhook_endpoints
		 set consecutive_failures = consecutive_failures + 1,
		     disabled_at = case
		         when active and consecutive_failures + 1 >= $2 then now()
		         else disabled_at
		     end,
		     active = active and consecutive_failures + 1 < $2
		 where id = $1
		 returning coalesce(disabled_at = now(), false)`,
		endpointID, disableAfterFailedEvents,
	).Scan(&disabled)
	if err != nil {
		slog.ErrorContext(ctx, "webhook health update failed", "endpoint_id", endpointID, "err", err)
		return
	}
	if disabled {
		slog.WarnContext(ctx, "webhook endpoint disabled after repeated failures",
			"merchant_id", merchantID, "endpoint_id", endpointID)
		h.notifier.EndpointDisabled(ctx, merchantID, endpointID)
	}
}

func classify(status int, err error) (string, string) {
	if err == nil {
		return "success", ""
	}
	if errors.Is(err, ErrBlockedAddress) {
		return "blocked", ErrBlockedAddress.Error()
	}
	if errors.Is(err, errInvalidTarget) {
		return "invalid_url", "invalid delivery url"
	}
	if status != 0 {
		return "http_error", fmt.Sprintf("endpoint returned status %d", status)
	}

	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr):
		return "dns", "dns lookup failed"
	case errors.As(err, &certErr):
		return "tls", "tls certificate verification failed"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout", "request timed out"
	default:
		return "network", "connection failed"
	}
}

func isPermanent(err error) bool {
	return errors.Is(err, ErrBlockedAddress) || errors.Is(err, errInvalidTarget)
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func NewHTTPClient(allowPrivate bool) *http.Client {
	if allowPrivate {
		slog.Warn("webhook http client permits private destinations")
	}
	dialer := &net.Dialer{
		Timeout: dialTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			if allowPrivate {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || isBlocked(ip) {
				return ErrBlockedAddress
			}
			return nil
		},
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: headerTimeout,
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdlePerHost,
		IdleConnTimeout:       idleTimeout,
	}
	return &http.Client{
		Timeout:   deliveryTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func isBlocked(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}