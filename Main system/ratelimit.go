package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix        = "rl:"
	expectedReplyLen = 3
	allowedFlag      = 1
)

const tokenBucketLua = `
local ttl_slack_ms = 1000
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local t = redis.call("TIME")
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local data = redis.call("HMGET", KEYS[1], "tokens", "ts")
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now
end
tokens = math.min(capacity, tokens + math.max(0, now - ts) * refill / 1000)
local allowed = 0
local retry = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry = math.ceil((1 - tokens) / refill * 1000)
end
redis.call("HSET", KEYS[1], "tokens", tokens, "ts", now)
redis.call("PEXPIRE", KEYS[1], math.ceil(capacity / refill * 1000) + ttl_slack_ms)
return {allowed, math.floor(tokens), retry}
`

var (
	ErrInvalidPolicy        = errors.New("ratelimit: key must be non-empty and policy values must be positive")
	ErrUnexpectedReply      = errors.New("ratelimit: unexpected script reply")
	ErrUnexpectedReplyTypes = errors.New("ratelimit: unexpected script reply types")
)

type Policy struct {
	Capacity  int
	PerMinute int
}

type Result struct {
	Allowed    bool
	Remaining  int64
	RetryAfter time.Duration
}

type Limiter struct {
	rdb    redis.Scripter
	script *redis.Script
}

func New(rdb redis.Scripter) *Limiter {
	return &Limiter{rdb: rdb, script: redis.NewScript(tokenBucketLua)}
}

func (p Policy) valid() bool {
	return p.Capacity > 0 && p.PerMinute > 0
}

func (l *Limiter) Allow(ctx context.Context, key string, p Policy) (Result, error) {
	if key == "" || !p.valid() {
		return Result{}, ErrInvalidPolicy
	}

	refillPerSecond := float64(p.PerMinute) / time.Minute.Seconds()

	vals, err := l.script.Run(ctx, l.rdb, []string{keyPrefix + key}, p.Capacity, refillPerSecond).Slice()
	if err != nil {
		return Result{}, fmt.Errorf("ratelimit: script run for key %q: %w", key, err)
	}
	if len(vals) != expectedReplyLen {
		return Result{}, ErrUnexpectedReply
	}

	allowed, okAllowed := vals[0].(int64)
	remaining, okRemaining := vals[1].(int64)
	retryMS, okRetry := vals[2].(int64)
	if !okAllowed || !okRemaining || !okRetry {
		return Result{}, ErrUnexpectedReplyTypes
	}

	return Result{
		Allowed:    allowed == allowedFlag,
		Remaining:  remaining,
		RetryAfter: time.Duration(retryMS) * time.Millisecond,
	}, nil
}