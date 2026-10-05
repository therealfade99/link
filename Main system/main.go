package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"

	// we need to replace this  with the go.mod i can't do it as of right now i don't have a  way to do it, if  there is a way that is simple let me know. also if some one can do it and add the correct dependencies thank you //
	"module/internal/config"
	"module/internal/webhooks"
)

const (
	workerConcurrency = 20
	sweepEvery        = 15 * time.Second
	sweepTimeout      = 10 * time.Second
	dbPingTimeout     = 5 * time.Second
	unlockTimeout     = 5 * time.Second
	poolHeadroom      = 5
	shutdownTimeout   = 30 * time.Second

	
	// only one replica sweeps at a time we can not reuse it for anything else.
	sweepLockID int64 = 7340210001
)


type sweeper interface {
	Sweep(ctx context.Context) error
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	
	poolCfg.MaxConns = int32(workerConcurrency + poolHeadroom)
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("create db pool: %w", err)
	}
	defer pool.Close()

	pingCtx, cancelPing := context.WithTimeout(ctx, dbPingTimeout)
	defer cancelPing()
	if err := pool.Ping(pingCtx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	
	redisOpt := asynq.RedisClientOpt{
		Addr:      cfg.RedisAddr,
		Password:  cfg.RedisPassword,
		DB:        cfg.RedisDB,
		TLSConfig: cfg.RedisTLS,
	}
	asynqClient := asynq.NewClient(redisOpt)
	defer asynqClient.Close()

	mux := asynq.NewServeMux()
	mux.Handle(webhooks.TaskType, webhooks.NewHandler(pool, webhooks.NewHTTPClient(cfg.AllowPrivateWebhooks)))

	srv := asynq.NewServer(redisOpt, asynq.Config{
		Concurrency:     workerConcurrency,
		RetryDelayFunc:  webhooks.RetryDelay,
		ShutdownTimeout: shutdownTimeout,
		ErrorHandler: asynq.ErrorHandlerFunc(func(ctx context.Context, task *asynq.Task, err error) {
			slog.Error("task failed", "type", task.Type(), "err", err)
		}),
	})
	if err := srv.Start(mux); err != nil {
		return fmt.Errorf("start asynq server: %w", err)
	}
	defer srv.Shutdown()
	slog.Info("worker started", "concurrency", workerConcurrency)

	enqueuer := webhooks.NewEnqueuer(pool, asynqClient)
	runSweep := func() {
		if err := sweepOnce(ctx, pool, enqueuer); err != nil {
			slog.Error("sweep failed", "err", err)
		}
	}

	ticker := time.NewTicker(sweepEvery)
	defer ticker.Stop()

	
	runSweep()
	for {
		select {
		case <-ctx.Done():
			stop()
			slog.Info("shutting down")
			return nil
		case <-ticker.C:
			runSweep()
		}
	}
}


func sweepOnce(ctx context.Context, pool *pgxpool.Pool, s sweeper) error {
	ctx, cancel := context.WithTimeout(ctx, sweepTimeout)
	defer cancel()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire lock connection: %w", err)
	}
	defer conn.Release()

	var locked bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", sweepLockID).Scan(&locked); err != nil {
		return fmt.Errorf("try advisory lock: %w", err)
	}
	if !locked {
		return nil
	}
	defer func() {
		unlockCtx, cancelUnlock := context.WithTimeout(context.Background(), unlockTimeout)
		defer cancelUnlock()
		if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", sweepLockID); err != nil {
			slog.Error("release sweep lock", "err", err)
			if closeErr := conn.Hijack().Close(unlockCtx); closeErr != nil {
				slog.Error("close lock connection", "err", closeErr)
			}
		}
	}()

	if err := s.Sweep(ctx); err != nil {
		return fmt.Errorf("sweep: %w", err)
	}
	return nil
}