import crypto from "node:crypto";
import express from "express";

const KEY_BYTES = 32;
const PREFIX_LENGTH = 12;
const SECRET_CHARS = Math.ceil((KEY_BYTES * 4) / 3); // base64url length of KEY_BYTES, no padding
const TOUCH_INTERVAL_MS = 60_000;
const MODES = ["live", "test"];

const keyPattern = new RegExp(`^Bearer (sk_(?:test|live)_[A-Za-z0-9_-]{${SECRET_CHARS}})$`);
const lastTouched = new Map();

const hash = (k) => crypto.createHash("sha256").update(k).digest("hex");

const wrap = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);

export async function createKey(pool, { merchantId, mode }) {
  if (!MODES.includes(mode)) throw new Error(`invalid key mode: ${mode}`);
  const secret = crypto.randomBytes(KEY_BYTES).toString("base64url");
  const key = `sk_${mode}_${secret}`;
  const id = `key_${crypto.randomUUID()}`;
  const prefix = key.slice(0, PREFIX_LENGTH);
  await pool.query(
    "insert into api_keys(id, merchant_id, key_hash, prefix, mode) values($1,$2,$3,$4,$5)",
    [id, merchantId, hash(key), prefix, mode]
  );
  return { id, key, prefix };
}

function touchKey(pool, keyId, logger) {
  const now = Date.now();
  if (now - (lastTouched.get(keyId) ?? 0) < TOUCH_INTERVAL_MS) return;
  lastTouched.set(keyId, now); 
  pool
    .query(
      "update api_keys set last_used_at = now() where id = $1 and (last_used_at is null or last_used_at < now() - make_interval(secs => $2))",
      [keyId, TOUCH_INTERVAL_MS / 1000]
    )
    .catch((err) => logger.warn({ err, keyId }, "api_key_touch_failed"));
}

export function requireKey(pool, { logger = console } = {}) {
  return wrap(async (req, res, next) => {
    const match = keyPattern.exec(req.get("authorization") || "");
    if (!match) return res.status(401).json({ error: "invalid_api_key" });

    const { rows } = await pool.query(
      "select id, merchant_id, mode from api_keys where key_hash = $1 and revoked_at is null",
      [hash(match[1])]
    );
    const found = rows[0];
    if (!found) return res.status(401).json({ error: "invalid_api_key" });

    touchKey(pool, found.id, logger);
    req.auth = { merchantId: found.merchant_id, mode: found.mode, keyId: found.id };
    next();
  });
}

const requireLive = (req, res, next) =>
  req.auth.mode === "live" ? next() : res.status(403).json({ error: "live_key_required" });

function manageKeys(pool, mode) {
  const router = express.Router();

  router.post(
    "/",
    wrap(async (req, res) => {
      const out = await createKey(pool, { merchantId: req.auth.merchantId, mode });
      res.set("Cache-Control", "no-store");
      res.status(201).json(out);
    })
  );

  router.get(
    "/",
    wrap(async (req, res) => {
      const { rows } = await pool.query(
        "select id, prefix, mode, created_at, last_used_at, revoked_at from api_keys where merchant_id = $1 and mode = $2 order by created_at desc",
        [req.auth.merchantId, mode]
      );
      res.json({ data: rows });
    })
  );

  router.delete(
    "/:id",
    wrap(async (req, res) => {
      const result = await pool.query(
        "update api_keys set revoked_at = now() where id = $1 and merchant_id = $2 and mode = $3 and revoked_at is null",
        [req.params.id, req.auth.merchantId, mode]
      );
      if (result.rowCount === 0) return res.status(404).json({ error: "not_found" });
      res.status(204).end();
    })
  );

  return router;
}

export function apiKeyRouter(pool, { logger = console } = {}) {
  const router = express.Router();
  router.use(requireKey(pool, { logger }));

  const testArea = manageKeys(pool, "test");
  testArea.use((req, res) => res.status(404).json({ error: "not_found" })); 
  router.use("/test", testArea);

  router.use(requireLive);
  router.use(manageKeys(pool, "live"));

  return router;
}