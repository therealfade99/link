import crypto from "node:crypto";
import express from "express";

const KEY_BYTES = 32;
const PREFIX_LENGTH = 12;

const hash = (k) => crypto.createHash("sha256").update(k).digest("hex");

export async function createKey(pool, { merchantId, mode }) {
  const secret = crypto.randomBytes(KEY_BYTES).toString("base64url");
  const key = `sk_${mode}_${secret}`;
  const id = `key_${crypto.randomUUID()}`;
  await pool.query(
    "insert into api_keys(id, merchant_id, key_hash, prefix, mode) values($1,$2,$3,$4,$5)",
    [id, merchantId, hash(key), key.slice(0, PREFIX_LENGTH), mode]
  );
  return { id, key, prefix: key.slice(0, PREFIX_LENGTH) };
}

export function requireKey(pool) {
  return async (req, res, next) => {
    const m = /^Bearer (sk_(?:test|live)_[\w-]+)$/.exec(req.get("authorization") || "");
    if (!m) return res.status(401).json({ error: "invalid_api_key" });

    const { rows } = await pool.query(
      "select id, merchant_id, mode from api_keys where key_hash = $1 and revoked_at is null",
      [hash(m[1])]
    );
    if (!rows[0]) return res.status(401).json({ error: "invalid_api_key" });

    pool.query(
      "update api_keys set last_used_at = now() where id = $1 and (last_used_at is null or last_used_at < now() - interval '1 minute')",
      [rows[0].id]
    ).catch(() => {});
    req.auth = { merchantId: rows[0].merchant_id, mode: rows[0].mode, keyId: rows[0].id };
    next();
  };
}

export function apiKeyRouter(pool) {
  const router = express.Router();
  router.use(requireKey(pool));

  router.post("/", express.json(), async (req, res) => {
    const mode = req.body?.mode === "live" ? "live" : "test";
    if (mode === "live" && req.auth.mode !== "live") {
      return res.status(403).json({ error: "live_key_required" });
    }
    const out = await createKey(pool, { merchantId: req.auth.merchantId, mode });
    res.status(201).json(out);
  });

  router.get("/", async (req, res) => {
    const { rows } = await pool.query(
      "select id, prefix, mode, created_at, last_used_at, revoked_at from api_keys where merchant_id = $1 order by created_at desc",
      [req.auth.merchantId]
    );
    res.json({ data: rows });
  });

  router.delete("/:id", async (req, res) => {
    const r = await pool.query(
      "update api_keys set revoked_at = now() where id = $1 and merchant_id = $2 and revoked_at is null",
      [req.params.id, req.auth.merchantId]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: "not_found" });
    res.status(204).end();
  });

  return router;
}