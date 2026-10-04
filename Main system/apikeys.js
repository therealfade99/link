import crypto from "node:crypto";

const hash = (k) => crypto.createHash("sha256").update(k).digest("hex");
export async function createKey(pool, { merchantId, mode }) {
  const secret = crypto.randomBytes(32).toString("base64url");
  const key = `sk_${mode}_${secret}`;
  const id = `key_${crypto.randomUUID()}`;
  await pool.query(
    "insert into api_keys(id, merchant_id, key_hash, prefix, mode) values($1,$2,$3,$4,$5)",
    [id, merchantId, hash(key), key.slice(0, 12), mode]
  );
  return { id, key, prefix: key.slice(0, 12) }; 
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

    pool.query("update api_keys set last_used_at = now() where id = $1", [rows[0].id]).catch(() => {});
    req.auth = { merchantId: rows[0].merchant_id, mode: rows[0].mode, keyId: rows[0].id };
    next();
  };
}