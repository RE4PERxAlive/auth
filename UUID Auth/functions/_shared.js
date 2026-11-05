// ================================================================
// AzureGuard Auth - shared helpers for Cloudflare Pages Functions
// Data persists in Workers KV (free tier: 100k reads / 1k writes/day)
// ================================================================

export const DEFAULT_OWNER_ID = "e4b3c2a1-8765-4321-90ab-cdef12345678";
export const DEFAULT_SECRET_KEY = "bloody_sec_9f8e7d6c5b4a39281706f5e4d3c2b1a";

export const KV_UUIDS = "uuids"; // JSON array of registered systems
export const KV_META = "meta";   // JSON { owner_id, secret_key }

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Cache-Control": "no-store, no-cache, must-revalidate",
};

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

export function corsResponse() {
  return new Response(null, { status: 204, headers: CORS });
}

export function generateSecret() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let hex = "";
  for (let i = 0; i < 16; i++) {
    hex += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return "bloody_sec_" + hex;
}

export async function readDb(env) {
  try {
    const raw = await env.UUID_DB.get(KV_UUIDS);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

export async function writeDb(env, db) {
  await env.UUID_DB.put(KV_UUIDS, JSON.stringify(db));
}

export async function readMeta(env) {
  try {
    const raw = await env.UUID_DB.get(KV_META);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.owner_id && parsed.secret_key) return parsed;
    }
  } catch (e) {}
  return { owner_id: DEFAULT_OWNER_ID, secret_key: DEFAULT_SECRET_KEY };
}

// Mark entries whose access window has passed. Only writes to KV when
// something actually changed (keeps free-tier write quota low).
export async function markExpired(env, db) {
  const now = Math.floor(Date.now() / 1000);
  let changed = false;
  for (const item of db) {
    const exp = Number(item.expireTimestamp) || 0;
    if (exp > 0 && now > exp && item.status === "Active") {
      item.status = "Expired";
      changed = true;
    }
  }
  if (changed) await writeDb(env, db);
  return db;
}
