// ================================================================
// AzureGuard Auth - /api/keys endpoint (Cloudflare Pages Function)
// GET  /api/keys        -> list all registered UUIDs
// POST /api/keys        -> { action: 'add'|'toggle'|'delete'|'save_all'|'regenerate_meta', ... }
// Data persists in Workers KV under key "uuids" / "meta".
// ================================================================
import { json, corsResponse, readDb, writeDb, markExpired, readMeta, KV_META, generateSecret } from "../_shared.js";

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") return corsResponse();

  if (request.method === "GET") {
    const db = await markExpired(env, await readDb(env));
    return json(db);
  }

  if (request.method === "POST") {
    let payload;
    try {
      payload = await request.json();
    } catch (e) {
      return json({ success: false, message: "Invalid JSON body" }, 400);
    }

    const db = await readDb(env);
    const action = payload.action;
    const now = new Date();

    if (action === "add") {
      const days = parseInt(payload.days, 10) || 30;
      const sysUuid = (payload.system_uuid || payload.uuid || "").trim().toUpperCase();
      if (!sysUuid) return json({ success: false, message: "Missing system_uuid" }, 400);

      let expireTimestamp = 0;
      let expiresFormatted = "Lifetime";
      if (days > 0) {
        const exp = new Date(now.getTime() + days * 86400000);
        expireTimestamp = Math.floor(exp.getTime() / 1000);
        expiresFormatted = exp.toISOString().slice(0, 16).replace("T", " ");
      }

      const existing = db.find(x => (x.system_uuid || x.uuid || "").toUpperCase() === sysUuid);
      if (existing) {
        existing.user = payload.user || existing.user || "Client";
        existing.durationDays = days;
        existing.expireTimestamp = expireTimestamp;
        existing.expiresFormatted = expiresFormatted;
        existing.status = "Active";
      } else {
        db.unshift({
          system_uuid: sysUuid,
          uuid: sysUuid,
          user: payload.user || "Client",
          durationDays: days,
          expireTimestamp: expireTimestamp,
          expiresFormatted: expiresFormatted,
          status: "Active",
          createdAt: now.toISOString().slice(0, 16).replace("T", " "),
        });
      }
    } else if (action === "toggle") {
      const target = (payload.system_uuid || payload.uuid || "").trim().toUpperCase();
      for (const item of db) {
        if ((item.system_uuid || item.uuid || "").toUpperCase() === target) {
          item.status = item.status === "Active" ? "Revoked" : "Active";
        }
      }
    } else if (action === "delete") {
      const target = (payload.system_uuid || payload.uuid || "").trim().toUpperCase();
      const next = db.filter(item => (item.system_uuid || item.uuid || "").toUpperCase() !== target);
      db.length = 0;
      db.push(...next);
    } else if (action === "save_all" || action === "sync") {
      if (Array.isArray(payload.keys)) {
        db.length = 0;
        db.push(...payload.keys.map(k => ({
          ...k,
          system_uuid: (k.system_uuid || k.uuid || "").toUpperCase(),
          uuid: (k.uuid || k.system_uuid || "").toUpperCase(),
        })));
      }
    } else if (action === "regenerate_meta") {
      const meta = await readMeta(env);
      meta.secret_key = generateSecret();
      await env.UUID_DB.put(KV_META, JSON.stringify(meta));
      await writeDb(env, db);
      return json({ success: true, keys: db, meta });
    } else {
      return json({ success: false, message: "Unknown action" }, 400);
    }

    await writeDb(env, db);
    return json({ success: true, keys: db });
  }

  return json({ success: false, message: "Method not allowed" }, 405);
}
