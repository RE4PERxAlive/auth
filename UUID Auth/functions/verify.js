// ================================================================
// AzureGuard Auth - /verify endpoint (Cloudflare Pages Function)
// Used by C++ / C# desktop clients:
//   GET /verify?owner_id=...&secret_key=...&system_uuid=...
// Returns { status: 1, message, user, expires } when authorized.
// ================================================================
import { json, corsResponse, readDb, markExpired, readMeta, DEFAULT_OWNER_ID, DEFAULT_SECRET_KEY } from "./_shared.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const params = url.searchParams;

  const ownerId = (params.get("owner_id") || "").trim();
  const secretKey = (params.get("secret_key") || "").trim();
  const systemUuid = (params.get("system_uuid") || params.get("hwid") || params.get("uuid") || "").trim().toUpperCase();

  const meta = await readMeta(env);
  const validOwner = meta.owner_id || DEFAULT_OWNER_ID;
  const validSecret = meta.secret_key || DEFAULT_SECRET_KEY;

  if (ownerId && ownerId !== validOwner) {
    return json({ status: 0, message: "Invalid Owner ID" });
  }
  if (secretKey && secretKey !== validSecret) {
    return json({ status: 0, message: "Invalid Secret Key" });
  }
  if (!systemUuid) {
    return json({ status: 0, message: "Missing System UUID" });
  }

  const db = await markExpired(env, await readDb(env));
  const found = db.find(item => (item.system_uuid || item.uuid || "").trim().toUpperCase() === systemUuid);

  if (!found) {
    return json({ status: 0, message: "System UUID is not registered" });
  }
  if (found.status === "Revoked") {
    return json({ status: 0, message: "System UUID has been Revoked by Admin" });
  }
  if (found.status === "Expired") {
    return json({ status: 0, message: "System UUID Access has Expired" });
  }

  return json({
    status: 1,
    message: "Authorized",
    system_uuid: systemUuid,
    user: found.user || "Client",
    expires: found.expiresFormatted || "Lifetime",
  });
}

export async function onRequestOptions() {
  return corsResponse();
}
