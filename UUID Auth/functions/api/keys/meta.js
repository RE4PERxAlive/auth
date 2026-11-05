// ================================================================
// AzureGuard Auth - /api/keys/meta endpoint
// GET -> returns master owner credentials (owner_id, secret_key)
// ================================================================
import { json, corsResponse, readMeta } from "../../_shared.js";

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === "OPTIONS") return corsResponse();
  if (request.method === "GET") {
    return json(await readMeta(env));
  }
  return json({ success: false, message: "Method not allowed" }, 405);
}
