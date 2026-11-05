// ================================================================
// AzureGuard Auth - /api/my_uuid endpoint
// On Cloudflare there is no local machine, so this returns null.
// It exists only for local testing with server.py (which detects
// the machine running the Python server).
// ================================================================
import { json, corsResponse } from "../_shared.js";

export async function onRequestGet() {
  return json({ system_uuid: null, note: "Not available on Cloudflare. Only the local server.py detects a machine UUID." });
}

export async function onRequestOptions() {
  return corsResponse();
}
