# AzureGuard Auth — System UUID License Platform (Cloudflare Pages)

A free, cloud-hosted System UUID authorization dashboard. Built for **Cloudflare Pages
(free plan)** using **Pages Functions + Workers KV** — no server / VPS / database needed.

- Admin logs in from **any device, phone or browser** and sees **every registered UUID**
  because the data lives in Cloudflare KV, not on a single machine.
- Desktop clients (C++ / C#) verify their Windows System UUID against `/verify`.

---

## 📁 Project layout

```
UUID Auth/
├── index.html                 # UI (blue / white / black theme, static)
├── functions/
│   ├── _shared.js             # KV helpers + defaults (not a route)
│   ├── verify.js              # GET /verify  -> desktop client check
│   └── api/
│       ├── keys.js            # GET/POST /api/keys -> admin CRUD
│       ├── keys/meta.js       # GET /api/keys/meta -> owner credentials
│       └── my_uuid.js         # GET /api/my_uuid  -> only for local server.py
├── wrangler.toml              # Pages + KV binding config
├── package.json               # wrangler scripts
├── AuthClient.h               # C++ client (points to your pages.dev)
├── AuthClient.cs              # C# client (points to your pages.dev)
├── BloodyAuthClient.cs        # Extra C# client scaffold
└── server.py                  # OPTIONAL local-only fallback (not used on Cloudflare)
```

## 🔑 Admin login

| Field    | Value       |
|----------|-------------|
| Username | `re4per`    |
| Password | `re4per123` |

> The admin session is stored in the browser's `localStorage`, but the **UUID database is
> stored server-side in Cloudflare KV**, so logging in on any device shows all authorized UUIDs.

---

## 🚀 Deploy to Cloudflare Pages (free) — 3 steps

### 1. Create a KV namespace
1. Cloudflare dashboard → **Workers & Pages** → **KV** → **Create a namespace**.
2. Name it `UUID_DB` (any name works).
3. Copy its **namespace ID**.

### 2. Create the Pages project
1. **Workers & Pages** → **Create** → **Pages** → **Upload assets** (direct upload) or connect a Git repo.
2. Project name → e.g. `azureguard-auth` → your site will be `https://azureguard-auth.pages.dev`.
3. **Settings → Functions → KV namespace bindings → Add binding**:
   - Variable name: `UUID_DB`
   - KV namespace: the one you created
4. Upload the project folder (everything in this directory).
   - If using Git, build command: *(none)*, output directory: `/` (root).

### 3. Update the desktop clients
Open `AuthClient.h` / `AuthClient.cs` and set the host/URL to your site:

```cpp
// AuthClient.h
static const char* API_HOST = "azureguard-auth.pages.dev";   // your project
static const INTERNET_PORT API_PORT = INTERNET_DEFAULT_HTTPS_PORT;
static const char* API_PATH = "/verify";
```

```csharp
// AuthClient.cs
public static string ApiUrl = "https://azureguard-auth.pages.dev/verify";
```

Done! Clients now verify against your free Cloudflare host.

---

## 💻 Local development

Requires [Node.js](https://nodejs.org) (for wrangler).

```bash
npm install
npm run dev        # serves http://localhost:8788 (static + functions + local KV)
```

Or without npm, keep using the old Python server for a quick local test:
```bash
python server.py   # http://localhost:8080  (local-only, data in uuids.json)
```

---

## 📡 API reference

### `GET /verify?owner_id=...&secret_key=...&system_uuid=...`
Desktop client authorization check.

```json
{ "status": 1, "message": "Authorized", "system_uuid": "...", "user": "Client", "expires": "Lifetime" }
```

### `GET /api/keys`
Returns the full array of registered UUIDs (admin dashboard source of truth).

### `POST /api/keys`
Body actions: `add`, `toggle`, `delete`, `save_all`, `regenerate_meta`.

```json
{ "action": "add", "system_uuid": "4C4C4544-...", "user": "Client_PC", "days": 30 }
```

### `GET /api/keys/meta`
Returns `{ "owner_id": "...", "secret_key": "..." }`.

---

## ⚠️ Notes & limits (free plan)

- **KV free tier:** ~100,000 reads/day, 1,000 writes/day. The dashboard only writes when you
  add / toggle / delete a UUID, so a normal admin workload stays far under the limit.
- Expired entries are marked automatically on read — no extra writes unless a status changes.
- Keep the UUID list reasonably small (a few thousand max) since the whole array is stored as
  one KV value.
- Admin password is checked client-side (static hosting has no private backend), same as before.
  For stronger protection, add Cloudflare **Access** in front of the dashboard later.
