// api/verify.js
export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const { owner_id, secret_key, system_uuid } = req.query;

  // 1. Validate Credentials
  if (owner_id !== "e4b3c2a1-8765-4321-90ab-cdef12345678" || secret_key !== "bloody_sec_9f8e7d6c5b4a39281706f5e4d3c2b1a") {
    return res.status(403).json({ status: 0, message: "Invalid Owner or Secret Key" });
  }

  // 2. Validate UUID
  const authorizedUUIDs = [
    "4C4C4544-0059-3510-804D-B6C04F5A4833",
    "YOUR_OTHER_UUIDS_HERE"
  ];

  if (system_uuid && authorizedUUIDs.includes(system_uuid.toUpperCase())) {
    return res.status(200).json({ status: 1, message: "Authorized", user: "Client" });
  } else {
    return res.status(200).json({ status: 0, message: "System UUID is not authorized" });
  }
}