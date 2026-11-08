import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
import { createHmac } from "node:crypto";

function adminApp() {
  if (getApps().length) return getApps()[0];
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error("Firebase Admin credentials are not configured.");
  let serviceAccount;
  try { serviceAccount = JSON.parse(raw); }
  catch { throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON must contain valid JSON."); }
  return initializeApp({ credential: cert(serviceAccount) });
}
export function authAdmin() { adminApp(); return getAuth(); }
export function dbAdmin() { adminApp(); return getFirestore(); }
export async function requireModerator(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) throw Object.assign(new Error("Authentication required."), { status: 401 });
  const decoded = await authAdmin().verifyIdToken(header.slice(7));
  // Hard-coded owner account plus database-managed moderators.
  const isHardcodedOwner = String(decoded.email || "").toLowerCase() === "nico@accounts.mxprofiles.invalid";
  const moderator = await dbAdmin().doc("moderators/" + decoded.uid).get();
  if (!isHardcodedOwner && (!moderator.exists || moderator.data().active !== true)) throw Object.assign(new Error("Moderator access required."), { status: 403 });
  return decoded;
}
export function clientIp(req) {
  // Vercel supplies x-real-ip at the edge. Do not trust arbitrary X-Forwarded-For values.
  return String(req.headers["x-real-ip"] || "").trim();
}
export function ipHash(ip) {
  const key = process.env.IP_HASH_SECRET;
  if (!key) throw new Error("IP_HASH_SECRET is not configured.");
  return createHmac("sha256", key).update(ip).digest("hex");
}
export function sendJson(res, status, body) {
  res.status(status).setHeader("Content-Type","application/json; charset=utf-8");
  res.setHeader("Cache-Control","no-store");
  res.end(JSON.stringify(body));
}
export { FieldValue };
