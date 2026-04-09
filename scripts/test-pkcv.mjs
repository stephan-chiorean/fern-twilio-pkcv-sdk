import fs from "node:fs";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import * as dotenv from "dotenv";

dotenv.config();

const {
  TWILIO_ACCOUNT_SID,
  TWILIO_API_KEY_SID,
  TWILIO_CREDENTIAL_SID,
} = process.env;

const privateKeyPem = {
  key: fs.readFileSync("./private_key.pem", "utf8"),
  passphrase: process.env.PRIVATE_KEY_PASSPHRASE,
};

// --- Simulate a real request ---
const method = "GET";
const url = new URL("https://accounts.twilio.com/v1/Credentials/PublicKeys");
const body = "";

// 1. Canonicalize
function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

const headers = {
  host: url.host,
  authorization: `Basic ${Buffer.from(`${TWILIO_API_KEY_SID}:placeholder`).toString("base64")}`,
};

const normalizedHeaders = Object.entries(headers)
  .map(([k, v]) => [k.trim().toLowerCase(), v.trim().replace(/\s+/g, " ")])
  .sort(([a], [b]) => a.localeCompare(b));

const canonicalHeaders = normalizedHeaders.map(([k, v]) => `${k}:${v}\n`).join("");
const signedHeaders = normalizedHeaders.map(([k]) => k).join(";");

const parts = [
  method,
  url.pathname || "/",
  "", // no query string
  canonicalHeaders,
  signedHeaders,
];
if (body) parts.push(sha256Hex(body));

const canonicalRequest = parts.join("\n");
const requestHash = sha256Hex(canonicalRequest);

// 2. Build JWT
const now = Math.floor(Date.now() / 1000);

const token = jwt.sign(
  {
    iss: TWILIO_API_KEY_SID,
    sub: TWILIO_ACCOUNT_SID,
    nbf: now,
    exp: now + 300,
    hrh: signedHeaders,
    rqh: requestHash,
  },
  privateKeyPem,
  {
    algorithm: "RS256",
    header: {
      typ: "JWT",
      alg: "RS256",
      kid: TWILIO_CREDENTIAL_SID,
      cty: "twilio-pkrv;v=1",
    },
  }
);

// 3. Decode and print
const [rawHeader, rawPayload] = token.split(".");
const header = JSON.parse(Buffer.from(rawHeader, "base64url").toString());
const payload = JSON.parse(Buffer.from(rawPayload, "base64url").toString());

console.log("\n=== JWT Header ===");
console.log(JSON.stringify(header, null, 2));

console.log("\n=== JWT Payload ===");
console.log(JSON.stringify(payload, null, 2));

console.log("\n=== Canonical Request ===");
console.log(JSON.stringify(canonicalRequest));

console.log("\n=== Full Token ===");
console.log(token);
