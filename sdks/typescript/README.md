# fern-twilio-pkcv-sdk

Twilio Verify TypeScript SDK generated with Fern and extended with PKCV authentication via custom code.

## What this package demonstrates
- Fern-generated, strongly typed SDK surface for Twilio Verify endpoints.
- PKCV signing injected at the request layer (`Twilio-Client-Validation` header on every request).
- Regeneration-safe custom code boundaries (`pkcv/**`, `wrapper/**`, `index.ts` override).

## Install

```bash
npm install fern-twilio-pkcv-sdk
```

## Quick usage

```ts
import fs from "node:fs";
import { TwilioClient } from "fern-twilio-pkcv-sdk";

const client = new TwilioClient({
  username: process.env.TWILIO_API_KEY_SID!,
  password: process.env.TWILIO_API_KEY_SECRET!,
  pkcv: {
    apiKeySid: process.env.TWILIO_API_KEY_SID!,
    accountSid: process.env.TWILIO_ACCOUNT_SID!,
    credentialSid: process.env.TWILIO_CREDENTIAL_SID!,
    privateKeyPem: fs.readFileSync(process.env.PRIVATE_KEY_PATH!, "utf8"),
    privateKeyPassphrase: process.env.PRIVATE_KEY_PASSPHRASE
  }
});

const services = await client.services.list({ pageSize: 20 });
for await (const service of services) {
  console.log(service.sid, service.friendlyName);
}
```

## Example consumer app

See `examples/test-app` for a runnable SDK consumer that demonstrates:
- live mode against Twilio APIs,
- dry-run mode for deterministic local verification,
- proof that PKCV header injection occurs in real request flow.
