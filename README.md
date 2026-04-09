# Fern + Twilio PKCV SDK
---

## Objective
I started from what I saw as the customer's underlying business intent: improve trust and adoption through the SDK. 

I translated that into two concrete technical goals:

- Trust: every request should be signed and verifiable (PKCV).
- Adoption: SDK consumers should get a clean dev-friendly experience without carrying auth complexity into endpoint-level usage.

---
## Problem Framing

Twilio's PKCV flow requires canonicalization, hashing, JWT signing, and custom header injection on every request.

- Generated code owns API shape, typing, and serialization.
- Custom code owns PKCV signing behavior.
- Regeneration safety is mandatory.

That boundary drove everything I did afterward.

### Documentation Citations I Used
Twilio sources:

- [T1] [Twilio PKCV quickstart](https://www.twilio.com/docs/iam/pkcv/quickstart)
- [T2] [Twilio OpenAPI structure](https://www.twilio.com/docs/openapi/structure-of-twilio-openapi-spec)
- [T3] [Twilio OpenAPI repo (`twilio-oai`)](https://github.com/twilio/twilio-oai)

Fern sources:

- [F1] [Fern TypeScript quickstart](https://buildwithfern.com/learn/sdks/generators/typescript/quickstart)
- [F2] [Fern TypeScript configuration](https://buildwithfern.com/learn/sdks/generators/typescript/configuration)
- [F3] [Fern dynamic authentication (`allowCustomFetcher`)](https://buildwithfern.com/learn/sdks/generators/typescript/dynamic-authentication)
- [F4] [Fern OpenAPI overlays](https://buildwithfern.com/learn/api-definitions/openapi/overlays)
- [F5] [Fern OpenAPI extensions overview](https://buildwithfern.com/learn/api-definitions/openapi/extensions/overview)
- [F6] [Fern method names extension](https://buildwithfern.com/learn/api-definition/openapi/extensions/method-names)
- [F7] [Fern custom code in TypeScript SDKs](https://buildwithfern.com/learn/sdks/generators/typescript/custom-code)

---

## Research Phase (What I Needed to Understand First)
Before I implemented anything, I had two research tracks in parallel: Twilio protocol details and Fern generation/customization mechanics.

### 1. Twilio Research Track
Primary references: [T1], [T2], [T3].

I focused on answering:

- What exactly is Twilio expecting for PKCV signing flow?
- Which canonicalization mistakes would cause silent auth failures?
- How is Twilio OpenAPI organized so I can choose the right scope for this project?

What I extracted:

- PKCV flow: canonical request -> SHA-256 request hash (`rqh`) -> JWT with `hrh` + `rqh` -> `Twilio-Client-Validation` header ([T1]).
- Canonicalization is strict: method/path/query/headers/body formatting must be exact ([T1]).
- JWT claim/header semantics (`iss`, `sub`, `kid`, `nbf`, `exp`, `hrh`, `rqh`, `cty`) are non-negotiable ([T1]).

To make sure I truly understood the protocol before SDK wiring, I wrote a proof script:

```js
// scripts/test-pkcv.mjs
const parts = [method, url.pathname || "/", "", canonicalHeaders, signedHeaders];
if (body) parts.push(sha256Hex(body));

const canonicalRequest = parts.join("\n");
const requestHash = sha256Hex(canonicalRequest);

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
    header: { kid: TWILIO_CREDENTIAL_SID, cty: "twilio-pkrv;v=1" },
  }
);
```

I wanted protocol confidence before architecture wiring. Once this script behaved correctly, I knew implementation risk was mostly integration risk, not crypto interpretation risk.

#### OpenAPI Slice Selection (Research Decision)

I selected `twilio_verify_v2.yaml`.

I chose it because:

- It has enough breadth to validate generation quality.
- It has meaningful list endpoints with `PageToken` and `meta.next_page_url`, which made pagination overlays testable.
- It has nested resources where method/group naming improves real SDK usability.


### 2. Fern Research Track
Primary references: [F1], [F2], [F3], [F4], [F5], [F6], [F7].

I focused on answering:

- How should I structure TS generation config cleanly?
- What is the official integration point for non-standard auth?
- How do I use overlays and fern extensions to improve SDK UX instead of post-processing generated code?
- How do I keep customization regeneration-safe?

What I extracted and used:

- `allowCustomFetcher` is the right hook for auth that cannot be modeled in OpenAPI ([F3]).
- `generators.yml` should own generator behavior and package settings ([F1], [F2]).
- Overlays should carry method naming, grouping, and pagination metadata ([F4], [F5], [F6]).
- Custom code should be isolated and protected from regeneration ([F7]).

Directly applied configuration:

```yaml
# fern/generators.yml
config:
  allowCustomFetcher: true
  offsetSemantics: page-index
```

```yaml
# fern/openapi-overlays.yml
- target: "$.paths['/v2/Services'].get"
  update:
    x-fern-pagination:
      cursor: $request.PageToken
      next_cursor: $response.meta.next_page_url
      results: $response.services

- target: "$.paths['/v2/Services'].get"
  update:
    x-fern-sdk-group-name: services
    x-fern-sdk-method-name: list
```

---

## Planning Phase
I spent most of my effort in planning so implementation could stay predictable.

Planning inputs I used:

- Twilio protocol/spec sources: [T1], [T2], [T3]
- Fern generation/customization sources: [F1], [F2], [F3], [F4], [F5], [F6], [F7]

### Planning Decision 1: Define a Stable Auth Contract Before Writing Any Integration Code
I wanted to lock the abstraction boundary first so I would not leak Twilio-specific logic into generated clients.

```ts
// planned contract (now implemented in sdks/typescript/pkcv/RequestSigner.ts)
export interface CanonicalRequest {
  method: string;
  url: string;
  headers: Record<string, string | string[]>;
  body?: string;
}

export interface RequestSigner {
  sign(request: CanonicalRequest): Record<string, string>;
}

export interface TwilioPkcvSignerOptions {
  apiKeySid: string;
  accountSid: string;
  credentialSid: string;
  privateKeyPem: string;
  privateKeyPassphrase?: string;
  algorithm?: "RS256" | "PS256";
  hashedRequestHeaders?: string[];
  debug?: boolean;
}
```

Why I planned this first:
I wanted the fetcher and wrapper to depend on one stable interface, while keeping canonicalization/JWT details isolated to one signer class.
Reference trail: [T1], [F3], [F7].

### Planning Decision 2: Design the Full Request-Boundary Signing Pipeline Up Front
This fetcher resolves the final URL/query, materializes headers and body, signs that exact request, adds the Twilio-Client-Validation header, and then sends it through Fern’s default fetcher.

```ts
// planned shape (implemented in sdks/typescript/wrapper/createPkcvFetcher.ts)
export function createPkcvFetcher(signer: RequestSigner): FetchFunction {
  return async function pkcvFetcher<R = unknown>(args: Fetcher.Args) {
    const resolvedUrl = createRequestUrl(args.url, args.queryParameters);
    const parsedUrl = new URL(resolvedUrl);

    const signingHeaders: Record<string, string> = { host: parsedUrl.host };
    if (args.headers != null) {
      for (const [key, value] of Object.entries(args.headers)) {
        const resolved = await EndpointSupplier.get(value, {
          endpointMetadata: args.endpointMetadata ?? {},
        });
        if (resolved != null) signingHeaders[key.toLowerCase()] = String(resolved);
      }
    }

    const requestBody = await getRequestBody({
      body: args.body,
      type: args.requestType ?? "other",
    });
    const body = bodyToString(requestBody);

    const authHeaders = signer.sign({
      method: args.method,
      url: resolvedUrl,
      headers: signingHeaders,
      body: body || undefined,
    });

    return fetcherImpl<R>({
      ...args,
      headers: { ...args.headers, ...authHeaders },
    });
  };
}
```



### Planning Decision 3: Usability in Overlays Before Generation
I wanted generated output to already map to developer mental models (`list`, `fetch`, `create`, `update`, `delete`) and support iterator-friendly list behavior.
Reference trail: [F4], [F5], [F6].

```yaml
# fern/openapi-overlays.yml (representative subset)
- target: "$.paths['/v2/Services'].get"
  update:
    x-fern-pagination:
      cursor: $request.PageToken
      next_cursor: $response.meta.next_page_url
      results: $response.services
    x-fern-sdk-group-name: services
    x-fern-sdk-method-name: list

- target: "$.paths['/v2/Services/{ServiceSid}/Entities'].get"
  update:
    x-fern-pagination:
      cursor: $request.PageToken
      next_cursor: $response.meta.next_page_url
      results: $response.entities
    x-fern-sdk-group-name: entities
    x-fern-sdk-method-name: list

- target: "$.paths['/v2/Services/{ServiceSid}/Entities/{Identity}/Factors/{Sid}'].post"
  update:
    x-fern-sdk-group-name: factors
    x-fern-sdk-method-name: update
```

### Planning Decision 4: Define a Concrete Test Matrix Before Implementing Production Code
I planned a test matrix with explicit behaviors to catch both protocol bugs and integration drift.

```ts
// planned matrix shape (mapped directly into real test files)
describe("TwilioPkcvSigner.canonicalize()", () => {
  it("omits body hash when body is empty/undefined");
  it("sorts query params as encoded key=value pairs");
  it("normalizes header names/values and enforces required hrh headers");
  it("handles dot-segment path normalization");
});

describe("TwilioPkcvSigner.buildJwt()", () => {
  it("sets iss/sub/hrh/rqh and cty=twilio-pkrv;v=1");
  it("supports RS256 and PS256");
  it("supports passphrase-protected private keys");
});

describe("createPkcvFetcher()", () => {
  it("passes resolved URL + headers + body to signer");
  it("injects Twilio-Client-Validation and preserves caller headers");
});

describe("SDK consumer flow", () => {
  it("constructs TwilioClient with pkcv config");
  it("observes outbound Twilio-Client-Validation header");
});
```

---
## Implementation Phase
Implementation was relatively straightforward.

Execution sequence I followed:

1. Generate SDK from `twilio_verify_v2.yaml`.
2. Apply overlay strategy for pagination/naming/grouping.
3. Implement `RequestSigner` and `TwilioPkcvSigner`.
4. Implement `createPkcvFetcher`.
5. Implement `TwilioPkcvClient`.
6. Export wrapper as package-level `TwilioClient`.
7. Protect custom files with `.fernignore`.

### Core Implementation Snippet 1: Twilio Signer (Canonicalization + JWT)
```ts
// sdks/typescript/pkcv/TwilioPkcvSigner.ts (representative excerpt)
public canonicalize(request: CanonicalRequest, hrh: string[]): string {
  const parsedUrl = new URL(request.url);
  const canonicalMethod = request.method.trim().toUpperCase();
  const canonicalUri = this.canonicalizePath(parsedUrl.pathname);
  const canonicalQuery = this.canonicalizeQuery(parsedUrl.searchParams);
  const { canonicalHeaders, signedHeaders } = this.canonicalizeHeaders(request.headers, hrh);

  const parts = [canonicalMethod, canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders];
  if (request.body !== undefined && request.body !== null && request.body !== "") {
    parts.push(this.sha256Hex(request.body));
  }
  return parts.join("\n");
}

private buildJwt(canonicalString: string, hrh: string[]): string {
  const now = Math.floor(Date.now() / 1000);
  const requestHash = this.sha256Hex(canonicalString);
  const key = this.options.privateKeyPassphrase
    ? { key: this.options.privateKeyPem, passphrase: this.options.privateKeyPassphrase }
    : this.options.privateKeyPem;

  return jwt.sign(
    {
      iss: this.options.apiKeySid,
      sub: this.options.accountSid,
      nbf: now,
      exp: now + 300,
      hrh: hrh.join(";"),
      rqh: requestHash,
    },
    key,
    {
      algorithm: this.options.algorithm,
      header: {
        typ: "JWT",
        alg: this.options.algorithm,
        kid: this.options.credentialSid,
        cty: "twilio-pkrv;v=1",
      },
    },
  );
}
```

### Core Implementation Snippet 2: Custom Fetcher Wiring
```ts
// sdks/typescript/wrapper/createPkcvFetcher.ts (representative excerpt)
const resolvedUrl = createRequestUrl(args.url, args.queryParameters);
const parsedUrl = new URL(resolvedUrl);
const signingHeaders: Record<string, string> = { host: parsedUrl.host };

for (const [key, value] of Object.entries(args.headers ?? {})) {
  const resolved = await EndpointSupplier.get(value, {
    endpointMetadata: args.endpointMetadata ?? {},
  });
  if (resolved != null) {
    signingHeaders[key.toLowerCase()] = String(resolved);
  }
}

const requestBody = await getRequestBody({
  body: args.body,
  type: args.requestType ?? "other",
});
const body = bodyToString(requestBody);

const authHeaders = signer.sign({
  method: args.method,
  url: resolvedUrl,
  headers: signingHeaders,
  body: body || undefined,
});

return fetcherImpl<R>({
  ...args,
  headers: { ...args.headers, ...authHeaders },
});
```

### Core Implementation Snippet 3: Generated Client + Pagination + Wrapper Integration
```ts
// generated call path (sdks/typescript/api/resources/services/client/Client.ts)
const _response = await (this._options.fetcher ?? core.fetcher)({
  url: core.url.join(baseUrl, "v2/Services"),
  method: "GET",
  headers: _headers,
  queryParameters: { PageSize: pageSize, Page: page, PageToken: pageToken },
});

return new core.Page({
  response: dataWithRawResponse.data,
  hasNextPage: (response) =>
    response?.meta?.nextPageUrl != null &&
    !(typeof response?.meta?.nextPageUrl === "string" && response?.meta?.nextPageUrl === ""),
  getItems: (response) => response?.services ?? [],
  loadPage: (response) => list(core.setObjectProperty(request, "pageToken", response?.meta?.nextPageUrl)),
});
```

```ts
// wrapper constructor (sdks/typescript/wrapper/TwilioPkcvClient.ts)
const { auth, pkcv, ...baseOptions } = options;
const signer = auth ?? (pkcv != null ? new TwilioPkcvSigner(pkcv) : undefined);
if (signer == null) {
  throw new Error("TwilioPkcvClient requires either auth or pkcv options");
}
super({
  ...baseOptions,
  fetcher: createPkcvFetcher(signer),
});
```

---

## Testing Phase 
I validated everything against real code afterward.

### 1. Unit Tests (Signer and Canonicalization)
Primary files:

- `tests/unit/pkcv/canonicalize.test.ts`
- `tests/unit/pkcv/buildJwt.test.ts`
- `tests/unit/pkcv/sign.test.ts`

What I validated:

- Canonical shape and known hash expectations.
- Empty body omission behavior.
- Query encoding/sorting behavior.
- Header normalization and required signed-header enforcement.
- Path canonicalization edge cases.
- JWT claims/header and signature behavior.
- RS256/PS256 and encrypted key passphrase handling.

Representative assertions:

```ts
expect(canonical.split("\n")[2]).toBe(""); // empty query line
expect(canonical.split("\n")).toHaveLength(7); // GET with no body
expect(lines[7]).toBe(sha256(body)); // body hash when present
```


### 2. Integration Tests (Fetcher + Wrapper Wiring)
Primary files:

- `tests/integration/fetcher.test.ts`
- `tests/integration/wrapper.test.ts`

What I validated:

- `signer.sign()` called once per request.
- Resolved URL/headers/body propagated correctly to signer input.
- `Twilio-Client-Validation` injected correctly.
- Existing caller headers preserved.
- Wrapper constructor modes (`auth` vs `pkcv`) behave correctly.

Representative assertion:

```ts
expect(argsPassedToFetcherImpl?.headers).toMatchObject({
  "Twilio-Client-Validation": "mock-jwt",
});
```


### 3. End-to-End Consumer Flow
Primary file:

- `examples/test-app/src/index.ts`

What I validated:

- Consumer import path (`fern-twilio-pkcv-sdk`).
- Real client setup with environment variables.
- Dry-run mode for deterministic checks.
- Live-mode path for real request flow.
- Runtime guard verifying outbound PKCV header presence.

Representative e2e guard:

```ts
if (!sawPkcvHeader) {
  throw new Error("PKCV signing check failed: request was sent without Twilio-Client-Validation");
}
```

Current snapshot:

- `npm test` passes `65/65`.

---

## Publishing and Consumer Readiness

Artifacts:

- `sdks/typescript/package.json` for build/publish identity.
- `sdks/typescript/README.md` for npm consumer usage.
- `examples/test-app` consuming SDK via package name.
- `.bluekit/research/phase-6-publish/*` for repeatable publishing/validation runbooks.

Published package:
- [fern-twilio-pkcv-sdk](https://www.npmjs.com/package/fern-twilio-pkcv-sdk)

Install commands:

```bash
# install the published prerelease tag used in this project
npm install fern-twilio-pkcv-sdk@next

# or install the pinned published version
npm install fern-twilio-pkcv-sdk@0.1.0-alpha.0
```

Repo scripts for publish + consumer validation:

```bash
npm run publish:dry-run
npm run publish:sdk
npm run example:dry-run
npm run example:start
```

---

## How to Use This Authentication Pattern in the SDK

Pattern:

1. Provide standard Twilio credentials (`username`, `password`).
2. Provide PKCV options once at client construction.
3. Call generated SDK methods as usual.
4. PKCV signing is automatically enforced at request time.

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
    privateKeyPassphrase: process.env.PRIVATE_KEY_PASSPHRASE,
  },
});

const page = await client.services.list({ pageSize: 20 });
for await (const service of page) {
  console.log(service.sid, service.friendlyName);
}
```

Advanced mode is also supported:

- pass `auth: RequestSigner` to inject a custom signer.

---
## Extensibility and Limitations

### Current project limitations
- Full server-side PKCV verification depends on Twilio Enterprise/Security Edition capabilities.
- This repository is intentionally scoped to one OpenAPI slice, not a full multi-spec Twilio SDK rollout.
- Multi-spec expansion may require broader Fern project/license and packaging orchestration.

### Extensibility I designed in
- `RequestSigner` abstraction lets me add alternate signers without touching generated endpoint clients.
- `TwilioPkcvSigner` isolates Twilio-specific canonicalization/JWT rules for future changes.
- Fetcher-level injection keeps behavior consistent as endpoint surface expands.
- Overlay + generator workflow scales to additional slices while preserving SDK UX.
- `.fernignore` boundaries keep regeneration safe over time.

---
