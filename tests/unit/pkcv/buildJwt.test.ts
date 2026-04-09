import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import jwt from "jsonwebtoken";
import { TwilioPkcvSigner } from "../../../sdks/typescript/pkcv/TwilioPkcvSigner.js";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
const ENCRYPTED_KEY_PASSPHRASE = "test-passphrase";
const { privateKey: encryptedPrivateKeyPem, publicKey: encryptedPublicKeyPem } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: ENCRYPTED_KEY_PASSPHRASE,
    },
});

const BASE_OPTIONS = {
    apiKeySid: "SK_api_key_sid",
    accountSid: "AC_account_sid",
    credentialSid: "CR_credential_sid",
    privateKeyPem,
};

const SIMPLE_REQUEST = {
    method: "GET",
    url: "https://api.twilio.com/v2/Services",
    headers: { authorization: "Basic x", host: "api.twilio.com" },
} as const;

describe("JWT structure", () => {
    describe("header fields", () => {
        it("sets typ to JWT", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token, { complete: true })!;
            expect(decoded.header.typ).toBe("JWT");
        });

        it("sets alg to RS256 by default", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token, { complete: true })!;
            expect(decoded.header.alg).toBe("RS256");
        });

        it("sets alg to PS256 when configured", () => {
            const signer = new TwilioPkcvSigner({ ...BASE_OPTIONS, algorithm: "PS256" });
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token, { complete: true })!;
            expect(decoded.header.alg).toBe("PS256");
        });

        it("sets kid to credentialSid", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token, { complete: true })!;
            expect(decoded.header.kid).toBe("CR_credential_sid");
        });

        it("sets cty to twilio-pkrv;v=1 (not pkCV)", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token, { complete: true })!;
            expect(decoded.header.cty).toBe("twilio-pkrv;v=1");
        });
    });

    describe("payload fields", () => {
        it("sets iss to apiKeySid", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token) as Record<string, unknown>;
            expect(decoded.iss).toBe("SK_api_key_sid");
        });

        it("sets sub to accountSid", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token) as Record<string, unknown>;
            expect(decoded.sub).toBe("AC_account_sid");
        });

        it("sets hrh to semicolon-joined sorted lowercase header names", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token) as Record<string, unknown>;
            expect(decoded.hrh).toBe("authorization;host");
        });

        it("sets rqh to SHA-256 hex of the canonical request string", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const request = {
                method: "POST",
                url: "https://api.twilio.com/v2/Services",
                headers: { authorization: "Basic x", host: "api.twilio.com" },
                body: '{"key":"value"}',
            };
            const hrh = ["authorization", "host"];
            const canonicalString = signer.canonicalize(request, hrh);
            const expectedRqh = createHash("sha256").update(canonicalString, "utf8").digest("hex");

            const { "Twilio-Client-Validation": token } = signer.sign(request);
            const decoded = jwt.decode(token) as Record<string, unknown>;
            expect(decoded.rqh).toBe(expectedRqh);
        });

        it("sets exp - nbf <= 300 seconds", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token) as Record<string, number>;
            expect(decoded.exp - decoded.nbf).toBeLessThanOrEqual(300);
            expect(decoded.exp - decoded.nbf).toBeGreaterThan(0);
        });
    });

    describe("signature verification", () => {
        it("is verifiable with RS256 and the corresponding public key", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            expect(() => jwt.verify(token, publicKeyPem)).not.toThrow();
        });

        it("is verifiable with PS256 and the corresponding public key", () => {
            const signer = new TwilioPkcvSigner({ ...BASE_OPTIONS, algorithm: "PS256" });
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            expect(() => jwt.verify(token, publicKeyPem, { algorithms: ["PS256"] })).not.toThrow();
        });

        it("fails verification with a different public key", () => {
            const { publicKey: otherPublicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
            const otherPublicKeyPem = otherPublicKey.export({ type: "spki", format: "pem" }) as string;

            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            expect(() => jwt.verify(token, otherPublicKeyPem)).toThrow();
        });

        it("is verifiable when signing with encrypted private key and passphrase", () => {
            const signer = new TwilioPkcvSigner({
                ...BASE_OPTIONS,
                privateKeyPem: encryptedPrivateKeyPem,
                privateKeyPassphrase: ENCRYPTED_KEY_PASSPHRASE,
            });
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            expect(() => jwt.verify(token, encryptedPublicKeyPem)).not.toThrow();
        });
    });
});
