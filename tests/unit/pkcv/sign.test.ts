import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import jwt from "jsonwebtoken";
import { TwilioPkcvSigner } from "../../../sdks/typescript/pkcv/TwilioPkcvSigner.js";

const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

const BASE_OPTIONS = {
    apiKeySid: "SK000",
    accountSid: "AC000",
    credentialSid: "CR000",
    privateKeyPem,
};

const SIMPLE_REQUEST = {
    method: "GET",
    url: "https://api.twilio.com/v2/Services",
    headers: { authorization: "Basic x", host: "api.twilio.com" },
} as const;

describe("sign()", () => {
    describe("output shape", () => {
        it("returns exactly one header: Twilio-Client-Validation", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const result = signer.sign(SIMPLE_REQUEST);
            expect(Object.keys(result)).toEqual(["Twilio-Client-Validation"]);
        });

        it("Twilio-Client-Validation value is a non-empty JWT string", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            expect(typeof token).toBe("string");
            expect(token.split(".")).toHaveLength(3);
        });
    });

    describe("hrh consistency — JWT hrh claim equals SIGNED_HEADERS line in canonical request", () => {
        it("single signer call: hrh in JWT is present in canonical string", () => {
            const signer = new TwilioPkcvSigner(BASE_OPTIONS);
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token) as Record<string, string>;

            const hrh = decoded.hrh.split(";");
            const canonical = signer.canonicalize(SIMPLE_REQUEST, hrh);

            expect(canonical.split("\n")).toContain(decoded.hrh);
        });

        it("custom hashedRequestHeaders: hrh claim and SIGNED_HEADERS remain identical", () => {
            const signer = new TwilioPkcvSigner({
                ...BASE_OPTIONS,
                hashedRequestHeaders: ["authorization", "host", "x-custom"],
            });
            const request = {
                method: "POST",
                url: "https://api.twilio.com/v2/Services",
                headers: { authorization: "Basic x", host: "api.twilio.com", "x-custom": "val" },
                body: "data",
            };
            const { "Twilio-Client-Validation": token } = signer.sign(request);
            const decoded = jwt.decode(token) as Record<string, string>;

            const hrh = decoded.hrh.split(";");
            const canonical = signer.canonicalize(request, hrh);
            expect(canonical.split("\n")).toContain(decoded.hrh);
        });
    });

    describe("constructor validation", () => {
        it("throws when host is absent from hashedRequestHeaders", () => {
            expect(() =>
                new TwilioPkcvSigner({ ...BASE_OPTIONS, hashedRequestHeaders: ["authorization"] }),
            ).toThrow(/"host"/);
        });

        it("throws when authorization is absent from hashedRequestHeaders", () => {
            expect(() =>
                new TwilioPkcvSigner({ ...BASE_OPTIONS, hashedRequestHeaders: ["host"] }),
            ).toThrow(/"authorization"/);
        });

        it("deduplicates hashedRequestHeaders", () => {
            const signer = new TwilioPkcvSigner({
                ...BASE_OPTIONS,
                hashedRequestHeaders: ["authorization", "host", "authorization", "host"],
            });
            const { "Twilio-Client-Validation": token } = signer.sign(SIMPLE_REQUEST);
            const decoded = jwt.decode(token) as Record<string, string>;
            const hrhParts = decoded.hrh.split(";");
            expect(new Set(hrhParts).size).toBe(hrhParts.length);
            expect(hrhParts.filter((h) => h === "authorization")).toHaveLength(1);
        });

        it("normalizes hashedRequestHeaders to lowercase", () => {
            const signer = new TwilioPkcvSigner({
                ...BASE_OPTIONS,
                hashedRequestHeaders: ["Authorization", "Host"],
            });
            const request = {
                method: "GET",
                url: "https://api.twilio.com/v2/Services",
                headers: { authorization: "Basic x", host: "api.twilio.com" },
            };
            expect(() => signer.sign(request)).not.toThrow();
            const { "Twilio-Client-Validation": token } = signer.sign(request);
            const decoded = jwt.decode(token) as Record<string, string>;
            expect(decoded.hrh).toBe("authorization;host");
        });

        it("sorts hashedRequestHeaders regardless of input order", () => {
            const signer = new TwilioPkcvSigner({
                ...BASE_OPTIONS,
                hashedRequestHeaders: ["host", "x-custom", "authorization"],
            });
            const request = {
                method: "GET",
                url: "https://api.twilio.com/v2/Services",
                headers: { authorization: "Basic x", host: "api.twilio.com", "x-custom": "v1" },
            };
            const { "Twilio-Client-Validation": token } = signer.sign(request);
            const decoded = jwt.decode(token) as Record<string, string>;
            expect(decoded.hrh).toBe("authorization;host;x-custom");
        });

        it("throws when privateKeyPassphrase does not match encrypted private key", () => {
            const { privateKey: encryptedPrivateKeyPem } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: { type: "spki", format: "pem" },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "pem",
                    cipher: "aes-256-cbc",
                    passphrase: "correct-passphrase",
                },
            });
            const signer = new TwilioPkcvSigner({
                ...BASE_OPTIONS,
                privateKeyPem: encryptedPrivateKeyPem,
                privateKeyPassphrase: "wrong-passphrase",
            });
            expect(() => signer.sign(SIMPLE_REQUEST)).toThrow();
        });
    });

    describe("debug mode", () => {
        it("does not throw with debug: true", () => {
            const signer = new TwilioPkcvSigner({ ...BASE_OPTIONS, debug: true });
            expect(() => signer.sign(SIMPLE_REQUEST)).not.toThrow();
        });

        it("still returns the Twilio-Client-Validation header in debug mode", () => {
            const signer = new TwilioPkcvSigner({ ...BASE_OPTIONS, debug: true });
            const result = signer.sign(SIMPLE_REQUEST);
            expect(result).toHaveProperty("Twilio-Client-Validation");
        });
    });
});
