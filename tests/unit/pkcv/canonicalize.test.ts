import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { TwilioPkcvSigner } from "../../../sdks/typescript/pkcv/TwilioPkcvSigner.js";

const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

const BASE_OPTIONS = {
    apiKeySid: "SK000",
    accountSid: "AC000",
    credentialSid: "CR000",
    privateKeyPem,
};

function sha256(s: string): string {
    return createHash("sha256").update(s, "utf8").digest("hex");
}

const signer = new TwilioPkcvSigner(BASE_OPTIONS);
const HRH = ["authorization", "host"];

describe("canonicalize()", () => {
    describe("canonical request structure", () => {
        it("matches Twilio quickstart canonical request and hash exactly", () => {
            const authValue =
                "Basic QUMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDpmb29iYXI=";
            const body = "FriendlyName=my new friendly name";

            const canonical = signer.canonicalize(
                {
                    method: "POST",
                    url: "https://api.twilio.com/2010-04-01/Accounts/AC00000000000000000000000000000000",
                    headers: { authorization: authValue, host: "api.twilio.com" },
                    body,
                },
                HRH,
            );

            const expectedCanonical = [
                "POST",
                "/2010-04-01/Accounts/AC00000000000000000000000000000000",
                "",
                `authorization:${authValue}`,
                "host:api.twilio.com",
                "",
                "authorization;host",
                "b8e20591615abc52293f088c87be6df8e9b7b40c3da573f134c9132add851e2d",
            ].join("\n");

            expect(canonical).toBe(expectedCanonical);
            expect(sha256(canonical)).toBe(
                "245eece1e638d9b0081ca0621183cd417fc97a1818bd822aa26697f9aa70c792",
            );
        });

        it("matches the Twilio spec example format for POST with body", () => {
            const authValue =
                "Basic QUMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDpmb29iYXI=";
            const body = "AccountSid=AC00&To=%2B15017122661&From=%2B15558675310";

            const canonical = signer.canonicalize(
                {
                    method: "POST",
                    url: "https://api.twilio.com/2010-04-01/Accounts/AC00000000000000000000000000000000",
                    headers: { authorization: authValue, host: "api.twilio.com" },
                    body,
                },
                HRH,
            );

            const lines = canonical.split("\n");
            expect(lines[0]).toBe("POST");
            expect(lines[1]).toBe("/2010-04-01/Accounts/AC00000000000000000000000000000000");
            expect(lines[2]).toBe("");
            expect(lines[3]).toBe(`authorization:${authValue}`);
            expect(lines[4]).toBe("host:api.twilio.com");
            expect(lines[5]).toBe("");
            expect(lines[6]).toBe("authorization;host");
            expect(lines[7]).toBe(sha256(body));
            expect(lines).toHaveLength(8);
        });

        it("produces exactly 7 lines for a GET with no body and no query", () => {
            const canonical = signer.canonicalize(
                {
                    method: "GET",
                    url: "https://api.twilio.com/v2/Services",
                    headers: { authorization: "Basic x", host: "api.twilio.com" },
                },
                HRH,
            );
            expect(canonical.split("\n")).toHaveLength(7);
        });
    });

    describe("body hash", () => {
        it("omits body hash line when body is empty string", () => {
            const canonical = signer.canonicalize(
                {
                    method: "POST",
                    url: "https://api.twilio.com/v2/Services",
                    headers: { authorization: "x", host: "h" },
                    body: "",
                },
                HRH,
            );
            const lines = canonical.split("\n");
            expect(lines[6]).toBe("authorization;host");
            expect(lines).toHaveLength(7);
        });

        it("omits body hash line when body is undefined", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/v2/Services", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")).toHaveLength(7);
        });

        it("includes SHA-256 hex body hash for non-empty body", () => {
            const body = '{"key":"value"}';
            const canonical = signer.canonicalize(
                { method: "POST", url: "https://api.twilio.com/v2/Services", headers: { authorization: "x", host: "h" }, body },
                HRH,
            );
            const lines = canonical.split("\n");
            expect(lines[7]).toBe(sha256(body));
        });
    });

    describe("query string", () => {
        it("produces blank line for empty query string", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/v2/Services", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[2]).toBe("");
        });

        it("sorts query params as full key=value ASCII strings", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/v2/Services?z=1&a=2", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[2]).toBe("a=2&z=1");
        });

        it("RFC 3986-encodes query values (space → %20)", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/v2/Services?name=foo+bar", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[2]).toBe("name=foo%20bar");
        });

        it("preserves empty query values as key=", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/v2/Services?empty=", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[2]).toBe("empty=");
        });

        it("handles multiple query params with same key (repeating)", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/v2/Services?tag=b&tag=a", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[2]).toBe("tag=a&tag=b");
        });
    });

    describe("headers", () => {
        it("lowercases header names", () => {
            const canonical = signer.canonicalize(
                {
                    method: "GET",
                    url: "https://api.twilio.com/",
                    headers: { Authorization: "Basic xyz", Host: "api.twilio.com" },
                },
                HRH,
            );
            const lines = canonical.split("\n");
            expect(lines[3]).toBe("authorization:Basic xyz");
            expect(lines[4]).toBe("host:api.twilio.com");
        });

        it("collapses consecutive whitespace in header values to single space", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/", headers: { authorization: "Basic  x  y", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[3]).toBe("authorization:Basic x y");
        });

        it("excludes headers not present in hrh", () => {
            const canonical = signer.canonicalize(
                {
                    method: "GET",
                    url: "https://api.twilio.com/",
                    headers: { authorization: "x", host: "h", "x-extra": "should-not-appear" },
                },
                HRH,
            );
            expect(canonical).not.toContain("x-extra");
        });

        it("sorts multiple values for the same header key and joins with comma", () => {
            const canonical = signer.canonicalize(
                {
                    method: "GET",
                    url: "https://api.twilio.com/",
                    headers: { authorization: "x", host: "h", "x-custom": ["b", "a"] },
                },
                ["authorization", "host", "x-custom"],
            );
            const customLine = canonical.split("\n").find((l) => l.startsWith("x-custom:"));
            expect(customLine).toBe("x-custom:a,b");
        });

        it("each canonical header line ends with \\n (producing a blank line before signedHeaders)", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            const lines = canonical.split("\n");
            expect(lines[5]).toBe("");
            expect(lines[6]).toBe("authorization;host");
        });

        it("throws when a required hrh header is missing from request headers", () => {
            expect(() =>
                signer.canonicalize(
                    { method: "GET", url: "https://api.twilio.com/", headers: { host: "h" } },
                    HRH,
                ),
            ).toThrow(/Missing required hashed request header: authorization/);
        });
    });

    describe("URI canonicalization", () => {
        it("removes dot segments from path", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/foo/./bar/../baz", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[1]).toBe("/foo/baz");
        });

        it("normalizes root path to /", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[1]).toBe("/");
        });

        it("RFC 3986-encodes path segments with special characters", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/v2/Services/foo%20bar", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[1]).toBe("/v2/Services/foo%20bar");
        });

        it("preserves trailing slash while removing dot segments", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/foo/./bar/../baz/", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[1]).toBe("/foo/baz/");
        });

        it("preserves repeated slashes while removing dot segments", () => {
            const canonical = signer.canonicalize(
                { method: "GET", url: "https://api.twilio.com/foo//bar/./baz", headers: { authorization: "x", host: "h" } },
                HRH,
            );
            expect(canonical.split("\n")[1]).toBe("/foo//bar/baz");
        });
    });
});
