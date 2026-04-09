import { createHash } from "node:crypto";
import jwt from "jsonwebtoken";
import type { CanonicalRequest, RequestSigner } from "./RequestSigner.js";

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

export class TwilioPkcvSigner implements RequestSigner {
    private readonly options: Required<
        Pick<TwilioPkcvSignerOptions, "algorithm" | "debug" | "hashedRequestHeaders">
    > &
        Omit<TwilioPkcvSignerOptions, "algorithm" | "debug" | "hashedRequestHeaders">;

    constructor(options: TwilioPkcvSignerOptions) {
        const rawHrh = options.hashedRequestHeaders ?? ["host", "authorization"];
        const normalizedHrh = [...new Set(rawHrh.map((h) => h.trim().toLowerCase()))].sort();

        if (!normalizedHrh.includes("host")) {
            throw new Error('hashedRequestHeaders must include "host"');
        }
        if (!normalizedHrh.includes("authorization")) {
            throw new Error('hashedRequestHeaders must include "authorization"');
        }

        this.options = {
            algorithm: "RS256",
            debug: false,
            ...options,
            hashedRequestHeaders: normalizedHrh,
        };
    }

    public sign(request: CanonicalRequest): Record<string, string> {
        const hrh = this.options.hashedRequestHeaders;

        const canonicalString = this.canonicalize(request, hrh);
        const token = this.buildJwt(canonicalString, hrh);

        if (this.options.debug) {
            try {
                const [rawHeader, rawPayload] = token.split(".");
                const header = JSON.parse(Buffer.from(rawHeader, "base64url").toString());
                const payload = JSON.parse(Buffer.from(rawPayload, "base64url").toString());
                console.debug("[PKCV] Canonical request:", JSON.stringify(canonicalString));
                console.debug("[PKCV] JWT header:", JSON.stringify(header, null, 2));
                console.debug("[PKCV] JWT payload:", JSON.stringify(payload, null, 2));
            } catch {}
        }

        return { "Twilio-Client-Validation": token };
    }

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

    private canonicalizePath(pathname: string): string {
        const normalized = this.removeDotSegments(pathname || "/") || "/";
        return (
            normalized
                .split("/")
                .map((segment) => this.rfc3986Encode(this.safeDecodeUriComponent(segment)))
                .join("/") || "/"
        );
    }

    private canonicalizeQuery(searchParams: URLSearchParams): string {
        const pairs: string[] = [];
        for (const [key, value] of searchParams.entries()) {
            pairs.push(`${this.rfc3986Encode(key)}=${this.rfc3986Encode(value)}`);
        }
        return pairs.sort().join("&");
    }

    private canonicalizeHeaders(
        headers: Record<string, string | string[]>,
        hrh: string[],
    ): { canonicalHeaders: string; signedHeaders: string } {
        const hrhSet = new Set(hrh);
        const grouped = new Map<string, string[]>();
        for (const [rawKey, rawValue] of Object.entries(headers)) {
            const key = rawKey.trim().toLowerCase();
            if (!hrhSet.has(key)) {
                continue;
            }
            const values = Array.isArray(rawValue) ? rawValue : [rawValue];
            for (const value of values) {
                const normalizedValue = value.trim().replace(/\s+/g, " ");
                const existing = grouped.get(key) ?? [];
                existing.push(normalizedValue);
                grouped.set(key, existing);
            }
        }

        for (const key of hrh) {
            if (!grouped.has(key) || grouped.get(key)!.length === 0) {
                throw new Error(`Missing required hashed request header: ${key}`);
            }
        }

        const canonicalHeaders = hrh
            .map((key) => {
                const values = grouped.get(key)!.sort();
                return `${key}:${values.join(",")}\n`;
            })
            .join("");

        const signedHeaders = hrh.join(";");

        return { canonicalHeaders, signedHeaders };
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

    private rfc3986Encode(value: string): string {
        return encodeURIComponent(value)
            .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
            .replace(/%7E/g, "~");
    }

    private safeDecodeUriComponent(value: string): string {
        try {
            return decodeURIComponent(value);
        } catch {
            return value;
        }
    }

    private removeDotSegments(path: string): string {
        let input = path;
        let output = "";

        while (input.length > 0) {
            if (input.startsWith("../")) {
                input = input.slice(3);
                continue;
            }
            if (input.startsWith("./")) {
                input = input.slice(2);
                continue;
            }
            if (input.startsWith("/./")) {
                input = `/${input.slice(3)}`;
                continue;
            }
            if (input === "/.") {
                input = "/";
                continue;
            }
            if (input.startsWith("/../")) {
                input = `/${input.slice(4)}`;
                output = this.removeLastPathSegment(output);
                continue;
            }
            if (input === "/..") {
                input = "/";
                output = this.removeLastPathSegment(output);
                continue;
            }
            if (input === "." || input === "..") {
                input = "";
                continue;
            }

            const nextSlash = input.indexOf("/", input.startsWith("/") ? 1 : 0);
            if (nextSlash === -1) {
                output += input;
                input = "";
            } else {
                output += input.slice(0, nextSlash);
                input = input.slice(nextSlash);
            }
        }

        return output;
    }

    private removeLastPathSegment(path: string): string {
        if (path === "") {
            return "";
        }

        const lastSlash = path.lastIndexOf("/");
        if (lastSlash <= 0) {
            return "";
        }

        return path.slice(0, lastSlash);
    }

    private sha256Hex(input: string): string {
        return createHash("sha256").update(input, "utf8").digest("hex");
    }
}
