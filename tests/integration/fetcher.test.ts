import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CanonicalRequest, RequestSigner } from "../../sdks/typescript/pkcv/RequestSigner.js";

const mockFetcherImpl = vi.fn();

vi.mock("../../sdks/typescript/core/fetcher/Fetcher.js", () => ({
    fetcherImpl: mockFetcherImpl,
}));

const { createPkcvFetcher } = await import("../../sdks/typescript/wrapper/createPkcvFetcher.js");

class MockSigner implements RequestSigner {
    calls: CanonicalRequest[] = [];
    sign(request: CanonicalRequest): Record<string, string> {
        this.calls.push(request);
        return { "Twilio-Client-Validation": "mock-jwt" };
    }
}

describe("createPkcvFetcher()", () => {
    let mockSigner: MockSigner;

    beforeEach(() => {
        mockSigner = new MockSigner();
        mockFetcherImpl.mockReset();
        mockFetcherImpl.mockResolvedValue({ ok: true, body: null });
    });

    it("calls signer.sign() exactly once per request", async () => {
        const fetcher = createPkcvFetcher(mockSigner);
        await fetcher({ url: "https://api.twilio.com/v2/Services", method: "GET" });
        expect(mockSigner.calls).toHaveLength(1);
    });

    it("passes the correct HTTP method to signer.sign()", async () => {
        const fetcher = createPkcvFetcher(mockSigner);
        await fetcher({ url: "https://api.twilio.com/v2/Services", method: "DELETE" });
        expect(mockSigner.calls[0]!.method).toBe("DELETE");
    });

    it("passes the full resolved URL (including query params) to signer.sign()", async () => {
        const fetcher = createPkcvFetcher(mockSigner);
        await fetcher({
            url: "https://api.twilio.com/v2/Services",
            method: "GET",
            queryParameters: { PageSize: "20" },
        });
        expect(mockSigner.calls[0]!.url).toBe("https://api.twilio.com/v2/Services?PageSize=20");
    });

    it("always includes host extracted from URL in signing headers", async () => {
        const fetcher = createPkcvFetcher(mockSigner);
        await fetcher({ url: "https://api.twilio.com/v2/Services", method: "GET" });
        expect(mockSigner.calls[0]!.headers).toMatchObject({ host: "api.twilio.com" });
    });

    it("passes caller-supplied headers (lowercased) to signer.sign()", async () => {
        const fetcher = createPkcvFetcher(mockSigner);
        await fetcher({
            url: "https://api.twilio.com/v2/Services",
            method: "GET",
            headers: { Authorization: "Basic dXNlcjpwYXNz" },
        });
        expect(mockSigner.calls[0]!.headers).toMatchObject({
            authorization: "Basic dXNlcjpwYXNz",
        });
    });

    it("passes serialized body string to signer.sign()", async () => {
        const fetcher = createPkcvFetcher(mockSigner);
        await fetcher({
            url: "https://api.twilio.com/v2/Services",
            method: "POST",
            body: { name: "My Service" },
            requestType: "json",
        });
        expect(typeof mockSigner.calls[0]!.body).toBe("string");
        expect(mockSigner.calls[0]!.body).toContain("My Service");
    });

    it("passes undefined body to signer.sign() when no body is provided", async () => {
        const fetcher = createPkcvFetcher(mockSigner);
        await fetcher({ url: "https://api.twilio.com/v2/Services", method: "GET" });
        expect(mockSigner.calls[0]!.body).toBeUndefined();
    });

    it("injects Twilio-Client-Validation header into the outgoing request", async () => {
        const fetcher = createPkcvFetcher(mockSigner);
        await fetcher({ url: "https://api.twilio.com/v2/Services", method: "GET" });

        const argsPassedToFetcherImpl = mockFetcherImpl.mock.calls[0]?.[0];
        expect(argsPassedToFetcherImpl?.headers).toMatchObject({
            "Twilio-Client-Validation": "mock-jwt",
        });
    });

    it("preserves original caller headers alongside the injected auth header", async () => {
        const fetcher = createPkcvFetcher(mockSigner);
        await fetcher({
            url: "https://api.twilio.com/v2/Services",
            method: "GET",
            headers: { "X-Custom": "my-value" },
        });

        const argsPassedToFetcherImpl = mockFetcherImpl.mock.calls[0]?.[0];
        expect(argsPassedToFetcherImpl?.headers).toMatchObject({
            "X-Custom": "my-value",
            "Twilio-Client-Validation": "mock-jwt",
        });
    });

    it("keeps authorization and host values aligned between signing input and outgoing request context", async () => {
        const fetcher = createPkcvFetcher(mockSigner);
        const authorization = "Basic dXNlcjpwYXNz";

        await fetcher({
            url: "https://api.twilio.com/v2/Services?PageSize=20",
            method: "GET",
            headers: { Authorization: authorization },
        });

        const signingCall = mockSigner.calls[0]!;
        const outgoingArgs = mockFetcherImpl.mock.calls[0]?.[0];

        expect(signingCall.headers.authorization).toBe(authorization);
        expect(outgoingArgs?.headers?.Authorization).toBe(authorization);
        expect(signingCall.headers.host).toBe(new URL(signingCall.url).host);
        expect(new URL(String(outgoingArgs?.url)).host).toBe(signingCall.headers.host);
    });
});
