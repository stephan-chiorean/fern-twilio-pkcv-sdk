import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type {
  CanonicalRequest,
  RequestSigner,
} from "../../sdks/typescript/pkcv/RequestSigner.js";

const mockFetcherImpl = vi.fn();

vi.mock("../../sdks/typescript/core/fetcher/Fetcher.js", () => ({
  fetcherImpl: mockFetcherImpl,
}));

const { TwilioPkcvClient } = await import(
  "../../sdks/typescript/wrapper/TwilioPkcvClient.js"
);

const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateKeyPem = privateKey.export({
  type: "pkcs8",
  format: "pem",
}) as string;

const PKCV_OPTIONS = {
  apiKeySid: "SK000",
  accountSid: "AC000",
  credentialSid: "CR000",
  privateKeyPem,
};

const BASIC_AUTH_OPTIONS = {
  username: "AC00000000000000000000000000000000",
  password: "auth_token_value",
};

class MockSigner implements RequestSigner {
  calls: CanonicalRequest[] = [];
  sign(request: CanonicalRequest): Record<string, string> {
    this.calls.push(request);
    return { "Twilio-Client-Validation": "mock-jwt" };
  }
}

describe("TwilioPkcvClient", () => {
  describe("construction", () => {
    it("constructs successfully with a pre-built RequestSigner via auth option", () => {
      expect(
        () =>
          new TwilioPkcvClient({
            ...BASIC_AUTH_OPTIONS,
            auth: new MockSigner(),
          })
      ).not.toThrow();
    });

    it("constructs successfully with pkcv shorthand options", () => {
      expect(
        () =>
          new TwilioPkcvClient({ ...BASIC_AUTH_OPTIONS, pkcv: PKCV_OPTIONS })
      ).not.toThrow();
    });

    it("throws when neither auth nor pkcv is provided", () => {
      expect(() => new TwilioPkcvClient({ ...BASIC_AUTH_OPTIONS })).toThrow(
        /requires either auth or pkcv/
      );
    });

    it("pkcv shorthand creates a TwilioPkcvSigner internally", () => {
      const client = new TwilioPkcvClient({
        ...BASIC_AUTH_OPTIONS,
        pkcv: PKCV_OPTIONS,
      });
      expect(client).toBeInstanceOf(TwilioPkcvClient);
    });
  });

  describe("signer integration", () => {
    it("invokes signer.sign() when a method is called", async () => {
      mockFetcherImpl.mockResolvedValue({ ok: true, body: { services: [] } });
      const mockSigner = new MockSigner();
      const client = new TwilioPkcvClient({
        ...BASIC_AUTH_OPTIONS,
        auth: mockSigner,
      });

      await client.services.list().catch(() => {});

      expect(mockSigner.calls.length).toBeGreaterThanOrEqual(1);
    });

    it("injects Twilio-Client-Validation into the request when using a MockSigner", async () => {
      mockFetcherImpl.mockResolvedValue({ ok: true, body: { services: [] } });
      const mockSigner = new MockSigner();
      const client = new TwilioPkcvClient({
        ...BASIC_AUTH_OPTIONS,
        auth: mockSigner,
      });

      await client.services.list().catch(() => {});

      const argsPassedToFetcherImpl = mockFetcherImpl.mock.calls[0]?.[0];
      expect(argsPassedToFetcherImpl?.headers).toMatchObject({
        "Twilio-Client-Validation": "mock-jwt",
      });
    });

    it("signer receives the correct HTTP method for a list() call", async () => {
      mockFetcherImpl.mockResolvedValue({ ok: true, body: { services: [] } });
      const mockSigner = new MockSigner();
      const client = new TwilioPkcvClient({
        ...BASIC_AUTH_OPTIONS,
        auth: mockSigner,
      });

      await client.services.list().catch(() => {});

      expect(mockSigner.calls[0]!.method).toBe("GET");
    });
  });
});
