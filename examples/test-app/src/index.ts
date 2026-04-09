import { existsSync, readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { TwilioClient } from "fern-twilio-pkcv-sdk";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "../../..");

dotenv.config({ path: path.join(projectRoot, ".env"), quiet: true });
dotenv.config({ quiet: true });

function isEnabled(value: string | undefined): boolean {
    return value === "1" || value === "true" || value === "yes";
}

function requiredEnv(name: string, dryRun: boolean, dryRunFallback?: string): string {
    const raw = process.env[name]?.trim();
    if (raw) {
        return raw;
    }
    if (dryRun && dryRunFallback != null) {
        return dryRunFallback;
    }
    throw new Error(`Missing required environment variable: ${name}`);
}

function loadPrivateKeyPem(dryRun: boolean): { privateKeyPem: string; privateKeyPassphrase?: string } {
    const explicitPathRaw = process.env.PRIVATE_KEY_PATH?.trim();
    const explicitPath =
        explicitPathRaw == null || explicitPathRaw === ""
            ? undefined
            : path.isAbsolute(explicitPathRaw)
              ? explicitPathRaw
              : path.resolve(projectRoot, explicitPathRaw);
    const inferredPath = path.join(projectRoot, "private_key.pem");
    const candidatePath = explicitPath ?? inferredPath;

    if (existsSync(candidatePath)) {
        return {
            privateKeyPem: readFileSync(candidatePath, "utf8"),
            privateKeyPassphrase: process.env.PRIVATE_KEY_PASSPHRASE?.trim() || undefined,
        };
    }

    if (!dryRun) {
        throw new Error(
            `Could not find private key at ${candidatePath}. Set PRIVATE_KEY_PATH correctly or place private_key.pem at ${inferredPath}`,
        );
    }

    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    return {
        privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    };
}

const dryRun = isEnabled(process.env.TWILIO_PKCV_EXAMPLE_DRY_RUN);
const debugPkcv = isEnabled(process.env.PKCV_DEBUG);

const accountSid = requiredEnv("TWILIO_ACCOUNT_SID", dryRun, "AC00000000000000000000000000000000");
const apiKeySid = requiredEnv("TWILIO_API_KEY_SID", dryRun, "SK00000000000000000000000000000000");
const apiKeySecret = requiredEnv("TWILIO_API_KEY_SECRET", dryRun, "example-secret");
const credentialSid = requiredEnv("TWILIO_CREDENTIAL_SID", dryRun, "CR00000000000000000000000000000000");
const { privateKeyPem, privateKeyPassphrase } = loadPrivateKeyPem(dryRun);

let sawPkcvHeader = false;
const baseFetch = globalThis.fetch.bind(globalThis);

const instrumentedFetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    const pkcvHeader = request.headers.get("Twilio-Client-Validation");

    if (pkcvHeader != null && pkcvHeader.length > 0) {
        sawPkcvHeader = true;
        const preview = `${pkcvHeader.slice(0, 18)}...${pkcvHeader.slice(-12)}`;
        console.log(`[example] Twilio-Client-Validation attached (${preview})`);
    } else {
        console.log("[example] Twilio-Client-Validation header missing on outgoing request");
    }

    if (dryRun) {
        const url = new URL(request.url);
        if (request.method === "GET" && url.pathname === "/v2/Services") {
            return new Response(
                JSON.stringify({
                    services: [
                        {
                            sid: "VA00000000000000000000000000000000",
                            account_sid: accountSid,
                            friendly_name: "PKCV Dry Run Service",
                        },
                    ],
                    meta: {
                        next_page_url: null,
                    },
                }),
                {
                    status: 200,
                    headers: { "content-type": "application/json" },
                },
            );
        }

        return new Response(JSON.stringify({}), {
            status: 200,
            headers: { "content-type": "application/json" },
        });
    }

    return baseFetch(request);
};

async function main(): Promise<void> {
    console.log(`[example] mode=${dryRun ? "dry-run" : "live"}`);
    console.log("[example] Creating Twilio PKCV-enabled SDK client");

    const client = new TwilioClient({
        username: apiKeySid,
        password: apiKeySecret,
        fetch: instrumentedFetch,
        pkcv: {
            apiKeySid,
            accountSid,
            credentialSid,
            privateKeyPem,
            privateKeyPassphrase,
            debug: debugPkcv,
        },
    });

    const page = await client.services.list({ pageSize: 5 });
    console.log(`[example] First page contains ${page.data.length} service(s)`);

    let iterated = 0;
    for await (const service of page) {
        iterated += 1;
        console.log(`[example] service #${iterated}: ${service.sid ?? "unknown"} ${service.friendlyName ?? ""}`.trim());
        if (iterated >= 3) {
            break;
        }
    }

    if (!sawPkcvHeader) {
        throw new Error("PKCV signing check failed: request was sent without Twilio-Client-Validation");
    }

    console.log("[example] PKCV signing verified from SDK consumer flow");
}

main().catch((error) => {
    console.error("[example] failed:", error);
    process.exit(1);
});
