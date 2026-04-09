import { EndpointSupplier } from "../core/fetcher/EndpointSupplier.js";
import { type Fetcher, type FetchFunction, fetcherImpl } from "../core/fetcher/Fetcher.js";
import { createRequestUrl } from "../core/fetcher/createRequestUrl.js";
import { getRequestBody } from "../core/fetcher/getRequestBody.js";
import type { RequestSigner } from "../pkcv/RequestSigner.js";

function bodyToString(body: BodyInit | undefined): string | undefined {
    if (body == null) {
        return undefined;
    }

    if (typeof body === "string") {
        return body;
    }

    if (body instanceof URLSearchParams) {
        return body.toString();
    }

    if (body instanceof ArrayBuffer) {
        return Buffer.from(body).toString("utf8");
    }

    if (ArrayBuffer.isView(body)) {
        return Buffer.from(body.buffer, body.byteOffset, body.byteLength).toString("utf8");
    }

    return undefined;
}

export function createPkcvFetcher(signer: RequestSigner): FetchFunction {
    return async function pkcvFetcher<R = unknown>(args: Fetcher.Args) {
        const resolvedUrl = createRequestUrl(args.url, args.queryParameters);
        const parsedUrl = new URL(resolvedUrl);

        const signingHeaders: Record<string, string> = {
            host: parsedUrl.host,
        };

        if (args.headers != null) {
            for (const [key, value] of Object.entries(args.headers)) {
                const resolved = await EndpointSupplier.get(value, {
                    endpointMetadata: args.endpointMetadata ?? {},
                });
                if (resolved != null) {
                    signingHeaders[key.toLowerCase()] = String(resolved);
                }
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

        const signedArgs: Fetcher.Args = {
            ...args,
            headers: {
                ...args.headers,
                ...authHeaders,
            },
        };

        return fetcherImpl<R>(signedArgs);
    };
}
