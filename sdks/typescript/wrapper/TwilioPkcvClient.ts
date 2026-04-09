import type { BaseClientOptions } from "../BaseClient.js";
import { TwilioClient } from "../Client.js";
import type { RequestSigner } from "../pkcv/RequestSigner.js";
import { TwilioPkcvSigner, type TwilioPkcvSignerOptions } from "../pkcv/TwilioPkcvSigner.js";
import { createPkcvFetcher } from "./createPkcvFetcher.js";

export interface TwilioPkcvClientOptions extends Omit<BaseClientOptions, "fetcher"> {
    auth?: RequestSigner;
    pkcv?: TwilioPkcvSignerOptions;
}

export class TwilioPkcvClient extends TwilioClient {
    constructor(options: TwilioPkcvClientOptions) {
        const { auth, pkcv, ...baseOptions } = options;
        const signer = auth ?? (pkcv != null ? new TwilioPkcvSigner(pkcv) : undefined);

        if (signer == null) {
            throw new Error("TwilioPkcvClient requires either auth or pkcv options");
        }

        super({
            ...baseOptions,
            fetcher: createPkcvFetcher(signer),
        });
    }
}
