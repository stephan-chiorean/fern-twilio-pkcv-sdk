export interface CanonicalRequest {
    method: string;
    url: string;
    headers: Record<string, string | string[]>;
    body?: string;
}

export interface RequestSigner {
    sign(request: CanonicalRequest): Record<string, string>;
}
