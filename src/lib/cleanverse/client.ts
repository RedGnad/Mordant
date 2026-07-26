import "server-only";

import { randomUUID } from "node:crypto";
import type { z } from "zod";

import { getCleanverseConfig, type CleanverseConfig } from "./config";
import { encryptCleanverseRequest } from "./crypto";
import {
  cleanverseEnvelopeSchema,
  launchATokenDataSchema,
  launchATokenRequestSchema,
  queryAPassDataSchema,
  queryAPassRequestSchema,
  queryApplyStatusDataSchema,
  querySupportedATokensDataSchema,
  querySupportedATokensRequestSchema,
  registerValidatorPoolDataSchema,
  registerValidatorPoolRequestSchema,
  requestIdSchema,
  verifyAPassDataSchema,
  verifyAPassRequestSchema,
  verifyValidatorPoolDataSchema,
  verifyValidatorPoolRequestSchema,
  type LaunchATokenData,
  type LaunchATokenRequest,
  type QueryAPassData,
  type QueryAPassRequest,
  type QueryApplyStatusData,
  type QuerySupportedATokensData,
  type QuerySupportedATokensRequest,
  type RegisterValidatorPoolData,
  type RegisterValidatorPoolRequest,
  type VerifyAPassData,
  type VerifyAPassRequest,
  type VerifyValidatorPoolData,
  type VerifyValidatorPoolRequest,
} from "./schemas";

export class CleanverseApiError extends Error {
  readonly upstreamCode?: string;
  readonly httpStatus?: number;

  constructor(message: string, options: { upstreamCode?: string; httpStatus?: number } = {}) {
    super(message);
    this.name = "CleanverseApiError";
    this.upstreamCode = options.upstreamCode;
    this.httpStatus = options.httpStatus;
  }
}

type RequestOptions = {
  method: "GET" | "POST";
  body?: unknown;
};

export type CleanverseFetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export class CleanverseClient {
  private readonly config: CleanverseConfig;
  private readonly fetchImpl: CleanverseFetch;

  constructor(config: CleanverseConfig, fetchImpl: CleanverseFetch = globalThis.fetch) {
    this.config = config;
    this.fetchImpl = fetchImpl;
  }

  private async request<T extends z.ZodType>(
    path: string,
    options: RequestOptions,
    dataSchema: T,
  ): Promise<z.output<T>> {
    const headers: Record<string, string> = {
      "api-id": this.config.apiId,
      "X-Request-ID": randomUUID(),
    };

    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    let response: Response;
    try {
      response = await this.fetchImpl(`${this.config.baseUrl}${path}`, {
        method: options.method,
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        cache: "no-store",
      });
    } catch {
      throw new CleanverseApiError("Cleanverse is unreachable");
    }

    if (!response.ok) {
      throw new CleanverseApiError("Cleanverse returned an HTTP error", { httpStatus: response.status });
    }

    let raw: unknown;
    try {
      raw = await response.json();
    } catch {
      throw new CleanverseApiError("Cleanverse returned invalid JSON");
    }

    const envelope = cleanverseEnvelopeSchema.safeParse(raw);
    if (!envelope.success) {
      throw new CleanverseApiError("Cleanverse returned an invalid response envelope");
    }
    if (envelope.data.code !== "0000") {
      throw new CleanverseApiError("Cleanverse rejected the request", {
        upstreamCode: envelope.data.code,
      });
    }

    const data = dataSchema.safeParse(envelope.data.data);
    if (!data.success) {
      throw new CleanverseApiError("Cleanverse returned invalid response data");
    }

    return data.data;
  }

  private encryptedBody(payload: unknown): { data: string } {
    return { data: encryptCleanverseRequest(payload, this.config.apiKey) };
  }

  async launchAToken(input: LaunchATokenRequest): Promise<LaunchATokenData> {
    const payload = launchATokenRequestSchema.parse(input);
    return this.request("/atoken/launch", { method: "POST", body: this.encryptedBody(payload) }, launchATokenDataSchema);
  }

  async queryApplyStatus(requestId: string): Promise<QueryApplyStatusData> {
    const parsedRequestId = requestIdSchema.parse(requestId);
    return this.request(
      `/atoken/query_apply_status/${encodeURIComponent(parsedRequestId)}`,
      { method: "GET" },
      queryApplyStatusDataSchema,
    );
  }

  async querySupportedATokens(input: QuerySupportedATokensRequest): Promise<QuerySupportedATokensData> {
    const payload = querySupportedATokensRequestSchema.parse(input);
    return this.request("/query_deposit_atoken_list", { method: "POST", body: payload }, querySupportedATokensDataSchema);
  }

  async queryAPass(input: QueryAPassRequest): Promise<QueryAPassData> {
    const payload = queryAPassRequestSchema.parse(input);
    return this.request("/query_apass", { method: "POST", body: payload }, queryAPassDataSchema);
  }

  async verifyAPass(input: VerifyAPassRequest): Promise<VerifyAPassData> {
    const payload = verifyAPassRequestSchema.parse(input);
    return this.request("/verify_apass", { method: "POST", body: payload }, verifyAPassDataSchema);
  }

  async registerValidatorPool(input: RegisterValidatorPoolRequest): Promise<RegisterValidatorPoolData> {
    const payload = registerValidatorPoolRequestSchema.parse(input);
    return this.request(
      "/validator/register",
      { method: "POST", body: this.encryptedBody(payload) },
      registerValidatorPoolDataSchema,
    );
  }

  async verifyValidatorPool(input: VerifyValidatorPoolRequest): Promise<VerifyValidatorPoolData> {
    const payload = verifyValidatorPoolRequestSchema.parse(input);
    return this.request("/validator/verify", { method: "POST", body: payload }, verifyValidatorPoolDataSchema);
  }
}

let cleanverseClient: CleanverseClient | undefined;

export function getCleanverseClient(): CleanverseClient {
  cleanverseClient ??= new CleanverseClient(getCleanverseConfig());
  return cleanverseClient;
}
