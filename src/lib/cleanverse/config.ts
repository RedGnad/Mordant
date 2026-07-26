import "server-only";

import { z } from "zod";

import { isValidCleanverseApiKey } from "./crypto";

const httpUrlSchema = z.string().url().refine((value) => {
  const protocol = new URL(value).protocol;
  return protocol === "http:" || protocol === "https:";
}, "Expected an HTTP or HTTPS URL");

const configSchema = z
  .object({
    baseUrl: httpUrlSchema,
    apiId: z.string().trim().min(1),
    apiKey: z.string().trim().min(1).refine(isValidCleanverseApiKey),
  })
  .strict();

export type CleanverseConfig = Readonly<z.output<typeof configSchema>>;

export class CleanverseConfigError extends Error {
  constructor() {
    super("Cleanverse server configuration is missing or invalid");
    this.name = "CleanverseConfigError";
  }
}

let cachedConfig: CleanverseConfig | undefined;

export type CleanverseEnvironment = {
  CLEANVERSE_API_BASE_URL?: string;
  CLEANVERSE_API_ID?: string;
  CLEANVERSE_API_KEY?: string;
};

export function parseCleanverseConfig(environment: CleanverseEnvironment): CleanverseConfig {
  const result = configSchema.safeParse({
    baseUrl: environment.CLEANVERSE_API_BASE_URL,
    apiId: environment.CLEANVERSE_API_ID,
    apiKey: environment.CLEANVERSE_API_KEY,
  });

  if (!result.success) {
    throw new CleanverseConfigError();
  }

  return Object.freeze({
    ...result.data,
    baseUrl: result.data.baseUrl.replace(/\/+$/, ""),
  });
}

export function getCleanverseConfig(): CleanverseConfig {
  if (cachedConfig) {
    return cachedConfig;
  }

  cachedConfig = parseCleanverseConfig({
    CLEANVERSE_API_BASE_URL: process.env.CLEANVERSE_API_BASE_URL,
    CLEANVERSE_API_ID: process.env.CLEANVERSE_API_ID,
    CLEANVERSE_API_KEY: process.env.CLEANVERSE_API_KEY,
  });
  return cachedConfig;
}
