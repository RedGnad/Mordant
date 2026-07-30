import { z } from "zod";

const personalEmailDomains = new Set([
  "gmail.com",
  "googlemail.com",
  "hotmail.com",
  "icloud.com",
  "live.com",
  "outlook.com",
  "proton.me",
  "protonmail.com",
  "yahoo.com",
]);

const requiredText = (label: string, maximum: number) => z.string()
  .trim()
  .min(2, `${label} is required.`)
  .max(maximum, `${label} is too long.`);

export const pilotApplicationSchema = z.object({
  organization: requiredText("Organization", 120),
  role: requiredText("Role", 100),
  portfolioType: requiredText("Portfolio type", 120),
  approximateVolume: requiredText("Approximate receivables volume", 80),
  conflictProcess: requiredText("Current conflict process", 1_000),
  dataSource: requiredText("System or data source", 500),
  workEmail: z.email("Enter a valid work email.")
    .max(254, "Email is too long.")
    .refine((email) => !personalEmailDomains.has(email.split("@").at(-1)?.toLowerCase() ?? ""), {
      message: "Use your professional email address.",
    }),
});

export type PilotApplication = z.infer<typeof pilotApplicationSchema>;

export type PilotApplicationEnvelope = {
  schema: "mordant.pilot-application.v1";
  applicationId: string;
  submittedAt: string;
  source: "mordant-public-pilot-form";
  application: PilotApplication;
};

export function parsePilotApplication(input: unknown) {
  return pilotApplicationSchema.safeParse(input);
}
