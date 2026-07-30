import { parsePilotApplication, type PilotApplicationEnvelope } from "@/lib/pilot/application";

export const runtime = "nodejs";

function json(body: unknown, status: number) {
  return Response.json(body, {
    status,
    headers: { "cache-control": "no-store, max-age=0" },
  });
}

function configuredWebhook(): URL | null {
  const configured = process.env.PILOT_APPLICATION_WEBHOOK_URL?.trim();
  if (!configured) return null;

  try {
    const endpoint = new URL(configured);
    const localDevelopment = process.env.NODE_ENV !== "production"
      && (endpoint.hostname === "127.0.0.1" || endpoint.hostname === "localhost");
    if (endpoint.protocol !== "https:" && !localDevelopment) return null;
    return endpoint;
  } catch {
    return null;
  }
}

export async function POST(request: Request) {
  const requestUrl = new URL(request.url);
  const origin = request.headers.get("origin");
  if (origin !== null && origin !== requestUrl.origin) {
    return json({ error: "Cross-origin applications are not accepted." }, 403);
  }

  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    return json({ error: "Expected a JSON application." }, 415);
  }

  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return json({ error: "The application could not be read." }, 400);
  }

  if (typeof raw === "object" && raw !== null && "website" in raw && raw.website !== "") {
    return json({ accepted: true }, 202);
  }

  const parsed = parsePilotApplication(raw);
  if (!parsed.success) {
    return json({
      error: "Review the highlighted application details.",
      fields: parsed.error.flatten().fieldErrors,
    }, 400);
  }

  const endpoint = configuredWebhook();
  if (endpoint === null) {
    return json({ error: "Application intake is not connected yet. No data was sent." }, 503);
  }

  const envelope: PilotApplicationEnvelope = {
    schema: "mordant.pilot-application.v1",
    applicationId: crypto.randomUUID(),
    submittedAt: new Date().toISOString(),
    source: "mordant-public-pilot-form",
    application: parsed.data,
  };
  const token = process.env.PILOT_APPLICATION_WEBHOOK_TOKEN?.trim();

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-mordant-event": "pilot.application.created",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(envelope),
      cache: "no-store",
      signal: AbortSignal.timeout(8_000),
    });

    if (!response.ok) {
      return json({ error: "The application channel did not accept the request. No receipt was issued." }, 502);
    }
  } catch {
    return json({ error: "The application channel is temporarily unavailable. Try again later." }, 502);
  }

  return json({ accepted: true, applicationId: envelope.applicationId }, 201);
}
