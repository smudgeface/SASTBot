/**
 * Thin fetch wrapper. All requests use credentials: "include" so the
 * sastbot_session cookie is sent automatically.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, body: unknown, message?: string) {
    super(message ?? `Request failed (${status})`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

export type ApiFetchOptions = RequestInit & {
  /** If provided, serialised as JSON and sent as the body with Content-Type: application/json. */
  json?: unknown;
};

export async function apiFetch<T = unknown>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const { json, headers, body, ...rest } = options;

  const finalHeaders = new Headers(headers ?? {});
  let finalBody: BodyInit | null | undefined = body as BodyInit | null | undefined;

  if (json !== undefined) {
    finalHeaders.set("Content-Type", "application/json");
    finalBody = JSON.stringify(json);
  }
  if (!finalHeaders.has("Accept")) {
    finalHeaders.set("Accept", "application/json");
  }

  const response = await fetch(path, {
    credentials: "include",
    ...rest,
    headers: finalHeaders,
    body: finalBody,
  });

  const contentType = response.headers.get("content-type") ?? "";
  const isJson = contentType.includes("application/json");
  const parsed: unknown = isJson
    ? await response.json().catch(() => null)
    : await response.text().catch(() => null);

  if (!response.ok) {
    const message =
      (isJson && parsed && typeof parsed === "object" && "detail" in parsed && typeof (parsed as { detail: unknown }).detail === "string"
        ? (parsed as { detail: string }).detail
        : undefined) ?? `Request failed (${response.status})`;
    throw new ApiError(response.status, parsed, message);
  }

  return parsed as T;
}
