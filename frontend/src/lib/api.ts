import createClient from "openapi-fetch";
import type { paths } from "../../api.d.ts";

/**
 * Shared typed client for the google-auth JSON API (`just types-routes`
 * regenerates `api.d.ts` from the router's OpenAPI document).
 *
 * No CSRF token: Datasette checks `Sec-Fetch-Site`/`Origin` (D30).
 * openapi-fetch sends `Content-Type: application/json` on every JSON body;
 * cookies go same-origin only.
 */
export const client = createClient<paths>({
  baseUrl: "/",
  credentials: "same-origin",
});

/** The JSON API's error body (`error_response()` in `errors.py`). */
export interface ApiError {
  ok: false;
  error: string;
  code: string;
}

/**
 * Normalize openapi-fetch results and thrown network errors into
 * `{ data }` or `{ errorMessage, code }` so callers can't silently ignore
 * failures.
 */
export async function api<T>(
  promise: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<{ data?: T; errorMessage?: string; code?: string }> {
  try {
    const { data, error, response } = await promise;
    if (error !== undefined || !response.ok) {
      const err = error as Partial<ApiError> | undefined;
      return {
        errorMessage: err?.error ?? `HTTP ${response.status}`,
        code: err?.code,
      };
    }
    return { data };
  } catch (e) {
    return { errorMessage: e instanceof Error ? e.message : String(e) };
  }
}
