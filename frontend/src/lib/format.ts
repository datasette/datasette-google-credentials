const AUTH_PREFIX = "https://www.googleapis.com/auth/";

/** `https://www.googleapis.com/auth/spreadsheets` → `spreadsheets`. */
export function shortScope(scope: string): string {
  return scope.startsWith(AUTH_PREFIX)
    ? scope.slice(AUTH_PREFIX.length)
    : scope;
}

/** An internal-DB timestamp (`2026-09-29T12:34:56.789Z`) as local time. */
export function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

/**
 * A non-secret peek at a pasted key file, to confirm the right file before
 * it's sent: its `client_email`, or why it doesn't look like a key. The
 * server does the real validation (and the live test).
 */
export function describeKey(
  text: string,
): { email: string } | { problem: string } | null {
  if (!text.trim()) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { problem: "This isn't valid JSON." };
  }
  if (typeof parsed !== "object" || parsed === null) {
    return { problem: "This isn't a service account key file." };
  }
  const key = parsed as Record<string, unknown>;
  if (key.type !== "service_account") {
    return {
      problem:
        'This isn\'t a service account key ("type" should be "service_account").',
    };
  }
  return typeof key.client_email === "string"
    ? { email: key.client_email }
    : { problem: "The key has no client_email." };
}
