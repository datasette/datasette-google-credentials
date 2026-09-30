import type { components } from "../../../api.d.ts";

/** One row of `GET /-/google-auth/api/credentials` (also the page data's). */
export type Credential = components["schemas"]["ListedCredential"];

export type Notice = { kind: "info" | "warning" | "error"; text: string };
