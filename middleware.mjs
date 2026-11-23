/**
 * Magpie Gateway Middleware (`onProvider`) for Agy2API PromptSanitizer.
 *
 * Pure ES2023 module targeting Go `github.com/MoeForge/moejs v0.1.0`:
 * - Zero Node.js APIs, zero ctx cloning, zero prompt logging.
 * - Fail-open: unexpected errors return `undefined` (passthrough original body).
 *
 * Magpie also passes the body through untouched when this hook exceeds its
 * 250 ms budget, so the provider `fetch` (`lib/fetch.mjs`) repeats the same
 * pass without a time limit.
 */

import { sanitizeRequestBody } from "./lib/sanitize-request.mjs";

export const DEFAULT_TARGET_PROVIDER_ID = "agy2api";

export function onProvider(body, ctx) {
  try {
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return undefined;
    }

    const options = ctx?.options;
    const targetProviderId =
      (typeof options?.providerId === "string" && options.providerId.trim()) ||
      DEFAULT_TARGET_PROVIDER_ID;

    if (ctx?.provider?.id !== targetProviderId) {
      return undefined;
    }

    return sanitizeRequestBody(ctx?.protocol, body, options);
  } catch {
    return undefined;
  }
}
