/**
 * Magpie Gateway Middleware (`onRequest`) for Antigravity2API.
 *
 * Pure ES2023 module targeting Go `github.com/MoeForge/moejs v0.1.0`:
 * - Zero Node.js APIs, zero ctx cloning, zero prompt logging.
 * - Verifies HMAC-signed `_agy2api_relay` payloads from `hooks.mjs` to apply
 *   pre-routing auxiliary model/effort rewrites, and unconditionally strips
 *   any `_agy2api_relay` field before upstream routing.
 * - Prompt sanitization runs exclusively in the provider `fetch` (`lib/fetch.mjs`)
 *   without the 250 ms `moejs` hook budget.
 */

import {
  MIN_RELAY_SECRET_LEN,
  RELAY_FIELD,
  applyEffortToBody,
  verifyRelayPayload,
} from "./lib/relay-crypto.mjs";
import { RELAY_SECRET } from "./lib/relay-secret.mjs";

export function onRequest(body, ctx) {
  try {
    if (!body || typeof body !== "object" || Array.isArray(body) || !(RELAY_FIELD in body)) {
      return undefined;
    }

    const nextBody = { ...body };
    const relayObj = body[RELAY_FIELD];
    delete nextBody[RELAY_FIELD];

    const optSecret = ctx?.options?.relaySecret;
    const secret =
      typeof optSecret === "string" && optSecret.length >= MIN_RELAY_SECRET_LEN
        ? optSecret
        : RELAY_SECRET;

    const verified = verifyRelayPayload(secret, relayObj, ctx?.protocol, Date.now());
    if (!verified.valid) {
      return nextBody;
    }

    nextBody.model = verified.toModel;
    if (verified.toEffort) {
      return applyEffortToBody(ctx?.protocol, nextBody, verified.toEffort);
    }
    return nextBody;
  } catch {
    try {
      if (body && typeof body === "object" && !Array.isArray(body) && RELAY_FIELD in body) {
        const stripped = { ...body };
        delete stripped[RELAY_FIELD];
        return stripped;
      }
    } catch {
      // ignore
    }
    return undefined;
  }
}
