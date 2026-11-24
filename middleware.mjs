/**
 * Magpie Gateway Middleware (`onRequest` & `onProvider`) for Agy2API.
 *
 * Pure ES2023 module targeting Go `github.com/MoeForge/moejs v0.1.0`:
 * - Zero Node.js APIs, zero ctx cloning, zero prompt logging.
 * - Fail-open: unexpected errors return `undefined` (passthrough original body),
 *   except `onRequest` always strips any untrusted `_agy2api_relay` field.
 *
 * Magpie also passes the body through untouched when this hook exceeds its
 * 250 ms budget, so the provider `fetch` (`lib/fetch.mjs`) repeats the
 * sanitization pass without a time limit and also strips any stale `_agy2api_relay`.
 */

import { sanitizeRequestBody } from "./lib/sanitize-request.mjs";
import {
  MIN_RELAY_SECRET_LEN,
  RELAY_FIELD,
  applyEffortToBody,
  verifyRelayPayload,
} from "./lib/relay-crypto.mjs";
import { RELAY_SECRET } from "./lib/relay-secret.mjs";

export const DEFAULT_TARGET_PROVIDER_IDS = ["agy2api", "agy2api-plugin"];

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

export function onProvider(body, ctx) {
  try {
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return undefined;
    }

    const options = ctx?.options;
    const explicitProviderId =
      typeof options?.providerId === "string" ? options.providerId.trim() : "";
    const providerId = ctx?.provider?.id;
    const matched = explicitProviderId
      ? providerId === explicitProviderId
      : DEFAULT_TARGET_PROVIDER_IDS.includes(providerId);
    if (!matched) {
      return undefined;
    }

    if (ctx?.provider?.account === "plugin" && options?.forceMiddlewareOnPlugin !== true) {
      return undefined;
    }

    return sanitizeRequestBody(ctx?.protocol, body, options);
  } catch {
    return undefined;
  }
}
