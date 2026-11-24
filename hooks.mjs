import { handleGatewayOnRequest, handleGatewayOnResponse } from "./lib/aux-router.mjs";
import { RELAY_FIELD } from "./lib/relay-crypto.mjs";

function stripRelayIfPresent(body) {
  if (!body || typeof body !== "object" || Array.isArray(body) || !(RELAY_FIELD in body)) {
    return undefined;
  }
  const next = { ...body };
  delete next[RELAY_FIELD];
  return next;
}

export async function onRequest(body, ctx) {
  try {
    return await handleGatewayOnRequest(body, ctx);
  } catch {
    return stripRelayIfPresent(body);
  }
}

export async function onResponse(reply, ctx) {
  try {
    await handleGatewayOnResponse(reply, ctx);
  } catch {
    // fail-open observer
  }
}
