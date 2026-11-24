/**
 * Pure ES2023 cryptographic and relay payload helpers shared by `hooks.mjs` (Bun)
 * and `middleware.mjs` (Go `moejs v0.1.0`).
 *
 * Zero Node.js APIs, zero Web APIs, zero prompt logging.
 */

export const RELAY_FIELD = "_agy2api_relay";
export const RELAY_TTL_MS = 30_000;
export const MIN_RELAY_SECRET_LEN = 32;

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const SHA256_H = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const EFFORT_TO_BUDGET = {
  minimal: 512,
  low: 1024,
  medium: 8192,
  high: 16384,
  xhigh: 24576,
  max: 32768,
};

const VALID_EFFORTS = new Set(["minimal", "low", "medium", "high", "xhigh", "max", "none"]);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

export function utf8Bytes(str) {
  const s = typeof str === "string" ? str : String(str ?? "");
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let code = s.charCodeAt(i);
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        const cp = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        out.push(
          0xf0 | (cp >> 18),
          0x80 | ((cp >> 12) & 0x3f),
          0x80 | ((cp >> 6) & 0x3f),
          0x80 | (cp & 0x3f),
        );
        i++;
      } else {
        out.push(0xef, 0xbf, 0xbd);
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      out.push(0xef, 0xbf, 0xbd);
    } else {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  return out;
}

export function sha256Bytes(input) {
  const msg = Array.isArray(input)
    ? input.slice()
    : input && typeof input === "object" && typeof input.length === "number"
      ? Array.from(input)
      : utf8Bytes(input);

  const bitLen = msg.length * 8;
  msg.push(0x80);
  while (msg.length % 64 !== 56) {
    msg.push(0);
  }
  const hi = Math.floor(bitLen / 0x100000000) >>> 0;
  const lo = bitLen >>> 0;
  msg.push(
    (hi >>> 24) & 0xff,
    (hi >>> 16) & 0xff,
    (hi >>> 8) & 0xff,
    hi & 0xff,
    (lo >>> 24) & 0xff,
    (lo >>> 16) & 0xff,
    (lo >>> 8) & 0xff,
    lo & 0xff,
  );

  let h0 = SHA256_H[0];
  let h1 = SHA256_H[1];
  let h2 = SHA256_H[2];
  let h3 = SHA256_H[3];
  let h4 = SHA256_H[4];
  let h5 = SHA256_H[5];
  let h6 = SHA256_H[6];
  let h7 = SHA256_H[7];

  const w = new Array(64);

  for (let offset = 0; offset < msg.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = ((msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]) | 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0;
    h5 = (h5 + f) | 0;
    h6 = (h6 + g) | 0;
    h7 = (h7 + h) | 0;
  }

  const words = [h0, h1, h2, h3, h4, h5, h6, h7];
  const digest = new Array(32);
  for (let i = 0; i < 8; i++) {
    const v = words[i];
    digest[i * 4] = (v >>> 24) & 0xff;
    digest[i * 4 + 1] = (v >>> 16) & 0xff;
    digest[i * 4 + 2] = (v >>> 8) & 0xff;
    digest[i * 4 + 3] = v & 0xff;
  }
  return digest;
}

function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const hex = (bytes[i] & 0xff).toString(16);
    out += hex.length === 1 ? "0" + hex : hex;
  }
  return out;
}

export function sha256Hex(input) {
  return bytesToHex(sha256Bytes(input));
}

export function hmacSha256Hex(key, message) {
  let keyBytes = utf8Bytes(key);
  if (keyBytes.length > 64) {
    keyBytes = sha256Bytes(keyBytes);
  }
  const ipad = new Array(64);
  const opad = new Array(64);
  for (let i = 0; i < 64; i++) {
    const k = i < keyBytes.length ? keyBytes[i] : 0;
    ipad[i] = k ^ 0x36;
    opad[i] = k ^ 0x5c;
  }
  const msgBytes = utf8Bytes(message);
  const innerInput = ipad.concat(msgBytes);
  const innerHash = sha256Bytes(innerInput);
  const outerInput = opad.concat(innerHash);
  return bytesToHex(sha256Bytes(outerInput));
}

export function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length === 0 || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function canonicalRelayMessage(toModel, toEffort, proto, ts, nonce) {
  return JSON.stringify([1, toModel, toEffort, proto, ts, nonce]);
}

export function signRelayPayload(secret, { toModel, toEffort = "", proto, ts = Date.now(), nonce } = {}) {
  if (typeof secret !== "string" || secret.length < MIN_RELAY_SECRET_LEN) {
    return null;
  }
  const cleanModel = typeof toModel === "string" ? toModel.trim() : "";
  const cleanProto = typeof proto === "string" ? proto.trim() : "";
  if (!cleanModel || !cleanProto) {
    return null;
  }
  const rawEffort = typeof toEffort === "string" ? toEffort.trim().toLowerCase() : "";
  const cleanEffort = rawEffort && VALID_EFFORTS.has(rawEffort) ? rawEffort : "";
  const cleanTs = typeof ts === "number" && Number.isFinite(ts) ? Math.floor(ts) : Math.floor(Date.now());
  const cleanNonce =
    typeof nonce === "string" && nonce.trim()
      ? nonce.trim()
      : `${cleanTs.toString(36)}-${Math.random().toString(36).slice(2, 12)}`;

  const msg = canonicalRelayMessage(cleanModel, cleanEffort, cleanProto, cleanTs, cleanNonce);
  const sig = hmacSha256Hex(secret, msg);
  return {
    v: 1,
    toModel: cleanModel,
    ...(cleanEffort ? { toEffort: cleanEffort } : {}),
    proto: cleanProto,
    ts: cleanTs,
    nonce: cleanNonce,
    sig,
  };
}

export function verifyRelayPayload(secret, relayObj, expectedProto, nowMs = Date.now()) {
  if (typeof secret !== "string" || secret.length < MIN_RELAY_SECRET_LEN) {
    return { valid: false, reason: "missing_secret" };
  }
  if (!relayObj || typeof relayObj !== "object" || Array.isArray(relayObj)) {
    return { valid: false, reason: "invalid_shape" };
  }
  if (relayObj.v !== 1) {
    return { valid: false, reason: "unsupported_version" };
  }
  const toModel = typeof relayObj.toModel === "string" ? relayObj.toModel.trim() : "";
  if (!toModel) {
    return { valid: false, reason: "missing_model" };
  }
  if (relayObj.toEffort !== undefined && typeof relayObj.toEffort !== "string") {
    return { valid: false, reason: "invalid_effort" };
  }
  const rawEffort = typeof relayObj.toEffort === "string" ? relayObj.toEffort.trim().toLowerCase() : "";
  if (rawEffort && !VALID_EFFORTS.has(rawEffort)) {
    return { valid: false, reason: "invalid_effort" };
  }
  const proto = typeof relayObj.proto === "string" ? relayObj.proto.trim() : "";
  if (!proto || typeof expectedProto !== "string" || proto !== expectedProto.trim()) {
    return { valid: false, reason: "protocol_mismatch" };
  }
  const ts = relayObj.ts;
  if (typeof ts !== "number" || !Number.isFinite(ts)) {
    return { valid: false, reason: "invalid_timestamp" };
  }
  if (Math.abs(nowMs - ts) > RELAY_TTL_MS) {
    return { valid: false, reason: "expired" };
  }
  const nonce = typeof relayObj.nonce === "string" ? relayObj.nonce.trim() : "";
  if (!nonce || nonce.length > 128) {
    return { valid: false, reason: "invalid_nonce" };
  }
  const sig = typeof relayObj.sig === "string" ? relayObj.sig.trim().toLowerCase() : "";
  if (!/^[0-9a-f]{64}$/.test(sig)) {
    return { valid: false, reason: "invalid_sig_format" };
  }
  const expectedSig = hmacSha256Hex(secret, canonicalRelayMessage(toModel, rawEffort, proto, ts, nonce));
  if (!timingSafeEqualHex(sig, expectedSig)) {
    return { valid: false, reason: "bad_signature" };
  }
  return {
    valid: true,
    toModel,
    toEffort: rawEffort,
  };
}

function isPlainObject(val) {
  return Boolean(val) && typeof val === "object" && !Array.isArray(val);
}

/**
 * Pure ES2023 non-mutating effort rewriter shared between `middleware.mjs` and `lib/aux-router.mjs`.
 * If `targetEffort === "none"`, removes/clears thinking parameters safely.
 */
export function applyEffortToBody(protocol, body, targetEffort) {
  if (!isPlainObject(body)) return body;
  const eff = typeof targetEffort === "string" ? targetEffort.trim().toLowerCase() : "";
  if (!eff || !VALID_EFFORTS.has(eff)) return body;

  const next = { ...body };

  if (protocol === "gemini") {
    const genKey = isPlainObject(next.generationConfig)
      ? "generationConfig"
      : isPlainObject(next.generation_config)
        ? "generation_config"
        : "generationConfig";
    const existingGen = isPlainObject(next[genKey]) ? next[genKey] : null;
    if (eff === "none") {
      if (!existingGen) return next;
      const nextGen = { ...existingGen };
      delete nextGen.thinkingConfig;
      delete nextGen.thinking_config;
      if (Object.keys(nextGen).length === 0) {
        delete next[genKey];
      } else {
        next[genKey] = nextGen;
      }
      return next;
    }
    const nextGen = existingGen ? { ...existingGen } : {};
    const tcKey = isPlainObject(nextGen.thinkingConfig)
      ? "thinkingConfig"
      : isPlainObject(nextGen.thinking_config)
        ? "thinking_config"
        : genKey === "generation_config"
          ? "thinking_config"
          : "thinkingConfig";
    const nextTc = isPlainObject(nextGen[tcKey]) ? { ...nextGen[tcKey] } : {};
    const levelKey =
      "thinkingLevel" in nextTc
        ? "thinkingLevel"
        : "thinking_level" in nextTc
          ? "thinking_level"
          : tcKey === "thinking_config"
            ? "thinking_level"
            : "thinkingLevel";
    delete nextTc.thinkingBudget;
    delete nextTc.thinking_budget;
    nextTc[levelKey] = eff;
    nextGen[tcKey] = nextTc;
    next[genKey] = nextGen;
    return next;
  }

  if (protocol === "anthropic") {
    if (eff === "none") {
      delete next.thinking;
      if (isPlainObject(next.output_config)) {
        const nextOc = { ...next.output_config };
        delete nextOc.effort;
        if (Object.keys(nextOc).length === 0) {
          delete next.output_config;
        } else {
          next.output_config = nextOc;
        }
      }
      return next;
    }

    if (isPlainObject(next.thinking) && (next.thinking.type === "disabled" || next.thinking.type === "between_tools")) {
      return next;
    }

    if (
      isPlainObject(next.thinking) &&
      next.thinking.type === "enabled" &&
      typeof next.thinking.budget_tokens === "number" &&
      !isPlainObject(next.output_config)
    ) {
      let budget = EFFORT_TO_BUDGET[eff] ?? 1024;
      if (typeof next.max_tokens === "number" && Number.isFinite(next.max_tokens) && next.max_tokens > 1) {
        if (budget >= next.max_tokens) {
          budget = Math.max(1024, next.max_tokens - 1);
        }
      }
      if (typeof next.max_tokens !== "number" || budget < next.max_tokens) {
        next.thinking = { ...next.thinking, budget_tokens: budget };
        return next;
      }
    }

    next.output_config = {
      ...(isPlainObject(next.output_config) ? next.output_config : {}),
      effort: eff,
    };
    return next;
  }

  if (protocol === "chat") {
    if (eff === "none") {
      delete next.reasoning_effort;
      if (isPlainObject(next.reasoning)) {
        const nextR = { ...next.reasoning };
        delete nextR.effort;
        if (Object.keys(nextR).length === 0) {
          delete next.reasoning;
        } else {
          next.reasoning = nextR;
        }
      }
      if (isPlainObject(next.extra_body?.google?.thinking_config)) {
        const nextGoogle = { ...next.extra_body.google };
        delete nextGoogle.thinking_config;
        const nextExtra = { ...next.extra_body };
        if (Object.keys(nextGoogle).length === 0) {
          delete nextExtra.google;
        } else {
          nextExtra.google = nextGoogle;
        }
        if (Object.keys(nextExtra).length === 0) {
          delete next.extra_body;
        } else {
          next.extra_body = nextExtra;
        }
      }
      return next;
    }

    if (isPlainObject(next.extra_body?.google?.thinking_config)) {
      const nextGoogle = {
        ...next.extra_body.google,
        thinking_config: {
          ...next.extra_body.google.thinking_config,
          thinking_level: eff,
        },
      };
      delete nextGoogle.thinking_config.thinking_budget;
      next.extra_body = { ...next.extra_body, google: nextGoogle };
      return next;
    }

    if (isPlainObject(next.reasoning) && typeof next.reasoning.effort === "string") {
      next.reasoning = { ...next.reasoning, effort: eff };
      return next;
    }
    next.reasoning_effort = eff;
    return next;
  }

  if (protocol === "responses") {
    if (eff === "none") {
      if (isPlainObject(next.reasoning)) {
        const nextR = { ...next.reasoning };
        delete nextR.effort;
        if (Object.keys(nextR).length === 0) {
          delete next.reasoning;
        } else {
          next.reasoning = nextR;
        }
      }
      return next;
    }

    next.reasoning = {
      ...(isPlainObject(next.reasoning) ? next.reasoning : {}),
      effort: eff,
    };
    return next;
  }

  return next;
}
