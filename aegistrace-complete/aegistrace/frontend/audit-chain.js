// Browser-only demonstration format. Not a claim of compatibility with the
// existing backend's canonicalization or event schema: confirm those in the repo.
export const GENESIS = '0'.repeat(64);
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonicalize(value[key])).join(',') + '}';
}
export async function sha256(value) {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto is unavailable. Open this app over HTTPS or localhost.');
  const bytes = new TextEncoder().encode(typeof value === 'string' ? value : canonicalize(value));
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
export function contentOf(event) { const { hash, ...content } = event; return content; }
export async function appendEvent(events, input, sessionId) {
  const start = performance.now();
  const seq = events.length + 1;
  const event = {
    id: `evt-${String(seq).padStart(3, '0')}`, seq, session_id: sessionId,
    timestamp: input.timestamp || new Date().toISOString(),
    type: input.type, label: input.label, payload: structuredClone(input.payload),
    parent_ids: input.parent_ids || (events.length ? [events.at(-1).id] : []),
    flagged: Boolean(input.flagged), prev_hash: events.at(-1)?.hash || GENESIS
  };
  event.hash = await sha256(event);
  return { event, durationMs: performance.now() - start };
}
export function receiptFor(events) { return { length: events.length, head_hash: events.at(-1)?.hash || GENESIS }; }
export async function sealEvents(inputs, sessionId) {
  const events = []; let sealMs = 0;
  for (const input of inputs) { const result = await appendEvent(events, input, sessionId); events.push(result.event); sealMs += result.durationMs; }
  return { events, sealMs, receipt: receiptFor(events) };
}
export async function verifyChain(events, receipt) {
  const start = performance.now(); const errors = []; const recalculated = {};
  for (let index = 0; index < events.length; index++) {
    const event = events[index];
    const expectedPrev = index ? events[index - 1].hash : GENESIS;
    const hash = await sha256(contentOf(event)); recalculated[event.id] = hash;
    if (event.seq !== index + 1) errors.push({ seq: index + 1, reason: 'Sequence mismatch' });
    if (index && event.session_id !== events[0].session_id) errors.push({ seq: index + 1, reason: 'Session mismatch' });
    if (event.prev_hash !== expectedPrev) errors.push({ seq: index + 1, reason: 'Previous-hash link mismatch' });
    if (event.hash !== hash) errors.push({ seq: index + 1, reason: 'Payload or metadata hash mismatch' });
  }
  if (receipt && events.length !== receipt.length) errors.push({ seq: Math.min(events.length, receipt.length) + 1, reason: 'Length differs from the local receipt' });
  if (receipt && (events.at(-1)?.hash || GENESIS) !== receipt.head_hash) errors.push({ seq: Math.max(1, events.length), reason: 'Head hash differs from the local receipt' });
  return { ok: errors.length === 0, checked: events.length, firstBroken: errors.length ? Math.min(...errors.map(e => e.seq)) : null, errors, recalculated, durationMs: performance.now() - start };
}
export const shortHash = (hash, size = 10) => hash ? `${hash.slice(0, size)}…${hash.slice(-6)}` : '—';
export const formatMs = value => value === null || value === undefined ? '—' : value < .01 ? '<0.01' : value.toFixed(2);
