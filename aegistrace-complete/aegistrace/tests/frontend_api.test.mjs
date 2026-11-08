import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../frontend/api.js', import.meta.url), 'utf8');
const moduleURL = `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
let instance = 0;
const id = 'case /?#é';
const session = `/api/session/${encodeURIComponent(id)}`;
const routes = [
  ['config', [], '/api/config'],
  ['sessions', [], '/api/sessions'],
  ['graph', [id], `${session}/graph`],
  ['verify', [id], `${session}/verify`],
  ['entries', [id], `${session}/entries`],
  ['chat', [id, 'Hello'], '/chat', { session_id: id, message: 'Hello' }],
  ['seed', [id, 'verified'], '/demo/session', { session_id: id, mode: 'verified' }],
  ['tamper', [id, 7, { message: 'changed' }], `${session}/tamper`, { entry_id: 7, payload: { message: 'changed' } }],
  ['export', [id], `${session}/export`],
];

async function harness(t, fetchImpl, configuredBase = '  https://api.example.invalid/prefix///  ') {
  // Each import gets a fresh module-scoped base; no browser or network is used.
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  Object.defineProperty(globalThis, 'window', {
    configurable: true, value: configuredBase === undefined ? {} : { AEGIS_API_BASE: configuredBase },
  });
  t.after(() => {
    if (previous) Object.defineProperty(globalThis, 'window', previous);
    else delete globalThis.window;
  });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const schedule = t.mock.method(globalThis, 'setTimeout');
  const clear = t.mock.method(globalThis, 'clearTimeout');
  const fetch = t.mock.method(globalThis, 'fetch', fetchImpl);
  const { api } = await import(`${moduleURL}#${instance++}`);
  return { api, fetch, schedule, clear };
}

function assertTimerCleared({ schedule, clear }) {
  assert.equal(schedule.mock.callCount(), 1);
  assert.equal(schedule.mock.calls[0].arguments[1], 35000);
  assert.equal(clear.mock.callCount(), 1);
  assert.equal(clear.mock.calls[0].arguments[0], schedule.mock.calls[0].result);
}

for (const [name, args, path, body] of routes) {
  test(`${name}: configured base, encoded route, request options and response`, async t => {
    const data = { result: name };
    const blob = new Blob(['{"exported":true}'], { type: 'application/json' });
    const h = await harness(t, async () => ({
      ok: true,
      json: async () => { assert.notEqual(name, 'export'); return data; },
      blob: async () => { assert.equal(name, 'export'); return blob; },
    }));
    assert.deepEqual(Object.keys(h.api).sort(), routes.map(route => route[0]).sort());
    assert.equal(await h.api[name](...args), name === 'export' ? blob : data);
    assert.equal(h.fetch.mock.callCount(), 1);
    const [url, options] = h.fetch.mock.calls[0].arguments;
    assert.equal(url, `https://api.example.invalid/prefix${path}`);
    assert.equal(options.method ?? 'GET', body ? 'POST' : 'GET');
    assert.equal(options.body, body ? JSON.stringify(body) : undefined);
    assert.deepEqual(options.headers, { 'Content-Type': 'application/json' });
    assert.equal(options.cache, 'no-store');
    assert.ok(options.signal instanceof AbortSignal);
    assert.equal(options.signal.aborted, false);
    assertTimerCleared(h);
    t.mock.timers.tick(35000);
    assert.equal(options.signal.aborted, false, 'completed request timer must not abort later');
    if (name === 'export') assert.equal(await blob.text(), '{"exported":true}');
  });
}

for (const configuredBase of ['', '   ', null]) {
  test(`same-origin base: ${JSON.stringify(configuredBase)}`, async t => {
    const h = await harness(t, async () => ({ ok: true, json: async () => ({}) }), configuredBase);
    await h.api.config();
    assert.equal(h.fetch.mock.calls[0].arguments[0], '/api/config');
    assertTimerCleared(h);
  });
}

test('missing window.AEGIS_API_BASE preserves same-origin routing', async t => {
  const h = await harness(t, async () => ({ ok: true, json: async () => ({}) }), '');
  delete window.AEGIS_API_BASE;
  const { api } = await import(`${moduleURL}#${instance++}`);
  await api.sessions();
  assert.equal(h.fetch.mock.calls[0].arguments[0], '/api/sessions');
  assertTimerCleared(h);
});

for (const name of ['config', 'export']) {
  for (const [data, message] of [
    [{ message: 'Friendly message', error: 'code', detail: 'detail' }, 'Friendly message'],
    [{ error: 'error_code', detail: 'detail' }, 'error_code'],
    [{ detail: 'Session missing' }, 'Session missing'],
    [{ detail: [{ msg: 'Invalid input' }] }, 'Request failed'],
    [{}, 'Request failed'],
  ]) {
    test(`${name}: JSON error ${message}`, async t => {
      const h = await harness(t, async () => ({
        ok: false, status: 422, json: async () => data,
        blob: async () => assert.fail('failed export must parse JSON, not a blob'),
      }));
      await assert.rejects(h.api[name](id), error => {
        assert.equal(error.message, message);
        assert.equal(error.status, 422);
        assert.equal(error.data, data);
        return true;
      });
      assertTimerCleared(h);
    });
  }

  test(`${name}: network/CORS failure is sanitized`, async t => {
    const h = await harness(t, async () => { throw new TypeError('private network details'); });
    await assert.rejects(h.api[name](id), { message: 'Backend unreachable: check API URL / CORS.' });
    assertTimerCleared(h);
  });

  for (const ok of (name === 'export' ? [false] : [true, false])) {
    test(`${name}: non-JSON ${ok ? 'success' : 'failure'} is sanitized`, async t => {
      const h = await harness(t, async () => ({
        ok, status: ok ? 200 : 502,
        json: async () => { throw new SyntaxError('<html>gateway error</html>'); },
      }));
      await assert.rejects(h.api[name](id), { message: 'Backend unreachable: check API URL / CORS.' });
      assertTimerCleared(h);
    });
  }
}

for (const [name, args] of routes) {
  test(`${name}: aborts at 35000ms without real waiting`, async t => {
    let signal;
    const h = await harness(t, (_url, options) => new Promise((_resolve, reject) => {
      signal = options.signal;
      signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
    }));
    const pending = h.api[name](...args);
    const rejected = assert.rejects(pending, {
      message: 'Request timed out. Check the recorded session before retrying; the turn may have completed.',
    });
    t.mock.timers.tick(34999);
    assert.equal(signal.aborted, false);
    t.mock.timers.tick(1);
    assert.equal(signal.aborted, true);
    await rejected;
    assert.equal(h.fetch.mock.callCount(), 1, 'a timeout must not retry a potentially completed turn');
    assertTimerCleared(h);
  });
}

test('export blob read failure still clears its timer', async t => {
  const failure = new Error('blob stream failed');
  const h = await harness(t, async () => ({ ok: true, blob: async () => { throw failure; } }));
  await assert.rejects(h.api.export(id), error => error === failure);
  assertTimerCleared(h);
});
