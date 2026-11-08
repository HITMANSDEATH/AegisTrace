"""Run against a started Docker deployment: python tests/limits_smoke.py
Uses the host-side gateway only. Set FRONTEND_PORT, MAX_REQUEST_BODY_BYTES,
MAX_PROMPT_CHARS, and SMOKE_ORIGIN to the values used by the deployment.
The burst intentionally consumes the chat rate budget and may call the
configured live provider a few times.
"""
import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = f"http://127.0.0.1:{os.getenv('FRONTEND_PORT', '3000')}"
ORIGIN = os.getenv('SMOKE_ORIGIN', 'http://localhost:3000')
BODY_LIMIT = int(os.getenv('MAX_REQUEST_BODY_BYTES', '131072'))
PROMPT_LIMIT = int(os.getenv('MAX_PROMPT_CHARS', '4000'))


def post(payload, origin=None):
    headers = {'Content-Type': 'application/json'}
    if origin:
        headers['Origin'] = origin
    request = urllib.request.Request(
        BASE + '/chat', data=json.dumps(payload).encode(), headers=headers, method='POST')
    try:
        with urllib.request.urlopen(request, timeout=40) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


def header(headers, name):
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


def expect(status, payload, code, origin=None):
    actual, headers, body = post(payload, origin)
    assert actual == status, (actual, body[:200])
    parsed = json.loads(body)
    assert parsed.get('error') == code, parsed
    assert isinstance(parsed.get('message'), str) and parsed['message'], parsed
    if origin:
        assert header(headers, 'Access-Control-Allow-Origin') == origin, headers
    print(f'PASS: {status} {code}')


def main():
    expect(413, {'session_id': 'limits-smoke', 'message': 'x' * (BODY_LIMIT + 1024)},
           'payload_too_large', ORIGIN)
    expect(422, {'session_id': 'limits-smoke', 'message': 'x' * (PROMPT_LIMIT + 1)},
           'prompt_too_long', ORIGIN)

    def burst(index):
        return post({'session_id': f'limits-burst-{index}', 'message': 'hello'})

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(burst, range(20)))
    codes = [result[0] for result in results]
    assert 429 in codes, f'rate limit did not trigger: {codes}'
    limited = next(result for result in results if result[0] == 429)
    assert json.loads(limited[2]).get('error') == 'rate_limited', limited[2]
    print(f'PASS: rate limit returned {codes.count(429)} x 429 in a 20-request burst')
    print('PASS: gateway body, prompt, and rate limits')


if __name__ == '__main__':
    main()
