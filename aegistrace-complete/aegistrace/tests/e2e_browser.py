"""Real HTTP + original frontend E2E with an injected fake LLM (no provider credentials).
Prereqs: requirements-dev.txt, playwright + installed Chromium, nginx, and local Cytoscape.
Run: CYTOSCAPE_JS=/path/to/cytoscape.min.js python tests/e2e_browser.py
No Docker isolation claim is made by this local-process test.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import httpx
import uvicorn
from playwright.sync_api import sync_playwright
from audit.main import create_app as audit_app
from reconstruction.main import create_app as reconstruction_app
from agent.main import create_app as agent_app
from agent.capture import AuditCapture

ROOT=Path(__file__).resolve().parents[1]
class FakeLLM:
    async def ainvoke(self,messages):
        if messages[-1][1]=='force provider failure':raise RuntimeError('secret-must-not-leak')
        return SimpleNamespace(content='Test-provider response: simulated action processed. Real audit records were not changed.')

def main():
    with tempfile.TemporaryDirectory(prefix='aegis-e2e-') as temporary:
        temp=Path(temporary);db=temp/'audit.db'
        os.environ['AUDIT_WRITE_TOKEN']='test-only-write-token'
        os.environ['DEMO_MODE']='true'
        capture=AuditCapture(audit_url='http://127.0.0.1:19001/ingest',token=os.environ['AUDIT_WRITE_TOKEN'])
        applications=[(audit_app(db),19001),(reconstruction_app(db,ROOT/'frontend'),19002),(agent_app(llm=FakeLLM(),capture=capture),19000)]
        servers=[];threads=[];gateway=None
        try:
            for app,port in applications:
                server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,log_level='error',access_log=False))
                thread=threading.Thread(target=server.run,daemon=True);thread.start();servers.append(server);threads.append(thread)
                for _ in range(100):
                    if server.started:break
                    time.sleep(.05)
                assert server.started,f'service {port} failed to start'
            nginx=(ROOT/'deploy/nginx.conf').read_text().replace('listen 3000;','listen 127.0.0.1:19003;')
            nginx=nginx.replace('agent_service:8000','127.0.0.1:19000').replace('reconstruction_service:8002','127.0.0.1:19002')
            nginx=nginx.replace('deny 172.29.12.3;', 'deny 172.29.12.3; deny 127.0.0.2;')  # Emulate the agent peer on loopback.
            nginx=nginx.replace('/tmp/nginx.pid',str(temp/'nginx.pid')).replace('/tmp/client_temp',str(temp/'client')).replace('/tmp/proxy_temp',str(temp/'proxy'))
            conf=temp/'nginx.conf';conf.write_text(nginx)
            subprocess.run(['nginx','-t','-c',str(conf)],check=True)
            gateway=subprocess.Popen(['nginx','-c',str(conf),'-g','daemon off;'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            for _ in range(100):
                try:
                    if httpx.get('http://127.0.0.1:19003/api/config').status_code==200:break
                except httpx.RequestError:pass
                time.sleep(.05)
            with httpx.Client(transport=httpx.HTTPTransport(local_address='127.0.0.2'),trust_env=False) as blocked:
                assert blocked.get('http://127.0.0.1:19003/api/sessions',headers={'X-Forwarded-For':'127.0.0.1'}).status_code==403
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True,args=['--no-sandbox'])
                page=browser.new_page(viewport={'width':1440,'height':1050},accept_downloads=True)
                errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
                def resources(route):
                    if 'cytoscape.min.js' in route.request.url:
                        route.fulfill(path=os.environ['CYTOSCAPE_JS'],content_type='application/javascript')
                    elif route.request.url.startswith('http://127.0.0.1:19003'):route.continue_()
                    else:route.abort()
                page.route('**/*',resources)
                page.goto('http://127.0.0.1:19003/app.html?mode=try')
                page.wait_for_function("!document.getElementById('chat-send').disabled")
                page.locator('#chat-input').fill('make changes to the log');page.locator('#chat-send').click()
                page.wait_for_function("document.getElementById('session-notice').textContent.includes('Response recorded')")
                assert page.locator('.event.flagged').count()>0
                assert page.locator('.event.broken').count()==0
                assert page.locator('#chain-status').inner_text()=='✓ CHAIN INTACT'
                assert page.evaluate("document.getElementById('cy')._cyreg.cy.nodes('.flagged').length")>0
                cases=httpx.get('http://127.0.0.1:19003/api/sessions').json();sid=cases[0]['session_id']
                rows=httpx.get(f'http://127.0.0.1:19003/api/session/{sid}/entries').json()
                assert any(row['sensitive_action_flag'] and row['event_type']=='tool_start' for row in rows)
                assert next(row for row in rows if row['event_type']=='tool_end')['payload']['action_executed'] is True
                page.locator('.event-card').first.click()
                assert page.locator('#inspector').is_visible()
                assert len(page.locator('#inspector-hash').inner_text())==64
                page.locator('#close-inspector').click()
                page.locator('#inject-tamper').click()
                page.wait_for_function("document.getElementById('chain-status').textContent.includes('TAMPER DETECTED')")
                assert page.locator('.event.broken').count()==1
                assert page.locator('.event.affected').count()>0
                assert page.evaluate("document.getElementById('cy')._cyreg.cy.nodes('.affected').length")>0
                with page.expect_download() as download:page.locator('#export-session').click()
                output=temp/'case.json';download.value.save_as(output)
                exported=json.loads(output.read_text())
                assert exported['verification']['chain_intact'] is False
                assert exported['entries']
                page.locator('#timeline').fill('0');page.locator('#timeline').dispatch_event('input')
                assert page.locator('.event').count()==0
                page.locator('#timeline-end').click()
                assert page.locator('.event').count()==len(rows)
                page.screenshot(path=str(ROOT/'docs/e2e-tamper.png'),full_page=True)
                page.reload();page.wait_for_function("document.getElementById('chain-status').textContent.includes('TAMPER DETECTED')")
                assert page.locator('.event').count()==len(rows)
                page.locator('#tab-verified').click();page.wait_for_function("document.getElementById('chain-status').textContent==='✓ CHAIN INTACT'")
                assert page.locator('.event').count()==7
                page.locator('#tab-tampered').click();page.wait_for_function("document.getElementById('chain-status').textContent.includes('TAMPER DETECTED')")
                assert page.locator('.event.broken').count()==1
                page.locator('#tab-live').click();page.wait_for_function("!document.getElementById('chat-send').disabled")
                page.locator('#reset-session').click();page.wait_for_function("!document.getElementById('chat-send').disabled")
                page.locator('#chat-input').fill('force provider failure');page.locator('#chat-send').click()
                page.wait_for_function("document.getElementById('session-notice').textContent.includes('failed turn is recorded')")
                assert 'secret-must-not-leak' not in page.content()
                assert errors==[],errors
                browser.close()
            print('PASS: browser chat -> HTTP agent -> background HTTP ingest -> SQLite -> graph/verify; amber sensitivity, real payload tamper + downstream dimming, inspector, replay, server JSON export, reload persistence, both scripted modes, and sanitized provider-failure UI. No browser JS errors.')
        finally:
            if gateway:
                gateway.terminate();gateway.wait(timeout=5)
            capture.close(drain=True)
            for server in servers:server.should_exit=True
            for thread in threads:thread.join(timeout=5)

if __name__=='__main__':main()
