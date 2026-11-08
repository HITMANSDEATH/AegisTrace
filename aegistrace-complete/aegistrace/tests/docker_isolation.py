"""Run against a started Docker deployment: python tests/docker_isolation.py
Optional: COMPOSE_FILES=compose.yaml:compose.demo.yaml python tests/docker_isolation.py
Makes no Groq inference call and uses no API key. Fails closed on unexpected reachability.
"""
import os
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
compose=['docker','compose']
for filename in os.getenv('COMPOSE_FILES','compose.yaml').split(':'):compose.extend(['-f',filename])

def execute(service,code):
    result=subprocess.run(compose+['exec','-T',service,'python','-'],input=code,text=True,cwd=ROOT,capture_output=True)
    print(result.stdout,end='')
    if result.returncode:raise RuntimeError(result.stderr or result.stdout)

execute('agent_service',r'''
import os,socket,httpx
client=httpx.Client(timeout=2,trust_env=False)
assert not os.path.exists('/data/audit.db'), 'agent has audit volume access'
assert not os.path.exists('/anchor_data'), 'agent has anchor volume access'
# No shared network to reconstruction. DNS resolution should fail or connection be blocked.
for host,port in [('reconstruction_service',8002),('172.29.13.3',8002),('172.29.14.3',8002),('anchor_service',8003),('172.29.16.2',8003)]:
    try:
        with socket.create_connection((host,port),timeout=2):pass
    except OSError:pass
    else:raise AssertionError('agent reached reconstruction or anchor: '+host)
# Gateway must not become a read oracle, including when XFF is forged.
for headers in ({},{'X-Forwarded-For':'127.0.0.1'}):
    response=client.get('http://frontend:3000/api/sessions',headers=headers)
    assert response.status_code==403,response.text
# Ingest auth is mandatory and no read surface exists, even with a valid write token.
body={'session_id':'isolation-probe','timestamp':1.0,'event_type':'state_transition','payload':{'message':'deployment isolation test'},'client_seq':1}
assert client.post('http://audit_service:8001/ingest',json=body).status_code==403
for path in ('/api/sessions','/docs','/openapi.json','/health','/ingest'):
    assert client.get('http://audit_service:8001'+path,headers={'Authorization':'Bearer '+os.environ['AUDIT_WRITE_TOKEN']}).status_code in (404,405)
assert client.post('http://audit_service:8001/ingest',json=body,headers={'Authorization':'Bearer '+os.environ['AUDIT_WRITE_TOKEN']}).json()=={'status':'recorded'}
# CONNECT to disallowed hosts/ports is denied by the proxy before any external request.
for target in ('example.com:443','api.groq.com:80','127.0.0.1:443'):
    with socket.create_connection(('groq_proxy',3128),timeout=3) as connection:
        connection.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
        result=connection.recv(1024)
        assert b' 403 ' in result,result
# Direct external TCP bypass is blocked by the internal-only agent networks.
try:
    with socket.create_connection(('1.1.1.1',443),timeout=2):pass
except OSError:pass
else:raise AssertionError('unrestricted direct egress is possible')
print('PASS: agent cannot read DB/reconstruction/gateway; sink write-only; disallowed proxy traffic and direct internet blocked.')
''')
execute('reconstruction_service',r'''
import os,sqlite3
connection=sqlite3.connect('file:/data/audit.db?mode=ro',uri=True)
try:connection.execute('UPDATE audit_log SET payload=payload WHERE 0')
except sqlite3.OperationalError:pass
else:raise AssertionError('mode=ro connection accepted a write')
connection.close()
if os.getenv('DEMO_MODE')!='true':
    connection=sqlite3.connect('/data/audit.db')
    try:connection.execute('UPDATE audit_log SET payload=payload WHERE 0')
    except sqlite3.OperationalError:pass
    else:raise AssertionError('production audit volume is writable')
    connection.close()
print('PASS: reconstruction read-only enforcement (demo exception acknowledged if enabled).')
''')
