import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from audit.main import create_app as audit_app
from reconstruction.main import create_app as reconstruction_app, open_ro

@pytest.fixture
def services(tmp_path,monkeypatch):
    path=tmp_path/'audit.db'
    monkeypatch.setenv('AUDIT_WRITE_TOKEN','test-write-only-secret')
    monkeypatch.setenv('DEMO_MODE','true')
    with TestClient(audit_app(path)) as sink, TestClient(reconstruction_app(path)) as reader:
        yield path,sink,reader

def ingest(sink,session='case',n=3):
    for i in range(n):
        response=sink.post('/ingest',headers={'Authorization':'Bearer test-write-only-secret'},json={
            'session_id':session,'event_type':'retrieval' if i==0 else 'tool_end','timestamp':1700000000.0+i/10,
            'client_seq':i+1,
            'payload':{'message':f'Event {i}','label':f'Event {i}','unicode':'é中','_aegis':{'forged':True}},
            'sensitive_action_flag':i==1})
        assert response.status_code==200,response.text
        assert response.json()=={'status':'recorded'}


def test_write_only_contract_and_schema(services):
    path,sink,reader=services
    for headers in ({},{'Authorization':'Bearer wrong'},{'x-ingest-token':'test-write-only-secret'}):
        response=sink.post('/ingest',headers=headers,json={'session_id':'x','timestamp':1.0,'event_type':'retrieval','payload':{},'client_seq':1})
        assert response.status_code==403
    for route in ('/ingest','/docs','/openapi.json','/health','/api/sessions'):
        assert sink.get(route).status_code in (404,405)
    ingest(sink)
    conn=sqlite3.connect(path)
    assert [r[1] for r in conn.execute('PRAGMA table_info(audit_log)')]==['id','session_id','timestamp','event_type','payload','sensitive_action_flag','prev_hash','hash']
    rows=reader.get('/api/session/case/entries').json()
    assert rows[0]['prev_hash']=='0'*64
    assert rows[0]['payload']['_aegis']['session_id']=='case'
    for row in rows:
        assert hashlib.sha256((row['timestamp_repr']+row['payload_str']+row['prev_hash']).encode()).hexdigest()==row['hash']
    verify=reader.get('/api/session/case/verify').json()
    assert verify['chain_intact'] and verify['ok'] and verify['session_id']=='case' and verify['entry_count']==3
    conn.close()


def test_concurrent_ingest_and_session_separation(services):
    _,sink,reader=services
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i:ingest(sink,'parallel' if i%2 else 'other',1),range(32)))
    for sid in ('parallel','other'):
        result=reader.get(f'/api/session/{sid}/verify').json()
        assert result['chain_intact'] and result['entry_count']==16
    assert len(reader.get('/api/sessions').json())==2


def test_payload_tamper_graph_export(services):
    _,sink,reader=services
    ingest(sink)
    rows=reader.get('/api/session/case/entries').json()
    graph=reader.get('/api/session/case/graph').json()
    assert graph['nodes'][1]['sensitive_action_flag'] is True
    assert all(not node['tampered'] for node in graph['nodes'])
    assert [n['position']['y'] for n in graph['nodes']]==[90,360,360]
    payload={**rows[1]['payload'],'message':'out-of-band change'}
    assert reader.post('/api/session/case/tamper',json={'entry_id':rows[1]['id'],'payload':payload}).status_code==200
    changed=reader.get('/api/session/case/graph').json()
    assert changed['verification']['broken_entry_ids']==[rows[1]['id']]
    assert changed['verification']['firstBroken']==2
    assert [node['tampered'] for node in changed['nodes']]==[False,True,True]
    assert [node['directly_broken'] for node in changed['nodes']]==[False,True,False]
    assert all(edge['broken'] for edge in changed['edges'])
    export=reader.get('/api/session/case/export')
    assert 'attachment' in export.headers['content-disposition']
    document=export.json()
    assert document['verification']['chain_intact'] is False
    assert document['entries'][1]['payload']['message']=='out-of-band change'
    assert document['entries'][1]['hash']==rows[1]['hash']
    assert document['verification']['recalculated']['evt-002']!=rows[1]['hash']

@pytest.mark.parametrize('column,value',[('event_type','state_transition'),('sensitive_action_flag',0),('payload','{bad json'),('prev_hash','f'*64),('timestamp',12.0),('timestamp','corrupt timestamp')])
def test_out_of_band_edits(services,column,value):
    path,sink,reader=services
    ingest(sink)
    with sqlite3.connect(path) as db: db.execute(f'UPDATE audit_log SET {column}=? WHERE id=2',(value,))
    result=reader.get('/api/session/case/verify')
    assert result.status_code==200
    assert result.json()['broken_entry_ids']==[2]
    assert reader.get('/api/session/case/graph').status_code==200


def test_middle_deletion_detected_suffix_limitation_explicit(services):
    path,sink,reader=services
    ingest(sink,n=4)
    with sqlite3.connect(path) as db: db.execute('DELETE FROM audit_log WHERE id=2')
    assert reader.get('/api/session/case/verify').json()['broken_entry_ids']==[3]
    ingest(sink,'suffix',3)
    with sqlite3.connect(path) as db: db.execute("DELETE FROM audit_log WHERE id=(SELECT MAX(id) FROM audit_log WHERE session_id='suffix')")
    assert reader.get('/api/session/suffix/verify').json()['chain_intact'] is True
    assert 'suffix deletion' in reader.get('/api/session/suffix/export').json()['trust_boundary']


def test_read_only_and_no_demo_route(services,monkeypatch):
    path,sink,reader=services
    ingest(sink)
    connection=open_ro(path)
    with pytest.raises(sqlite3.OperationalError): connection.execute('DELETE FROM audit_log')
    connection.close()
    monkeypatch.setenv('DEMO_MODE','false')
    app=reconstruction_app(path)
    assert all('tamper' not in getattr(route,'path','') and '/demo/' not in getattr(route,'path','') for route in app.routes)
    with TestClient(app) as prod:
        assert prod.post('/api/session/case/tamper',json={'entry_id':1,'payload':{}}).status_code in (404,405)


def test_invalid_and_unknown_input(services):
    _,sink,reader=services
    ingest(sink)
    assert reader.get('/api/session/unknown/graph').status_code==404
    assert reader.get('/api/session/invalid%20id/export').status_code==422
    assert reader.post('/api/session/other/tamper',json={'entry_id':1,'payload':{}}).status_code==404
    response=sink.post('/ingest',headers={'Authorization':'Bearer test-write-only-secret'},json={'session_id':'x','timestamp':'nan','event_type':'retrieval','payload':{},'client_seq':1})
    assert response.status_code==422
