import asyncio
import threading
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from agent.main import create_app, sensitive_action_requested, classify, SessionRegistry
from agent.capture import AuditCapture
from agent import llm_provider

class FakeLLM:
    def __init__(self): self.messages=[]
    async def ainvoke(self,messages):
        self.messages.append(messages)
        return SimpleNamespace(content='Mock-provider response: tool result processed.')

@pytest.mark.parametrize('message,expected',[('make changes to the log',True),('delete audit records',True),('overwrite the evidence',True),('remove history',True),('the trace should be altered',False),('erase ledger',True),('What is an audit log?',False),('delete a temporary picture',False)])
def test_classification(message,expected):
    assert sensitive_action_requested(message)==expected

@pytest.mark.parametrize('message,event_type,sensitive',[('What is the access policy?','retrieval',False),('Investigate account access','tool_start',False),('make changes to the log','tool_start',True),('Hello there','state_transition',False)])
def test_graph_chat_capture(message,event_type,sensitive):
    events=[];model=FakeLLM()
    with TestClient(create_app(llm=model,capture=events.append)) as client:
        response=client.post('/chat',json={'session_id':'live','message':message})
        assert response.status_code==200,response.text
        body=response.json()
        assert body['event_type']==event_type
        assert body['sensitive_action_flag']==sensitive
        assert all(event['payload']['turn_id']==body['turn_id'] for event in events)
        assert events[-1]['payload']['actor']=='assistant'
        if event_type=='tool_start':
            start=next(event for event in events if event['event_type']=='tool_start')
            end=next(event for event in events if event['event_type']=='tool_end')
            assert start['sensitive_action_flag']==sensitive
            assert end['payload']['action_executed'] is True
            assert end['payload']['real_world_action_executed'] is False
        client.post('/chat',json={'session_id':'live','message':'And why?'})
        assert ('human',message) in model.messages[-1]
        client.post('/chat',json={'session_id':'separate','message':'Hello'})
        assert ('human',message) not in model.messages[-1]


def test_provider_failure_sanitized_and_audited():
    class Broken:
        async def ainvoke(self,messages): raise RuntimeError('sk-secret-key full stack trace')
    events=[]
    with TestClient(create_app(llm=Broken(),capture=events.append)) as client:
        response=client.post('/chat',json={'session_id':'failed','message':'hello'})
    assert response.status_code==503
    assert response.json()['error']=='live_agent_unavailable'
    assert 'secret' not in response.text and 'RuntimeError' not in response.text
    assert events[-1]['payload']['state']=='error'


def test_sink_block_or_failure_does_not_block_chat():
    release=threading.Event();received=[]
    def slow_sink(event):
        release.wait(3);received.append(event)
        raise RuntimeError('sink failed')
    capture=AuditCapture(sink=slow_sink,maxsize=32)
    started=time.monotonic()
    with TestClient(create_app(llm=FakeLLM(),capture=capture)) as client:
        response=client.post('/chat',json={'session_id':'unblocked','message':'make changes to the log'})
    assert response.status_code==200
    assert time.monotonic()-started<1
    release.set();capture.close(drain=True)
    assert received[0]['payload']['state']=='received'
    assert received[-1]['payload']['state']=='complete'


def test_fifo_and_queue_bound():
    entered=threading.Event();release=threading.Event();received=[]
    def sink(event):
        entered.set();release.wait(3);received.append(event['payload']['i'])
    capture=AuditCapture(sink=sink,maxsize=2)
    capture.capture(session_id='s',event_type='retrieval',payload={'i':0})
    assert entered.wait(1)
    for i in range(1,10):capture.capture(session_id='s',event_type='retrieval',payload={'i':i})
    assert capture.pending<=2
    release.set();capture.close(drain=True)
    assert received==[0,1,2]


def test_provider_factory(monkeypatch):
    seen=[]
    monkeypatch.setattr(llm_provider,'ChatGroq',lambda **kwargs:seen.append(('groq',kwargs)) or object())
    monkeypatch.setattr(llm_provider,'ChatOllama',lambda **kwargs:seen.append(('ollama',kwargs)) or object())
    monkeypatch.setenv('LLM_PROVIDER','groq');monkeypatch.setenv('GROQ_API_KEY','fake')
    monkeypatch.delenv('GROQ_MODEL',raising=False)
    llm_provider.get_llm()
    assert seen[-1][1]['model']=='llama-3.3-70b-versatile'
    assert seen[-1][1]['max_retries']==0
    monkeypatch.setenv('LLM_PROVIDER','ollama');llm_provider.get_llm()
    assert seen[-1][0]=='ollama'
    monkeypatch.setenv('LLM_PROVIDER','groq');monkeypatch.delenv('GROQ_API_KEY')
    with pytest.raises(llm_provider.ProviderConfigurationError):llm_provider.get_llm()


def test_demo_fixtures_through_capture_only(monkeypatch):
    monkeypatch.setenv('DEMO_MODE','true');events=[]
    with TestClient(create_app(llm=FakeLLM(),capture=events.append)) as client:
        response=client.post('/demo/session',json={'session_id':'demo','mode':'tampered'})
        assert response.status_code==202
    assert len(events)==7
    assert events[3]['payload']['amount_usd']==8400
    monkeypatch.setenv('DEMO_MODE','false')
    assert all(getattr(route,'path','')!='/demo/session' for route in create_app(capture=events.append).routes)


def test_session_capacity_counts_waiters():
    registry=SessionRegistry(1)
    first=registry.acquire('a')
    with pytest.raises(Exception):registry.acquire('b')
    first.users-=1
    assert registry.acquire('b') is not first
