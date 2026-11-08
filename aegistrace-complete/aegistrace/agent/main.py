"""Bounded LangGraph agent with best-effort, write-only event capture."""
import asyncio
import json
import os
import re
import uuid
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict, Literal

from fastapi import HTTPException
from common.cors import BrowserAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, ConfigDict
from langgraph.graph import StateGraph, START, END
from .capture import AuditCapture
from .llm_provider import get_llm
from .mock_tools import execute_action, retrieve_context

class ChatBody(BaseModel):
    model_config = ConfigDict(extra='forbid')
    session_id: str = Field(pattern=r'^[A-Za-z0-9_-]{1,96}$')
    message: str = Field(min_length=1,max_length=1000)
    @field_validator('message')
    @classmethod
    def nonempty(cls,value):
        if not value.strip(): raise ValueError('message cannot be blank')
        return value.strip()

class DemoBody(BaseModel):
    session_id: str = Field(pattern=r'^[A-Za-z0-9_-]{1,96}$')
    mode: Literal['verified','tampered']

_ACTION = re.compile(r'\b(modify|delete|erase|overwrite|alter|remove|change|changes|rewrite|clear|tamper)\b',re.I)
_TARGET = re.compile(r'\b(logs?|audit|ledger|records?|history|traces?|evidence|trails?)\b',re.I)
def sensitive_action_requested(text): return bool(_ACTION.search(text) and _TARGET.search(text))
def classify(text):
    if sensitive_action_requested(text): return 'sensitive_action'
    if re.search(r'\b(please|perform|execute|run|make|update|check|lookup|look up|investigate|analy[sz]e|modify|delete|remove)\b',text,re.I): return 'request'
    if '?' in text or re.match(r'^(who|what|when|where|why|how|can|could|would|is|are|do|does|which)\b',text,re.I): return 'question'
    return 'casual'

class Turn(TypedDict,total=False):
    session_id: str
    message: str
    turn_id: str
    category: str
    sensitive: bool
    history: list
    context: dict
    response: str

class Session:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.users = 0
        self.history = deque(maxlen=20)

class SessionRegistry:
    def __init__(self,max_sessions=256):
        self.items = OrderedDict()
        self.max_sessions = max_sessions
    def acquire(self,sid):
        # Called without awaits on one event loop. Count waiters as active too.
        if sid not in self.items:
            if len(self.items)>=self.max_sessions:
                inactive = next((key for key,value in self.items.items() if value.users==0),None)
                if inactive is None: raise HTTPException(503,'agent at capacity')
                del self.items[inactive]
            self.items[sid] = Session()
        result = self.items[sid]
        if result.users>=8: raise HTTPException(429,'too many queued turns for session')
        result.users += 1
        self.items.move_to_end(sid)
        return result


def create_app(*,llm=None,llm_provider=None,capture=None):
    owned = capture is None
    handler = capture if capture is not None else AuditCapture()
    @asynccontextmanager
    async def lifespan(app):
        handler.start() if hasattr(handler,'start') else None
        yield
        if owned: handler.close()
    app = BrowserAPI(lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
    registry = SessionRegistry(int(os.getenv('AGENT_MAX_SESSIONS','256')))
    app.state.capture = handler
    app.state.llm = llm

    def emit(turn,event_type,payload,sensitive=None,timestamp=None,client_seq=None):
        data = dict(session_id=turn['session_id'],event_type=event_type,
                    payload={**payload,'turn_id':turn['turn_id']},
                    sensitive_action_flag=turn.get('sensitive',False) if sensitive is None else sensitive,
                    timestamp=timestamp)
        if client_seq is not None:
            data['client_seq'] = client_seq
        try:
            handler.capture(**data) if hasattr(handler,'capture') else handler(data)
        except Exception:
            pass # Capture health never controls the agent's work.

    async def classify_node(turn):
        category = classify(turn['message'])
        sensitive = category=='sensitive_action'
        emit({**turn,'sensitive':sensitive},'state_transition',
             {'actor':'agent','state':'classified','category':category,'label':'Message classified','message':category})
        return {'category':category,'sensitive':sensitive}

    async def tool_node(turn):
        category = turn['category']
        context = {}
        if category=='question':
            emit(turn,'tool_start',{'actor':'tool','label':'Retrieve context started','tool':'retrieve_context','message':turn['message'],'simulated':True})
            context = retrieve_context(turn['message'])
            emit(turn,'retrieval',{'actor':'tool','label':'Retrieved context','message':context['context'],**context})
            emit(turn,'tool_end',{'actor':'tool','label':'Retrieve context complete','tool':'retrieve_context','message':context['context'],'simulated':True})
        elif category in ('request','sensitive_action'):
            emit(turn,'tool_start',{'actor':'tool','label':'Execute simulated action','message':turn['message'],'tool':'execute_action','simulated':True})
            context = execute_action(turn['message'],sensitive=turn['sensitive'])
            emit(turn,'tool_end',{'actor':'tool','label':'Simulated action complete','tool':'execute_action',**context})
        emit(turn,'state_transition',{'actor':'agent','state':'responding','label':'Preparing response','message':'Tools processed; preparing a response.'})
        return {'context':context}

    async def respond_node(turn):
        factory = llm_provider or get_llm
        model = app.state.llm if app.state.llm is not None else factory()
        # User text never becomes the system instruction. Context/history are data.
        messages = [('system','You are Atlas, an AI assistant. Respond helpfully and concisely. Never refer to yourself as AegisTrace. '
                     'Tools operate only on fictional demo data. Sensitive requests are flagged for audit, not blocked by that flag. '
                     'Explain simulated tool results accurately; never claim to modify the real audit database.\nTool result: '+json.dumps(turn.get('context',{})))]
        for old in turn['history']:
            messages.extend([('human',old['user']),('ai',old['assistant'])])
        messages.append(('human',turn['message']))
        if hasattr(model,'ainvoke'):
            result = await asyncio.wait_for(model.ainvoke(messages),timeout=25)
        else:
            result = await asyncio.wait_for(asyncio.to_thread(model.invoke,messages),timeout=25)
        content = result if isinstance(result,str) else getattr(result,'content','')
        if not isinstance(content,str) or not content.strip(): raise ValueError('empty provider response')
        emit(turn,'state_transition',{'actor':'assistant','state':'complete','label':'Assistant response','message':content})
        return {'response':content}

    builder = StateGraph(Turn)
    builder.add_node('classify',classify_node)
    builder.add_node('tools',tool_node)
    builder.add_node('respond',respond_node)
    builder.add_edge(START,'classify')
    builder.add_edge('classify','tools')
    builder.add_edge('tools','respond')
    builder.add_edge('respond',END)
    graph = builder.compile()
    app.state.graph = graph

    @app.get('/health')
    def health(): return {'status':'ok'}

    @app.post('/chat')
    async def chat(body: ChatBody):
        session = registry.acquire(body.session_id)
        try:
            async with session.lock:
                turn = {'session_id':body.session_id,'message':body.message,'turn_id':'turn-'+uuid.uuid4().hex,
                        'sensitive':sensitive_action_requested(body.message),'history':list(session.history)}
                emit(turn,'state_transition',{'actor':'user','state':'received','label':'User instruction','message':body.message})
                try:
                    result = await graph.ainvoke(turn)
                    session.history.append({'user':body.message,'assistant':result['response']})
                    event_type = {'question':'retrieval','request':'tool_start','sensitive_action':'tool_start','casual':'state_transition'}[result['category']]
                    return {'response':result['response'],'event_type':event_type,'sensitive_action_flag':result['sensitive'],'turn_id':turn['turn_id']}
                except Exception:
                    message = 'Live agent unavailable. Check the server provider configuration, credentials, connectivity, or rate limit, then retry.'
                    emit(turn,'state_transition',{'actor':'system','state':'error','label':'Agent unavailable','message':message})
                    return JSONResponse(status_code=503,content={'error':'live_agent_unavailable','message':message,'turn_id':turn['turn_id']})
        finally:
            session.users -= 1

    if os.getenv('DEMO_MODE','false').lower()=='true':
        @app.post('/demo/session',status_code=202)
        async def demo_session(body: DemoBody):
            fixtures = json.loads(Path(__file__).with_name('demo_fixtures.json').read_text())[body.mode]
            turn = {'session_id':body.session_id,'turn_id':'demo-'+uuid.uuid4().hex,'sensitive':False}
            for seq, item in enumerate(fixtures, 1):
                c_seq = item.get('client_seq', seq)
                emit(turn,item['type'],{**item['payload'],'label':item['label'],'authored_parent_ids':item.get('parent_ids',[]),'client_seq':c_seq},
                     timestamp=datetime.fromisoformat(item['timestamp'].replace('Z','+00:00')).timestamp(),
                     client_seq=c_seq)
            return {'session_id':body.session_id,'event_count':len(fixtures)}
    return app

app = create_app()
