import { formatMs, appendEvent, verifyChain, receiptFor } from './audit-chain.js';
import { api } from './api.js';
const modes={
 verified:{title:'The midnight access alert',session:'SOC',badge:'SCRIPTED CASE · SERVER-SEALED',note:'Fictional SOC triage · durable audit records'},
 tampered:{title:'The altered expense record',session:'FIN',badge:'EXPLICIT DEMO TAMPER',note:'Fictional financial review · one payload altered after ingestion'},
 try:{title:'Your interactive investigation',session:'LAB',badge:'SIMULATED RESPONSES — NO LIVE MODEL',note:'Rule-based browser demo · no live model or network calls'},
 live:{title:'Live agent investigation',session:'LIVE',badge:'LIVE AGENT · SERVER-SIDE PROVIDER',note:'Groq by default; Ollama selectable on the server'}
};
let config={demo_mode:false};
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function refresh(target) {
 const snapshot=await api.graph(target.session);if(state!==target)return false;
 target.events=snapshot.events;target.verification=snapshot.verification;target.graph=snapshot;
 target.position=target.events.length;target.tampered=!snapshot.verification.ok;
 renderAll();return true;
}
async function awaitEvidence(target,predicate) {
 const deadline=Date.now()+10000;
 while(state===target && Date.now()<deadline){
  try{await refresh(target);if(predicate(target.events))return true;}catch(error){if(error.status!==404)throw error;}
  await pause(300);
 }
 return false;
}

import { initGraph, renderGraph, selectGraph, fitGraph, zoomGraph } from './graph.js';
const $ = id => document.getElementById(id);
let state, replayTimer = null, toastTimer = null, lastFocus = null;
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
function el(tag, className, text) { const element=document.createElement(tag); if(className)element.className=className; if(text!==undefined)element.textContent=text; return element; }
function notify(text) { $('toast').textContent=text; $('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,4000); }
function note(text, kind='') { state.notice=text;state.noticeKind=kind;$('session-notice').textContent=text;$('session-notice').className='session-notice '+kind; }
function stopReplay() { clearInterval(replayTimer);replayTimer=null;const button=$('replay');button.textContent='▶ Replay';button.setAttribute('aria-label','Replay session'); }
function eventState(event) {
  if(!state.verification) return { className:'', label:'NOT RECHECKED', note:'Verify the full chain to compare this artifact with its stored hash.' };
  if(event.directly_broken || state.verification.firstBroken===event.seq) return {className:'bad',label:'HASH MISMATCH',note:'This artifact does not match its recorded seal. Its payload or metadata was changed after hashing.'};
  if(state.verification.firstBroken && event.seq>state.verification.firstBroken) return {className:'warn',label:'DOWNSTREAM OF MISMATCH',note:'This artifact depends on a chain with an earlier discrepancy. That does not by itself prove this payload was edited.'};
  if(event.flagged)return {className:'warn',label:'FLAGGED · HASH MATCHES',note:'A sensitive action was requested and recorded. An amber flag is a review signal, not a cryptographic failure.'};
  return {className:'ok',label:'HASH MATCHES',note:'This artifact’s hash and preceding link match in the server verification. This chain is internally consistent; it has no independent external head anchor.'};
}
let transcriptView = 'chat';
function setTranscriptView(view) {
  transcriptView = view;
  const isChat = view === 'chat';
  $('view-chat').classList.toggle('active', isChat);
  $('view-chat').setAttribute('aria-selected', String(isChat));
  $('view-transcript').classList.toggle('active', !isChat);
  $('view-transcript').setAttribute('aria-selected', String(!isChat));
  $('chat-view').hidden = !isChat;
  $('transcript').hidden = isChat;
  if (isChat) renderChatView();
  else renderTranscript();
}
function renderChatView() {
  const container = $('chat-view');
  const oldTop = container.scrollTop;
  container.replaceChildren();

  const visibleEvents = state.events.slice(0, state.position);
  const turns = [];

  for (const event of visibleEvents) {
    const p = event.payload || {};
    if (p.actor === 'user' || p.actor === 'analyst' || event.label === 'User instruction' || (event.seq === 1 && !p.state && event.label !== 'Message classified')) {
      turns.push({
        role: 'user',
        name: 'YOU',
        message: p.message || event.label,
        timestamp: event.timestamp ? event.timestamp.slice(11, 19) + ' UTC' : '',
        flagged: Boolean(event.flagged)
      });
    } else if (p.actor === 'assistant' || (p.state === 'complete' && event.type === 'state_transition')) {
      let msg = p.message || event.label;
      if (typeof msg === 'string' && msg.startsWith('Atlas: ')) msg = msg.slice(7);
      turns.push({
        role: 'agent',
        name: 'ATLAS',
        message: msg,
        timestamp: event.timestamp ? event.timestamp.slice(11, 19) + ' UTC' : '',
        flagged: Boolean(event.flagged)
      });
    } else if (p.actor === 'system' || p.state === 'error') {
      turns.push({
        role: 'system',
        name: 'SYSTEM',
        message: p.message || event.label,
        timestamp: event.timestamp ? event.timestamp.slice(11, 19) + ' UTC' : '',
        flagged: Boolean(event.flagged)
      });
    }
  }

  if (turns.length === 0) {
    const empty = el('div', 'chat-empty');
    empty.append(el('div', 'empty-symbol', '⌁'));
    empty.append(el('h3', '', 'Chat with Atlas'));
    empty.append(el('p', '', 'Send a prompt or choose a sample action below to begin your investigation.'));
    container.append(empty);
    return;
  }

  for (const turn of turns) {
    const turnEl = el('div', `chat-turn ${turn.role}`);
    const meta = el('div', 'chat-turn-meta');
    meta.append(el('strong', '', turn.name));
    if (turn.flagged) {
      const flag = el('span', 'chat-flag', '⚑ flagged');
      flag.style.color = 'var(--amber)';
      meta.append(flag);
    }
    if (turn.timestamp) {
      meta.append(el('span', '', turn.timestamp));
    }
    const bubble = el('div', 'chat-bubble', turn.message);
    turnEl.append(meta, bubble);
    container.append(turnEl);
  }

  if (state.busy) {
    const typing = el('div', 'chat-typing', 'Atlas is responding…');
    container.append(typing);
  }

  container.scrollTop = oldTop;
}
function renderTranscript() {
  const list=$('transcript'); const oldTop=list.scrollTop; list.replaceChildren();
  if(!state.events.length) {
    const empty=el('div','transcript-empty');empty.append(el('div','empty-symbol',state.mode==='live'?'⌁':'⌕'));
    empty.append(el('h3','',state.busy?'Opening the case…':'A fresh page in the ledger.'));
    empty.append(el('p','',state.busy?'Waiting for the server evidence snapshot.':'Enter a message below. Agent events are captured asynchronously in the isolated audit sink.'));
    list.append(empty);return;
  }
  if(state.position===0) { const empty=el('div','transcript-empty');empty.append(el('h3','','Before the first event.'),el('p','','Press Replay or move the timeline to reconstruct the sequence.'));list.append(empty);return; }
  state.events.slice(0,state.position).forEach(event => {
    const condition=eventState(event);let classes='event';if(event.flagged)classes+=' flagged';if(condition.className==='bad')classes+=' broken';else if(state.verification?.firstBroken && event.seq>state.verification.firstBroken)classes+=' affected';if(event.id===state.selected)classes+=' selected';
    const item=el('article',classes);item.setAttribute('role','listitem');item.dataset.event=event.id;
    const time=el('div','event-time');time.append(el('span','',event.timestamp.slice(11,19)+' UTC'),el('span','',event.id.toUpperCase()));
    const button=el('button','event-card');button.type='button';button.setAttribute('aria-label',`${event.id}, ${event.label}. ${condition.label}. Inspect artifact.`);button.append(el('span','event-kind',event.flagged?'⚑ Sensitive action':event.type.replaceAll('_',' ')),el('strong','',event.label),el('p','',event.payload.message || JSON.stringify(event.payload)));
    button.onclick=()=>selectEvent(event.id,true);item.append(time,button);list.append(item);
  });
  list.scrollTop=oldTop;
}
function updateControls() {
  const has=state.events.length>0, busy=state.busy;
  $('export-session').disabled=!has||busy;
  $('verify-session').disabled=!has||busy;
  $('reset-session').disabled=busy;
  $('timeline').disabled=!has||busy; $('replay').disabled=!has||busy; $('timeline-end').disabled=!has||busy;
  $('chat-input').disabled=busy||state.tampered; $('chat-send').disabled=busy||state.tampered;
  document.querySelectorAll('.sample-prompt').forEach(button=>button.disabled=busy||state.tampered);
  $('inject-tamper').hidden=!((config.demo_mode&&state.mode==='live')||state.mode==='try');
  $('inject-tamper').disabled=state.events.length<2||busy||state.tampered;
  $('engine').setAttribute('aria-busy',String(busy));
}
function renderStatus() {
  const status=$('chain-status'); let text='NO EVENTS',kind='neutral';
  if(state.busy){text='PROCESSING';}
  else if(state.events.length){ if(!state.verification){text='NOT RECHECKED';kind='warn';}else if(state.verification.ok){text='✓ CHAIN INTACT';kind='ok';}else{text='↯ TAMPER DETECTED';kind='bad';} }
  status.textContent=text;status.className='stamp '+kind;
  $('seal-caption').textContent=state.verification ? `${state.verification.checked} EVENTS CHECKED · SERVER`:'SERVER VERIFICATION';
  $('event-count').textContent=`${state.position} / ${state.events.length} EVENTS`;
  $('timeline').max=state.events.length; $('timeline').value=state.position;$('timeline').setAttribute('aria-valuetext',`${state.position} of ${state.events.length} events visible`);
  $('timeline-count').textContent=`${state.position} / ${state.events.length}`;
  $('metric-events').replaceChildren(document.createTextNode(state.events.length+' '),el('small','','artifacts'));
  $('metric-seal').textContent='—';$('metric-verify').textContent=formatMs(state.verification?.durationMs);
  $('graph-empty').textContent=state.position===0&&state.events.length?'The story begins with its first event.':'Your next task will leave a trail here.';
  $('graph-annotation').hidden=!state.position;
  $('session-notice').textContent=state.notice||'';$('session-notice').className='session-notice '+(state.noticeKind||'');updateControls();
}
function renderAll() { renderChatView();renderTranscript();renderGraph(state.events,state.position,state.verification,state.selected);renderStatus();if(!$('inspector').hidden)renderInspector(); }
async function verifyCurrent() {
 const target=state;target.busy=true;renderStatus();
 try{
  if(target.mode==='try'){
   const result=await verifyChain(target.events,receiptFor(target.events));
   target.verification=result;
   note(result.ok?`All ${result.checked} stored events match their seals and links. No mismatch detected.`:`First discrepancy: EVT-${String(result.firstBroken).padStart(3,'0')}. ${result.errors[0]?.reason||'Mismatch detected'}.`,result.ok?'ok':'bad');
   return;
  }
  await refresh(target);if(state!==target)return;const result=target.verification;
  note(result.ok?`All ${result.checked} stored events match their seals and links. No mismatch detected.`:`First discrepancy: EVT-${String(result.firstBroken).padStart(3,'0')}. ${result.errors[0].reason}.`,result.ok?'ok':'bad');
 }
 catch(error){if(state===target)note('Verification unavailable: '+error.message,'bad');}
 finally{if(state===target){target.busy=false;renderAll();}}
}

function classifyPrompt(text) {
  const lower = text.toLowerCase();
  const sensitiveWords = ['delete', 'export', 'grant', 'revoke', 'modify', 'drop', 'terminate', 'escalate', 'override', 'change', 'purge', 'remove'];
  if (sensitiveWords.some(w => lower.includes(w))) return 'sensitive_action';
  const requestWords = ['investigate', 'check', 'summarize', 'analyze', 'audit', 'scan', 'inspect', 'trace', 'find'];
  if (requestWords.some(w => lower.includes(w))) return 'request';
  const questionWords = ['who', 'what', 'why', 'when', 'where', 'how', 'is', 'are', 'can', 'does', 'did', 'status', 'ip', 'alert', 'log', '?'];
  if (questionWords.some(w => lower.includes(w))) return 'question';
  return 'casual';
}

function generateSimulatedEvents(text, category, existingEvents) {
  const lastId = existingEvents.length ? existingEvents.at(-1).id : null;
  const parentBase = lastId ? [lastId] : [];
  if (category === 'question') {
    return [
      { type: 'state_transition', label: 'User instruction', payload: { actor: 'user', state: 'received', message: text }, parent_ids: parentBase, flagged: false },
      { type: 'state_transition', label: 'Message classified', payload: { actor: 'agent', state: 'classified', category, message: 'question' }, flagged: false },
      { type: 'tool_start', label: 'Query knowledge index', payload: { actor: 'tool', tool: 'retrieve_context', message: `Querying index for: ${text}`, simulated: true }, flagged: false },
      { type: 'retrieval', label: 'Audit policy retrieved', payload: { actor: 'tool', document: 'soc2-access-policy.md', chunk: 2, message: 'Retrieved access log retention and verification standards.', simulated: true }, flagged: false },
      { type: 'tool_end', label: 'Knowledge retrieval complete', payload: { actor: 'tool', tool: 'retrieve_context', message: 'Context retrieved successfully from local index.', simulated: true }, flagged: false },
      { type: 'state_transition', label: 'Assistant response', payload: { actor: 'assistant', state: 'complete', message: `I have queried the knowledge base and access records regarding "${text}". All system components report normal operational parameters, and all agent actions remain cryptographically sealed in the audit sink.` }, flagged: false }
    ];
  }
  if (category === 'request') {
    return [
      { type: 'state_transition', label: 'User instruction', payload: { actor: 'user', state: 'received', message: text }, parent_ids: parentBase, flagged: false },
      { type: 'state_transition', label: 'Message classified', payload: { actor: 'agent', state: 'classified', category, message: 'request' }, flagged: false },
      { type: 'tool_start', label: 'Inspect log sink', payload: { actor: 'tool', tool: 'log_inspector', message: `Scanning audit sink for: ${text}`, simulated: true }, flagged: false },
      { type: 'retrieval', label: 'Telemetry log sample', payload: { actor: 'tool', document: 'auth-telemetry-stream.json', chunk: 1, message: 'Found 12 authentication events in the preceding 60 minutes.', simulated: true }, flagged: false },
      { type: 'tool_end', label: 'Endpoint reputation check', payload: { actor: 'tool', tool: 'reputation_check', message: 'Checked endpoint 203.0.113.42: reputation score 0.98 (Benign).', simulated: true }, flagged: false },
      { type: 'state_transition', label: 'Assistant response', payload: { actor: 'assistant', state: 'complete', message: `Investigation completed for "${text}". The telemetry stream and IP reputation checks confirm no anomalous egress, unverified sessions, or hash discrepancies.` }, flagged: false }
    ];
  }
  if (category === 'sensitive_action') {
    return [
      { type: 'state_transition', label: 'User instruction', payload: { actor: 'user', state: 'received', message: text }, parent_ids: parentBase, flagged: true },
      { type: 'state_transition', label: 'Message classified', payload: { actor: 'agent', state: 'classified', category, message: 'sensitive_action' }, flagged: true },
      { type: 'tool_start', label: 'Check privileged policy', payload: { actor: 'tool', tool: 'policy_engine', message: `Validating authorization rules for sensitive operation: ${text}`, simulated: true }, flagged: true },
      { type: 'retrieval', label: 'Privileged policy rule', payload: { actor: 'tool', document: 'privileged-access-rules.json', chunk: 5, message: 'Rule #104: Modifying or deleting security records requires high-assurance dual control.', simulated: true }, flagged: true },
      { type: 'tool_end', label: 'Flag recorded in ledger', payload: { actor: 'tool', tool: 'policy_engine', message: 'Flagged for supervisor review. High-priority audit record sealed.', simulated: true }, flagged: true },
      { type: 'state_transition', label: 'Assistant response', payload: { actor: 'assistant', state: 'complete', message: `Notice: Your request ("${text}") involves a sensitive operation. As required by audit policies, this action is flagged (⚑) and immutably sealed in the audit chain for compliance verification.` }, flagged: true }
    ];
  }
  return [
    { type: 'state_transition', label: 'User instruction', payload: { actor: 'user', state: 'received', message: text }, parent_ids: parentBase, flagged: false },
    { type: 'state_transition', label: 'Message classified', payload: { actor: 'agent', state: 'classified', category, message: 'casual' }, flagged: false },
    { type: 'state_transition', label: 'Assistant response', payload: { actor: 'assistant', state: 'complete', message: `Hello! I am Atlas, your AI assistant. You are currently in the simulated Try-It-Yourself laboratory. Try asking an investigation question, checking logs, or testing a sensitive command to see the DAG and cryptographic hash chain in action!` }, flagged: false }
  ];
}

async function switchMode(mode,fresh=false,explicitSession=null) {
 if(!modes[mode])mode='live';stopReplay();closeInspector(false);
 const session=explicitSession||`${modes[mode].session}-${crypto.randomUUID().slice(0,16)}`;
 state={mode,session,events:[],position:0,selected:null,verification:null,busy:false,tampered:false,notice:'',noticeKind:''};
 const target=state,settings=modes[mode];
 document.querySelectorAll('.mode-tab').forEach(button=>{const active=button.dataset.mode===mode;button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;});
 $('case-panel').setAttribute('aria-labelledby','tab-'+mode);$('case-subtitle').textContent=`CASE / ${session} — ${settings.title}`;
 $('mode-label').textContent=settings.badge;$('mode-note').textContent=settings.note;$('chat-box').hidden=!['try','live'].includes(mode);$('chat-input').value='';
 try{history.replaceState(null,'',`?mode=${mode}`);}catch{}

 const isLive=mode==='live';
 $('view-switcher').hidden=!isLive;
 $('transcript-title').hidden=isLive;
 if(!isLive){
  setTranscriptView('transcript');
 }else{
  setTranscriptView('chat');
 }

 if(mode==='try'){
  target.busy=false;
  note('Ready. Client-side simulation active with local cryptographic sealing.','ok');
  renderAll();
  return;
 }
 if(mode==='live'){
  target.busy=false;
  note('Ready. Messages use the configured live provider; tools operate on fictional data.','ok');
  renderAll();
  return;
 }
 target.busy=true;
 note('Opening the server case…');renderAll();
 try{
  try{await refresh(target);if(state===target)note('Recorded case loaded. Reset opens a new case without deleting this record.');}
  catch(error){
   if(error.status!==404)throw error;
   if(['verified','tampered'].includes(mode)){
    if(!config.demo_mode)throw new Error('Scripted walkthroughs require the explicit demo deployment. Use Live Agent or Try It Yourself.');
    const seeded=await api.seed(session,mode);
    if(!await awaitEvidence(target,events=>events.length>=seeded.event_count))throw new Error('Audit capture is pending or unavailable. Reload this case later; no evidence was invented.');
    if(state!==target)return;
    if(mode==='tampered'){
     const event=target.events[3];
     await api.tamper(session,event.db_id,{...event.payload,amount_usd:840,message:'EXP-2048: $840, one approver. Secondary approval missing.'});
     await refresh(target);
    }
    await verifyCurrent();
   }else note('Ready. Messages use the configured live provider; tools operate on fictional data.');
  }
 }catch(error){if(state===target)note(error.message,'bad');}
 finally{if(state===target){target.busy=false;renderAll();}}
}

function selectEvent(id,open=false) {
  if(!state.events.slice(0,state.position).some(event=>event.id===id))return;
  state.selected=id;selectGraph(id);
  document.querySelectorAll('.event').forEach(item=>item.classList.toggle('selected',item.dataset.event===id));
  const active=[...document.querySelectorAll('.event')].find(item=>item.dataset.event===id);
  if(active){const list=$('transcript'),r=active.getBoundingClientRect(),lr=list.getBoundingClientRect();if(r.top<lr.top||r.bottom>lr.bottom)list.scrollTop+=r.top-lr.top-12;}
  if(open){stopReplay();lastFocus=document.activeElement;$('drawer-backdrop').hidden=false;$('inspector').hidden=false;document.body.style.overflow='hidden';$('main').inert=true;document.querySelector('.topbar').inert=true;document.querySelector('.footer').inert=true;renderInspector();$('close-inspector').focus();}
}
function renderInspector() {
  const event=state.events.find(item=>item.id===state.selected);if(!event){closeInspector(false);return;}const condition=eventState(event);
  $('inspector-id').textContent=`${state.session} / ${event.id.toUpperCase()}`;$('inspector-title').textContent=event.label;
  $('inspector-status').textContent=condition.label;$('inspector-status').className='stamp '+(condition.className||'neutral');
  const meta=$('inspector-meta');meta.replaceChildren();
  [['EVENT TYPE',event.type],['SEQUENCE',String(event.seq).padStart(3,'0')],['RECORDED AT',event.timestamp],['CAUSAL PARENTS',event.parent_ids.join(', ')||'Genesis event']].forEach(([label,value])=>{const pair=el('div');pair.append(el('dt','',label),el('dd','',value));meta.append(pair);});
  $('inspector-json').textContent=JSON.stringify(event.payload,null,2);$('inspector-prev').textContent=event.prev_hash;$('inspector-hash').textContent=event.hash;
  const computed=state.verification?.recalculated[event.id];$('recomputed-field').hidden=!computed;$('inspector-recomputed').textContent=computed||'';
  $('inspector-note').textContent=condition.note+' Hash input is timestamp + exact stored payload JSON + previous hash. Sink-owned metadata inside the payload seals the session, type, and flag. Display sequence and causal links are derived from stored order; no external head anchor is claimed.';
}
function closeInspector(restore=true) { $('inspector').hidden=true;$('drawer-backdrop').hidden=true;document.body.style.overflow='';$('main').inert=false;document.querySelector('.topbar').inert=false;document.querySelector('.footer').inert=false;if(restore&&lastFocus?.isConnected)lastFocus.focus(); }
function moveTimeline(position) { state.position=Math.max(0,Math.min(state.events.length,position));if(!state.events.slice(0,state.position).some(event=>event.id===state.selected)){state.selected=null;closeInspector(false);}renderAll(); }
async function sendPrompt(text) {
 text=text.trim();if(!text||!['try','live'].includes(state.mode)||state.busy||state.tampered)return;
 if(text.length>1000){notify('Keep the task under 1,000 characters.');return;}
 stopReplay();const target=state;target.busy=true;$('chat-input').value='';
 if(target.mode==='try'){
  note('Generating simulated response and computing local SHA-256 chain…');renderStatus();renderChatView();
  try{
   const category=classifyPrompt(text);
   const isSensitive=category==='sensitive_action';
   const eventDefs=generateSimulatedEvents(text,category,target.events);
   for(const def of eventDefs){
    const result=await appendEvent(target.events,def,target.session);
    target.events.push(result.event);
   }
   target.position=target.events.length;
   target.verification=await verifyChain(target.events,receiptFor(target.events));
   note(isSensitive?'Sensitive action simulated and recorded with review flag. Local SHA-256 chain intact.':'Simulated response generated. Local SHA-256 chain intact.',target.verification.ok?'ok':'bad');
  }catch(err){note('Simulation error: '+err.message,'bad');}
  finally{
   if(state===target){
    target.busy=false;renderAll();
    if(transcriptView==='chat'){$('chat-view').scrollTop=$('chat-view').scrollHeight;}
    else{$('transcript').scrollTop=$('transcript').scrollHeight;}
    $('chat-input').focus();
   }
  }
  return;
 }
 note('Agent processing… audit dispatch runs independently.');renderStatus();renderChatView();
 let result,failure;
 try{
  try{result=await api.chat(target.session,text);}catch(error){failure=error;result=error.data;}
  if(state!==target)return;
  let recorded=false;
  if(result?.turn_id)recorded=await awaitEvidence(target,events=>events.some(event=>event.payload.turn_id===result.turn_id&&['complete','error'].includes(event.payload.state)&&['assistant','system'].includes(event.payload.actor)));
  if(state!==target)return;
  if(failure)note(failure.message+(recorded?' The failed turn is recorded.':' Audit confirmation is pending; inspect this case before retrying.'),'bad');
  else if(!recorded)note(`Agent response: ${result.response} — Audit confirmation is pending or unavailable. Do not treat this reply as a sealed artifact.`,'warn');
  else note(target.verification.ok?'Response recorded. Server chain intact. Sensitive flags indicate review, not tampering.':'Response received, but the recorded chain contains a mismatch.',target.verification.ok?'ok':'bad');
 }catch(error){if(state===target)note(error.message,'bad');}
 finally{
  if(state===target){
   target.busy=false;renderAll();
   if(transcriptView==='chat'){$('chat-view').scrollTop=$('chat-view').scrollHeight;}
   else{$('transcript').scrollTop=$('transcript').scrollHeight;}
   $('chat-input').focus();
  }
 }
}

async function injectTamper() {
 if(state.busy||state.tampered||state.events.length<2)return;
 stopReplay();const target=state;
 if(target.mode==='try'){
  const event=target.events.find(e=>e.type==='tool_end')||target.events[1];
  event.payload={...event.payload,message:'[DEMO ALTERED] '+(event.payload.message||'Payload altered in memory after sealing.')};
  event.directly_broken=true;
  target.tampered=true;
  target.selected=event.id;
  target.verification=await verifyChain(target.events,receiptFor(target.events));
  note(`${event.id.toUpperCase()} payload altered in memory. Local verification detects the mismatch; downstream nodes are dimmed.`,'bad');
  renderAll();
  return;
 }
 if(!config.demo_mode)return;
 const event=target.events.find(event=>event.type==='tool_end')||target.events[1];
 target.busy=true;renderStatus();
 try{await api.tamper(target.session,event.db_id,{...event.payload,message:'[DEMO ALTERED] '+(event.payload.message||'Stored record changed after hashing.')});
 if(state!==target)return;target.selected=event.id;await refresh(target);note(`${event.id.toUpperCase()} payload altered. Server verification detects the mismatch; downstream nodes are dimmed.`,'bad');}
 catch(error){if(state===target)note(error.message,'bad');}
 finally{if(state===target){target.busy=false;renderAll();}}
}

async function exportSession() {
 if(!state.events.length||state.busy)return;
 const target=state;
 try{
  let blob, noteMsg;
  if(target.mode==='try'){
   const data={format:'aegistrace-client-session-v1',session_id:target.session,mode:target.mode,exported_at:new Date().toISOString(),entries:target.events,verification:target.verification};
   blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
   noteMsg='Client case JSON downloaded, including local hashes and verification.';
  }else{
   blob=await api.export(target.session);
   noteMsg='Server case JSON downloaded, including exact hash inputs and verification.';
  }
  const url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download=`aegistrace-${target.session}.json`;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);notify(noteMsg);
 }catch(error){notify(error.message);}
}

initGraph(selectEvent);
document.querySelectorAll('.mode-tab').forEach(button=>{
  button.addEventListener('click',()=>switchMode(button.dataset.mode));
  button.addEventListener('keydown',event=>{if(!['ArrowRight','ArrowLeft','Home','End'].includes(event.key))return;event.preventDefault();const tabs=[...document.querySelectorAll('.mode-tab')];let index=tabs.indexOf(button);index=event.key==='Home'?0:event.key==='End'?tabs.length-1:(index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;tabs[index].focus();switchMode(tabs[index].dataset.mode);});
});
$('view-chat').onclick=()=>setTranscriptView('chat');
$('view-transcript').onclick=()=>setTranscriptView('transcript');
$('verify-session').onclick=()=>{stopReplay();verifyCurrent();};$('reset-session').onclick=()=>switchMode(state.mode,true);$('inject-tamper').onclick=injectTamper;$('export-session').onclick=exportSession;
$('close-inspector').onclick=()=>closeInspector();$('drawer-backdrop').onclick=()=>closeInspector();
document.addEventListener('keydown',event=>{if($('inspector').hidden)return;if(event.key==='Escape'){event.preventDefault();closeInspector();}if(event.key==='Tab'){event.preventDefault();$('close-inspector').focus();}});
$('timeline').addEventListener('input',()=>{stopReplay();moveTimeline(Number($('timeline').value));});$('timeline-end').onclick=()=>{stopReplay();moveTimeline(state.events.length);};
$('replay').onclick=()=>{if(replayTimer){stopReplay();return;}closeInspector(false);if(state.position===state.events.length)moveTimeline(0);$('replay').textContent='Ⅱ Pause';$('replay').setAttribute('aria-label','Pause replay');replayTimer=setInterval(()=>{moveTimeline(state.position+1);if(transcriptView==='chat'){$('chat-view').scrollTop=$('chat-view').scrollHeight;}else{$('transcript').scrollTop=$('transcript').scrollHeight;}if(state.position>=state.events.length)stopReplay();},700);};
$('fit-graph').onclick=fitGraph;$('zoom-in').onclick=()=>zoomGraph(1.25);$('zoom-out').onclick=()=>zoomGraph(.8);
$('chat-form').onsubmit=event=>{event.preventDefault();sendPrompt($('chat-input').value);};$('chat-input').addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.shiftKey&&!event.isComposing){event.preventDefault();sendPrompt($('chat-input').value);}});
document.querySelectorAll('.sample-prompt').forEach(button=>button.onclick=()=>sendPrompt(button.dataset.prompt));
document.addEventListener('graph-hover',event=>{document.querySelectorAll('.event-card').forEach(button=>button.style.outline='');if(event.detail){const item=[...document.querySelectorAll('.event')].find(item=>item.dataset.event===event.detail);if(item)item.querySelector('.event-card').style.outline='1px solid var(--green)';}});
(async()=>{
 try{config=await api.config();}catch(error){notify('Backend unavailable: '+error.message);}
 const initialMode=new URLSearchParams(location.search).get('mode');
 await switchMode(modes[initialMode]?initialMode:config.demo_mode?'verified':'live');
})();
