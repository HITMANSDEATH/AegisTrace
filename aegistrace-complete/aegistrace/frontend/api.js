// The gateway sends /chat and /demo to the agent, /api to reconstruction.
// config.js supplies the only API base; empty preserves same-origin routing.
const base = (window.AEGIS_API_BASE || '').trim().replace(/\/+$/, '');
const unreachable = () => new Error('Backend unreachable: check API URL / CORS.');
const statusMessages = {
  413: 'The request is too large. Shorten the message and try again.',
  422: 'The request was rejected. Check the message and try again.',
  429: 'Too many requests. Wait a moment and try again.',
  504: 'The live model timed out. The turn may have been recorded; check the session before retrying.'
};

async function request(path, options={}, asBlob=false) {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),35000);
  try {
    let response;
    try {
      response=await fetch(base+path,{...options,signal:controller.signal,cache:'no-store',headers:{'Content-Type':'application/json',...options.headers}});
    } catch(error) {
      if(error.name==='AbortError')throw new Error('Request timed out. Check the recorded session before retrying; the turn may have completed.');
      throw unreachable();
    }
    if(asBlob && response.ok)return await response.blob();
    let data;
    try {data=await response.json();} catch {throw unreachable();}
    if(!response.ok){const message=(data&&data.message)||(data&&data.error)||(data&&typeof data.detail==='string'&&data.detail)||statusMessages[response.status]||'Request failed';const error=new Error(message);error.status=response.status;error.data=data;throw error;}
    return data;
  } finally {clearTimeout(timer);}
}
const sessionPath=id=>'/api/session/'+encodeURIComponent(id);
export const api={
  config:()=>request('/api/config'),
  sessions:()=>request('/api/sessions'),
  graph:id=>request(sessionPath(id)+'/graph'),
  verify:id=>request(sessionPath(id)+'/verify'),
  entries:id=>request(sessionPath(id)+'/entries'),
  chat:(id,message)=>request('/chat',{method:'POST',body:JSON.stringify({session_id:id,message})}),
  seed:(id,mode)=>request('/demo/session',{method:'POST',body:JSON.stringify({session_id:id,mode})}),
  tamper:(id,entry_id,payload)=>request(sessionPath(id)+'/tamper',{method:'POST',body:JSON.stringify({entry_id,payload})}),
  export:id=>request(sessionPath(id)+'/export',{},true)
};
