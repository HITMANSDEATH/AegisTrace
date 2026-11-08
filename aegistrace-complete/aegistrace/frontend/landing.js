import { sealEvents, verifyChain, shortHash } from './audit-chain.js';
const $ = id => document.getElementById(id);
let events = [], receipt, version = 0;
const inputs = [
  { type:'state_transition', label:'Alert received', payload:{ message:'An access alert enters triage.' } },
  { type:'tool_end', label:'Risk assessment', payload:{ result:'risk: high' } },
  { type:'state_transition', label:'Investigation escalated', payload:{ message:'Escalated for analyst review.' } }
];
function disable(value) { ['lab-alter','lab-verify','lab-reset','lab-payload'].forEach(id => $(id).disabled = value); }
function status(text, kind, stamp) { $('lab-result').textContent = text; $('lab-result').className = 'lab-result ' + kind; $('lab-stamp').className = 'stamp ' + (kind || 'neutral'); $('lab-stamp').textContent = stamp; }
async function reset() {
  disable(true); version++;
  try {
    const sealed = await sealEvents(inputs, 'chain-lab'); events = sealed.events; receipt = sealed.receipt;
    $('lab-payload').value = 'risk: high';
    events.forEach((event, index) => { $(`lab-hash-${index + 1}`).textContent = shortHash(event.hash); $(`lab-card-${index + 1}`).className = 'chain-card'; });
    const result = await verifyChain(events, receipt);
    status(`All ${result.checked} events match their sealed hashes. Change the middle artifact to test the chain.`, 'ok', '✓ CHAIN INTACT'); disable(false);
  } catch(error) { status(error.message, 'bad', 'UNAVAILABLE'); }
}
function edit() {
  if (!events.length) return;
  version++; events[1].payload.result = $('lab-payload').value;
  const changed = events[1].payload.result !== 'risk: high';
  $('lab-card-2').className = 'chain-card' + (changed ? ' modified' : ''); $('lab-card-3').className = 'chain-card';
  status(changed ? 'The payload changed, but its sealed hash did not. Verify to locate the discrepancy.' : 'Original payload restored. Verify again to check the record.', '', 'NOT RECHECKED');
}
$('lab-payload').addEventListener('input', edit);
$('lab-alter').addEventListener('click', () => { $('lab-payload').value = $('lab-payload').value === 'risk: low' ? 'risk: high' : 'risk: low'; edit(); $('lab-payload').focus(); });
$('lab-reset').addEventListener('click', reset);
$('lab-verify').addEventListener('click', async () => {
  disable(true); const current = version;
  try {
    const result = await verifyChain(events, receipt); if (version !== current) return;
    $('lab-card-2').className = 'chain-card' + (result.ok ? '' : ' broken'); $('lab-card-3').className = 'chain-card' + (result.ok ? '' : ' affected');
    status(result.ok ? '3 / 3 sealed hashes match. This local chain is internally consistent.' : 'Mismatch at EVT-002. Its content no longer matches its seal. Later events depend on that altered record.', result.ok ? 'ok' : 'bad', result.ok ? '✓ CHAIN INTACT' : '↯ TAMPER DETECTED');
  } catch(error) { status(error.message, 'bad', 'VERIFY FAILED'); } finally { disable(false); }
});
function scrollProgress() { const extent = document.documentElement.scrollHeight - innerHeight; $('scroll-progress').style.width = `${extent > 0 ? Math.min(100, scrollY / extent * 100) : 0}%`; }
addEventListener('scroll', scrollProgress, { passive:true }); addEventListener('resize', scrollProgress); scrollProgress(); reset();
