"""Snapshot-consistent read-only reconstruction; explicit demo-only mutation exception."""
import hashlib
import json
import math
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from collections import Counter

import networkx as nx
from fastapi import HTTPException, Path as ApiPath
from common.cors import BrowserAPI
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from typing import Annotated
from common.hash import entry_hash, canonical_json, event_id

SessionID = Annotated[str, ApiPath(pattern=r'^[A-Za-z0-9_-]{1,96}$')]

class TamperBody(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    entry_id: int = Field(gt=0)
    payload: dict

def open_ro(path):
    conn = sqlite3.connect('file:'+quote(str(Path(path).resolve()))+'?mode=ro', uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA query_only=ON')
    conn.execute('BEGIN')
    return conn

def load_rows(path, session_id=None):
    conn = None
    try:
        conn = open_ro(path)
        if session_id is None:
            rows = conn.execute('SELECT * FROM audit_log ORDER BY id').fetchall()
        else:
            rows = conn.execute('SELECT * FROM audit_log WHERE session_id=? ORDER BY id',(session_id,)).fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error:
        raise HTTPException(503, 'audit database unavailable')
    finally:
        if conn: conn.close()

def parse_payload(value):
    try:
        parsed = json.loads(value, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        if isinstance(parsed,dict): return parsed
    except (ValueError, TypeError, RecursionError):
        pass
    return None

def raw_entry(row):
    try:
        numeric_timestamp = float(row['timestamp'])
        valid = math.isfinite(numeric_timestamp)
    except (TypeError,ValueError,OverflowError):
        numeric_timestamp,valid = None,False
    return {**row,'payload':parse_payload(row['payload']),'payload_str':row['payload'],
            'timestamp':numeric_timestamp if valid else None,
            'timestamp_repr':str(numeric_timestamp) if valid else None,
            'timestamp_raw':str(row['timestamp']),
            'sensitive_action_flag':bool(row['sensitive_action_flag'])}

def verify_anchor_log(log_path):
    if log_path is None or not Path(log_path).exists() or Path(log_path).stat().st_size == 0:
        return True, []
    records = []
    prev_hash = '0' * 64
    log_intact = True
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    anchor_hash = rec.get('anchor_hash')
                    rec_copy = {k: v for k, v in rec.items() if k != 'anchor_hash'}
                    canonical = canonical_json(rec_copy)
                    expected_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
                    if rec.get('prev_anchor_hash') != prev_hash or anchor_hash != expected_hash:
                        log_intact = False
                    prev_hash = anchor_hash
                    records.append(rec)
                except Exception:
                    log_intact = False
    except Exception:
        log_intact = False
    return log_intact, records

def check_sequences(rows, parsed_payloads):
    row_seqs = []
    has_v1 = False
    has_v2 = False
    for r, p in zip(rows, parsed_payloads):
        aegis = p.get('_aegis') if isinstance(p, dict) else None
        s_ver = aegis.get('schema_version') if isinstance(aegis, dict) else None
        c_seq = aegis.get('client_seq') if isinstance(aegis, dict) else None
        if s_ver == 1 or (s_ver != 2 and c_seq is None):
            has_v1 = True
            row_seqs.append(None)
        elif s_ver == 2 and isinstance(c_seq, int) and not isinstance(c_seq, bool) and c_seq >= 1:
            has_v2 = True
            row_seqs.append(c_seq)
        else:
            has_v1 = True
            row_seqs.append(None)

    if not has_v2:
        return {
            'sequence_check': 'not_available',
            'sequence_complete': None,
            'sequence_gaps': [],
            'missing_events_total': 0,
            'duplicate_seq': [],
            'out_of_order_seq': []
        }

    is_partial = has_v1 and has_v2
    v2_indices = [i for i, s in enumerate(row_seqs) if s is not None]
    start_idx = v2_indices[0] if is_partial else 0
    seqs_to_check = [s for s in row_seqs[start_idx:] if s is not None]

    sequence_gaps = []
    missing_events_total = 0
    duplicate_seq = []
    out_of_order_seq = []

    if not is_partial:
        expected = 1
        seen = set()
        for s in seqs_to_check:
            if s in seen:
                duplicate_seq.append(s)
            elif s < expected:
                out_of_order_seq.append(s)
            elif s > expected:
                gap = {'after': expected - 1, 'before': s, 'missing': s - expected}
                sequence_gaps.append(gap)
                missing_events_total += (s - expected)
                expected = s + 1
            else:
                expected += 1
            seen.add(s)
        sequence_complete = (len(sequence_gaps) == 0 and len(duplicate_seq) == 0 and len(out_of_order_seq) == 0 and (len(seqs_to_check) == 0 or seqs_to_check[0] == 1))
        check_type = 'full'
    else:
        expected = seqs_to_check[0] + 1
        seen = {seqs_to_check[0]}
        for s in seqs_to_check[1:]:
            if s in seen:
                duplicate_seq.append(s)
            elif s < expected:
                out_of_order_seq.append(s)
            elif s > expected:
                gap = {'after': expected - 1, 'before': s, 'missing': s - expected}
                sequence_gaps.append(gap)
                missing_events_total += (s - expected)
                expected = s + 1
            else:
                expected += 1
            seen.add(s)
        sequence_complete = (len(sequence_gaps) == 0 and len(duplicate_seq) == 0 and len(out_of_order_seq) == 0)
        check_type = 'partial'

    return {
        'sequence_check': check_type,
        'sequence_complete': sequence_complete,
        'sequence_gaps': sequence_gaps,
        'missing_events_total': missing_events_total,
        'duplicate_seq': duplicate_seq,
        'out_of_order_seq': out_of_order_seq
    }

def check_anchors(session_id, rows, errors, anchor_records, anchor_log_intact):
    session_anchors = [a for a in anchor_records if a.get('session_id') == session_id]
    if not session_anchors:
        return {
            'anchor_status': 'no_anchor',
            'anchored_count': 0,
            'unanchored_tail_events': len(rows),
            'anchor_log_intact': anchor_log_intact
        }

    max_count = max(a['count'] for a in session_anchors)
    if len(rows) < max_count:
        prefix_ok = True
        if any(e['seq'] <= len(rows) for e in errors):
            prefix_ok = False
        for a in session_anchors:
            if a['count'] <= len(rows):
                if rows[a['count'] - 1]['hash'] != a['head_hash']:
                    prefix_ok = False
                    break
        status = 'truncation_detected' if prefix_ok else 'anchor_mismatch'
        return {
            'anchor_status': status,
            'anchored_count': max_count,
            'unanchored_tail_events': 0,
            'anchor_log_intact': anchor_log_intact
        }
    else:
        all_match = True
        for a in session_anchors:
            idx = a['count'] - 1
            if idx >= len(rows) or rows[idx]['hash'] != a['head_hash']:
                all_match = False
                break
        status = 'verified' if all_match else 'anchor_mismatch'
        return {
            'anchor_status': status,
            'anchored_count': max_count,
            'unanchored_tail_events': max(0, len(rows) - max_count),
            'anchor_log_intact': anchor_log_intact
        }

def reconstruct(rows, session_id, anchor_path=None):
    started = time.perf_counter()
    errors, recalculated, broken_ids, events = [], {}, [], []
    parsed_payloads = []
    previous = '0'*64
    for seq,row in enumerate(rows,1):
        eid = event_id(seq)
        payload = parse_payload(row['payload'])
        parsed_payloads.append(payload)
        reasons = []
        if row['prev_hash'] != previous: reasons.append('Previous-hash link mismatch')
        if payload is None: reasons.append('Stored payload is not a valid JSON object')
        else:
            aegis = payload.get('_aegis')
            if not isinstance(aegis, dict):
                reasons.append('Missing sealed _aegis envelope')
            else:
                s_ver = aegis.get('schema_version')
                if s_ver == 1:
                    envelope = {'schema_version':1,'session_id':row['session_id'],'event_type':row['event_type'],
                                'sensitive_action_flag':bool(row['sensitive_action_flag'])}
                    if aegis != envelope:
                        reasons.append('Sealed metadata differs from stored columns')
                elif s_ver == 2:
                    c_seq = aegis.get('client_seq')
                    if not isinstance(c_seq, int) or isinstance(c_seq, bool) or c_seq < 1:
                        reasons.append('Sealed metadata client_seq invalid')
                    else:
                        envelope = {'schema_version':2,'session_id':row['session_id'],'event_type':row['event_type'],
                                    'sensitive_action_flag':bool(row['sensitive_action_flag']),'client_seq':c_seq}
                        if aegis != envelope:
                            reasons.append('Sealed metadata differs from stored columns')
                else:
                    reasons.append('Unsupported envelope schema_version')
        try:
            computed = entry_hash(row['timestamp'],row['payload'],row['prev_hash'])
        except (ValueError,TypeError,OverflowError):
            computed = 'invalid'
        recalculated[eid] = computed
        if computed != row['hash']: reasons.append('Payload or timestamp hash mismatch')
        if reasons:
            broken_ids.append(row['id'])
            errors.extend({'seq':seq,'entry_id':row['id'],'reason':reason} for reason in reasons)
        try:
            timestamp = datetime.fromtimestamp(row['timestamp'],timezone.utc).isoformat().replace('+00:00','Z')
        except (ValueError,TypeError,OverflowError,OSError):
            timestamp = 'Invalid timestamp'
        events.append({'id':eid,'seq':seq,'db_id':row['id'],'session_id':session_id,
                       'timestamp':timestamp,'type':row['event_type'],
                       'label':str((payload or {}).get('label',row['event_type'].replace('_',' '))),
                       'payload':payload or {'message':'Malformed stored payload; inspect raw export.'},
                       'parent_ids':[event_id(seq-1)] if seq>1 else [],
                       'flagged':bool(row['sensitive_action_flag']),
                       'prev_hash':row['prev_hash'],'hash':row['hash'],
                       'directly_broken':bool(reasons)})
        previous = row['hash']
    first = min((error['seq'] for error in errors),default=None)

    seq_info = check_sequences(rows, parsed_payloads)
    a_path = Path(anchor_path) if anchor_path else Path(os.getenv('ANCHOR_DATA_DIR', '/anchor_data')) / 'anchors.jsonl'
    log_intact, anchor_records = verify_anchor_log(a_path)
    anchor_info = check_anchors(session_id, rows, errors, anchor_records, log_intact)

    verification = {'session_id':session_id,'entry_count':len(rows),'chain_intact':not errors,
                    'broken_entry_ids':broken_ids,'ok':not errors,'checked':len(rows),
                    'firstBroken':first,'errors':errors,'recalculated':recalculated,
                    'durationMs':(time.perf_counter()-started)*1000,
                    **seq_info, **anchor_info}
    dag = nx.DiGraph()
    counts = Counter(event['type'] if event['type']=='retrieval' else 'tool' if event['type'].startswith('tool_') else 'state' for event in events)
    offsets = Counter()
    width = (max(3,*counts.values())-1)*185
    for event in events:
        tier = 'retrieval' if event['type']=='retrieval' else 'tool' if event['type'].startswith('tool_') else 'state'
        count = counts[tier]
        x = 90+offsets[tier]*width/(count-1) if count>1 else 90+width/2
        offsets[tier] += 1
        event['position'] = {'x':x,'y':{'retrieval':90,'state':240,'tool':360}[tier]}
        event['tampered'] = first is not None and event['seq'] >= first
        dag.add_node(event['id'],**event,event_type=event['type'],sensitive_action_flag=event['flagged'],tier=tier)
        for parent in event['parent_ids']:
            dag.add_edge(parent,event['id'],broken=event['tampered'])
    return {'session_id':session_id,'events':events,'verification':verification,
            'nodes':[data for _,data in dag.nodes(data=True)],
            'edges':[{'source':source,'target':target,**data} for source,target,data in dag.edges(data=True)],
            'graph_semantics':'Recorded-order dependency DAG; not a proof of unobserved causal reasoning.'}

def create_app(db_path=None, frontend_dir=None, anchor_data_dir=None):
    path = Path(db_path or os.getenv('DB_PATH','/data/audit.db'))
    demo = os.getenv('DEMO_MODE','false').lower()=='true'
    anchor_path = Path(anchor_data_dir or os.getenv('ANCHOR_DATA_DIR','/anchor_data')) / 'anchors.jsonl'
    app = BrowserAPI(docs_url=None,redoc_url=None,openapi_url=None)
    def session_rows(session_id):
        rows = load_rows(path,session_id)
        if not rows: raise HTTPException(404,'session not found')
        return rows

    @app.get('/health')
    def health():
        conn = None
        try:
            conn = open_ro(path)
            conn.execute('SELECT id FROM audit_log LIMIT 1')
            return {'status':'ok'}
        except sqlite3.Error:
            raise HTTPException(503,'audit database unavailable')
        finally:
            if conn: conn.close()

    @app.get('/config.js', include_in_schema=False)
    def frontend_config():
        base = os.getenv('AEGIS_API_BASE', '').strip().rstrip('/')
        return Response('window.AEGIS_API_BASE = '+json.dumps(base)+';\n',
                        media_type='application/javascript', headers={'Cache-Control':'no-store'})

    @app.get('/api/config')
    def config(): return {'demo_mode':demo}

    @app.get('/api/sessions')
    def sessions():
        groups = {}
        for row in load_rows(path): groups.setdefault(row['session_id'],[]).append(row)
        return [{'session_id':sid,'status':'verified' if reconstruct(rows,sid,anchor_path=anchor_path)['verification']['ok'] else 'tampered',
                 'entry_count':len(rows)} for sid,rows in groups.items()]

    @app.get('/api/session/{session_id}/entries')
    def entries(session_id: SessionID): return [raw_entry(row) for row in session_rows(session_id)]

    @app.get('/api/session/{session_id}/verify')
    def verify(session_id: SessionID): return reconstruct(session_rows(session_id),session_id,anchor_path=anchor_path)['verification']

    @app.get('/api/session/{session_id}/graph')
    def graph(session_id: SessionID): return reconstruct(session_rows(session_id),session_id,anchor_path=anchor_path)

    @app.get('/api/session/{session_id}/export')
    def export(session_id: SessionID):
        rows = session_rows(session_id)
        snapshot = reconstruct(rows,session_id,anchor_path=anchor_path)
        document = {'format':'aegistrace-audit/v1','exported_at':datetime.now(timezone.utc).isoformat(),
                    'session_id':session_id,'entries':[raw_entry(row) for row in rows],**snapshot,
                    'hash_algorithm':'SHA-256',
                    'hash_input':'UTF-8(timestamp_repr + payload_str + prev_hash); genesis = 64 zero characters',
                    'canonicalization':'Payload: sorted JSON keys, compact separators, ensure_ascii=False, finite numbers only.',
                    'trust_boundary':'Internal consistency only. No external head anchor; suffix deletion and full history rewrite are not detectable without a trusted checkpoint.'}
        return Response(json.dumps(document,ensure_ascii=False,indent=2),media_type='application/json',
                        headers={'Content-Disposition':f'attachment; filename="aegistrace-{session_id}.json"','Cache-Control':'no-store'})

    if demo:
        @app.post('/api/session/{session_id}/tamper')
        def tamper(session_id: SessionID,body: TamperBody):
            try:
                serialized = canonical_json(body.payload)
                if len(serialized.encode())>131072: raise ValueError('too large')
            except (ValueError,TypeError,RecursionError):
                raise HTTPException(422,'payload must be finite JSON under 128 KiB')
            conn = None
            try:
                # mode=rw never creates a missing database. Only this explicit demo handler writes.
                conn = sqlite3.connect('file:'+quote(str(path.resolve()))+'?mode=rw',uri=True,timeout=5)
                conn.execute('BEGIN IMMEDIATE')
                updated = conn.execute('UPDATE audit_log SET payload=? WHERE id=? AND session_id=?',(serialized,body.entry_id,session_id))
                if updated.rowcount!=1: raise HTTPException(404,'entry not found in session')
                conn.commit()
            except sqlite3.Error:
                raise HTTPException(503,'Demo requires the explicit writable demo Compose override')
            finally:
                if conn: conn.close()
            return {'status':'tampered','entry_id':body.entry_id}

    static = Path(frontend_dir or os.getenv('FRONTEND_DIR','frontend'))
    if static.is_dir(): app.mount('/',StaticFiles(directory=static,html=True),name='frontend')
    return app

app = create_app()
