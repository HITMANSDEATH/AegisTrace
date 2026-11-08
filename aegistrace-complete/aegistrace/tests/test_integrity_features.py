import copy
import hashlib
import json
import os
import sys
from pathlib import Path
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.hash import entry_hash, canonical_json, event_id
from reconstruction.main import reconstruct, verify_anchor_log
from anchor.main import create_app as anchor_app, AnchorRequest
from audit.main import create_app as audit_app, IngestEvent, initialize as init_audit_db

def make_v2_row(row_id, session_id, seq, client_seq, prev_hash, timestamp=1710000000.0, event_type='state_transition', sensitive=False, payload_extra=None):
    payload = {
        'step': seq,
        'message': f'Event {seq}',
        **(payload_extra or {}),
        '_aegis': {
            'schema_version': 2,
            'session_id': session_id,
            'event_type': event_type,
            'sensitive_action_flag': sensitive,
            'client_seq': client_seq
        }
    }
    serialized = canonical_json(payload)
    digest = entry_hash(timestamp, serialized, prev_hash)
    return {
        'id': row_id,
        'session_id': session_id,
        'timestamp': timestamp,
        'event_type': event_type,
        'payload': serialized,
        'sensitive_action_flag': int(sensitive),
        'prev_hash': prev_hash,
        'hash': digest
    }

def make_v1_row(row_id, session_id, seq, prev_hash, timestamp=1710000000.0, event_type='state_transition', sensitive=False):
    payload = {
        'step': seq,
        'message': f'Legacy event {seq}',
        '_aegis': {
            'schema_version': 1,
            'session_id': session_id,
            'event_type': event_type,
            'sensitive_action_flag': sensitive
        }
    }
    serialized = canonical_json(payload)
    digest = entry_hash(timestamp, serialized, prev_hash)
    return {
        'id': row_id,
        'session_id': session_id,
        'timestamp': timestamp,
        'event_type': event_type,
        'payload': serialized,
        'sensitive_action_flag': int(sensitive),
        'prev_hash': prev_hash,
        'hash': digest
    }

def create_anchor_record(session_id, count, head_hash, last_client_seq, prev_anchor_hash='0'*64, ts=1710000100.0):
    rec = {
        'count': count,
        'head_hash': head_hash,
        'last_client_seq': last_client_seq,
        'prev_anchor_hash': prev_anchor_hash,
        'session_id': session_id,
        'ts': ts
    }
    canonical = canonical_json(rec)
    rec['anchor_hash'] = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    return rec

def test_clean_session_and_anchor_verified():
    with tempfile.TemporaryDirectory() as tmp:
        anchor_path = Path(tmp) / 'anchors.jsonl'
        rows = []
        prev = '0'*64
        for i in range(1, 11):
            r = make_v2_row(i, 'sess-clean', i, i, prev, timestamp=1710000000.0 + i)
            rows.append(r)
            prev = r['hash']
        
        anchor = create_anchor_record('sess-clean', 10, rows[-1]['hash'], 10)
        anchor_path.write_text(canonical_json(anchor) + '\n', encoding='utf-8')

        res = reconstruct(rows, 'sess-clean', anchor_path=anchor_path)
        v = res['verification']
        assert v['ok'] is True
        assert v['chain_intact'] is True
        assert v['sequence_complete'] is True
        assert v['sequence_check'] == 'full'
        assert v['sequence_gaps'] == []
        assert v['missing_events_total'] == 0
        assert v['duplicate_seq'] == []
        assert v['out_of_order_seq'] == []
        assert v['anchor_status'] == 'verified'
        assert v['anchored_count'] == 10
        assert v['unanchored_tail_events'] == 0
        assert v['anchor_log_intact'] is True

def test_dropped_event_gap_visibility():
    with tempfile.TemporaryDirectory() as tmp:
        # Event 4 dropped before ingestion; sequences emitted: 1, 2, 3, 5, 6
        seqs = [1, 2, 3, 5, 6]
        rows = []
        prev = '0'*64
        for idx, cseq in enumerate(seqs, 1):
            r = make_v2_row(idx, 'sess-gap', idx, cseq, prev, timestamp=1710000000.0 + idx)
            rows.append(r)
            prev = r['hash']

        res = reconstruct(rows, 'sess-gap', anchor_path=Path(tmp)/'none.jsonl')
        v = res['verification']
        assert v['chain_intact'] is True, "Hash chain must remain unbroken despite client drop"
        assert v['sequence_complete'] is False
        assert v['sequence_gaps'] == [{'after': 3, 'before': 5, 'missing': 1}]
        assert v['missing_events_total'] == 1
        assert v['sequence_check'] == 'full'

def test_duplicate_and_out_of_order_seq():
    with tempfile.TemporaryDirectory() as tmp:
        # Duplicate 2 and out-of-order 3
        seqs = [1, 2, 2, 4, 3, 5]
        rows = []
        prev = '0'*64
        for idx, cseq in enumerate(seqs, 1):
            r = make_v2_row(idx, 'sess-dups', idx, cseq, prev, timestamp=1710000000.0 + idx)
            rows.append(r)
            prev = r['hash']

        res = reconstruct(rows, 'sess-dups', anchor_path=Path(tmp)/'none.jsonl')
        v = res['verification']
        assert v['chain_intact'] is True
        assert v['sequence_complete'] is False
        assert 2 in v['duplicate_seq']
        assert 3 in v['out_of_order_seq']

def test_suffix_truncation_detected():
    with tempfile.TemporaryDirectory() as tmp:
        anchor_path = Path(tmp) / 'anchors.jsonl'
        rows = []
        prev = '0'*64
        for i in range(1, 11):
            r = make_v2_row(i, 'sess-trunc', i, i, prev, timestamp=1710000000.0 + i)
            rows.append(r)
            prev = r['hash']
        
        # Anchored at 10 rows
        anchor = create_anchor_record('sess-trunc', 10, rows[-1]['hash'], 10)
        anchor_path.write_text(canonical_json(anchor) + '\n', encoding='utf-8')

        # Adversary deletes the last 3 rows (leaving 7 rows)
        truncated_rows = rows[:7]
        res = reconstruct(truncated_rows, 'sess-trunc', anchor_path=anchor_path)
        v = res['verification']
        assert v['chain_intact'] is True
        assert v['anchor_status'] == 'truncation_detected'
        assert v['anchored_count'] == 10

def test_unanchored_tail_events():
    with tempfile.TemporaryDirectory() as tmp:
        anchor_path = Path(tmp) / 'anchors.jsonl'
        rows = []
        prev = '0'*64
        for i in range(1, 13):
            r = make_v2_row(i, 'sess-tail', i, i, prev, timestamp=1710000000.0 + i)
            rows.append(r)
            prev = r['hash']
        
        # Anchored at 10 rows (events 11 and 12 unanchored)
        anchor = create_anchor_record('sess-tail', 10, rows[9]['hash'], 10)
        anchor_path.write_text(canonical_json(anchor) + '\n', encoding='utf-8')

        res = reconstruct(rows, 'sess-tail', anchor_path=anchor_path)
        v = res['verification']
        assert v['anchor_status'] == 'verified'
        assert v['anchored_count'] == 10
        assert v['unanchored_tail_events'] == 2

        # If event 12 is deleted: events after last anchor deleted
        truncated = rows[:11]
        res2 = reconstruct(truncated, 'sess-tail', anchor_path=anchor_path)
        v2 = res2['verification']
        assert v2['anchor_status'] == 'verified'
        assert v2['unanchored_tail_events'] == 1

def test_history_rewrite_detected():
    with tempfile.TemporaryDirectory() as tmp:
        anchor_path = Path(tmp) / 'anchors.jsonl'
        rows = []
        prev = '0'*64
        for i in range(1, 11):
            r = make_v2_row(i, 'sess-rewrite', i, i, prev, timestamp=1710000000.0 + i)
            rows.append(r)
            prev = r['hash']
        
        # Valid anchor for original history
        anchor = create_anchor_record('sess-rewrite', 10, rows[-1]['hash'], 10)
        anchor_path.write_text(canonical_json(anchor) + '\n', encoding='utf-8')

        # Adversary tampers event 3 and recomputes all subsequent hashes to make chain internally valid
        rewritten_rows = rows[:2]
        prev = rewritten_rows[-1]['hash']
        for i in range(3, 11):
            extra = {'tampered': True} if i == 3 else None
            r = make_v2_row(i, 'sess-rewrite', i, i, prev, timestamp=1710000000.0 + i, payload_extra=extra)
            rewritten_rows.append(r)
            prev = r['hash']

        res = reconstruct(rewritten_rows, 'sess-rewrite', anchor_path=anchor_path)
        v = res['verification']
        assert v['chain_intact'] is True, "Adversary recomputed hashes, so chain is internally consistent"
        assert v['anchor_status'] == 'anchor_mismatch', "Anchor check must catch the rewritten history"

def test_anchor_log_tamper_detected():
    with tempfile.TemporaryDirectory() as tmp:
        anchor_path = Path(tmp) / 'anchors.jsonl'
        a1 = create_anchor_record('sess-1', 10, 'a'*64, 10, prev_anchor_hash='0'*64)
        a2 = create_anchor_record('sess-2', 10, 'b'*64, 10, prev_anchor_hash=a1['anchor_hash'])
        # Tamper a1 anchor_hash
        a1['anchor_hash'] = 'f'*64
        lines = [canonical_json(a1), canonical_json(a2)]
        anchor_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')

        rows = [make_v2_row(1, 'sess-1', 1, 1, '0'*64)]
        res = reconstruct(rows, 'sess-1', anchor_path=anchor_path)
        assert res['verification']['anchor_log_intact'] is False

def test_legacy_v1_ledger_rows():
    with tempfile.TemporaryDirectory() as tmp:
        rows = []
        prev = '0'*64
        for i in range(1, 6):
            r = make_v1_row(i, 'sess-v1', i, prev, timestamp=1710000000.0 + i)
            rows.append(r)
            prev = r['hash']

        res = reconstruct(rows, 'sess-v1', anchor_path=Path(tmp)/'none.jsonl')
        v = res['verification']
        assert v['ok'] is True
        assert v['chain_intact'] is True
        assert v['sequence_check'] == 'not_available'
        assert v['sequence_complete'] is None
        assert v['sequence_gaps'] == []
        assert v['anchor_status'] == 'no_anchor'

def test_mixed_ledger_rows():
    with tempfile.TemporaryDirectory() as tmp:
        # Rows 1-3 are v1, Rows 4-8 are v2
        rows = []
        prev = '0'*64
        for i in range(1, 4):
            r = make_v1_row(i, 'sess-mixed', i, prev, timestamp=1710000000.0 + i)
            rows.append(r)
            prev = r['hash']
        for i in range(4, 9):
            # v2 rows with client_seq 1..5
            r = make_v2_row(i, 'sess-mixed', i, i - 3, prev, timestamp=1710000000.0 + i)
            rows.append(r)
            prev = r['hash']

        res = reconstruct(rows, 'sess-mixed', anchor_path=Path(tmp)/'none.jsonl')
        v = res['verification']
        assert v['ok'] is True
        assert v['chain_intact'] is True
        assert v['sequence_check'] == 'partial'
        assert v['sequence_complete'] is True
        assert v['sequence_gaps'] == []

        # If a gap occurs in the v2 portion:
        rows_with_gap = list(rows)
        # Change client_seq of last row from 5 to 7 (missing 6)
        rows_with_gap[-1] = make_v2_row(8, 'sess-mixed', 8, 7, rows_with_gap[-2]['hash'], timestamp=1710000008.0)
        res_gap = reconstruct(rows_with_gap, 'sess-mixed', anchor_path=Path(tmp)/'none.jsonl')
        v_gap = res_gap['verification']
        assert v_gap['sequence_check'] == 'partial'
        assert v_gap['sequence_complete'] is False
        assert v_gap['sequence_gaps'] == [{'after': 4, 'before': 7, 'missing': 2}]

def test_concurrent_50_anchors_and_integrity():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ['ANCHOR_WRITE_TOKEN'] = 'test-token'
        app = anchor_app(data_dir=tmp)
        anchor_file = Path(tmp) / 'anchors.jsonl'
        
        handler = None
        for route in app.routes:
            if getattr(route, 'path', '') == '/anchor' and 'POST' in getattr(route, 'methods', []):
                handler = route.endpoint
                break
        assert handler is not None

        def post_anchor(i):
            req = AnchorRequest(
                session_id=f'sess-{i%5}',
                count=i * 10,
                head_hash=hashlib.sha256(f'hash-{i}'.encode()).hexdigest(),
                last_client_seq=i * 10,
                ts=1710000000.0 + i
            )
            return handler(req)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(post_anchor, i) for i in range(1, 51)]
            results = [f.result() for f in futures]

        assert len(results) == 50
        intact, records = verify_anchor_log(anchor_file)
        assert intact is True, "Concurrent anchor log must remain linear and tamper-evident"
        assert len(records) == 50
        assert records[0]['prev_anchor_hash'] == '0'*64
        for i in range(1, 50):
            assert records[i]['prev_anchor_hash'] == records[i-1]['anchor_hash']

def test_v2_tamper_classes_regression():
    # Verify all 6 tamper classes on v2 rows:
    # A1: payload altered
    # A2: timestamp altered
    # A3: prev_hash altered
    # A4: table column altered (session_id, event_type, sensitive_action_flag)
    # A5: middle row deleted
    # A6: rows swapped
    base_rows = []
    prev = '0'*64
    for i in range(1, 7):
        r = make_v2_row(i, 'sess-tamper', i, i, prev, timestamp=1710000000.0 + i)
        base_rows.append(r)
        prev = r['hash']

    # Clean check
    clean_res = reconstruct(base_rows, 'sess-tamper')
    assert clean_res['verification']['ok'] is True
    assert clean_res['verification']['errors'] == []

    # A1: payload altered
    a1_rows = copy.deepcopy(base_rows)
    p = json.loads(a1_rows[2]['payload'])
    p['message'] = 'tampered'
    a1_rows[2]['payload'] = json.dumps(p)
    assert reconstruct(a1_rows, 'sess-tamper')['verification']['ok'] is False

    # A2: timestamp altered
    a2_rows = copy.deepcopy(base_rows)
    a2_rows[2]['timestamp'] = 1710009999.0
    assert reconstruct(a2_rows, 'sess-tamper')['verification']['ok'] is False

    # A3: prev_hash altered
    a3_rows = copy.deepcopy(base_rows)
    a3_rows[2]['prev_hash'] = 'e'*64
    assert reconstruct(a3_rows, 'sess-tamper')['verification']['ok'] is False

    # A4: table columns altered
    # a) session_id altered in SQLite column
    a4_sid = copy.deepcopy(base_rows)
    a4_sid[2]['session_id'] = 'forged-session'
    v_a4_sid = reconstruct(a4_sid, 'sess-tamper')['verification']
    assert v_a4_sid['ok'] is False
    assert any('Sealed metadata differs' in e['reason'] for e in v_a4_sid['errors'])

    # b) event_type altered in SQLite column
    a4_etype = copy.deepcopy(base_rows)
    a4_etype[2]['event_type'] = 'retrieval'
    v_a4_etype = reconstruct(a4_etype, 'sess-tamper')['verification']
    assert v_a4_etype['ok'] is False
    assert any('Sealed metadata differs' in e['reason'] for e in v_a4_etype['errors'])

    # c) sensitive_action_flag altered in SQLite column
    a4_sens = copy.deepcopy(base_rows)
    a4_sens[2]['sensitive_action_flag'] = 1
    v_a4_sens = reconstruct(a4_sens, 'sess-tamper')['verification']
    assert v_a4_sens['ok'] is False
    assert any('Sealed metadata differs' in e['reason'] for e in v_a4_sens['errors'])

    # A5: middle row deleted
    a5_rows = [base_rows[0], base_rows[1], base_rows[3], base_rows[4], base_rows[5]]
    assert reconstruct(a5_rows, 'sess-tamper')['verification']['ok'] is False

    # A6: rows swapped
    a6_rows = [base_rows[0], base_rows[2], base_rows[1], base_rows[3], base_rows[4], base_rows[5]]
    assert reconstruct(a6_rows, 'sess-tamper')['verification']['ok'] is False

def test_audit_fail_open_when_anchor_down():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / 'audit.db'
        os.environ['AUDIT_WRITE_TOKEN'] = 'test-token'
        os.environ['ANCHOR_WRITE_TOKEN'] = 'test-anchor-token'
        os.environ['ANCHOR_EVERY'] = '1'  # Anchor every single event
        os.environ['ANCHOR_SINK_URL'] = 'http://127.0.0.1:59999/anchor'  # Intentionally dead port

        init_audit_db(db_path)
        app = audit_app(db_path=db_path)
        handler = None
        for route in app.routes:
            if getattr(route, 'path', '') == '/ingest' and 'POST' in getattr(route, 'methods', []):
                handler = route.endpoint
                break
        assert handler is not None

        evt = IngestEvent(
            session_id='fail-open-test',
            client_seq=1,
            event_type='state_transition',
            payload={'message': 'testing fail open'},
            timestamp=1710000000.0
        )
        res = handler(evt)
        assert res == {'status': 'recorded'}

if __name__ == '__main__':
    print("Running test_clean_session_and_anchor_verified...")
    test_clean_session_and_anchor_verified()
    print("Running test_dropped_event_gap_visibility...")
    test_dropped_event_gap_visibility()
    print("Running test_duplicate_and_out_of_order_seq...")
    test_duplicate_and_out_of_order_seq()
    print("Running test_suffix_truncation_detected...")
    test_suffix_truncation_detected()
    print("Running test_unanchored_tail_events...")
    test_unanchored_tail_events()
    print("Running test_history_rewrite_detected...")
    test_history_rewrite_detected()
    print("Running test_anchor_log_tamper_detected...")
    test_anchor_log_tamper_detected()
    print("Running test_legacy_v1_ledger_rows...")
    test_legacy_v1_ledger_rows()
    print("Running test_mixed_ledger_rows...")
    test_mixed_ledger_rows()
    print("Running test_concurrent_50_anchors_and_integrity...")
    test_concurrent_50_anchors_and_integrity()
    print("Running test_v2_tamper_classes_regression...")
    test_v2_tamper_classes_regression()
    print("Running test_audit_fail_open_when_anchor_down...")
    test_audit_fail_open_when_anchor_down()
    print("\nALL 12 INTEGRITY AND REGRESSION TESTS PASSED SUCCESSFULLY!")
