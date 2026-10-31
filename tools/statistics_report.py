"""Generate delivery tables directly from recorded observations, independent of runner summaries."""
import sys,json,csv,math,statistics,collections,hashlib
from pathlib import Path
from datetime import datetime,timezone
B=Path(__file__).resolve().parents[1]
def load(p):return json.loads(p.read_text(encoding='utf-8'))
def lines(p):return [json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x]
def write(p,x):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('x',encoding='utf-8') as f:json.dump(x,f,ensure_ascii=False,indent=2,allow_nan=False)
def stats(values,failures=0):
    assert values and all(math.isfinite(v) and v>=0 for v in values)
    s=sorted(values);return {'n':len(s),'median_ms':statistics.median(s),'p95_ms':s[math.ceil(.95*len(s))-1],'min_ms':s[0],'max_ms':s[-1],'failures':failures}
def main():
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--runs',nargs='*');args=parser.parse_args()
    out=B/'I21-RESULTS/results/aggregate'
    if out.exists():out=out.with_name('aggregate_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    out.mkdir(parents=True,exist_ok=False)
    runs=[];allrows=[];seen=set();keys=set();links=[];design_notes=[];isolated_audience_count=0
    for d in sorted((B/'I21-RESULTS/results').iterdir()):
        if not (d/'run_summary.json').exists():continue
        if args.runs and d.name not in args.runs:continue
        config=load(B/'I21-INPUT/metadata'/d.name/'configuration.json');rows=lines(d/'cases.jsonl');plan=load(B/'I21-INPUT/metadata'/d.name/'expected_cases.json')['cases'];exp={x['case_id']:x for x in plan}
        assert len(rows)==len(plan)
        for x in rows:
            assert x['case_id'] not in seen;seen.add(x['case_id']);assert x['actual']['reason']==exp[x['case_id']]['expected_reason']
            raw=(B/x['input_file']).read_bytes();assert hashlib.sha256(raw).hexdigest()==x['input_sha256']
        identities=load(B/'I21-INPUT/input'/d.name/'TEST_ONLY_identities.json')
        for x in identities:
            assert x['authentication_key'] not in keys;keys.add(x['authentication_key'])
        presenter_dids=set()
        for x in rows:
            try:presenter_dids.add(load(B/x['input_file'])['presentation']['holder'])
            except (KeyError,ValueError):pass
        audits=sorted((B/'work_records').glob('audit_'+d.name+'_*'))
        candidates=[(a,load(a/'audit_summary.json')) for a in audits if (a/'audit_summary.json').exists()]
        auditdir,audit=candidates[-1];assert audit['passed'] and audit['transaction_and_receipt_trie_roots_checked']>0
        isolated_audience_count+=audit.get('isolated_audience_records',0)
        rechecks={x['case_id']:x for x in load(auditdir/'individual_recheck.json')}
        for row in rows:
            if row['category']=='wrong_audience' and rechecks[row['case_id']]['challenge_signature_recomputed'] is False:
                design_notes.append({'case_id':row['case_id'],'note':'早期接收方负例同时存在挑战签名归属与nonce来源差异；保留实际拒绝结果，不计入单条件隔离证据。以三组audience_isolation补测为隔离证据。'})
        tx=lines(d/'transactions.jsonl');receipt_count=len(list((B/'I21-RESULTS/receipts'/d.name).glob('0x*.json')))
        counts=dict(collections.Counter(x['actual']['status'] for x in rows));counted={'run_id':d.name,'mode':config['mode'],'holder_identities_registered':config['identities'],'presenter_dids_in_saved_requests':len(presenter_dids),'test_dids_including_issuers_and_rogue':len(identities),'records':len(rows),'verification_records':sum(x['kind']=='verification' for x in rows),'state_operation_test_records':sum(x['kind']=='transaction' for x in rows),'status_counts':counts,'receipts':receipt_count,'block_headers':audit['block_headers_checked'],'ed25519_recomputations':audit['cryptographic_operations'],'audit_path':(auditdir/'audit_summary.json').relative_to(B).as_posix(),'mismatches':sum(x['actual']['reason']!=exp[x['case_id']]['expected_reason'] for x in rows)}
        runs.append(counted);allrows.extend(rows);links.extend(load(auditdir/'case_transaction_links.json'))
    batchrows=[r for r in allrows if next(x['mode'] for x in runs if x['run_id']==r['run_id'])=='batch']
    performance=[r for r in runs if r['mode']=='performance'];assert performance
    pr=sorted(performance,key=lambda r:r['run_id'])[-1]['run_id'];prows=[r for r in allrows if r['run_id']==pr and r.get('phase')=='measured'];warmup=[r for r in allrows if r['run_id']==pr and r.get('phase')=='warmup']
    performance_stats={}
    for field in ['elapsed_ms','rpc_ms','offchain_ms']:
        for group,predicate in [('normal',lambda r:r['actual']['status']=='accepted'),('business_rejection',lambda r:r['actual']['status']=='rejected' and r['kind']=='verification'),('state_unavailable',lambda r:r['actual']['status']=='dependency_error')]:
            values=[r['actual'][field] for r in prows if predicate(r) and field in r['actual']]
            if values:performance_stats[group+'_'+field]=stats(values)
    for cat in sorted(set(x['category'] for x in prows)):
        rr=[r for r in prows if r['category']==cat];performance_stats['case_'+cat]=stats([r['actual']['elapsed_ms'] for r in rr],sum(r['actual']['status']=='program_error' for r in rr))
    tx=lines(B/'I21-RESULTS/results'/pr/'transactions.jsonl')
    for label in ['register','issue','revoke','rotate_holder','rotate_issuer','deactivate']:
        rr=[r for r in tx if r['label'].startswith(label+':')]
        if rr:performance_stats['chain_'+label]=stats([r['confirmation_observed_ms'] for r in rr],sum(r['status']!='0x1' for r in rr))
    issued=lines(B/'I21-RESULTS/results'/pr/'issuance_timings.jsonl');performance_stats['offchain_issuance_signing']=stats([r['elapsed_ms'] for r in issued])
    sync=lines(B/'I21-RESULTS/receipts'/pr/'synchronization.jsonl');performance_stats['post_confirmation_shared_block_wait']=stats([r['wait_ms'] for r in sync])
    batch_by_category={cat:{'n':len(rr:= [r for r in batchrows if r['category']==cat]),'expected_reason':rr[0]['expected_reason'],'actual_reasons':dict(collections.Counter(r['actual']['reason'] for r in rr)),'mismatches':sum(not r['matches_expected'] for r in rr)} for cat in sorted(set(x['category'] for x in batchrows))}
    total_counts=collections.Counter(x['actual']['status'] for x in allrows)
    summary={'generated_utc':datetime.now(timezone.utc).isoformat(),'runs':runs,'complete_run_count':len(runs),'all_records':len(allrows),'correctness_batch_records':len(batchrows),'performance_measured_records':len(prows),'performance_warmup_records':len(warmup),'verification_records':sum(x['kind']=='verification' for x in allrows),'state_operation_test_records':sum(x['kind']=='transaction' for x in allrows),'status_counts':dict(total_counts),'fully_audited_receipts':sum(r['receipts'] for r in runs),'all_receipt_files_including_aborted_setup':len(list((B/'I21-RESULTS/receipts').glob('*/0x*.json'))),'blocks_audited':sum(r['block_headers'] for r in runs),'ed25519_recomputations':sum(r['ed25519_recomputations'] for r in runs),'holder_identities_registered_complete_runs':sum(r['holder_identities_registered'] for r in runs),'distinct_presenter_dids':sum(r['presenter_dids_in_saved_requests'] for r in runs),'mismatches':sum(r['mismatches'] for r in runs)}
    summary.update(early_audience_cases_with_multiple_invalid_conditions=len(design_notes),independently_confirmed_isolated_audience_cases=isolated_audience_count,aggregate_directory=out.relative_to(B).as_posix())
    write(out/'summary.json',summary);write(out/'performance_statistics.json',performance_stats);write(out/'batch_category_results.json',batch_by_category);write(out/'case_transaction_links.json',links);write(out/'case_design_notes.json',design_notes)
    for name,data,cols in [('performance_statistics',performance_stats,['n','median_ms','p95_ms','min_ms','max_ms','failures'])]:
        with (out/(name+'.csv')).open('x',encoding='utf-8-sig',newline='') as f:
            writer=csv.writer(f);writer.writerow(['stage']+cols)
            for k,v in data.items():writer.writerow([k]+[v[c] for c in cols])
    with (out/'all_cases.csv').open('x',encoding='utf-8-sig',newline='') as f:
        writer=csv.writer(f);writer.writerow(['run_id','case_id','category','phase','kind','expected_reason','actual_status','actual_reason','elapsed_ms','input_file','input_sha256','transaction_hash'])
        for r in allrows:writer.writerow([r['run_id'],r['case_id'],r['category'],r.get('phase','correctness'),r['kind'],r['expected_reason'],r['actual']['status'],r['actual']['reason'],r['actual']['elapsed_ms'],r['input_file'],r['input_sha256'],r['transaction_hash']])
    print(json.dumps(summary,ensure_ascii=False))
if __name__=='__main__':sys.stdout.reconfigure(encoding='utf-8');main()
