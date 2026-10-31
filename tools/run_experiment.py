import argparse, copy, secrets, shutil, subprocess, traceback, urllib.request, platform
from common import *
from chain import Chain, Account

CATEGORIES={
 'valid_a':'OK','valid_b':'OK','tampered_body':'CREDENTIAL_SIGNATURE','tampered_credential_signature':'CREDENTIAL_SIGNATURE',
 'unauthorized_issuer':'UNAUTHORIZED_ISSUER','attacker_resigns_victim_did':'HOLDER_KEY_NOT_AUTHORIZED','subject_holder_mismatch':'SUBJECT_HOLDER_MISMATCH',
 'credential_expired':'CREDENTIAL_EXPIRED','credential_future':'CREDENTIAL_NOT_YET_VALID','replay_seed':'OK','nonce_replay':'NONCE_REPLAY',
 'wrong_audience':'AUDIENCE_MISMATCH','wrong_context':'CONTEXT_MISMATCH','expired_challenge':'CHALLENGE_EXPIRED',
 'missing_field':'MISSING_FIELD','invalid_encoding':'INVALID_ENCODING','duplicate_json_key':'DUPLICATE_JSON_KEY','holder_signature_tampered':'HOLDER_SIGNATURE',
 'state_query_failure':'STATE_UNAVAILABLE','unauthorized_did_update':'TX_REVERT_STATE_UNCHANGED','unauthorized_revocation':'TX_REVERT_STATE_UNCHANGED',
 'revoked_credential':'CREDENTIAL_REVOKED','rotation_new_key':'OK','rotation_old_key':'HOLDER_KEY_NOT_AUTHORIZED',
 'issuer_rotation_old_credential':'CREDENTIAL_SIGNATURE','issuer_rotation_new_credential':'OK','deactivated_identity':'IDENTITY_INACTIVE','replay_after_restart':'NONCE_REPLAY'}

def post(port,path,obj=None,raw=None):
    if raw is None: raw=canonical(obj)
    req=urllib.request.Request('http://127.0.0.1:'+str(port)+path,raw,{'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=40) as f: return parse(f.read())
def keyrec(k): return k.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()

def run(args):
    run_id=args.mode+'_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'_'+secrets.token_hex(3)
    inp=BASE/'I21-INPUT/input'/run_id; meta=BASE/'I21-INPUT/metadata'/run_id; res=BASE/'I21-RESULTS/results'/run_id
    for p in [inp,meta,res]: p.mkdir(parents=True,exist_ok=False)
    logs=BASE/'I21-RESULTS/logs'/run_id; logs.mkdir(parents=True)
    code=BASE/'I21-RESULTS/metadata'/run_id/'code'; code.mkdir(parents=True)
    for p in (BASE/'tools').iterdir():
        if p.is_file(): shutil.copy2(p,code/p.name)
    component_version=digest(canonical({p.name:digest(p.read_bytes()) for p in code.iterdir()}))
    n=args.per_class; count=args.identities; assert count>=max(2,n)
    categories=dict(CATEGORIES)
    if args.mode=='audience_isolation':categories={k:v for k,v in categories.items() if k in ['valid_a','valid_b','wrong_audience']}
    if args.mode=='performance':categories.update(warmup_a='OK',warmup_b='OK')
    plan=[{'case_id':f'{run_id}_{cat}_{i:03d}','category':cat,'index':i,'phase':'warmup' if cat.startswith('warmup') else 'measured' if args.mode=='performance' else 'correctness','expected_reason':reason,'expected_status':('accepted' if reason=='OK' else 'dependency_error' if reason=='STATE_UNAVAILABLE' else 'rejected'),'kind':'transaction' if cat.startswith('unauthorized_') and cat!='unauthorized_issuer' else 'verification'} for cat,reason in categories.items() for i in range(5 if cat.startswith('warmup') else n)]
    save(meta/'expected_cases.json',{'written_utc':now(),'run_id':run_id,'cases':plan})
    save(meta/'configuration.json',{'run_id':run_id,'mode':args.mode,'per_class':n,'identities':count,'chain_id':args.chain_id,'rpc_ports':[args.port,args.port+1],'source':'I21-SUPPLEMENT-INDEPENDENT-BASELINE','component_version':component_version,'created_utc':now(),'python':sys.version,'platform':platform.platform()})
    people=[]
    for i in range(count+3):
        people.append({'did':f'did:i21:{run_id}:{i:03d}','controller':Account.create(),'key':Ed25519PrivateKey.generate(),'new_key':Ed25519PrivateKey.generate()})
    issuers=people[:2]; rogue=people[2]; holders=people[3:]
    governor=Account.create(); allaccounts=[governor]+[p['controller'] for p in people]
    save(inp/'TEST_ONLY_identities.json',[{'did':p['did'],'controller_address':p['controller'].address,'TEST_ONLY_controller_private_key':p['controller'].key.hex(),'authentication_key':public(p['key']),'TEST_ONLY_authentication_private_key':keyrec(p['key']),'rotated_key':public(p['new_key']),'TEST_ONLY_rotated_private_key':keyrec(p['new_key'])} for p in people])
    save(inp/'TEST_ONLY_governor.json',{'address':governor.address,'key':governor.key.hex()})
    chain=Chain(run_id,allaccounts,[args.port,args.port+1],args.chain_id); servers=[]; cfgs=[]; results=[]; credentials={}
    def txs(batch):
        records=chain.settle(batch)
        for r in records: append(res/'transactions.jsonl',{'run_id':run_id,'label':r['label'],'transaction_hash':r['transaction_hash'],'status':r['receipt']['status'],'block_number':r['receipt']['blockNumber'],'confirmation_observed_ms':r['confirmation_observed_ms']})
        return records
    def idbytes(p): return bytes.fromhex(digest(p['did'].encode()))
    def issue(holder,tag,issuer=None,key=None,nb=None,exp=None,register=True):
        issuer=issuer or issuers[int(tag[-1])%2 if tag[-1].isdigit() else 0]; key=key or issuer['key']; ts=int(time.time())
        body={'format':'I21-VC-v1','id':f'urn:i21:{run_id}:{tag}:{holder["did"].split(":")[-1]}','issuer':issuer['did'],'subject':holder['did'],'not_before':ts-60 if nb is None else nb,'expires_at':ts+7200 if exp is None else exp,'claims':{'research_role':'test_member','sample_token':secrets.token_hex(16)}}
        st=time.perf_counter_ns(); vc={'body':body,'signature':sign(key,body,VC_DOMAIN)}; elapsed=(time.perf_counter_ns()-st)/1e6
        save(inp/'credentials'/(digest(body['id'].encode())+'.json'),{'credential':vc,'signed_bytes_base64url':b64(VC_DOMAIN+canonical(body))})
        append(res/'issuance_timings.jsonl',{'credential_id':body['id'],'elapsed_ms':elapsed,'utc':now(),'register':register})
        item=chain.send(issuer['controller'],'issue',[bytes.fromhex(digest(body['id'].encode())),idbytes(issuer),idbytes(holder),bytes.fromhex(digest(canonical(body)))],'issue:'+body['id']) if register else None
        return vc,item
    def launch(k):
        path=BASE/'environment/chains'/run_id/f'verifier{k}.json'
        f=(logs/f'verifier{k}_process_{secrets.token_hex(2)}.log').open('wb'); p=subprocess.Popen([sys.executable,str(BASE/'tools/verifier.py'),str(path)],stdout=f,stderr=f,creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        servers.append((p,f)); deadline=time.monotonic()+20
        while True:
            try:
                with urllib.request.urlopen('http://127.0.0.1:'+str(cfgs[k]['port']),timeout=1) as response: response.read()
                break
            except Exception:
                if time.monotonic()>deadline: raise RuntimeError('VERIFIER_START_FAILED')
                time.sleep(.1)
        append(logs/'processes.jsonl',{'utc':now(),'role':'verifier','index':k,'pid':p.pid}); return p,f
    def presentation(vc,holder,key=None,k=0,ttl=600,override=None):
        key=key or holder['key']; ch=post(cfgs[k]['port'],'/challenge',{'holder':holder['did'],'credential_sha256':digest(canonical(vc)),'ttl':ttl,'test_context_override':override or {}})
        p={'holder':holder['did'],'public_key':public(key),'credential_sha256':digest(canonical(vc)),'challenge':ch}
        return {'credential':copy.deepcopy(vc),'presentation':p,'holder_signature':sign(key,p,VP_DOMAIN)}
    def execute(cat,i,request=None,k=0,raw=None,txrecord=None,before=None,after=None):
        case=next(x for x in plan if x['category']==cat and x['index']==i)
        path=inp/'requests'/(case['case_id']+'.json'); path.parent.mkdir(exist_ok=True)
        if txrecord:
            evidence={'transaction_hash':txrecord['transaction_hash'],'before':before,'after':after,'raw_transaction':txrecord['signed_raw_transaction']}
            raw=canonical(evidence); actual={'status':'rejected' if txrecord['receipt']['status']=='0x0' and before['holder']==after['holder'] and before['credential']==after['credential'] else 'program_error','reason':'TX_REVERT_STATE_UNCHANGED' if txrecord['receipt']['status']=='0x0' and before['holder']==after['holder'] and before['credential']==after['credential'] else 'TX_UNEXPECTED','elapsed_ms':txrecord['confirmation_observed_ms'],'state':after,'utc':now()}
        else:
            raw=raw or canonical(request)
            if cat=='state_query_failure': post(cfgs[k]['port'],'/test/fail-next-state-read',{})
        with path.open('xb') as f: f.write(raw)
        if not txrecord: actual=post(cfgs[k]['port'],'/verify',raw=raw)
        identifiers={}
        try:
            parsed=parse(raw); cb=parsed['credential']['body']; pp=parsed['presentation']; identifiers={'issuer_did':cb.get('issuer'),'subject_did':cb.get('subject'),'holder_did':pp.get('holder'),'credential_id':cb.get('id'),'verifier':cfgs[k]['audience']}
        except (ValueError,KeyError,TypeError): pass
        item={**case,'run_id':run_id,'source':'I21-SUPPLEMENT-INDEPENDENT-BASELINE','component_version':component_version,'identifiers':identifiers,'input_file':path.relative_to(BASE).as_posix(),'input_sha256':digest(raw),'actual':actual,'matches_expected':actual['status']==case['expected_status'] and actual['reason']==case['expected_reason'],'transaction_hash':txrecord['transaction_hash'] if txrecord else None,'log_path':(logs/f'verifier{k}_results.jsonl').relative_to(BASE).as_posix() if not txrecord else (chain.receipts/(txrecord['transaction_hash']+'.json')).relative_to(BASE).as_posix()}
        append(res/'cases.jsonl',item); results.append(item)
        if not item['matches_expected']: print('MISMATCH',cat,i,actual['status'],actual['reason'],flush=True)
        return item
    def finish():
        chain.sync(); final_block=chain.rpcs[0].call('eth_getBlockByNumber',['latest',False])
        for number in range(int(final_block['number'],16)+1):
            blocks=[rpc.call('eth_getBlockByNumber',[hex(number),True]) for rpc in chain.rpcs]
            if blocks[1] is None: chain.sync(); blocks[1]=chain.rpcs[1].call('eth_getBlockByNumber',[hex(number),True])
            save(chain.receipts/'blocks'/f'{number:06d}.json',{'node1':blocks[0],'node2':blocks[1]})
        save(res/'run_summary.json',{'run_id':run_id,'mode':args.mode,'identities':count,'planned':len(plan),'records':len(results),'verification_records':sum(x['kind']=='verification' for x in results),'transaction_test_records':sum(x['kind']=='transaction' for x in results),'mismatches':sum(not x['matches_expected'] for x in results),'status_counts':{s:sum(x['actual']['status']==s for x in results) for s in ['accepted','rejected','dependency_error','program_error']},'finished_utc':now(),'component_version':component_version})
        print(run_id,'FINISHED',len(results),'records, mismatches',sum(not x['matches_expected'] for x in results),flush=True)
        return 0 if all(x['matches_expected'] for x in results) else 2
    try:
        print(run_id,'starting 2 Geth nodes',flush=True); chain.start(); chain.deploy()
        txs([chain.send(p['controller'],'register',[idbytes(p),bytes.fromhex(public(p['key']))],'register:'+p['did']) for p in people])
        txs([chain.send(governor,'authorizeIssuer',[idbytes(p),True],'authorize:'+p['did']) for p in issuers])
        deployment=json.loads((chain.receipts/'deployment.json').read_text())
        for k in range(2):
            key=Ed25519PrivateKey.generate(); cfg={**deployment,'port':args.port+10+k,'rpc_url':chain.rpcs[k].url,'audience':f'verifier-{k}-{run_id}','TEST_ONLY_secret':keyrec(key),'public_key':public(key),'database':str(chain.dir/f'verifier{k}.sqlite'),'rpc_log':str(logs/f'verifier{k}_rpc.jsonl'),'challenge_log':str(logs/f'verifier{k}_challenges.jsonl'),'result_log':str(logs/f'verifier{k}_results.jsonl'),'fault_log':str(logs/f'verifier{k}_errors.jsonl')}
            cfgs.append(cfg); save(chain.dir/f'verifier{k}.json',cfg); launch(k)
        pending=[]
        for i,h in enumerate(holders):
            for tag in ['base']+(['expired','future'] if i<n else []):
                ts=int(time.time()); vc,tx=issue(h,tag+str(i),issuer=issuers[i%2],nb=ts+3600 if tag=='future' else ts-3600,exp=ts-1 if tag=='expired' else ts+7200)
                credentials[(i,tag)]=vc; pending.append(tx)
        txs(pending)
        if args.mode=='performance':
            for i in range(5):
                for k,cat in [(0,'warmup_a'),(1,'warmup_b')]: execute(cat,i,presentation(credentials[(i,'base')],holders[i],k=k),k=k)
        print(run_id,'registered',count,'holders; executing verification cases',flush=True)
        if args.mode=='audience_isolation':
            for i in range(n):
                h=holders[i];vc=credentials[(i,'base')]
                execute('valid_a',i,presentation(vc,h));execute('valid_b',i,presentation(vc,h,k=1),k=1)
                execute('wrong_audience',i,presentation(vc,h,override={'audience':cfgs[1]['audience']}))
            return finish()
        replays=[]
        for i in range(n):
            h=holders[i]; vc=credentials[(i,'base')]
            execute('valid_a',i,presentation(vc,h)); execute('valid_b',i,presentation(vc,h,k=1),k=1)
            bad=copy.deepcopy(vc); bad['body']['claims']['research_role']='tampered'; execute('tampered_body',i,presentation(bad,h))
            bad=copy.deepcopy(vc); b=bytearray(unb64(bad['signature'],64)); b[0]^=1; bad['signature']=b64(b); execute('tampered_credential_signature',i,presentation(bad,h))
            bad,_=issue(h,'rogue'+str(i),issuer=rogue,register=False); execute('unauthorized_issuer',i,presentation(bad,h))
            execute('attacker_resigns_victim_did',i,presentation(vc,h,key=rogue['key']))
            execute('subject_holder_mismatch',i,presentation(vc,holders[(i+1)%count]))
            execute('credential_expired',i,presentation(credentials[(i,'expired')],h)); execute('credential_future',i,presentation(credentials[(i,'future')],h))
            req=presentation(vc,h); execute('replay_seed',i,req); execute('nonce_replay',i,req); replays.append(req)
            execute('wrong_audience',i,presentation(vc,h,override={'audience':cfgs[1]['audience']})); execute('wrong_context',i,presentation(vc,h,override={'chain_id':args.chain_id+999}))
            execute('expired_challenge',i,presentation(vc,h,ttl=-1))
            req=presentation(vc,h); del req['credential']['body']['issuer']; execute('missing_field',i,req)
            req=presentation(vc,h); req['holder_signature']='%%%'; execute('invalid_encoding',i,req)
            req=presentation(vc,h); raw=canonical(req); raw=b'{"holder_signature":"x",'+raw[1:]; execute('duplicate_json_key',i,raw=raw)
            req=presentation(vc,h); b=bytearray(unb64(req['holder_signature'],64)); b[-1]^=1;req['holder_signature']=b64(b); execute('holder_signature_tampered',i,req)
            execute('state_query_failure',i,presentation(vc,h))
        print(run_id,'checking on-chain access control',flush=True)
        from chain import state_snapshot
        for cat in ['unauthorized_did_update','unauthorized_revocation']:
            before=[state_snapshot(chain.rpcs[0],deployment,credentials[(i,'base')]['body'],holders[i]['did']) for i in range(n)]
            pending=[]
            for i in range(n):
                method,args2=('rotate',[idbytes(holders[i]),bytes.fromhex(public(rogue['key']))]) if cat=='unauthorized_did_update' else ('revoke',[bytes.fromhex(digest(credentials[(i,'base')]['body']['id'].encode()))])
                pending.append(chain.send(rogue['controller'],method,args2,cat+':'+str(i)))
            recs=txs(pending)
            for i,r in enumerate(recs): execute(cat,i,txrecord=r,before=before[i],after=state_snapshot(chain.rpcs[1],deployment,credentials[(i,'base')]['body'],holders[i]['did']))
        # Persisted nonce regression: restart verifier A with the same SQLite state.
        p,f=servers[0];p.terminate();p.wait();f.close(); launch(0)
        for i,req in enumerate(replays): execute('replay_after_restart',i,req)
        # Separate credentials for revocation, preserving base credentials for rotation.
        pending=[]; rev=[]
        for i in range(n):
            v,t=issue(holders[i],'revoke'+str(i),issuer=issuers[i%2]); rev.append(v);pending.append(t)
        txs(pending); txs([chain.send(issuers[i%2]['controller'],'revoke',[bytes.fromhex(digest(v['body']['id'].encode()))],'revoke:'+str(i)) for i,v in enumerate(rev)])
        for i,v in enumerate(rev): execute('revoked_credential',i,presentation(v,holders[i],k=i%2),k=i%2)
        txs([chain.send(holders[i]['controller'],'rotate',[idbytes(holders[i]),bytes.fromhex(public(holders[i]['new_key']))],'rotate_holder:'+str(i)) for i in range(n)])
        for i in range(n):
            execute('rotation_new_key',i,presentation(credentials[(i,'base')],holders[i],key=holders[i]['new_key']))
            execute('rotation_old_key',i,presentation(credentials[(i,'base')],holders[i]))
        txs([chain.send(p['controller'],'rotate',[idbytes(p),bytes.fromhex(public(p['new_key']))],'rotate_issuer:'+p['did']) for p in issuers])
        pending=[]; newvc=[]
        for i in range(n):
            v,t=issue(holders[i],'newissuer'+str(i),issuer=issuers[i%2],key=issuers[i%2]['new_key']);newvc.append(v);pending.append(t)
        txs(pending)
        for i in range(n):
            execute('issuer_rotation_old_credential',i,presentation(credentials[(i,'base')],holders[i],key=holders[i]['new_key']))
            execute('issuer_rotation_new_credential',i,presentation(newvc[i],holders[i],key=holders[i]['new_key']))
        txs([chain.send(holders[i]['controller'],'deactivate',[idbytes(holders[i])],'deactivate:'+str(i)) for i in range(n)])
        for i in range(n): execute('deactivated_identity',i,presentation(newvc[i],holders[i],key=holders[i]['new_key']))
        return finish()
    except Exception:
        failure={'run_id':run_id,'utc':now(),'traceback':traceback.format_exc(),'completed_records':len(results)}; save(BASE/'work_records'/(run_id+'_failure.json'),failure);print(failure['traceback'],flush=True);return 1
    finally:
        for p,f in servers:
            if p.poll() is None: p.terminate();p.wait()
            if not f.closed:f.close()
        chain.stop()
        append(logs/'lifecycle.jsonl',{'utc':now(),'action':'stopped_experiment_processes'})

if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8'); p=argparse.ArgumentParser();p.add_argument('--mode',choices=['smoke','batch','regression','performance','audience_isolation'],default='smoke');p.add_argument('--per-class',type=int,default=1);p.add_argument('--identities',type=int,default=4);p.add_argument('--chain-id',type=int,default=2721001);p.add_argument('--port',type=int,default=18545)
    sys.exit(run(p.parse_args()))
