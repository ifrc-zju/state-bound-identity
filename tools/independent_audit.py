"""Offline reconstruction. Does not import common, chain, verifier or runner.
Signatures are recomputed using Node/OpenSSL; contract state from mined tx/events.
"""
import sys,json,hashlib,base64,re,subprocess,collections,math,csv,statistics
from pathlib import Path
from datetime import datetime,timezone
B=Path(__file__).resolve().parents[1]

from web3 import Web3
from eth_account import Account
from eth_account._utils.legacy_transactions import Transaction
from eth_keys import keys
import rlp
from trie import HexaryTrie

def sha(b): return hashlib.sha256(b).hexdigest()
def canon(x):
    def valid(v):
        if isinstance(v,dict): return all(isinstance(k,str) and k.isascii() and valid(w) for k,w in v.items())
        if isinstance(v,list): return all(valid(w) for w in v)
        return (isinstance(v,str) and v.isascii()) or v is None or type(v) in (int,bool)
    if not valid(x): raise ValueError('INVALID_ENCODING')
    return json.dumps(x,sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode()
def pairs(rows):
    d={}
    for k,v in rows:
        if k in d: raise ValueError('DUPLICATE_JSON_KEY')
        d[k]=v
    return d
def readraw(b): return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('INVALID_JSON')))
def dec(s,size):
    if not isinstance(s,str) or not re.fullmatch('[A-Za-z0-9_-]+',s): raise ValueError('INVALID_ENCODING')
    v=base64.urlsafe_b64decode(s+'='*(-len(s)%4))
    if len(v)!=size or base64.urlsafe_b64encode(v).decode().rstrip('=')!=s: raise ValueError('INVALID_ENCODING')
    return v
def load(p): return json.loads(p.read_text(encoding='utf-8'))
def lines(p): return [json.loads(l) for l in p.read_text(encoding='utf-8').splitlines() if l]
def write(p,x):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('x',encoding='utf-8') as f:json.dump(x,f,ensure_ascii=False,indent=2,allow_nan=False)
def hx(b): return '0x'+b.hex()
def keyid(s): return '0x'+sha(s.encode())
def encint(n): return int(n,16)

def audit(run_id):
    resultdir=B/'I21-RESULTS/results'/run_id; receipts=B/'I21-RESULTS/receipts'/run_id
    out=B/'work_records'/('audit_'+run_id+'_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    out.mkdir(parents=True,exist_ok=False); errors=[]; warnings=[]
    for name in ['independent_audit.py','crypto_check.mjs']:
        (out/name).write_bytes((B/'tools'/name).read_bytes())
    def ck(ok,msg):
        if not ok: errors.append(msg)
    config=load(B/'I21-INPUT/metadata'/run_id/'configuration.json'); deploy=load(receipts/'deployment.json'); w=Web3(); contract=w.eth.contract(abi=deploy['abi'])
    rows=lines(resultdir/'cases.jsonl'); expected=load(B/'I21-INPUT/metadata'/run_id/'expected_cases.json')['cases']; expect={x['case_id']:x for x in expected}
    ck(len(rows)==len(expected),'record_count'); ck(len({x['case_id'] for x in rows})==len(rows),'duplicate_case_id');ck(set(x['case_id'] for x in rows)==set(expect),'missing_or_extra_case_id')
    identities=load(B/'I21-INPUT/input'/run_id/'TEST_ONLY_identities.json')
    ck(len(identities)==config['identities']+3,'identity_count')
    for field in ['did','controller_address','authentication_key','rotated_key']:
        ck(len(set(x[field] for x in identities))==len(identities),'duplicate_identity_field:'+field)
    duplicate_inputs=collections.defaultdict(list)
    for row in rows:duplicate_inputs[row['input_sha256']].append(row['category'])
    for digest,categories in duplicate_inputs.items():
        if len(categories)>1:ck(set(categories)<= {'replay_seed','nonce_replay','replay_after_restart'},'unplanned_duplicate_input:'+digest)
    blocks={}; seen_txs={}; block_signers=collections.Counter(); nodekeys=load(B/'environment/chains'/run_id/'TEST_ONLY_node_keys.json'); allowed={x['address'].lower() for x in nodekeys}
    header_fields=['parentHash','sha3Uncles','miner','stateRoot','transactionsRoot','receiptsRoot','logsBloom','difficulty','number','gasLimit','gasUsed','timestamp','extraData','mixHash','nonce','baseFeePerGas']
    intfields={'difficulty','number','gasLimit','gasUsed','timestamp','baseFeePerGas'}
    for path in sorted((receipts/'blocks').glob('*.json')):
        pair=load(path); b=pair['node1']; ck(pair['node2'] is not None and pair['node2']['hash']==b['hash'],'node_block_mismatch:'+path.name)
        fields=[int(b[k],16) if k in intfields else bytes.fromhex(b[k][2:]) for k in header_fields]
        ck(hx(w.keccak(rlp.encode(fields)))==b['hash'],'block_header_hash:'+path.name)
        num=int(b['number'],16);blocks[num]=b
        if num>0:
            ck(blocks[num-1]['hash']==b['parentHash'],'parent_hash:'+str(num))
            seal=bytes.fromhex(b['extraData'][2:])[-65:];fields[12]=fields[12][:-65]
            signer=keys.Signature(seal).recover_public_key_from_msg_hash(w.keccak(rlp.encode(fields))).to_checksum_address().lower()
            ck(signer in allowed,'clique_signer:'+str(num));block_signers[signer]+=1
        for t in b['transactions']: seen_txs[t['hash']]=t
    ck(len(block_signers)==2,'both_clique_signers_must_produce_blocks')
    txrecs={}; events=[]; tx_status_counts=collections.Counter()
    identity_event=hx(w.keccak(text='IdentityChanged(bytes32,address,bytes32,bool,bool,uint64)'))
    credential_event=hx(w.keccak(text='CredentialChanged(bytes32,bytes32,bytes32,bytes32,bool)'))
    for p in receipts.glob('0x*.json'):
        rec=load(p);h=rec['transaction_hash'];txrecs[h]=rec;r=rec['receipt'];t=rec['transaction']; raw=bytes.fromhex(rec['signed_raw_transaction'][2:])
        ck(hx(w.keccak(raw))==h,'tx_hash:'+h); ck(Account.recover_transaction(raw).lower()==t['from'].lower()==rec['from'].lower(),'tx_sender:'+h)
        decoded=rlp.decode(raw,Transaction);ck(decoded.data.hex()==t['input'][2:],'tx_calldata:'+h);ck(decoded.nonce==int(t['nonce'],16),'tx_nonce:'+h)
        ck(h in seen_txs and seen_txs[h]['blockHash']==r['blockHash'],'receipt_block_membership:'+h)
        ck(blocks[int(r['blockNumber'],16)]['hash']==r['blockHash'],'receipt_block_hash:'+h)
        ck(t['hash']==r['transactionHash']==h,'receipt_tx_link:'+h)
        tx_status_counts[r['status']]+=1
        for ev in r['logs']:
            ck(ev['address'].lower()==deploy['address'].lower(),'event_contract:'+h)
            typ=ev['topics'][0];data=bytes.fromhex(ev['data'][2:]);ident=ev['topics'][1]
            if typ==identity_event:
                vals=w.codec.decode(['address','bytes32','bool','bool','uint64'],data);state={'controller':vals[0],'key':hx(vals[1]),'active':vals[2],'issuer':vals[3],'version':vals[4]};kind='identity'
            elif typ==credential_event:
                vals=w.codec.decode(['bytes32','bytes32','bytes32','bool'],data);state={'issuer':hx(vals[0]),'subject':hx(vals[1]),'digest':hx(vals[2]),'revoked':vals[3]};kind='credential'
            else: errors.append('unknown_event:'+h);continue
            events.append({'block':int(r['blockNumber'],16),'tx_index':int(r['transactionIndex'],16),'log_index':int(ev['logIndex'],16),'kind':kind,'id':ident,'state':state,'transaction_hash':h})
    events.sort(key=lambda e:(e['block'],e['tx_index'],e['log_index']))
    for num,b in blocks.items():
        txtrie=HexaryTrie({});rctrie=HexaryTrie({})
        for index,t in enumerate(b['transactions']):
            rec=txrecs[t['hash']];r=rec['receipt']
            txtrie[rlp.encode(index)]=bytes.fromhex(rec['signed_raw_transaction'][2:])
            logs=[[bytes.fromhex(l['address'][2:]),[bytes.fromhex(x[2:]) for x in l['topics']],bytes.fromhex(l['data'][2:])] for l in r['logs']]
            payload=rlp.encode([encint(r['status']),encint(r['cumulativeGasUsed']),bytes.fromhex(r['logsBloom'][2:]),logs])
            tx_type=encint(r.get('type','0x0'))
            if tx_type:payload=bytes([tx_type])+payload
            rctrie[rlp.encode(index)]=payload
        ck(hx(txtrie.root_hash)==b['transactionsRoot'],'transactions_trie_root:'+str(num))
        ck(hx(rctrie.root_hash)==b['receiptsRoot'],'receipts_trie_root:'+str(num))
    # Replay actual transaction inputs through independently written contract transition rules.
    ids={}; vcs={}; governor=load(B/'I21-INPUT/input'/run_id/'TEST_ONLY_governor.json')['address'].lower()
    def identity(did): return ids.get(did,{'controller':'0x'+'00'*20,'key':'0x'+'00'*32,'active':False,'issuer':False,'version':0})
    def cred(cid): return vcs.get(cid,{'issuer':'0x'+'00'*32,'subject':'0x'+'00'*32,'digest':'0x'+'00'*32,'revoked':False})
    states_by_block={0:({}, {})}; previous_block=0
    for h,t in sorted(seen_txs.items(),key=lambda q:(encint(q[1]['blockNumber']),encint(q[1]['transactionIndex']))):
        rec=txrecs[h];r=rec['receipt'];bn=encint(r['blockNumber']);sender=t['from'].lower()
        if bn!=previous_block:
            states_by_block[previous_block]=(json.loads(json.dumps(ids)),json.loads(json.dumps(vcs)));previous_block=bn
        if t['to'] is None:
            ck(r['status']=='0x1' and r['contractAddress'].lower()==deploy['address'].lower(),'deploy_receipt');continue
        fn,a=contract.decode_function_input(t['input']);a={k:hx(v) if isinstance(v,bytes) else v for k,v in a.items()};name=fn.fn_name; expected_success=False; change=None
        if name=='register':
            did=a['did'];expected_success=identity(did)['controller']=='0x'+'00'*20 and a['key']!='0x'+'00'*32
            change=('identity',did,{'controller':sender,'key':a['key'],'active':True,'issuer':False,'version':1})
        elif name=='authorizeIssuer':
            did=a['did'];s=dict(identity(did));expected_success=sender==governor and s['active'];s['issuer']=a['allowed'];change=('identity',did,s)
        elif name=='rotate':
            did=a['did'];s=dict(identity(did));expected_success=sender==s['controller'].lower() and s['active'] and a['key']!='0x'+'00'*32;s['key']=a['key'];s['version']+=1;change=('identity',did,s)
        elif name=='deactivate':
            did=a['did'];s=dict(identity(did));expected_success=sender==s['controller'].lower();s['active']=False;change=('identity',did,s)
        elif name=='issue':
            cid=a['cid'];s=identity(a['issuer']);expected_success=sender==s['controller'].lower() and s['active'] and s['issuer'] and identity(a['subject'])['active'] and a['digest']!='0x'+'00'*32 and cred(cid)['digest']=='0x'+'00'*32
            change=('credential',cid,{'issuer':a['issuer'],'subject':a['subject'],'digest':a['digest'],'revoked':False})
        elif name=='revoke':
            cid=a['cid'];s=dict(cred(cid));expected_success=s['digest']!='0x'+'00'*32 and sender==identity(s['issuer'])['controller'].lower();s['revoked']=True;change=('credential',cid,s)
        ck(expected_success==(r['status']=='0x1'),'independent_contract_transition:'+h)
        matching=[e for e in events if e['transaction_hash']==h]
        if expected_success:
            typ,ident,s=change;(ids if typ=='identity' else vcs)[ident]=s
            ck(len(matching)==1 and matching[0]['id']==ident and matching[0]['state']==s,'event_vs_transition:'+h)
        else: ck(not matching,'reverted_tx_has_events:'+h)
    states_by_block[previous_block]=(json.loads(json.dumps(ids)),json.loads(json.dumps(vcs)))
    stateblocks=sorted(states_by_block)
    def snapshot_at(num): return states_by_block[max(k for k in stateblocks if k<=num)]
    crypto_tasks=[]; signatures={}; requests={}; validation_rows=[]; nonce_used=set(); challenge_map={}; configs={}
    for k in range(2):
        c=load(B/'environment/chains'/run_id/f'verifier{k}.json');configs[c['audience']]=c
        for row in lines(Path(c['challenge_log'])): challenge_map[(c['audience'],row['challenge']['body']['nonce'])]=row['challenge']['body']
    def addcrypto(case,name,key,signature,body,domain):
        try:
            msg=domain+canon(body);sig=dec(signature,64);idx=len(crypto_tasks)
            crypto_tasks.append({'public_key':key,'message_base64':base64.b64encode(msg).decode(),'signature_base64':base64.b64encode(sig).decode()});signatures[(case,name)]=idx
        except (ValueError,TypeError,KeyError): pass
    for row in rows:
        raw=(B/row['input_file']).read_bytes();cid=row['case_id']; ck(sha(raw)==row['input_sha256'],'input_sha:'+cid)
        if row['kind']=='transaction': continue
        try:
            req=readraw(raw);requests[cid]=req;p=req['presentation'];vc=req['credential'];ch=p['challenge'];state=row['actual']['state'];cfg=configs[row['actual']['audience']]
            addcrypto(cid,'challenge',cfg['public_key'],ch['signature'],ch['body'],b'I21-CH-v1\x00')
            addcrypto(cid,'holder',p['public_key'],req['holder_signature'],p,b'I21-VP-v1\x00')
            if state:addcrypto(cid,'issuer',state['issuer']['key'][2:],vc['signature'],vc['body'],b'I21-VC-v1\x00')
            elif config['mode']=='audience_isolation' and row['category']=='wrong_audience':
                control=next(x for x in rows if x['category']=='valid_a' and x['index']==row['index'])
                addcrypto(cid,'issuer',control['actual']['state']['issuer']['key'][2:],vc['signature'],vc['body'],b'I21-VC-v1\x00')
        except (ValueError,KeyError,TypeError): pass
    node=shutil_node=__import__('shutil').which('node')
    proc=subprocess.run([node,str(B/'tools/crypto_check.mjs')],input=json.dumps(crypto_tasks).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    crypto_results=json.loads(proc.stdout)
    def sigok(cid,name): return (cid,name) in signatures and crypto_results[signatures[(cid,name)]]
    state_links=[]
    for row in rows:
        cid=row['case_id'];actual=row['actual'];state=actual.get('state');raw=(B/row['input_file']).read_bytes();reason=None
        if state:
            bn=encint(state['block']['number']);ck(blocks[bn]['hash']==state['block']['hash'],'state_block:'+cid);si,sc=snapshot_at(bn)
            try:
                req=readraw(raw)
                if row['kind']=='transaction':
                    before=req['before'];after=req['after'];h=req['transaction_hash'];r=txrecs[h]['receipt'];reason='TX_REVERT_STATE_UNCHANGED' if r['status']=='0x0' and before['holder']==after['holder'] and before['credential']==after['credential'] else 'TX_UNEXPECTED'
                    # Both snapshots must match independent event history.
                    for sn in [before,after]:
                        ss,cc=snapshot_at(encint(sn['block']['number']));ck(sn['holder'] in ss.values() and sn['credential'] in cc.values(),'access_control_snapshot:'+cid)
                else:
                    v=req['credential']['body'];holder=req['presentation']['holder']
                    for name,did in [('issuer',v['issuer']),('holder',holder),('subject',v['subject'])]:ck(state[name]==si[keyid(did)],'state_identity:'+cid+':'+name)
                    default={'issuer':'0x'+'00'*32,'subject':'0x'+'00'*32,'digest':'0x'+'00'*32,'revoked':False}
                    ck(state['credential']==sc.get(keyid(v['id']),default),'state_credential:'+cid)
                    related=[e for e in events if e['block']<=bn and e['id'] in [keyid(v['issuer']),keyid(holder),keyid(v['id'])]]
                    state_links.append({'case_id':cid,'block_number':bn,'block_hash':state['block']['hash'],'evidence_transaction_hashes':list(dict.fromkeys(e['transaction_hash'] for e in related))})
            except (ValueError,KeyError,TypeError) as e:ck(False,'state_parse:'+cid+':'+str(e))
        if row['kind']=='verification':
            try:
                r=readraw(raw)
                assert isinstance(r,dict) and all(k in r for k in ['credential','presentation','holder_signature']),'MISSING_FIELD'
                v=r['credential'];p=r['presentation'];assert all(k in v for k in ['body','signature']),'MISSING_FIELD';vb=v['body']
                assert all(k in vb for k in ['format','id','issuer','subject','not_before','expires_at','claims']),'MISSING_FIELD'
                assert all(k in p for k in ['holder','public_key','credential_sha256','challenge']),'MISSING_FIELD'
                ch=p['challenge'];cb=ch['body'];assert all(k in cb for k in ['nonce','holder','credential_sha256','audience','chain_id','genesis','contract','issued_at','expires_at']),'MISSING_FIELD'
                for obj in [vb,cb,p]:canon(obj)
                for s in [v['signature'],ch['signature'],r['holder_signature']]:dec(s,64)
                assert re.fullmatch('[a-f0-9]{64}',p['public_key']),'INVALID_ENCODING'
                c=configs[actual['audience']];ts=actual['verification_epoch']
                assert cb['audience']==c['audience'],'AUDIENCE_MISMATCH'
                assert cb['chain_id']==c['chain_id'] and cb['genesis']==c['genesis'] and cb['contract']==c['address'],'CONTEXT_MISMATCH'
                assert sigok(cid,'challenge'),'CHALLENGE_SIGNATURE'
                assert cb['holder']==p['holder'] and cb['credential_sha256']==p['credential_sha256']==sha(canon(v)),'CHALLENGE_BINDING'
                nonce=(c['audience'],cb['nonce']);assert challenge_map.get(nonce)==cb,'UNKNOWN_CHALLENGE'
                assert nonce not in nonce_used,'NONCE_REPLAY';nonce_used.add(nonce)
                assert cb['issued_at']<=ts<cb['expires_at'],'CHALLENGE_EXPIRED'
                if state is None:
                    faultlog=Path(c['rpc_log']); faults=[l for l in lines(faultlog) if l.get('endpoint')=='http://127.0.0.1:1' and l.get('error') and (l.get('request_sha256')==sha(raw) or 'request_sha256' not in l)]
                    assert faults,'MISSING_RPC_FAILURE_EVIDENCE'
                    raise AssertionError('STATE_UNAVAILABLE')
                assert state['issuer']['active'] and state['issuer']['issuer'],'UNAUTHORIZED_ISSUER'
                assert ts>=vb['not_before'],'CREDENTIAL_NOT_YET_VALID';assert ts<vb['expires_at'],'CREDENTIAL_EXPIRED'
                assert sigok(cid,'issuer'),'CREDENTIAL_SIGNATURE'
                assert vb['subject']==p['holder'],'SUBJECT_HOLDER_MISMATCH';assert state['holder']['active'],'IDENTITY_INACTIVE'
                assert p['public_key']==state['holder']['key'][2:],'HOLDER_KEY_NOT_AUTHORIZED';assert sigok(cid,'holder'),'HOLDER_SIGNATURE'
                cs=state['credential'];assert cs['digest']!='0x'+'00'*32,'CREDENTIAL_NOT_REGISTERED'
                assert cs['issuer']==keyid(vb['issuer']) and cs['subject']==keyid(vb['subject']) and cs['digest'][2:]==sha(canon(vb)),'REGISTRY_BINDING'
                assert not cs['revoked'],'CREDENTIAL_REVOKED';reason='OK'
            except AssertionError as e:reason=str(e)
            except ValueError as e:reason=str(e)
            except Exception as e:reason='AUDIT_ERROR:'+str(e)
        match=reason==actual['reason'] and reason==expect[cid]['expected_reason'];ck(match,'independent_verdict:'+cid+':'+str(reason))
        if row['kind']=='verification':
            for name,stored in actual.get('signed_bytes_base64url',{}).items():
                try:
                    rq=readraw(raw);body={'credential':rq['credential']['body'],'challenge':rq['presentation']['challenge']['body'],'presentation':rq['presentation']}[name];domain={'credential':b'I21-VC-v1\x00','challenge':b'I21-CH-v1\x00','presentation':b'I21-VP-v1\x00'}[name]
                    ck(base64.urlsafe_b64decode(stored+'='*(-len(stored)%4))==domain+canon(body),'signed_bytes:'+cid)
                except Exception:ck(False,'signed_bytes_decode:'+cid)
        validation_rows.append({'case_id':cid,'recomputed_reason':reason,'matches':match,'issuer_signature_recomputed':sigok(cid,'issuer') if (cid,'issuer') in signatures else None,'holder_signature_recomputed':sigok(cid,'holder') if (cid,'holder') in signatures else None,'challenge_signature_recomputed':sigok(cid,'challenge') if (cid,'challenge') in signatures else None})
    write(out/'individual_recheck.json',validation_rows);write(out/'case_transaction_links.json',state_links)
    special=[];isolated_audience_records=0
    for row in rows:
        if row['category'] in ['attacker_resigns_victim_did','rotation_old_key','subject_holder_mismatch','unauthorized_issuer','nonce_replay','replay_after_restart','revoked_credential','unauthorized_did_update','unauthorized_revocation']:
            cid=row['case_id'];proof={'case_id':cid,'category':row['category'],'reason':row['actual']['reason']}
            if row['kind']=='verification':
                proof.update(holder_signature_recomputed=sigok(cid,'holder'),issuer_signature_recomputed=sigok(cid,'issuer'))
                if row['category'] in ['attacker_resigns_victim_did','rotation_old_key']:
                    ck(sigok(cid,'holder'),'substitution_attack_must_have_valid_attacker_signature:'+cid)
                    ck(requests[cid]['presentation']['public_key']!=row['actual']['state']['holder']['key'][2:],'substitution_binding_failure:'+cid)
                if row['category']=='unauthorized_issuer':ck(sigok(cid,'issuer'),'rogue_issuer_must_sign_correctly:'+cid)
                if row['category']=='subject_holder_mismatch':ck(sigok(cid,'holder') and sigok(cid,'issuer'),'subject_attack_signatures:'+cid)
            special.append(proof)
        if row['category']=='wrong_audience' and config['mode']=='audience_isolation':
            cid=row['case_id'];req=requests[cid];p=req['presentation'];vc=req['credential'];cb=p['challenge']['body'];c=configs[row['actual']['audience']]
            control=next(x for x in rows if x['category']=='valid_a' and x['index']==row['index']);cr=requests[control['case_id']];st=control['actual']['state'];ts=row['actual']['verification_epoch']
            checks={
                'only_audience_differs_from_receiver':cb['audience']!=c['audience'],
                'challenge_signature_valid_for_actual_receiver':sigok(cid,'challenge'),
                'holder_signature_valid':sigok(cid,'holder'),
                'issuer_signature_valid':sigok(cid,'issuer'),
                'nonce_issued_by_actual_receiver':challenge_map.get((c['audience'],cb['nonce']))==cb,
                'nonce_not_previously_consumed':(c['audience'],cb['nonce']) not in nonce_used,
                'challenge_time_valid':cb['issued_at']<=ts<cb['expires_at'],
                'credential_time_valid':vc['body']['not_before']<=ts<vc['body']['expires_at'],
                'context_valid':cb['chain_id']==c['chain_id'] and cb['genesis']==c['genesis'] and cb['contract']==c['address'],
                'holder_and_digest_bound':cb['holder']==p['holder']==vc['body']['subject'] and cb['credential_sha256']==p['credential_sha256']==sha(canon(vc)),
                'same_credential_as_positive_control':vc==cr['credential'],
                'same_authorized_holder_key_as_control':p['public_key']==st['holder']['key'][2:],
                'positive_control_accepted':control['actual']['status']=='accepted',
                'no_identity_or_credential_changes_after_control':not any(e['block']>encint(st['block']['number']) and e['id'] in [keyid(vc['body']['issuer']),keyid(p['holder']),keyid(vc['body']['id'])] for e in events)
            }
            for name,ok in checks.items():ck(ok,'audience_isolation:'+cid+':'+name)
            isolated_audience_records+=1;special.append({'case_id':cid,'category':'isolated_wrong_audience','checks':checks,'positive_control_case_id':control['case_id']})
    write(out/'security_regressions.json',special)
    code=B/'I21-RESULTS/metadata'/run_id/'code';version=sha(canon({p.name:sha(p.read_bytes()) for p in code.iterdir()}));ck(version==config['component_version'],'component_version')
    ck(sha((code/'Registry.sol').read_bytes())==deploy['source_sha256'],'contract_source_version')
    compiled=load(receipts/'compiled_contract.json');compiled_contract=next(iter(compiled['contracts'].values()))
    ck(txrecs[deploy['transaction_hash']]['transaction']['input'][2:]==compiled_contract['bin'],'deployed_creation_bytecode')
    for k in range(2):
        code_responses=[q['response']['result'] for q in lines(B/'I21-RESULTS/logs'/run_id/f'node{k+1}_rpc.jsonl') if q['method']=='eth_getCode' and 'response' in q]
        ck(code_responses and all(s==deploy['runtime_code'] for s in code_responses),'runtime_code_two_nodes:'+str(k))
    groups={}
    for cat in sorted(set(x['category'] for x in rows)):
        rr=[x for x in rows if x['category']==cat];tt=sorted(x['actual']['elapsed_ms'] for x in rr);ck(all(math.isfinite(v) and v>=0 for v in tt),'invalid_time:'+cat)
        groups[cat]={'n':len(rr),'median_ms':statistics.median(tt),'p95_ms':tt[math.ceil(.95*len(tt))-1],'mismatches':sum(x['actual']['reason']!=expect[x['case_id']]['expected_reason'] for x in rr),'status_counts':dict(collections.Counter(x['actual']['status'] for x in rr))}
    write(out/'statistics.json',groups)
    with (out/'statistics.csv').open('x',encoding='utf-8-sig',newline='') as f:
        writer=csv.writer(f);writer.writerow(['category','n','median_ms','p95_ms','mismatches'])
        for cat,v in groups.items():writer.writerow([cat,v['n'],v['median_ms'],v['p95_ms'],v['mismatches']])
    summary=load(resultdir/'run_summary.json');ck(summary['records']==len(rows) and summary['mismatches']==sum(not x['matches'] for x in validation_rows),'summary_consistency')
    report={'run_id':run_id,'reviewed_utc':datetime.now(timezone.utc).isoformat(),'records':len(rows),'isolated_audience_records':isolated_audience_records,'cryptographic_operations':len(crypto_tasks),'crypto_backend':'Node.js crypto/OpenSSL, independent of Python verifier','audit_code_sha256':sha(Path(__file__).read_bytes()),'transactions_checked':len(txrecs),'tx_status_counts':dict(tx_status_counts),'block_headers_checked':len(blocks),'transaction_and_receipt_trie_roots_checked':len(blocks)*2,'clique_signer_block_counts':dict(block_signers),'contract_transitions_recomputed':len(txrecs)-1,'state_links':len(state_links),'errors':errors,'warnings':warnings,'passed':not errors}
    write(out/'audit_summary.json',report);print(json.dumps(report,ensure_ascii=False));return not errors

if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8');sys.exit(0 if audit(sys.argv[1]) else 2)
