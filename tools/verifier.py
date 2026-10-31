import sqlite3, secrets, threading, traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from common import *
from chain import RPC, state_snapshot
from cryptography.exceptions import InvalidSignature

class Reject(Exception): pass
def need(ok,reason):
    if not ok: raise Reject(reason)

class Verifier:
    def __init__(self,config):
        self.c=config; self.key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(config['TEST_ONLY_secret']))
        self.db=sqlite3.connect(config['database']); self.db.execute('CREATE TABLE IF NOT EXISTS challenges (nonce TEXT PRIMARY KEY, body TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)'); self.db.commit()
        self.rpc=RPC(config['rpc_url'],config['rpc_log']); self.fault=False
    def challenge(self,args):
        ts=int(time.time()); body={'nonce':secrets.token_hex(32),'holder':args['holder'],'credential_sha256':args['credential_sha256'],'audience':self.c['audience'],'chain_id':self.c['chain_id'],'genesis':self.c['genesis'],'contract':self.c['address'],'issued_at':ts,'expires_at':ts+args.get('ttl',600)}
        # Explicit test-only fixture control, unavailable through /verify.
        body.update(args.get('test_context_override',{}))
        result={'body':body,'signature':sign(self.key,body,CH_DOMAIN)}
        self.db.execute('INSERT INTO challenges(nonce,body) VALUES (?,?)',(body['nonce'],canonical(body).decode())); self.db.commit()
        append(self.c['challenge_log'],{'utc':now(),'challenge':result}); return result
    def verify(self,raw):
        start=time.perf_counter_ns(); before_rpc=self.rpc.ms; current=int(time.time()); state=None; nonce_before=None; signed={}; checks=[]; request=None
        self.rpc.context={'request_sha256':digest(raw)}
        try:
            try: request=parse(raw)
            except ValueError as e: raise Reject('DUPLICATE_JSON_KEY' if 'DUPLICATE' in str(e) else 'INVALID_JSON')
            need(isinstance(request,dict) and all(k in request for k in ['credential','presentation','holder_signature']), 'MISSING_FIELD')
            vc=request['credential']; p=request['presentation']; need(isinstance(vc,dict) and all(k in vc for k in ['body','signature']), 'MISSING_FIELD')
            body=vc['body']; need(isinstance(body,dict) and all(k in body for k in ['format','id','issuer','subject','not_before','expires_at','claims']),'MISSING_FIELD')
            need(isinstance(p,dict) and all(k in p for k in ['holder','public_key','credential_sha256','challenge']),'MISSING_FIELD')
            ch=p['challenge']; need(isinstance(ch,dict) and 'body' in ch and 'signature' in ch,'MISSING_FIELD'); cb=ch['body']
            need(isinstance(cb,dict) and all(k in cb for k in ['nonce','holder','credential_sha256','audience','chain_id','genesis','contract','issued_at','expires_at']),'MISSING_FIELD')
            try:
                signed={n:b64(d+canonical(x)) for n,d,x in [('credential',VC_DOMAIN,body),('challenge',CH_DOMAIN,cb),('presentation',VP_DOMAIN,p)]}
                for x in [vc['signature'],ch['signature'],request['holder_signature']]: unb64(x,64)
                need(isinstance(p['public_key'],str) and bool(re.fullmatch('[a-f0-9]{64}',p['public_key'])),'INVALID_ENCODING')
                need(body['format']=='I21-VC-v1' and type(body['not_before']) is int and type(body['expires_at']) is int and type(cb['issued_at']) is int and type(cb['expires_at']) is int,'INVALID_SCHEMA')
            except ValueError: raise Reject('INVALID_ENCODING')
            need(cb['audience']==self.c['audience'],'AUDIENCE_MISMATCH')
            need(cb['chain_id']==self.c['chain_id'] and cb['genesis']==self.c['genesis'] and cb['contract']==self.c['address'],'CONTEXT_MISMATCH')
            try: verify(public(self.key),ch['signature'],cb,CH_DOMAIN)
            except InvalidSignature: raise Reject('CHALLENGE_SIGNATURE')
            need(cb['holder']==p['holder'] and cb['credential_sha256']==p['credential_sha256'] and p['credential_sha256']==digest(canonical(vc)),'CHALLENGE_BINDING')
            row=self.db.execute('SELECT body,used FROM challenges WHERE nonce=?',(cb['nonce'],)).fetchone()
            need(row is not None and row[0]==canonical(cb).decode(),'UNKNOWN_CHALLENGE')
            nonce_before=bool(row[1]); need(not nonce_before,'NONCE_REPLAY')
            updated=self.db.execute('UPDATE challenges SET used=1 WHERE nonce=? AND used=0',(cb['nonce'],)).rowcount; self.db.commit(); need(updated==1,'NONCE_REPLAY')
            need(cb['issued_at']<=current<cb['expires_at'],'CHALLENGE_EXPIRED')
            checks.append('challenge')
            try:
                if self.fault:
                    self.fault=False; broken=RPC('http://127.0.0.1:1',self.c['rpc_log'],timeout=.25); broken.context=self.rpc.context
                    try: broken.call('eth_blockNumber')
                    finally: self.rpc.ms+=broken.ms
                state=state_snapshot(self.rpc,self.c,body,p['holder'])
            except Exception as e:
                append(self.c['fault_log'],{'utc':now(),'exception':type(e).__name__,'message':str(e)}); raise Reject('STATE_UNAVAILABLE')
            checks.append('state_read')
            need(state['issuer']['active'] and state['issuer']['issuer'],'UNAUTHORIZED_ISSUER')
            need(current>=body['not_before'],'CREDENTIAL_NOT_YET_VALID')
            need(current<body['expires_at'],'CREDENTIAL_EXPIRED')
            try: verify(state['issuer']['key'][2:],vc['signature'],body,VC_DOMAIN)
            except InvalidSignature: raise Reject('CREDENTIAL_SIGNATURE')
            checks.append('issuer_signature')
            need(body['subject']==p['holder'],'SUBJECT_HOLDER_MISMATCH')
            need(state['holder']['active'],'IDENTITY_INACTIVE')
            need(state['holder']['key'][2:]==p['public_key'],'HOLDER_KEY_NOT_AUTHORIZED')
            try: verify(p['public_key'],request['holder_signature'],p,VP_DOMAIN)
            except InvalidSignature: raise Reject('HOLDER_SIGNATURE')
            checks.append('holder_signature')
            cr=state['credential']; need(cr['digest']!='0x'+'00'*32,'CREDENTIAL_NOT_REGISTERED')
            need(cr['issuer'][2:]==digest(body['issuer'].encode()) and cr['subject'][2:]==digest(body['subject'].encode()) and cr['digest'][2:]==digest(canonical(body)),'REGISTRY_BINDING')
            need(not cr['revoked'],'CREDENTIAL_REVOKED')
            status,reason='accepted','OK'
        except Reject as e: status,reason=('dependency_error' if str(e)=='STATE_UNAVAILABLE' else 'rejected'),str(e)
        except Exception as e:
            status,reason='program_error',type(e).__name__+': '+str(e); append(self.c['fault_log'],{'utc':now(),'traceback':traceback.format_exc()})
        total=(time.perf_counter_ns()-start)/1e6; rpc_ms=self.rpc.ms-before_rpc
        result={'status':status,'reason':reason,'utc':now(),'verification_epoch':current,'elapsed_ms':total,'rpc_ms':rpc_ms,'offchain_ms':max(0,total-rpc_ms),'state':state,'nonce_used_before':nonce_before,'signed_bytes_base64url':signed,'completed_checks':checks,'audience':self.c['audience'],'input_sha256':digest(raw)}
        append(self.c['result_log'],result); return result

def main():
    config=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); v=Verifier(config)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            data=b'{"ready":true}'; self.send_response(200);self.end_headers();self.wfile.write(data)
        def do_POST(self):
            raw=self.rfile.read(int(self.headers['Content-Length']))
            try:
                if self.path=='/verify': out=v.verify(raw)
                elif self.path=='/challenge': out=v.challenge(parse(raw))
                elif self.path=='/test/fail-next-state-read': v.fault=True; out={'armed':True}
                else: raise ValueError('UNKNOWN_ENDPOINT')
                data=json.dumps(out,ensure_ascii=False,allow_nan=False).encode('utf-8'); self.send_response(200)
            except Exception as e: data=json.dumps({'error':str(e)}).encode(); self.send_response(500)
            self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(data)
    HTTPServer(('127.0.0.1',config['port']),Handler).serve_forever()
if __name__=='__main__': main()
