from runtime import executable
import subprocess, os, time, json, secrets, urllib.request
from common import *
from eth_account import Account
from web3 import Web3

def clean(x):
    if isinstance(x,bytes): return '0x'+x.hex()
    if isinstance(x,dict): return {k:clean(v) for k,v in x.items()}
    if isinstance(x,(list,tuple)): return [clean(v) for v in x]
    return x

class RPC:
    def __init__(self,url,log=None,timeout=15): self.url=url; self.log=log; self.ms=0; self.timeout=timeout; self.context={}
    def call(self,method,params=[]):
        start=time.perf_counter_ns(); rec={'utc':now(),'endpoint':self.url,'method':method,'params':params,**self.context}
        try:
            raw=json.dumps({'jsonrpc':'2.0','id':secrets.randbelow(2**31),'method':method,'params':params}).encode()
            req=urllib.request.Request(self.url,raw,{'Content-Type':'application/json'})
            with urllib.request.urlopen(req,timeout=self.timeout) as f: reply=json.loads(f.read())
            rec['response']=reply
            if 'error' in reply: raise RuntimeError(str(reply['error']))
            return reply['result']
        except Exception as e:
            rec['error']=str(e); raise
        finally:
            rec['elapsed_ms']=(time.perf_counter_ns()-start)/1e6; self.ms+=rec['elapsed_ms']
            if self.log: append(self.log,rec)

class Chain:
    def __init__(self,run_id,accounts,ports,chain_id):
        self.run_id=run_id; self.dir=BASE/'environment/chains'/run_id; self.dir.mkdir(parents=True,exist_ok=False)
        self.logs=BASE/'I21-RESULTS/logs'/run_id; self.logs.mkdir(parents=True,exist_ok=True)
        self.receipts=BASE/'I21-RESULTS/receipts'/run_id; self.receipts.mkdir(parents=True,exist_ok=True)
        self.processes=[]; self.accounts=accounts; self.ports=ports; self.chain_id=chain_id; self.nonces={}; self.transactions=[]
        self.nodes=[Account.create() for _ in range(2)]
        alloc={a.address[2:]:{'balance':str(10**25)} for a in accounts+self.nodes}
        forks=['homesteadBlock','eip150Block','eip155Block','eip158Block','byzantiumBlock','constantinopleBlock','petersburgBlock','istanbulBlock','muirGlacierBlock','berlinBlock','londonBlock']
        config={k:0 for k in forks}; config.update(chainId=chain_id,clique={'period':1,'epoch':30000})
        genesis={'config':config,'nonce':'0x0','timestamp':hex(int(time.time())-10),'extraData':'0x'+'00'*32+''.join(sorted(a.address[2:].lower() for a in self.nodes))+'00'*65,'gasLimit':'0x5f5e100','difficulty':'0x1','mixHash':'0x'+'00'*32,'coinbase':'0x'+'00'*20,'alloc':alloc,'baseFeePerGas':'0x1'}
        save(self.dir/'genesis.json',genesis)
        save(self.dir/'TEST_ONLY_node_keys.json',[{'address':a.address,'key':a.key.hex()} for a in self.nodes])
        self.rpcs=[RPC('http://127.0.0.1:'+str(p),self.logs/f'node{i+1}_rpc.jsonl') for i,p in enumerate(ports)]
    def start(self):
        exe=executable('geth'); cmds=[]
        for i,a in enumerate(self.nodes):
            d=self.dir/f'node{i+1}'; d.mkdir(); (d/'password.txt').write_text('I21-test-only',encoding='utf-8'); (d/'signer.key').write_text(a.key.hex(),encoding='ascii')
            common=[exe,'--datadir',str(d)]
            with (self.logs/f'node{i+1}_init.log').open('wb') as out:
                subprocess.run(common+['init',str(self.dir/'genesis.json')],stdout=out,stderr=out,check=True,creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                subprocess.run(common+['account','import','--password',str(d/'password.txt'),str(d/'signer.key')],stdout=out,stderr=out,check=True,creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            cmd=common+['--networkid',str(self.chain_id),'--syncmode','full','--gcmode','archive','--state.scheme','hash','--port',str(self.ports[i]+10000),'--nodiscover','--nat','none','--netrestrict','127.0.0.0/8','--http','--http.addr','127.0.0.1','--http.port',str(self.ports[i]),'--http.api','eth,net,web3,admin,clique','--http.vhosts','localhost,127.0.0.1','--ipcdisable','--authrpc.port',str(self.ports[i]+20000),'--mine','--miner.etherbase',a.address,'--miner.gasprice','1','--unlock',a.address,'--password',str(d/'password.txt'),'--allow-insecure-unlock','--verbosity','3']
            f=(self.logs/f'node{i+1}.log').open('wb'); p=subprocess.Popen(cmd,stdout=f,stderr=f,creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)); self.processes.append((p,f)); cmds.append({'pid':p.pid,'command':cmd})
        save(self.dir/'commands.json',cmds)
        for rpc in self.rpcs:
            deadline=time.monotonic()+40
            while True:
                try: rpc.call('web3_clientVersion'); break
                except Exception:
                    if time.monotonic()>deadline: raise
                    time.sleep(.2)
        infos=[r.call('admin_nodeInfo') for r in self.rpcs]
        for i in range(2):
            enode=infos[1-i]['enode']; enode=enode[:enode.index('@')+1]+'127.0.0.1:'+str(self.ports[1-i]+10000)
            self.rpcs[i].call('admin_addPeer',[enode])
        deadline=time.monotonic()+30
        while any(int(r.call('net_peerCount'),16)<1 for r in self.rpcs):
            if time.monotonic()>deadline: raise RuntimeError('PEER_CONNECTION_TIMEOUT')
            time.sleep(.2)
        self.genesis=self.rpcs[0].call('eth_getBlockByNumber',['0x0',False])['hash']
        assert self.rpcs[1].call('eth_getBlockByNumber',['0x0',False])['hash']==self.genesis
        save(self.receipts/'network_start.json',{'utc':now(),'physical_machines':1,'nodes':2,'infos':infos,'peers':[r.call('admin_peers') for r in self.rpcs],'signers':[r.call('clique_getSigners',['latest']) for r in self.rpcs],'genesis_hash':self.genesis})
    def submit(self,account,data,label,to=None):
        nonce=self.nonces.get(account.address,0); self.nonces[account.address]=nonce+1
        tx={'chainId':self.chain_id,'nonce':nonce,'gas':8000000 if to is None else 500000,'gasPrice':2000000000,'value':0,'data':data}
        if to: tx['to']=Web3.to_checksum_address(to)
        signed=Account.sign_transaction(tx,account.key); raw='0x'+signed.raw_transaction.hex()
        started=time.perf_counter_ns(); h=self.rpcs[0].call('eth_sendRawTransaction',[raw])
        item={'label':label,'transaction_hash':h,'signed_raw_transaction':raw,'from':account.address,'tx_input':clean(tx),'submitted_utc':now(),'start_ns':started}
        self.transactions.append(item); return item
    def settle(self,items):
        records=[]
        for item in items:
            deadline=time.monotonic()+45
            while True:
                rc=self.rpcs[0].call('eth_getTransactionReceipt',[item['transaction_hash']])
                if rc: break
                if time.monotonic()>deadline: raise RuntimeError('TX_TIMEOUT')
                time.sleep(.08)
            elapsed=(time.perf_counter_ns()-item['start_ns'])/1e6
            block=self.rpcs[0].call('eth_getBlockByHash',[rc['blockHash'],False])
            tx=self.rpcs[0].call('eth_getTransactionByHash',[item['transaction_hash']])
            rec={k:v for k,v in item.items() if k!='start_ns'}; rec.update(receipt=rc,block=block,transaction=tx,confirmation_observed_ms=elapsed)
            save(self.receipts/(item['transaction_hash']+'.json'),rec); records.append(rec)
        self.sync(); return records
    def sync(self):
        a=self.rpcs[0].call('eth_getBlockByNumber',['latest',False]); deadline=time.monotonic()+30; started=time.perf_counter_ns()
        while True:
            b=self.rpcs[1].call('eth_getBlockByNumber',[a['number'],False])
            if b and b['hash']==a['hash']: break
            if time.monotonic()>deadline: raise RuntimeError('SHARED_LEDGER_TIMEOUT')
            time.sleep(.05)
        append(self.receipts/'synchronization.jsonl',{'utc':now(),'block_number':a['number'],'node1_hash':a['hash'],'node2_hash':b['hash'],'wait_ms':(time.perf_counter_ns()-started)/1e6})
        return a
    def stop(self):
        for p,f in self.processes:
            if p.poll() is None: p.terminate()
            try: p.wait(timeout=10)
            except subprocess.TimeoutExpired: p.kill(); p.wait()
            f.close()
    def deploy(self):
        raw=subprocess.check_output([executable('solc'),'--combined-json','abi,bin,bin-runtime','--optimize','--evm-version','paris',str(BASE/'tools/Registry.sol')],stderr=subprocess.STDOUT)
        compiled=json.loads(raw); c=next(iter(compiled['contracts'].values())); save(self.receipts/'compiled_contract.json',compiled)
        self.abi=c['abi']; self.contract=Web3().eth.contract(abi=self.abi)
        rec=self.settle([self.submit(self.accounts[0],'0x'+c['bin'],'deploy')])[0]; assert rec['receipt']['status']=='0x1'
        self.address=rec['receipt']['contractAddress']
        code=[r.call('eth_getCode',[self.address,rec['receipt']['blockNumber']]) for r in self.rpcs]
        assert code[0]==code[1] and len(code[0])>2
        save(self.receipts/'deployment.json',{'address':self.address,'chain_id':self.chain_id,'genesis':self.genesis,'transaction_hash':rec['transaction_hash'],'runtime_code':code[0],'abi':self.abi,'compiler':'0.8.24','evm':'paris','source_sha256':digest((BASE/'tools/Registry.sol').read_bytes())})
    def send(self,account,method,args,label): return self.submit(account,self.contract.encode_abi(method,args=args),label,self.address)

def state_snapshot(rpc,config,credential,holder):
    contract=Web3().eth.contract(abi=config['abi']); codec=Web3().codec
    b=rpc.call('eth_getBlockByNumber',['latest',False]); tag=b['number']
    def call(fn,args,types):
        data=contract.encode_abi(fn,args=args)
        raw=rpc.call('eth_call',[{'to':config['address'],'data':data},tag])
        return clean(codec.decode(types,bytes.fromhex(raw[2:])))
    def identity(did):
        v=call('identities',[bytes.fromhex(digest(did.encode()))],['address','bytes32','bool','bool','uint64'])
        return dict(zip(['controller','key','active','issuer','version'],v))
    issuer=credential['issuer']; subject=credential['subject']
    v=call('credentials',[bytes.fromhex(digest(credential['id'].encode()))],['bytes32','bytes32','bytes32','bool'])
    return {'block':b,'node':rpc.url,'issuer':identity(issuer),'holder':identity(holder),'subject':identity(subject),'credential':dict(zip(['issuer','subject','digest','revoked'],v))}
