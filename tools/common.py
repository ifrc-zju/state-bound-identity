import sys, json, hashlib, base64, re, time
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone

def now(): return datetime.now(timezone.utc).isoformat()
def digest(b): return hashlib.sha256(b).hexdigest()
def pairs(items):
    d={}
    for k,v in items:
        if k in d: raise ValueError('DUPLICATE_JSON_KEY')
        d[k]=v
    return d
def parse(raw):
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x: (_ for _ in ()).throw(ValueError('INVALID_JSON_NUMBER')))
def canonical(obj):
    def check(x):
        if isinstance(x,dict):
            for k,v in x.items():
                if not isinstance(k,str) or not k.isascii(): raise ValueError('ASCII_ONLY')
                check(v)
        elif isinstance(x,list):
            for v in x: check(v)
        elif isinstance(x,str):
            if not x.isascii(): raise ValueError('ASCII_ONLY')
        elif x is None or type(x) in (bool,int): pass
        else: raise ValueError('INTEGER_ONLY')
    check(obj)
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')
def unb64(s,n):
    if not isinstance(s,str) or not re.fullmatch('[A-Za-z0-9_-]+',s): raise ValueError('INVALID_ENCODING')
    b=base64.urlsafe_b64decode(s+'='*(-len(s)%4))
    if len(b)!=n or b64(b)!=s: raise ValueError('INVALID_ENCODING')
    return b
def sign(key,body,domain): return b64(key.sign(domain+canonical(body)))
def verify(key,sig,body,domain): Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(unb64(sig,64),domain+canonical(body))
def public(key): return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
def save(path,obj):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8',newline='\n') as f: json.dump(obj,f,ensure_ascii=False,indent=2,allow_nan=False)
def append(path,obj):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a',encoding='utf-8',newline='\n') as f: f.write(json.dumps(obj,ensure_ascii=False,allow_nan=False)+'\n')
VC_DOMAIN=b'I21-VC-v1\x00'
VP_DOMAIN=b'I21-VP-v1\x00'
CH_DOMAIN=b'I21-CH-v1\x00'
