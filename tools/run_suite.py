import subprocess,sys,json
from pathlib import Path
from datetime import datetime,timezone
B=Path(__file__).resolve().parents[1]
sys.stdout.reconfigure(encoding='utf-8')
stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S');log=B/'work_records'/('suite_'+stamp+'.jsonl')
def launch(mode,n,identities,chain_id):
    before=set((B/'I21-RESULTS/results').iterdir())
    cmd=[sys.executable,str(B/'tools/run_experiment.py'),'--mode',mode,'--per-class',str(n),'--identities',str(identities),'--chain-id',str(chain_id)]
    code=subprocess.call(cmd)
    new=list(set((B/'I21-RESULTS/results').iterdir())-before)
    with log.open('a',encoding='utf-8') as f:f.write(json.dumps({'utc':datetime.now(timezone.utc).isoformat(),'command':cmd,'exit_code':code,'runs':[p.name for p in new]})+'\n')
    if code:sys.exit(code)
    if len(new)!=1:raise RuntimeError('RUN_DISCOVERY_ERROR')
    code=subprocess.call([sys.executable,str(B/'tools/independent_audit.py'),new[0].name])
    if code:sys.exit(code)
for i in range(3):launch('batch',30,100,2721101+i)
launch('regression',3,10,2721201)
