import subprocess,sys
from pathlib import Path
B=Path(__file__).resolve().parents[1]
for i in range(3):
    before=set((B/'I21-RESULTS/results').iterdir())
    subprocess.run([sys.executable,str(B/'tools/run_experiment.py'),'--mode','audience_isolation','--per-class','30','--identities','100','--chain-id',str(2721401+i)],check=True)
    d=(set((B/'I21-RESULTS/results').iterdir())-before).pop()
    subprocess.run([sys.executable,str(B/'tools/independent_audit.py'),d.name],check=True)
