"""Step 0+1 of contorter PROBLEM_JUSTIFICATION §2.2:

Replay the target detector (NodLink VAE @ cutoff=130) on the saved (orig, adv)
NodLink/Cadets samples. Confirms the contorter README §2.2.5 numbers.

Reads the cell15 (baseline VAE on orig) and cell26 (VAE on adv) outputs from the
fresh nbconvert run we already executed, since the VAE forward pass is identical.

Output: results/contorter_nodlink_eval.json
"""
import json, re
from pathlib import Path

NB_PATH = Path('/Users/xinguohua/mimicattack/baselines/contorter/NodLink/Cadets/NodLink_Cadets_Contorter.run.ipynb')
OUT = Path('/Users/xinguohua/mimicattack/baselines/pipelines/contorter/results')
OUT.mkdir(parents=True, exist_ok=True)

nb = json.load(open(NB_PATH))

def cell_text(cell_idx):
    c = nb['cells'][cell_idx]
    if c['cell_type'] != 'code': return ''
    out_text = ''
    for o in c.get('outputs', []):
        if 'text' in o:
            out_text += ''.join(o['text']) if isinstance(o['text'], list) else o['text']
        if 'data' in o:
            for k, v in o['data'].items():
                if 'text' in k:
                    out_text += ''.join(v) if isinstance(v, list) else v
    return out_text

def extract_metrics(text):
    """Pull TP/FP/FN/TN/Precision/Recall/F1 from cell stdout."""
    m = {}
    for line in text.splitlines():
        for tag in ('TP', 'FP', 'FN', 'TN'):
            mt = re.search(rf'\b{tag}\s*[:=]?\s*(\d+)\b', line)
            if mt and tag not in m:
                m[tag] = int(mt.group(1))
        for label, key in [('Precision', 'precision'), ('Recall', 'recall'),
                           ('F1', 'f1'), ('TPR', 'tpr'), ('TNR', 'tnr'),
                           ('FPR', 'fpr')]:
            mt = re.search(rf'{label}.*?[:=]?\s*([0-9]*\.?[0-9]+)', line)
            if mt and key not in m:
                m[key] = float(mt.group(1))
    return m

baseline = extract_metrics(cell_text(15))
after = extract_metrics(cell_text(26))

result = {
    'detector': 'NodLink VAE',
    'cutoff': 130,
    'orig_processes': 15,
    'adv_processes': 15,
    'phase_baseline_on_orig': baseline,
    'phase_after_on_adv':     after,
    'recall_drop': baseline.get('recall', 0) - after.get('recall', 0),
    'recall_drop_pct': (baseline.get('recall', 0) - after.get('recall', 0)) * 100,
    'evidence_source': str(NB_PATH),
}

(OUT / 'contorter_nodlink_eval.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
