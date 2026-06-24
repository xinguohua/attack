"""Step 1 of contorter PROBLEM_JUSTIFICATION §2.1.

For each of the 15 attack processes saved by contorter NodLink/Cadets, compute the
diff between original and adversarial file-path sets: what was kept, what was added.

Output: diffs/pair_<i>_<process_name>.json   (15 files)
        diffs/_summary.json                  (aggregate stats)
"""
import json, os
from pathlib import Path

DEP = Path('/Users/xinguohua/mimicattack/baselines/contorter/NodLink/Cadets/dependancies')
OUT = Path('/Users/xinguohua/mimicattack/baselines/pipelines/contorter/diffs')
OUT.mkdir(parents=True, exist_ok=True)

def parse(path):
    procs = []
    cur = None
    with open(path) as f:
        for ln in f:
            ln = ln.rstrip('\n')
            if not ln: continue
            if '$$$' in ln:
                if cur: procs.append(cur)
                parts = ln.split('$$$')
                cur = {
                    'name': parts[0],
                    'uuid': parts[1] if len(parts) > 1 else '',
                    'malicious': parts[2] if len(parts) > 2 else '',
                    'paths': [],
                }
            else:
                if cur is not None:
                    cur['paths'].append(ln)
        if cur: procs.append(cur)
    return procs

orig = parse(DEP / 'A_Study_Stage-event-anomaly.txt')
adv  = parse(DEP / 'final-augmented-malicious-processes.txt')
assert len(orig) == len(adv), f'orig {len(orig)} != adv {len(adv)}'

summary = {'n_pairs': len(orig), 'pairs': []}
for i, (o, a) in enumerate(zip(orig, adv)):
    assert o['uuid'] == a['uuid'], f'pair {i} uuid mismatch'
    o_set = set(o['paths'])
    a_set = set(a['paths'])
    kept = o_set & a_set
    added = a_set - o_set
    removed = o_set - a_set
    pair = {
        'index': i,
        'process_name': o['name'],
        'uuid': o['uuid'],
        'orig_count': len(o['paths']),
        'adv_count': len(a['paths']),
        'kept': sorted(kept),
        'added_by_contorter': sorted(added),
        'removed_by_contorter': sorted(removed),
        'count_inflation': len(a['paths']) - len(o['paths']),
        'count_inflation_factor': len(a['paths']) / max(len(o['paths']), 1),
    }
    out_path = OUT / f'pair_{i:02d}_{o["name"].replace("/", "_")}.json'
    out_path.write_text(json.dumps(pair, indent=2))
    summary['pairs'].append({k: pair[k] for k in ['index', 'process_name', 'uuid',
                                                   'orig_count', 'adv_count',
                                                   'count_inflation', 'count_inflation_factor']})
    summary['pairs'][-1]['n_added'] = len(added)
    summary['pairs'][-1]['n_removed'] = len(removed)

# Aggregate
n_added_all = [p['n_added'] for p in summary['pairs']]
n_removed_all = [p['n_removed'] for p in summary['pairs']]
summary['aggregate'] = {
    'n_pairs': len(orig),
    'orig_count_min':   min(p['orig_count'] for p in summary['pairs']),
    'orig_count_max':   max(p['orig_count'] for p in summary['pairs']),
    'orig_count_mean':  sum(p['orig_count'] for p in summary['pairs']) / len(orig),
    'adv_count_min':    min(p['adv_count'] for p in summary['pairs']),
    'adv_count_max':    max(p['adv_count'] for p in summary['pairs']),
    'adv_count_mean':   sum(p['adv_count'] for p in summary['pairs']) / len(adv),
    'pairs_with_zero_removals': sum(1 for x in n_removed_all if x == 0),
    'total_files_added':   sum(n_added_all),
    'total_files_removed': sum(n_removed_all),
}
(OUT / '_summary.json').write_text(json.dumps(summary, indent=2))

print(f'wrote {len(orig)} pair JSONs + _summary.json -> {OUT}')
print(f'\n=== AGGREGATE ===')
for k, v in summary['aggregate'].items():
    print(f'  {k}: {v}')
