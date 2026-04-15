"""
BlockCert — Scoring Evaluation (Layer 2)
Weighted multi-factor scoring vs binary threshold baseline.
Run: python evaluation/evaluate_scoring.py --data dataset/output/structured_dataset.csv
"""
import csv, json, argparse
from sklearn.metrics import classification_report, confusion_matrix

W1,W2,W3=0.40,0.40,0.20; THRESHOLD=0.70

def binary(gpa,n): return int(float(gpa)>=3.0 and int(n)>=3)
def weighted(gpa,n,conf=0.85): return int(W1*(float(gpa)/4.0)+W2*(int(n)/5.0)+W3*float(conf)>=THRESHOLD)

def run(csv_path):
    records=[]; 
    with open(csv_path) as f:
        for r in csv.DictReader(f):
            courses = r['courses'].split('|') if r['courses'] else []
            records.append({'gpa':float(r['gpa']),'n':len(courses),'true':int(r['eligible'].lower()=='true')})

    bp=[binary(r['gpa'],r['n'])    for r in records]
    wp=[weighted(r['gpa'],r['n'])  for r in records]
    tl=[r['true']                  for r in records]

    def m(preds):
        rep=classification_report(tl,preds,output_dict=True,zero_division=0)
        cm=confusion_matrix(tl,preds); tn,fp,fn,tp=cm.ravel() if cm.size==4 else (0,0,0,0)
        return {'acc':rep['accuracy'],'f1':rep.get('1',{}).get('f1-score',0),
                'fpr':fp/(fp+tn) if fp+tn>0 else 0,'fnr':fn/(fn+tp) if fn+tp>0 else 0}

    bm=m(bp); wm=m(wp)
    print('\n'+'='*60)
    print('LAYER 2 — Weighted Scoring vs Binary Baseline')
    print('='*60)
    print(f"{'Metric':<20} {'Binary':>12} {'Weighted':>12} {'Δ':>8}")
    print('-'*55)
    for k,l in [('acc','Accuracy'),('f1','F1-Score'),('fpr','False Pos Rate'),('fnr','False Neg Rate')]:
        d=wm[k]-bm[k]; s='+' if d>=0 else ''
        print(f"  {l:<18} {bm[k]:>12.4f} {wm[k]:>12.4f} {s}{d:>7.4f}")
    print('='*60)
    with open('evaluation/scoring_results.json','w') as f:
        json.dump({'binary':bm,'weighted':wm}, f, indent=2)
    print('Saved to evaluation/scoring_results.json')

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--data',default='dataset/output/structured_dataset.csv')
    run(p.parse_args().data)
