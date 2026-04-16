"""
BlockCert — NLP Evaluation (Layer 1)
BERT vs regex baseline on precision, recall, F1 per course class.
Run: python evaluation/evaluate_nlp.py --data dataset/output/sentence_labels.json --model nlp/model
"""
import json, re, argparse
from sklearn.metrics import classification_report

LABEL2ID = {'NONE':0,'NSA3010':1,'NSA4020':2,'NSA4030':3,'NSA4040':4,'NSA4050':5}

def regex_predict(s):
    m = re.search(r'\b(NSA\s?\d{4})\b', s, re.I)
    return m.group(1).replace(' ','').upper() if m else 'NONE'

def run(data_path, model_dir):
    with open(data_path) as f: data = json.load(f)
    n     = int(len(data)*0.20)
    texts = [d['text']  for d in data[-n:]]
    labs  = [d['label'] for d in data[-n:]]

    r_preds = [regex_predict(t) for t in texts]

    from nlp.bert_classifier import BERTClassifier
    clf     = BERTClassifier(); clf.load(model_dir)
    b_preds = [clf.predict(t)['prediction'] for t in texts]

    r_rep = classification_report(labs, r_preds, labels=list(LABEL2ID.keys()), output_dict=True, zero_division=0)
    b_rep = classification_report(labs, b_preds, labels=list(LABEL2ID.keys()), output_dict=True, zero_division=0)

    print('\n' + '='*65)
    print('LAYER 1 — BERT vs Regex Baseline')
    print('='*65)
    print(f"{'Metric':<22} {'Regex':>12} {'BERT':>12} {'Δ':>8}")
    print('-'*55)
    for key, label in [('accuracy','Accuracy'),('macro avg','Macro F1')]:
        rv = r_rep[key] if key=='accuracy' else r_rep[key]['f1-score']
        bv = b_rep[key] if key=='accuracy' else b_rep[key]['f1-score']
        d  = bv-rv; s = '+' if d>=0 else ''
        print(f"  {label:<20} {rv:>12.4f} {bv:>12.4f} {s}{d:>7.4f}")
    print('='*65)
    with open('evaluation/nlp_results.json','w') as f:
        json.dump({'regex':r_rep,'bert':b_rep}, f, indent=2)
    print('Saved to evaluation/nlp_results.json')

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--data',  default='dataset/output/sentence_labels.json')
    p.add_argument('--model', default='nlp/model')
    args = p.parse_args()
    run(args.data, args.model)
