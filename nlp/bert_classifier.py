"""
BlockCert — BERT Transcript Classifier  (Layer 1)
====================================================
Fine-tunes BERT to classify individual transcript sentences
into FCSS course categories.

Thesis contribution:
  Replaces regex/keyword matching with a learned classifier that handles
  natural language variation — abbreviations, paraphrasing, formatting
  differences — that break rule-based parsers.

Evaluation baseline: regex parser in transcript_parser.py
Metrics:            Precision, Recall, F1-score per class
Run evaluation:     python evaluation/evaluate_nlp.py

Usage:
  python nlp/bert_classifier.py --train --data dataset/output/sentence_labels.json
  python nlp/bert_classifier.py --test "NSA4030 Digital Forensics Grade A" --model nlp/model
"""

import json, os, argparse
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import (
     BertTokenizer,
     BertForSequenceClassification,
     get_linear_schedule_with_warmup
)
from torch.optim import AdamW 
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# ── Label map ─────────────────────────────────────────────────────────────────
LABEL2ID  = {'NONE':0,'CIS4385C':1,'CIS4360':2,'CIS4361':3,'CNT4406':4,'COP3710':5}
ID2LABEL  = {v:k for k,v in LABEL2ID.items()}
NUM_LABELS = len(LABEL2ID)

# ── Hyperparameters ───────────────────────────────────────────────────────────
MAX_LEN    = 64
BATCH_SIZE = 16
EPOCHS     = 4
LR         = 2e-5
MODEL_NAME = 'bert-base-uncased'


class TranscriptSentenceDataset(Dataset):
    def __init__(self, texts, labels, tokenizer):
        self.encodings = tokenizer(
            texts, truncation=True, padding='max_length',
            max_length=MAX_LEN, return_tensors='pt'
        )
        self.labels = torch.tensor([LABEL2ID[l] for l in labels])

    def __len__(self): return len(self.labels)

    def __getitem__(self, idx):
        return {
            'input_ids':      self.encodings['input_ids'][idx],
            'attention_mask': self.encodings['attention_mask'][idx],
            'labels':         self.labels[idx],
        }


class BERTClassifier:
    """
    Fine-tuned BERT classifier for FCSS transcript sentence classification.

    Input:  one sentence from a student transcript
    Output: predicted FCSS course code (or NONE) + confidence score

    This is the core of Layer 1's algorithmic contribution.
    The model learns semantic representations of course descriptions,
    making it robust to variations that break regex-based parsers.
    """

    def __init__(self, model_dir: str = None):
        self.device    = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.tokenizer = BertTokenizer.from_pretrained(MODEL_NAME)
        self.model     = None
        if model_dir and os.path.exists(model_dir):
            self.load(model_dir)

    # ── Training ──────────────────────────────────────────────────────────────
    def train(self, data_path: str, save_dir: str = 'nlp/model'):
        print(f'Loading training data from {data_path}...')
        with open(data_path) as f:
            data = json.load(f)

        texts  = [d['text']  for d in data]
        labels = [d['label'] for d in data]

        X_tr, X_val, y_tr, y_val = train_test_split(
            texts, labels, test_size=0.20, random_state=42, stratify=labels
        )

        train_dl = DataLoader(
            TranscriptSentenceDataset(X_tr,  y_tr,  self.tokenizer),
            batch_size=BATCH_SIZE, shuffle=True
        )
        val_dl = DataLoader(
            TranscriptSentenceDataset(X_val, y_val, self.tokenizer),
            batch_size=BATCH_SIZE
        )

        self.model = BertForSequenceClassification.from_pretrained(
            MODEL_NAME, num_labels=NUM_LABELS,
            id2label=ID2LABEL, label2id=LABEL2ID,
        ).to(self.device)

        optimizer = AdamW(self.model.parameters(), lr=LR)
        total     = len(train_dl) * EPOCHS
        scheduler = get_linear_schedule_with_warmup(
            optimizer, num_warmup_steps=int(0.1*total), num_training_steps=total
        )

        print(f'Training: {len(X_tr)} | Validation: {len(X_val)} | Device: {self.device}\n')

        for epoch in range(EPOCHS):
            self.model.train()
            loss_sum = 0
            for batch in train_dl:
                batch   = {k: v.to(self.device) for k, v in batch.items()}
                out     = self.model(**batch)
                loss    = out.loss
                loss_sum += loss.item()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step(); scheduler.step(); optimizer.zero_grad()

            val = self._eval(val_dl)
            print(f'Epoch {epoch+1}/{EPOCHS} | '
                  f'Loss: {loss_sum/len(train_dl):.4f} | '
                  f'Val Acc: {val["accuracy"]:.4f} | '
                  f'Val F1: {val["macro_f1"]:.4f}')

        print('\n=== Final Validation ===')
        self._eval(val_dl, verbose=True)
        os.makedirs(save_dir, exist_ok=True)
        self.model.save_pretrained(save_dir)
        self.tokenizer.save_pretrained(save_dir)
        print(f'Model saved to {save_dir}/')

    # ── Evaluation ────────────────────────────────────────────────────────────
    def _eval(self, dl, verbose=False):
        self.model.eval()
        preds, labs = [], []
        with torch.no_grad():
            for batch in dl:
                batch = {k: v.to(self.device) for k, v in batch.items()}
                out   = self.model(**batch)
                preds.extend(torch.argmax(out.logits, dim=1).cpu().numpy())
                labs.extend(batch['labels'].cpu().numpy())

        rep = classification_report(labs, preds,
            target_names=list(LABEL2ID.keys()), output_dict=True, zero_division=0)
        if verbose:
            print(classification_report(labs, preds,
                target_names=list(LABEL2ID.keys()), zero_division=0))
        return {'accuracy': rep['accuracy'], 'macro_f1': rep['macro avg']['f1-score'], 'report': rep}

    # ── Inference ─────────────────────────────────────────────────────────────
    def load(self, model_dir: str):
        self.tokenizer = BertTokenizer.from_pretrained(model_dir)
        self.model     = BertForSequenceClassification.from_pretrained(model_dir).to(self.device)
        self.model.eval()

    def predict(self, sentence: str) -> dict:
        if self.model is None:
            raise RuntimeError('Model not loaded. Call load() or train() first.')
        enc  = self.tokenizer(sentence, return_tensors='pt', truncation=True,
                              padding='max_length', max_length=MAX_LEN)
        enc  = {k: v.to(self.device) for k, v in enc.items()}
        with torch.no_grad():
            probs = torch.softmax(self.model(**enc).logits, dim=1)[0]
        pid = torch.argmax(probs).item()
        return {
            'sentence':   sentence,
            'prediction': ID2LABEL[pid],
            'confidence': round(probs[pid].item(), 4),
            'scores':     {ID2LABEL[i]: round(probs[i].item(), 4) for i in range(NUM_LABELS)},
        }

    def parse_transcript(self, transcript_text: str) -> dict:
        if self.model is None: raise RuntimeError('Model not loaded.')
        lines         = [l.strip() for l in transcript_text.split('\n') if len(l.strip()) > 4]
        found_courses = {}
        for line in lines:
            r = self.predict(line)
            if r['prediction'] != 'NONE' and r['confidence'] >= 0.60:
                code = r['prediction']
                if code not in found_courses or r['confidence'] > found_courses[code]['confidence']:
                    found_courses[code] = r
        avg_conf = (sum(v['confidence'] for v in found_courses.values()) /
                    max(len(found_courses), 1))
        return {
            'courses_detected': list(found_courses.keys()),
            'detections':       found_courses,
            'bert_confidence':  round(avg_conf, 4),
        }


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--train',  action='store_true')
    p.add_argument('--data',   default='dataset/output/sentence_labels.json')
    p.add_argument('--model',  default='nlp/model')
    p.add_argument('--test',   type=str, help='Single sentence to classify')
    args = p.parse_args()

    clf = BERTClassifier()
    if args.train:
        clf.train(args.data, save_dir=args.model)
    if args.test:
        clf.load(args.model)
        print(json.dumps(clf.predict(args.test), indent=2))
