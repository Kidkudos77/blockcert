import json
import argparse
from sklearn.metrics import classification_report
from nlp.bert_classifier import BERTClassifier

def load_data(path):
    with open(path) as f:
        data = json.load(f)
    texts = [d["text"] for d in data]
    labels = [d["label"] for d in data]
    return texts, labels

def run(data_path, model_path):
    texts, true_labels = load_data(data_path)

    clf = BERTClassifier()
    clf.load(model_path)

    preds = [clf.predict(t)["prediction"] for t in texts]

    report = classification_report(true_labels, preds, output_dict=True, zero_division=0)

    acc = report.get("accuracy", 0.0)
    macro_f1 = report.get("macro avg", {}).get("f1-score", 0.0)

    print("\n" + "=" * 65)
    print("LAYER 1 — BERT Evaluation")
    print("=" * 65)
    print(f"Accuracy : {acc:.4f}")
    print(f"Macro F1 : {macro_f1:.4f}")
    print("=" * 65)

    with open("evaluation/nlp_results.json", "w") as f:
        json.dump(report, f, indent=2)

    print("Saved to evaluation/nlp_results.json")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--model", required=True)
    args = parser.parse_args()

    run(args.data, args.model)
