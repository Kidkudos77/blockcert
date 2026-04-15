# BlockCert
### FAMU FCSS Blockchain Micro-Credentialing System

[![CI/CD](https://github.com/YOUR_USERNAME/blockcert/actions/workflows/blockcert.yml/badge.svg)](https://github.com/YOUR_USERNAME/blockcert/actions)
[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://python.org)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green)](https://nodejs.org)
[![Hyperledger Fabric](https://img.shields.io/badge/Hyperledger-Fabric%202.5-orange)](https://hyperledger.org)
[![Post-Quantum](https://img.shields.io/badge/PQ%20Crypto-CRYSTALS--Dilithium3-purple)](https://pq-crystals.org)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

---

> **Thesis Statement:** A three-layer framework in which a BERT-based NLP classifier extracts
> structured eligibility features from unstructured student transcripts, a weighted multi-factor
> scoring algorithm evaluates those features against FCSS program requirements, and a Hyperledger
> Fabric smart contract conditionally issues tamper-proof micro-credentials based on that score —
> eliminating the manual review process that current systems require. Deployed on the National
> Research Platform using Kubernetes with GitHub Actions for CI/CD. Post-quantum signatures using
> CRYSTALS-Dilithium3 make issued credentials resilient against future quantum attacks — a gap
> unaddressed in the reviewed micro-credentialing literature.

---

## Table of Contents

- [Overview](#overview)
- [Thesis Contributions](#thesis-contributions)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Evaluation](#evaluation)
- [Kaggle Dataset](#kaggle-dataset)
- [NRP Deployment](#nrp-deployment)
- [Supervisor Customization](#supervisor-customization)
- [Research Gaps Addressed](#research-gaps-addressed)
- [Author](#author)

---

## Overview

BlockCert is a graduate thesis project developed at **Florida A&M University** for the
**Forensic Computer Science and Security (FCSS)** certificate program. The system automates
the micro-credential issuance process — a process that currently requires manual administrative
review — by combining natural language processing, a weighted eligibility scoring algorithm,
and a permissioned blockchain network.

The system processes raw student transcript text, automatically determines eligibility using
a trained BERT model and a multi-factor scoring function, and conditionally issues a
tamper-proof micro-credential onto a Hyperledger Fabric ledger. All issued credentials are
additionally signed using CRYSTALS-Dilithium3 post-quantum cryptography, making them
cryptographically valid against future quantum computing threats.

---

## Thesis Contributions

| # | Layer | Contribution Type | Description | Evaluation Metric |
|---|-------|------------------|-------------|-------------------|
| 1 | Layer 1 | **Algorithm** | Fine-tuned BERT classifier for FCSS course identification from transcript text | Precision, Recall, F1 vs. regex baseline |
| 2 | Layer 2 | **Algorithm** | Weighted multi-factor eligibility scoring function encoded on-chain | FPR, FNR vs. binary threshold baseline |
| 3 | Layer 3 | **System** | Hyperledger Fabric + IPFS + REST API + Kubernetes deployment on NRP | Latency (ms), Throughput (TPS) |
| 4 | PQ Layer | **Novel Gap** | CRYSTALS-Dilithium3 post-quantum signatures on credential hashes | No reviewed micro-credentialing paper addresses this |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  LAYER 1 — NLP ALGORITHM                                     │
│                                                              │
│  Input : Raw unstructured transcript text                    │
│  Model : Fine-tuned BERT (bert-base-uncased)                 │
│  Output: FCSS course codes + BERT confidence score           │
│  File  : nlp/bert_classifier.py                              │
│  Metric: Precision / Recall / F1 vs. regex baseline          │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  LAYER 2 — SCORING ALGORITHM                                 │
│                                                              │
│  Formula: 0.40 × (GPA/4.0)                                   │
│         + 0.40 × (courses_completed/5)                       │
│         + 0.20 × (bert_confidence)                           │
│  Threshold: Score ≥ 0.70 → ELIGIBLE                          │
│  File  : chaincode/blockcert.js (_computeScore)              │
│  Metric: False Positive Rate / False Negative Rate           │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  LAYER 3 — SYSTEM                                            │
│                                                              │
│  Blockchain : Hyperledger Fabric 2.5 (permissioned)          │
│  Storage    : IPFS off-chain + SHA-256 hash on-chain         │
│  Identity   : X.509 certificates with role attributes        │
│  API        : REST + JSON-LD (schema.org) responses          │
│  Deploy     : NRP Kubernetes + GitHub Actions CI/CD          │
│  Metric     : Latency / Throughput                           │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│  POST-QUANTUM LAYER                                          │
│                                                              │
│  Algorithm : CRYSTALS-Dilithium3 (NIST FIPS 204 / ML-DSA)   │
│  Signs     : Credential hash at issuance time                │
│  Purpose   : Quantum-resilient verification                  │
│  File      : quantum/pq_signer.py                            │
└──────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
blockcert/
│
├── .github/
│   └── workflows/
│       └── blockcert.yml          # GitHub Actions CI/CD pipeline
│
├── chaincode/
│   └── blockcert.js               # Hyperledger Fabric smart contract
│                                  # Contains Layer 2 weighted scoring algorithm
│                                  # Role-based access control, JSON-LD output
│                                  # Audit log, program analytics
│
├── nlp/
│   ├── bert_classifier.py         # BERT model — training and inference (Layer 1)
│   └── transcript_parser.py       # Combines BERT + regex GPA extraction
│
├── quantum/
│   └── pq_signer.py               # CRYSTALS-Dilithium3 post-quantum signatures
│
├── wallet/
│   └── wallet_setup.js            # X.509 identity enrollment and role assignment
│
├── storage/
│   └── ipfs_storage.js            # IPFS off-chain document storage
│
├── api/
│   └── server.js                  # REST API with JSON-LD credential endpoints
│
├── dataset/
│   └── data_loader.py             # Synthetic dataset generator + Kaggle drop-in
│
├── evaluation/
│   ├── evaluate_nlp.py            # Layer 1: BERT vs. regex baseline
│   ├── evaluate_scoring.py        # Layer 2: weighted vs. binary threshold
│   └── evaluate_system.py         # Layer 3: latency and throughput
│
├── integration/
│   └── pipeline.py                # End-to-end pipeline (all layers + PQ)
│
├── k8s/
│   └── nrp-deployment.yaml        # Kubernetes manifests for NRP deployment
│
├── config/
│   └── connection.json            # Hyperledger Fabric connection profile
│
└── requirements.txt               # Python dependencies
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Linux (Ubuntu 22.04+) | — | Operating system |
| Python | 3.10+ | NLP, dataset, evaluation |
| Node.js | 18+ | Chaincode, API, wallet |
| Docker | 24+ | Hyperledger Fabric containers |
| Go | 1.21+ | Fabric peer tools |
| Git | any | Version control |

---

## Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/blockcert.git
cd blockcert
```

### Step 2 — Install Python dependencies

```bash
pip3 install -r requirements.txt
```

### Step 3 — Install Node.js dependencies

```bash
cd chaincode  && npm install fabric-contract-api fabric-shim
cd ../api     && npm install express body-parser fabric-network fabric-ca-client
cd ../wallet  && npm install fabric-network fabric-ca-client
cd ../storage && npm install ipfs-http-client
cd ..
```

### Step 4 — Download Hyperledger Fabric

```bash
cd ~
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7
```

---

## Usage

### 1. Generate the Dataset

```bash
# Synthetic (default — no external data needed)
python3 dataset/data_loader.py --mode synthetic --n 200

# Kaggle dataset (when available — see Kaggle Dataset section)
python3 dataset/data_loader.py --mode kaggle --file dataset/kaggle/your_file.csv
```

### 2. Train the BERT Model

```bash
python3 nlp/bert_classifier.py \
  --train \
  --data dataset/output/sentence_labels.json \
  --model nlp/model
```

### 3. Start the Fabric Network

```bash
cd ~/fabric-samples/test-network
./network.sh up createChannel -c blockcertchannel -ca
./network.sh deployCC -ccn blockcert -ccp ~/blockcert/chaincode/ -ccl javascript
```

### 4. Copy Connection Profile and Enroll Identities

```bash
mkdir -p ~/blockcert/config
cp ~/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/connection-org1.json \
   ~/blockcert/config/connection.json

cd ~/blockcert
node -e "
const w = require('./wallet/wallet_setup');
(async()=>{
  await w.enrollAdmin();
  await w.registerUser({ userID:'famu-institution', role:'institution' });
  await w.registerUser({ userID:'public-verifier',  role:'verifier'     });
  await w.registerUser({ userID:'FAMU10001',         role:'student'      });
})();
"
```

### 5. Start the API Server

```bash
node api/server.js
# Running on http://localhost:3000
```

### 6. Run the Full Pipeline

```bash
# Single transcript
python3 integration/pipeline.py \
  --transcript path/to/transcript.txt \
  --student FAMU10001

# Batch — all students
python3 integration/pipeline.py \
  --batch dataset/output/transcripts.json \
  --output results.json
```

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET`  | `/health` | None | Health check |
| `POST` | `/issue` | institution | Issue credential from NLP payload |
| `GET`  | `/verify/:hash` | verifier | Verify credential — returns JSON-LD |
| `GET`  | `/student/:id` | student | All credentials for a student |
| `POST` | `/revoke` | institution | Revoke a credential |
| `GET`  | `/analytics?as=...` | institution | Program-level analytics |

### Example — Verify a Credential

```bash
curl http://localhost:3000/verify/abc123def456...
```

**Response (JSON-LD):**
```json
{
  "@context": "https://schema.org/",
  "@type": "EducationalOccupationalCredential",
  "isValid": true,
  "credentialStatus": "ACTIVE",
  "credentialCategory": "micro-credential",
  "recognizedBy": "famu.edu",
  "educationalProgram": "FAMU-FCSS",
  "competencyRequired": ["NSA3010", "NSA4020", "NSA4030"],
  "eligibilityScore": 0.84,
  "postQuantumSigned": true,
  "pqAlgorithm": "CRYSTALS-Dilithium3"
}
```

---

## Evaluation

Run all three evaluations after the system is operational. These produce your Chapter 4 thesis results.

```bash
# Layer 1 — BERT vs. regex baseline (Precision / Recall / F1)
python3 evaluation/evaluate_nlp.py \
  --data dataset/output/sentence_labels.json \
  --model nlp/model

# Layer 2 — Weighted scoring vs. binary threshold (FPR / FNR)
python3 evaluation/evaluate_scoring.py \
  --data dataset/output/structured_dataset.csv

# Layer 3 — System performance (Latency / Throughput)
python3 evaluation/evaluate_system.py \
  --api http://localhost:3000 \
  --n 50
```

Results are saved to:
- `evaluation/nlp_results.json`
- `evaluation/scoring_results.json`
- `evaluation/system_results.json`

---

## Kaggle Dataset

When you find a relevant dataset on Kaggle, integrating it requires three steps:

1. Download the CSV and place it in `dataset/kaggle/`
2. Open `dataset/data_loader.py` and fill in `KAGGLE_COLUMN_MAP` with your CSV's actual column names:

```python
KAGGLE_COLUMN_MAP = {
    'student_id': 'StudentID',    # your column name here
    'name':       'StudentName',  # your column name here
    'gpa':        'GPA',          # your column name here
    'courses':    'Courses',      # your column name here
    ...
}
```

3. Run:

```bash
python3 dataset/data_loader.py --mode kaggle --file dataset/kaggle/your_file.csv
```

All downstream components (BERT retraining, pipeline, evaluations) run without any other changes.

---

## NRP Deployment

Access to the National Research Platform is obtained through your faculty advisor.

Once access is approved:

```bash
# Create namespace
kubectl create namespace blockcert

# Deploy all components
kubectl apply -f k8s/nrp-deployment.yaml -n blockcert

# Check status
kubectl get pods -n blockcert
kubectl get services -n blockcert
```

To enable automatic deployment via GitHub Actions, add your NRP kubeconfig as a repository secret:

```
GitHub → Settings → Secrets and Variables → Actions → New repository secret
Name:  NRP_KUBECONFIG
Value: (contents of your kubeconfig file)
```

The BERT training job in `k8s/nrp-deployment.yaml` runs on NRP GPU nodes, reducing training time from 30 minutes (CPU) to under 5 minutes.

---

## Supervisor Customization

All key parameters are centralized in two files:
`chaincode/blockcert.js` and `nlp/transcript_parser.py`

| Parameter | Variable Name | Default |
|-----------|--------------|---------|
| Minimum GPA | `MIN_GPA` | `3.0` |
| Minimum courses required | `MIN_COURSES` | `3` |
| Scoring weight — GPA | `W1` | `0.40` |
| Scoring weight — Courses | `W2` | `0.40` |
| Scoring weight — BERT confidence | `W3` | `0.20` |
| Eligibility threshold | `THRESHOLD` | `0.70` |
| BERT confidence gate | `MIN_CONF` in `pipeline.py` | `0.60` |
| Dataset size | `--n` flag | `200` |
| BERT training epochs | `EPOCHS` in `bert_classifier.py` | `4` |

---

## Research Gaps Addressed

| Gap | Source Paper | BlockCert Solution |
|-----|-------------|--------------------|
| No automated transcript parsing | Blockchain Micro-Credential SLR | BERT classifier + pipeline |
| Lack of interoperability (41.7%) | Gap Analysis on Blockchain Frameworks | REST API + JSON-LD responses |
| Security concerns (41.7%) | Gap Analysis on Blockchain Frameworks | RBAC + IPFS off-chain + audit log |
| Blockchain and analytics treated separately | Empowering Home Tutors paper | Unified NLP-to-chain pipeline |
| No domain-specific systems | Blockchain Credentialing for Teachers | FCSS-specific implementation at FAMU |
| No post-quantum cryptography in micro-credentialing | Blockchain Forensics SLR (gap) | CRYSTALS-Dilithium3 signature layer |

---

## Author

**Javonte Carter**
Graduate Student, Computer Science
Florida A&M University

Thesis: *BlockCert: A Blockchain-Based Micro-Credentialing Framework with NLP-Driven Eligibility Evaluation and Post-Quantum Cryptographic Security for Cybersecurity Certificate Programs*

---

## Acknowledgments

- Hyperledger Foundation — Fabric framework
- Hugging Face — BERT pretrained models
- NIST Post-Quantum Cryptography Standardization Project — CRYSTALS-Dilithium3
- National Research Platform (NRP) / Nautilus HyperCluster — compute infrastructure
- Florida A&M University — FCSS program

---

*For setup instructions, see the [BlockCert Build Guide](BlockCert_Build_Guide.docx).*
