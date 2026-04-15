"""
BlockCert — Dataset Loader
============================
Handles two data sources with the same interface:

  MODE 1 — Synthetic (default, no Kaggle needed)
    Generates 200 FCSS student records automatically.
    Run: python dataset/data_loader.py --mode synthetic

  MODE 2 — Kaggle drop-in
    When you find a Kaggle dataset, drop the CSV into dataset/kaggle/
    and set the column mappings below. Everything else stays the same.
    Run: python dataset/data_loader.py --mode kaggle --file dataset/kaggle/your_file.csv

The output is always the same four files regardless of source:
  dataset/output/structured_dataset.csv
  dataset/output/transcripts.json
  dataset/output/sentence_labels.json
  dataset/output/eligible_payloads.json
"""

import csv, json, os, random, argparse
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import List, Optional

random.seed(42)

# ── FCSS Program Catalog ──────────────────────────────────────────────────────
COURSES = {
    'NSA3010': 'Network Security Fundamentals',
    'NSA4020': 'Penetration Testing',
    'NSA4030': 'Digital Forensics',
    'NSA4040': 'Incident Response',
    'NSA4050': 'Cryptography',
}

# Natural language sentence variations per course.
# Used to build sentence-level BERT training labels.
# When a Kaggle dataset is loaded, real transcript sentences
# are added to this pool automatically.
COURSE_VARIATIONS = {
    'NSA3010': [
        'NSA3010 Network Security Fundamentals A',
        'Completed Network Security Fundamentals with grade A-',
        'NSA 3010 - Intro to Network Security B+',
        'Network Security Fund. (NSA3010) — Pass',
        'Foundations of Network Security, Grade: B',
        'NSA3010: NetSec Fundamentals, Credits: 3, Grade: A',
        'Network Security NSA3010 completed with B+',
        'NSA3010 grade earned: A minus',
    ],
    'NSA4020': [
        'NSA4020 Penetration Testing A-',
        'Pen Testing (NSA4020) Grade: B+',
        'Completed: Penetration Testing and Ethical Hacking B',
        'NSA 4020 - PenTest Fundamentals, A',
        'Advanced Penetration Testing NSA4020 Grade B+',
        'NSA4020: Offensive Security — Grade: A-',
        'Penetration Testing NSA4020 credits 3 grade A',
        'NSA4020 pentest course passed grade B',
    ],
    'NSA4030': [
        'NSA4030 Digital Forensics B+',
        'Digital Forensics and Incident Investigation (NSA4030) A',
        'Completed NSA 4030: Forensic Analysis Grade B',
        'NSA4030 — Cyber Forensics, A-',
        'Digital Forensics NSA4030 Credits 3 Grade: B+',
        'Forensic Computing NSA4030 — Passed with Grade A',
        'NSA4030 digital forensics examination passed A-',
        'Cyber forensics NSA4030 grade B plus',
    ],
    'NSA4040': [
        'NSA4040 Incident Response A',
        'IR and Threat Management NSA4040 B+',
        'Completed Incident Response (NSA4040) with A-',
        'NSA 4040 Cyber Incident Response — Grade B',
        'NSA4040: IR Fundamentals, Credits 3, Grade A',
        'Incident Response and Handling NSA4040 Grade: B+',
        'NSA4040 incident response course grade A',
        'Threat and incident management NSA4040 B',
    ],
    'NSA4050': [
        'NSA4050 Cryptography A-',
        'Applied Cryptography NSA4050 B',
        'Cryptography and Data Security (NSA4050) Grade A',
        'NSA 4050 - Crypto Fundamentals B+',
        'NSA4050: Cryptographic Systems, Grade: A-',
        'Introduction to Cryptography NSA4050 Passed Grade B+',
        'NSA4050 cryptography completed grade A minus',
        'Applied crypto NSA4050 grade B plus',
    ],
    'NONE': [
        'COP3014 Programming Fundamentals A',
        'MAD2104 Discrete Mathematics B+',
        'COT3100 Introduction to Algorithms A-',
        'MAN3025 Management of Organizations B',
        'ENC1101 Freshman Composition A',
        'STA2023 Elementary Statistics B+',
        'PHY2053 College Physics I A-',
        'MAC2311 Calculus I B',
        'CGS1060 Computer Fluency A',
        'GEB1011 Introduction to Business B+',
        'SOP3004 Introduction to Psychology A',
        'AMH2010 American History B+',
        'BSC1010 General Biology A-',
        'CHM1045 General Chemistry B',
    ],
}

GRADES      = ['A', 'A-', 'B+', 'B', 'B-', 'C+', 'C']
GRADE_PTS   = {'A':4.0,'A-':3.7,'B+':3.3,'B':3.0,'B-':2.7,'C+':2.3,'C':2.0}
FIRST_NAMES = ['Marcus','Jasmine','Darius','Aaliyah','Terrence','Keisha',
               'Jordan','Brianna','DeAndre','Monique','Elijah','Tamara',
               'Isaiah','Destiny','Cameron','Imani','Xavier','Latoya',
               'Kendrick','Shanice','Malik','Tiara','Devon','Raven']
LAST_NAMES  = ['Johnson','Williams','Brown','Davis','Wilson','Taylor',
               'Anderson','Thomas','Jackson','White','Harris','Martin',
               'Thompson','Garcia','Robinson','Clark','Lewis','Walker',
               'Allen','Young','King','Wright','Scott','Green']

# ── Scoring constants (must match chaincode and transcript_parser) ────────────
W1, W2, W3      = 0.40, 0.40, 0.20
SCORE_THRESHOLD = 0.70
MIN_GPA         = 3.0
MIN_COURSES     = 3


# ─────────────────────────────────────────────────────────────────────────────
# KAGGLE COLUMN MAPPING
# When you find a Kaggle dataset, fill in the column names here.
# Set each key to the column name in your CSV that holds that data.
# If your dataset does not have a column for something, set it to None.
# ─────────────────────────────────────────────────────────────────────────────
KAGGLE_COLUMN_MAP = {
    'student_id':   None,    # e.g. 'StudentID' or 'student_id'
    'name':         None,    # e.g. 'Name' or 'student_name'
    'gpa':          None,    # e.g. 'GPA' or 'cumulative_gpa'
    'courses':      None,    # e.g. 'Courses' — comma or pipe separated course codes
    'grade':        None,    # e.g. 'Grade' — if one row = one course
    'program':      None,    # e.g. 'Program' — filter to FCSS rows only
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def compute_gpa(grades: dict) -> float:
    if not grades: return 0.0
    return round(sum(GRADE_PTS[g] for g in grades.values()) / len(grades), 2)


def weighted_score(gpa: float, n_courses: int, bert_conf: float = 0.90) -> float:
    return round(W1*(gpa/4.0) + W2*(n_courses/5.0) + W3*bert_conf, 4)


def make_transcript_text(name, student_id, enroll_date, course_grades, gpa) -> str:
    lines = []
    for code, grade in course_grades.items():
        lines.append(random.choice(COURSE_VARIATIONS[code]))
    for _ in range(random.randint(3, 5)):
        lines.append(random.choice(COURSE_VARIATIONS['NONE']))
    random.shuffle(lines)
    return f"""Florida A&M University — Official Academic Transcript
======================================================
Student Name:    {name}
Student ID:      {student_id}
Program:         Forensic Computer Science & Security (FCSS)
Enrollment Date: {enroll_date}

Completed Coursework:
  {'  '.join(chr(10)+'  ' + l for l in lines)}

Cumulative GPA: {gpa}
Issuing Office: Office of the Registrar, FAMU
"""


def make_sentence_labels(course_grades: dict) -> list:
    examples = []
    for code in course_grades:
        for variation in COURSE_VARIATIONS[code]:
            examples.append({'text': variation, 'label': code})
    for variation in COURSE_VARIATIONS['NONE']:
        examples.append({'text': variation, 'label': 'NONE'})
    return examples


def save_outputs(students: list, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)

    transcripts, sentence_labels, payloads = [], [], []

    for s in students:
        transcripts.append({
            'student_id': s['student_id'],
            'text':       make_transcript_text(
                s['name'], s['student_id'],
                s['enroll_date'], s['course_grades'], s['gpa']
            )
        })
        sentence_labels.extend(make_sentence_labels(s['course_grades']))
        if s['eligible']:
            payloads.append({
                'student_id':        s['student_id'],
                'gpa':               s['gpa'],
                'courses_completed': s['courses'],
                'bert_confidence':   0.90,
                'eligibility_score': s['score'],
            })

    # CSV
    with open(f'{out_dir}/structured_dataset.csv', 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=[
            'student_id','name','program','enroll_date',
            'courses','gpa','eligibility_score','eligible'])
        w.writeheader()
        for s in students:
            w.writerow({
                'student_id':        s['student_id'],
                'name':              s['name'],
                'program':           s['program'],
                'enroll_date':       s['enroll_date'],
                'courses':           '|'.join(s['courses']),
                'gpa':               s['gpa'],
                'eligibility_score': s['score'],
                'eligible':          s['eligible'],
            })

    with open(f'{out_dir}/transcripts.json',      'w') as f: json.dump(transcripts,     f, indent=2)
    with open(f'{out_dir}/sentence_labels.json',  'w') as f: json.dump(sentence_labels, f, indent=2)
    with open(f'{out_dir}/eligible_payloads.json','w') as f: json.dump(payloads,        f, indent=2)

    total    = len(students)
    eligible = sum(1 for s in students if s['eligible'])
    print(f'\nDataset saved to {out_dir}/')
    print(f'  Total     : {total}')
    print(f'  Eligible  : {eligible} ({round(eligible/total*100)}%)')
    print(f'  Ineligible: {total-eligible} ({round((total-eligible)/total*100)}%)')
    print(f'  Sentences : {len(sentence_labels)}')


# ─────────────────────────────────────────────────────────────────────────────
# MODE 1 — Synthetic Generator
# ─────────────────────────────────────────────────────────────────────────────
def generate_synthetic(n: int = 200) -> list:
    all_codes = list(COURSES.keys())
    students  = []

    n_elig   = int(n * 0.60)
    n_inelig = n - n_elig

    def make_student(idx, force):
        sid  = f'FAMU{10000+idx}'
        name = f'{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}'
        enroll = (datetime.now()-timedelta(days=random.randint(180,1460))).strftime('%Y-%m-%d')

        if force == 'eligible':
            selected = random.sample(all_codes, random.randint(MIN_COURSES, 5))
            grades   = {c: random.choice(['A','A-','B+','B']) for c in selected}
        elif force == 'ineligible':
            if random.random() < 0.5:
                selected = random.sample(all_codes, random.randint(1, MIN_COURSES-1))
                grades   = {c: random.choice(GRADES) for c in selected}
            else:
                selected = random.sample(all_codes, random.randint(MIN_COURSES, 5))
                grades   = {c: random.choice(['C+','C','B-']) for c in selected}
        else:
            selected = random.sample(all_codes, random.randint(1, 5))
            grades   = {c: random.choice(GRADES) for c in selected}

        gpa    = compute_gpa(grades)
        courses = list(grades.keys())
        score  = weighted_score(gpa, len(courses))
        return {
            'student_id':   sid,   'name':         name,
            'program':      'FCSS','enroll_date':  enroll,
            'course_grades':grades,'courses':       courses,
            'gpa':          gpa,   'score':         score,
            'eligible':     score >= SCORE_THRESHOLD,
        }

    for i in range(n_elig):
        students.append(make_student(i, 'eligible'))
    for i in range(n_inelig):
        students.append(make_student(n_elig+i, 'ineligible'))

    random.shuffle(students)
    return students


# ─────────────────────────────────────────────────────────────────────────────
# MODE 2 — Kaggle Drop-In Loader
# Fill in KAGGLE_COLUMN_MAP above and this handles the rest.
# ─────────────────────────────────────────────────────────────────────────────
def load_kaggle(filepath: str) -> list:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f'Kaggle file not found: {filepath}')

    # Validate mapping
    missing = [k for k, v in KAGGLE_COLUMN_MAP.items() if v is None and k in ['gpa','courses']]
    if missing:
        raise ValueError(
            f'KAGGLE_COLUMN_MAP is incomplete. Please set these columns: {missing}\n'
            f'Edit the KAGGLE_COLUMN_MAP dictionary in dataset/data_loader.py'
        )

    print(f'Loading Kaggle dataset from {filepath}...')
    students = []

    with open(filepath, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            try:
                gpa_col     = KAGGLE_COLUMN_MAP['gpa']
                courses_col = KAGGLE_COLUMN_MAP['courses']

                gpa  = float(row.get(gpa_col, 0) or 0)
                raw  = row.get(courses_col, '') or ''
                # Accept comma, pipe, or space separated course codes
                courses_raw = [c.strip().upper() for c in raw.replace('|',',').split(',') if c.strip()]
                courses     = [c for c in courses_raw if c in COURSES]

                sid  = row.get(KAGGLE_COLUMN_MAP['student_id'] or '', f'K{i:05d}') or f'K{i:05d}'
                name = row.get(KAGGLE_COLUMN_MAP['name'] or '', f'Student {i}') or f'Student {i}'

                # Build a fake course_grades dict for transcript generation
                course_grades = {c: random.choice(GRADES) for c in courses}
                score  = weighted_score(gpa, len(courses))

                students.append({
                    'student_id':    sid,   'name':         name,
                    'program':       'FCSS','enroll_date':  '2023-01-01',
                    'course_grades': course_grades, 'courses': courses,
                    'gpa':           gpa,   'score':         score,
                    'eligible':      score >= SCORE_THRESHOLD,
                })
            except Exception as e:
                print(f'  Skipping row {i}: {e}')

    print(f'Loaded {len(students)} records from Kaggle dataset.')
    return students


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--mode',   choices=['synthetic','kaggle'], default='synthetic')
    p.add_argument('--file',   default='dataset/kaggle/data.csv',
                   help='Path to Kaggle CSV (only used with --mode kaggle)')
    p.add_argument('--n',      type=int, default=200,
                   help='Number of synthetic students (only used with --mode synthetic)')
    p.add_argument('--output', default='dataset/output')
    args = p.parse_args()

    if args.mode == 'synthetic':
        print(f'Generating {args.n} synthetic FCSS students...')
        students = generate_synthetic(args.n)
    else:
        students = load_kaggle(args.file)

    save_outputs(students, args.output)
