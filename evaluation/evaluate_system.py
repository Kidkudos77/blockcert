"""
BlockCert — System Performance Evaluation (Layer 3)
Measures latency and throughput across all API endpoints.
Run after network + API are up: python evaluation/evaluate_system.py
"""
import time, json, statistics, argparse, requests

CALLER = 'famu-institution'
SAMPLE = {
    'studentID':'FAMU10001','callerID':CALLER,
    'nlpPayload':{'gpa':3.75,'courses_completed':['NSA3010','NSA4020','NSA4030'],
                  'bert_confidence':0.91,'eligibility_score':0.77,'student_name':'Marcus Johnson'}
}

def measure(api, method, path, payload=None, n=20):
    url=f'{api}{path}'; times=[]; errors=0
    for _ in range(n):
        try:
            t0=time.time()
            r=(requests.post(url,json=payload,timeout=30) if method=='POST'
               else requests.get(url,timeout=30))
            if r.status_code in [200,201]: times.append((time.time()-t0)*1000)
            else: errors+=1
        except: errors+=1
    if not times: return {'error':'All failed','n':n}
    return {'n':n,'errors':errors,
            'mean_ms':round(statistics.mean(times),2),
            'median_ms':round(statistics.median(times),2),
            'stdev_ms':round(statistics.stdev(times) if len(times)>1 else 0,2),
            'throughput_rps':round(1000/statistics.mean(times),2)}

def run(api,n):
    print(f'\nSystem evaluation — {api} ({n} samples)\n')
    results={
        'health':    measure(api,'GET','/health',n=n),
        'issue':     measure(api,'POST','/issue',SAMPLE,n=n),
        'verify':    measure(api,'GET','/verify/abc123',n=n),
        'analytics': measure(api,'GET',f'/analytics?as={CALLER}',n=n),
    }
    print('='*60)
    print('LAYER 3 — System Performance')
    print('='*60)
    print(f"{'Endpoint':<20} {'Mean(ms)':>10} {'Median':>8} {'TPS':>8}")
    print('-'*48)
    for k,r in results.items():
        if 'error' not in r:
            print(f"  {k:<18} {r['mean_ms']:>10} {r['median_ms']:>8} {r['throughput_rps']:>8}")
    print('='*60)
    with open('evaluation/system_results.json','w') as f: json.dump(results,f,indent=2)
    print('Saved to evaluation/system_results.json')

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--api',default='http://localhost:3000')
    p.add_argument('--n',type=int,default=20)
    args=p.parse_args()
    run(args.api,args.n)
