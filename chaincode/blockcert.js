'use strict';
/**
 * BlockCert Chaincode — Hyperledger Fabric Smart Contract
 * =========================================================
 * FAMU FCSS Micro-Credentialing System — Final Version
 *
 * Layer 2 — Weighted Eligibility Scoring Algorithm
 *   Score = 0.40*(GPA/4.0) + 0.40*(courses/5) + 0.20*(bert_confidence)
 *   Threshold: >= 0.70 → ELIGIBLE
 *
 * Layer 3 — System
 *   - Role-Based Access Control (Admin, Institution, Student, Verifier)
 *   - JSON-LD credential output for interoperability
 *   - Immutable audit log on every transaction
 *   - Off-chain hash model (IPFS hash + PQ signature stored on ledger)
 *   - Program analytics endpoint
 */

const { Contract } = require('fabric-contract-api');
const crypto       = require('crypto');

const PROGRAM      = 'FAMU-FCSS';
const ISSUER       = 'famu.edu';
const FCSS_COURSES = ['CIS4385C','CIS4360','CIS4361','CNT4406','COP3710'];
const MIN_GPA      = 3.0;
const MIN_COURSES  = 3;
const W1=0.40, W2=0.40, W3=0.20;
const THRESHOLD    = 0.70;
const ROLES        = {ADMIN:'admin',INSTITUTION:'institution',STUDENT:'student',VERIFIER:'verifier'};

class BlockCert extends Contract {

    // ── Init ──────────────────────────────────────────────────────────────────
    async initLedger(ctx) {
        const genesis = {
            type:'GENESIS', program:PROGRAM, issuer:ISSUER,
            timestamp: new Date().toISOString(), version:'1.0.0',
            scoring: { w1:W1, w2:W2, w3:W3, threshold:THRESHOLD },
            cryptography: { standard:'CRYSTALS-Dilithium3', nist:'FIPS 204 (ML-DSA)' },
        };
        await ctx.stub.putState('GENESIS', Buffer.from(JSON.stringify(genesis)));
        return JSON.stringify(genesis);
    }

    // ── Layer 2: Weighted Scoring Algorithm ───────────────────────────────────
    _computeScore(gpa, courses, bert_confidence) {
        const score = W1*(parseFloat(gpa)/4.0) +
                      W2*(courses.length/5.0)  +
                      W3*(parseFloat(bert_confidence||0));
        return {
            score:     Math.round(score*10000)/10000,
            eligible:  score >= THRESHOLD,
            breakdown: {
                gpa_component:    Math.round(W1*(parseFloat(gpa)/4.0)*10000)/10000,
                course_component: Math.round(W2*(courses.length/5.0)*10000)/10000,
                bert_component:   Math.round(W3*(parseFloat(bert_confidence||0))*10000)/10000,
            },
            threshold: THRESHOLD,
        };
    }

    // ── Issue Credential ──────────────────────────────────────────────────────
    async issueMicroCredential(ctx, studentID, nlpPayloadStr) {
        this._assertRole(ctx, [ROLES.INSTITUTION, ROLES.ADMIN]);

        let payload;
        try { payload = JSON.parse(nlpPayloadStr); }
        catch(e) { throw new Error('Invalid NLP payload JSON.'); }

        const { gpa, courses_completed, bert_confidence, student_name } = payload;
        const validCourses = (courses_completed||[]).filter(c => FCSS_COURSES.includes(c.toUpperCase()));

        // Hard pre-checks
        if (parseFloat(gpa) < MIN_GPA) {
            await this._log(ctx, studentID, 'REJECTED', `GPA ${gpa} < ${MIN_GPA}`);
            return JSON.stringify({ success:false, reason:`GPA ${gpa} below minimum ${MIN_GPA}.` });
        }
        if (validCourses.length < MIN_COURSES) {
            await this._log(ctx, studentID, 'REJECTED', `Only ${validCourses.length} FCSS courses`);
            return JSON.stringify({ success:false, reason:`Only ${validCourses.length} valid FCSS courses (need ${MIN_COURSES}).` });
        }

        // Layer 2: weighted scoring
        const scoring = this._computeScore(gpa, validCourses, bert_confidence);
        if (!scoring.eligible) {
            await this._log(ctx, studentID, 'REJECTED', `Score ${scoring.score} < ${THRESHOLD}`);
            return JSON.stringify({ success:false, reason:`Score ${scoring.score} below threshold ${THRESHOLD}.`, scoring });
        }

        const credentialID = `BLOCKCERT-${studentID}-${ctx.stub.getTxID().substring(0,8)}`;
        const issuedAt     = new Date().toISOString();

        const credential = {
            credentialID, studentID,
            student_name:      student_name||null,
            issuerID:          ISSUER,
            program:           PROGRAM,
            gpa:               parseFloat(gpa),
            courses_completed: validCourses,
            bert_confidence:   parseFloat(bert_confidence||0),
            eligibility_score: scoring.score,
            score_breakdown:   scoring.breakdown,
            issuedAt,
            status:            'ACTIVE',
            revokedAt:         null,
            revocationReason:  null,
            ipfs_cid:          null,   // set by attachIPFS()
            pq_signature:      null,   // set by attachPQSignature()
            pq_public_key:     null,
            pq_algorithm:      'CRYSTALS-Dilithium3',
            jsonld_context:    'https://schema.org/',
            jsonld_type:       'EducationalOccupationalCredential',
        };

        const credHash = crypto.createHash('sha256')
            .update(JSON.stringify(credential)).digest('hex');

        await ctx.stub.putState(`CRED~${credHash}`, Buffer.from(JSON.stringify(credential)));

        // Student index for range queries
        const idx = await ctx.stub.createCompositeKey('student~hash', [studentID, credHash]);
        await ctx.stub.putState(idx, Buffer.from('\u0000'));

        ctx.stub.setEvent('CredentialIssued', Buffer.from(JSON.stringify({
            credentialID, studentID, credHash, issuedAt, program:PROGRAM
        })));

        await this._log(ctx, studentID, 'ISSUED', credentialID);
        return JSON.stringify({ success:true, credentialID, credHash, scoring });
    }

    // ── Attach IPFS CID after off-chain storage ───────────────────────────────
    async attachIPFS(ctx, credHash, ipfsCID) {
        this._assertRole(ctx, [ROLES.INSTITUTION, ROLES.ADMIN]);
        const raw = await ctx.stub.getState(`CRED~${credHash}`);
        if (!raw||raw.length===0) throw new Error(`Credential ${credHash} not found.`);
        const c   = JSON.parse(raw.toString());
        c.ipfs_cid = ipfsCID;
        await ctx.stub.putState(`CRED~${credHash}`, Buffer.from(JSON.stringify(c)));
        return JSON.stringify({ success:true, credHash, ipfsCID });
    }

    // ── Attach Post-Quantum Signature ─────────────────────────────────────────
    async attachPQSignature(ctx, credHash, pqSignature, pqPublicKey) {
        this._assertRole(ctx, [ROLES.INSTITUTION, ROLES.ADMIN]);
        const raw = await ctx.stub.getState(`CRED~${credHash}`);
        if (!raw||raw.length===0) throw new Error(`Credential ${credHash} not found.`);
        const c      = JSON.parse(raw.toString());
        c.pq_signature  = pqSignature;
        c.pq_public_key = pqPublicKey;
        await ctx.stub.putState(`CRED~${credHash}`, Buffer.from(JSON.stringify(c)));
        await this._log(ctx, c.studentID, 'PQ_SIGNATURE_ATTACHED', credHash);
        return JSON.stringify({ success:true, credHash, pq_algorithm:'CRYSTALS-Dilithium3' });
    }

    // ── Verify — JSON-LD response for interoperability ────────────────────────
    async verifyCredential(ctx, credHash) {
        this._assertRole(ctx, [ROLES.VERIFIER, ROLES.STUDENT, ROLES.INSTITUTION, ROLES.ADMIN]);
        const raw = await ctx.stub.getState(`CRED~${credHash}`);
        await this._log(ctx, credHash, 'VERIFY_ATTEMPT', ctx.stub.getTxID());

        if (!raw||raw.length===0) {
            return JSON.stringify({
                '@context':'https://schema.org/',
                '@type':'EducationalOccupationalCredential',
                isValid:false, credHash, message:'Not found.'
            });
        }

        const c = JSON.parse(raw.toString());
        return JSON.stringify({
            '@context':             'https://schema.org/',
            '@type':                'EducationalOccupationalCredential',
            identifier:             c.credentialID,
            credentialHash:         credHash,
            isValid:                c.status === 'ACTIVE',
            credentialStatus:       c.status,
            credentialCategory:     'micro-credential',
            recognizedBy:           c.issuerID,
            educationalProgram:     c.program,
            competencyRequired:     c.courses_completed,
            dateCreated:            c.issuedAt,
            eligibilityScore:       c.eligibility_score,
            scoreBreakdown:         c.score_breakdown,
            ipfsCID:                c.ipfs_cid,
            postQuantumSigned:      c.pq_signature !== null,
            pqAlgorithm:            c.pq_algorithm,
            revokedAt:              c.revokedAt,
            revocationReason:       c.revocationReason,
        });
    }

    // ── Get all credentials for a student ─────────────────────────────────────
    async getStudentCredentials(ctx, studentID) {
        this._assertRole(ctx, [ROLES.STUDENT, ROLES.INSTITUTION, ROLES.ADMIN]);
        const results = [];
        const it      = await ctx.stub.getStateByPartialCompositeKey('student~hash', [studentID]);
        let   r       = await it.next();
        while (!r.done) {
            const { attributes } = ctx.stub.splitCompositeKey(r.value.key);
            results.push(JSON.parse(await this.verifyCredential(ctx, attributes[1])));
            r = await it.next();
        }
        return JSON.stringify(results);
    }

    // ── Revoke ─────────────────────────────────────────────────────────────────
    async revokeCredential(ctx, credHash, reason) {
        this._assertRole(ctx, [ROLES.INSTITUTION, ROLES.ADMIN]);
        const raw = await ctx.stub.getState(`CRED~${credHash}`);
        if (!raw||raw.length===0) throw new Error(`Credential ${credHash} not found.`);
        const c = JSON.parse(raw.toString());
        c.status          = 'REVOKED';
        c.revokedAt       = new Date().toISOString();
        c.revocationReason = reason||'No reason provided';
        await ctx.stub.putState(`CRED~${credHash}`, Buffer.from(JSON.stringify(c)));
        ctx.stub.setEvent('CredentialRevoked', Buffer.from(JSON.stringify({ credHash, reason:c.revocationReason })));
        await this._log(ctx, c.studentID, 'REVOKED', reason);
        return JSON.stringify({ success:true, credHash, status:'REVOKED' });
    }

    // ── Program Analytics ──────────────────────────────────────────────────────
    async getProgramAnalytics(ctx) {
        this._assertRole(ctx, [ROLES.INSTITUTION, ROLES.ADMIN]);
        let total=0, active=0, revoked=0, gpaSum=0, scoreSum=0, pqSigned=0;
        const courseCounts = {};
        FCSS_COURSES.forEach(c => courseCounts[c]=0);

        const it = await ctx.stub.getStateByRange('CRED~','CRED~\uFFFF');
        let r    = await it.next();
        while (!r.done) {
            const c = JSON.parse(r.value.value.toString());
            total++;
            if (c.status==='ACTIVE')  { active++;  gpaSum+=c.gpa; scoreSum+=c.eligibility_score; }
            if (c.status==='REVOKED')   revoked++;
            if (c.pq_signature)         pqSigned++;
            (c.courses_completed||[]).forEach(code => { if(courseCounts[code]!==undefined) courseCounts[code]++; });
            r = await it.next();
        }

        return JSON.stringify({
            program: PROGRAM, generatedAt: new Date().toISOString(),
            totalIssued:    total,
            activeCount:    active,
            revokedCount:   revoked,
            pqSignedCount:  pqSigned,
            averageGPA:     active>0 ? Math.round(gpaSum/active*100)/100 : 0,
            averageScore:   active>0 ? Math.round(scoreSum/active*10000)/10000 : 0,
            coursePopularity: courseCounts,
            scoringConfig:  { w1:W1, w2:W2, w3:W3, threshold:THRESHOLD },
            pqCryptography: 'CRYSTALS-Dilithium3 (FIPS 204)',
        });
    }

    // ── Helpers ────────────────────────────────────────────────────────────────
    _assertRole(ctx, allowed) {
        let role;
        try { role = ctx.clientIdentity.getAttributeValue('role'); }
        catch(e) { throw new Error('Cannot read caller role.'); }
        if (!role||!allowed.includes(role))
            throw new Error(`Role '${role}' not permitted. Need: [${allowed.join(',')}]`);
    }

    async _log(ctx, subject, action, detail) {
        await ctx.stub.putState(`LOG~${ctx.stub.getTxID()}`,
            Buffer.from(JSON.stringify({
                subject, action, detail,
                txID:      ctx.stub.getTxID(),
                timestamp: new Date().toISOString(),
            }))
        );
    }
}

module.exports = BlockCert;
