'use strict';
/**
 * CertChain Chaincode — Hyperledger Fabric Smart Contract
 * =========================================================
 * FAMU FCSS Micro-Credentialing System
 *
 * Layer 2 — Weighted Eligibility Scoring Algorithm
 *   Score = 0.40*(GPA/4.0) + 0.40*(courses/5) + 0.20*(bert_confidence)
 *   Threshold: >= 0.70 → ELIGIBLE
 *
 * Layer 3 — System
 *   - Role-Based Access Control (Admin, Institution, Student, Verifier)
 *   - JSON-LD credential output for interoperability
 *   - Immutable audit log on every transaction
 *
 * ── OFF-CHAIN vs ON-CHAIN DATA MODEL ──────────────────────────────────────────
 *
 *  ON-CHAIN (Hyperledger Fabric ledger):
 *    credentialID, studentID, issuerID, program, courses_completed,
 *    eligibility_score, score_breakdown, issuedAt, status,
 *    ipfs_cid, pq_signature, pq_public_key, pq_algorithm,
 *    revokedAt, revocationReason
 *
 *  OFF-CHAIN (IPFS — referenced by ipfs_cid):
 *    gpa, student_name, bert_confidence, raw_transcript,
 *    full_score_breakdown, issuer_metadata
 *
 *  NEVER ON-CHAIN (FERPA protected):
 *    raw GPA value, student name, transcript text, individual grades
 *    These never touch the ledger. Only the eligibility outcome is recorded.
 *
 * ── VERIFICATION LOGGING (Item 3) ─────────────────────────────────────────────
 *  Every verifyCredential call is logged regardless of outcome.
 *  Hash mismatches emit a VERIFY_MISMATCH event visible to admins.
 *  Admins can query the verification log via getVerificationLog().
 * ─────────────────────────────────────────────────────────────────────────────
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
const ROLES        = {
    ADMIN:       'admin',
    INSTITUTION: 'institution',
    STUDENT:     'student',
    VERIFIER:    'verifier'
};

class CertChain extends Contract {

    // ── Init ──────────────────────────────────────────────────────────────────
    async initLedger(ctx) {
        const genesis = {
            type:      'GENESIS',
            program:   PROGRAM,
            issuer:    ISSUER,
            timestamp: new Date().toISOString(),
            version:   '2.0.0',
            scoring: { w1:W1, w2:W2, w3:W3, threshold:THRESHOLD },
            cryptography: {
                standard:  'CRYSTALS-Dilithium3',
                nist:      'FIPS 204 (ML-DSA)',
                note:      'Dual-signature: ECDSA (Fabric layer) + Dilithium3 (credential layer)'
            },
            dataModel: {
                onChain:  ['credentialID','studentID','issuerID','program','courses_completed',
                           'eligibility_score','issuedAt','status','ipfs_cid','pq_signature'],
                offChain: ['gpa','student_name','bert_confidence','raw_transcript'],
                ferpaProtected: ['gpa','student_name','grades','transcript_text']
            }
        };
        await ctx.stub.putState('GENESIS', Buffer.from(JSON.stringify(genesis)));
        return JSON.stringify(genesis);
    }

    // ── Layer 2: Weighted Scoring Algorithm ───────────────────────────────────
    // NOTE: GPA and bert_confidence are used ONLY for scoring computation.
    // They are NOT stored on-chain. Only the resulting eligibility_score is.
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

        const { gpa, courses_completed, bert_confidence } = payload;
        // student_name and gpa intentionally NOT destructured for on-chain use

        const validCourses = (courses_completed||[]).filter(
            c => FCSS_COURSES.includes(c.toUpperCase())
        );

        // Hard pre-checks — computed from off-chain data, not stored
        if (parseFloat(gpa) < MIN_GPA) {
            await this._log(ctx, studentID, 'REJECTED', `GPA below minimum`);
            // Note: actual GPA value not logged — FERPA protection
            return JSON.stringify({
                success: false,
                reason: `GPA below minimum threshold of ${MIN_GPA}.`
            });
        }
        if (validCourses.length < MIN_COURSES) {
            await this._log(ctx, studentID, 'REJECTED',
                `Only ${validCourses.length} FCSS courses completed`);
            return JSON.stringify({
                success: false,
                reason: `Only ${validCourses.length} valid FCSS courses (need ${MIN_COURSES}).`
            });
        }

        // Layer 2: weighted scoring — computed from off-chain inputs
        const scoring = this._computeScore(gpa, validCourses, bert_confidence);
        if (!scoring.eligible) {
            await this._log(ctx, studentID, 'REJECTED',
                `Score ${scoring.score} below threshold`);
            return JSON.stringify({
                success: false,
                reason:  `Score ${scoring.score} below threshold ${THRESHOLD}.`,
                scoring
            });
        }

        const credentialID = `CERTCHAIN-${studentID}-${ctx.stub.getTxID().substring(0,8)}`;
        const issuedAt     = new Date().toISOString();

        // ── ON-CHAIN CREDENTIAL ───────────────────────────────────────────────
        // FERPA compliant: NO raw GPA, NO student name, NO grades
        // Only eligibility OUTCOME and course LIST stored on ledger
        const credential = {
            credentialID,
            studentID,
            issuerID:          ISSUER,
            program:           PROGRAM,
            courses_completed: validCourses,   // course codes only, no grades
            eligibility_score: scoring.score,  // computed score, not raw GPA
            score_breakdown:   scoring.breakdown,
            issuedAt,
            status:            'ACTIVE',
            revokedAt:         null,
            revocationReason:  null,
            // Off-chain reference — set by attachIPFS() after IPFS storage
            ipfs_cid:          null,
            // Post-quantum signature — set by attachPQSignature()
            pq_signature:      null,
            pq_public_key:     null,
            pq_algorithm:      'CRYSTALS-Dilithium3 (NIST FIPS 204 / ML-DSA-65)',
            jsonld_context:    'https://schema.org/',
            jsonld_type:       'EducationalOccupationalCredential',
        };
        // ─────────────────────────────────────────────────────────────────────
        // OFF-CHAIN DATA (stored in IPFS, referenced by ipfs_cid above):
        //   { gpa, student_name, bert_confidence, raw_transcript, ... }
        // The IPFS CID is attached later via attachIPFS()
        // This ensures FERPA-protected data never touches the Fabric ledger
        // ─────────────────────────────────────────────────────────────────────

        const credHash = crypto.createHash('sha256')
            .update(JSON.stringify(credential)).digest('hex');

        await ctx.stub.putState(
            `CRED~${credHash}`,
            Buffer.from(JSON.stringify(credential))
        );

        // Student composite index for range queries
        const idx = await ctx.stub.createCompositeKey(
            'student~hash', [studentID, credHash]
        );
        await ctx.stub.putState(idx, Buffer.from('\u0000'));

        ctx.stub.setEvent('CredentialIssued', Buffer.from(JSON.stringify({
            credentialID, studentID, credHash, issuedAt, program: PROGRAM
        })));

        await this._log(ctx, studentID, 'ISSUED', credentialID);
        return JSON.stringify({ success:true, credentialID, credHash, scoring });
    }

    // ── Attach IPFS CID (off-chain data reference) ────────────────────────────
    // Called after FERPA-protected data (GPA, name, transcript) is stored
    // in IPFS. The CID links on-chain credential to off-chain full record.
    async attachIPFS(ctx, credHash, ipfsCID) {
        this._assertRole(ctx, [ROLES.INSTITUTION, ROLES.ADMIN]);
        const raw = await ctx.stub.getState(`CRED~${credHash}`);
        if (!raw||raw.length===0) throw new Error(`Credential ${credHash} not found.`);
        const c    = JSON.parse(raw.toString());
        c.ipfs_cid = ipfsCID;
        await ctx.stub.putState(`CRED~${credHash}`, Buffer.from(JSON.stringify(c)));
        await this._log(ctx, c.studentID, 'IPFS_ATTACHED', ipfsCID);
        return JSON.stringify({ success:true, credHash, ipfsCID });
    }

    // ── Attach Post-Quantum Signature ─────────────────────────────────────────
    // CRYSTALS-Dilithium3 signature over the credential JSON
    // Applied at application layer — separate from Fabric's ECDSA layer
    async attachPQSignature(ctx, credHash, pqSignature, pqPublicKey) {
        this._assertRole(ctx, [ROLES.INSTITUTION, ROLES.ADMIN]);
        const raw = await ctx.stub.getState(`CRED~${credHash}`);
        if (!raw||raw.length===0) throw new Error(`Credential ${credHash} not found.`);
        const c         = JSON.parse(raw.toString());
        c.pq_signature  = pqSignature;
        c.pq_public_key = pqPublicKey;
        await ctx.stub.putState(`CRED~${credHash}`, Buffer.from(JSON.stringify(c)));
        await this._log(ctx, c.studentID, 'PQ_SIGNATURE_ATTACHED', credHash);
        return JSON.stringify({
            success:      true,
            credHash,
            pq_algorithm: 'CRYSTALS-Dilithium3 (NIST FIPS 204 / ML-DSA-65)'
        });
    }

    // ── Verify Credential ─────────────────────────────────────────────────────
    // Item 3: Every verification attempt is logged regardless of outcome.
    // Hash mismatches emit VERIFY_MISMATCH event for admin alerting.
    async verifyCredential(ctx, credHash) {
        this._assertRole(ctx, [ROLES.VERIFIER, ROLES.STUDENT, ROLES.INSTITUTION, ROLES.ADMIN]);

        const txID     = ctx.stub.getTxID();
        const callerID = this._getCallerID(ctx);
        const timestamp = new Date().toISOString();

        const raw = await ctx.stub.getState(`CRED~${credHash}`);

        if (!raw || raw.length === 0) {
            // ── HASH MISMATCH / NOT FOUND ─────────────────────────────────────
            // Log the failed verification attempt
            await this._logVerification(ctx, {
                credHash,
                result:    'NOT_FOUND',
                callerID,
                timestamp,
                txID,
                alert:     true,
                alertMsg:  `Hash ${credHash.substring(0,16)}... not found on ledger`
            });

            // Emit event for admin dashboard alerting (Item 3)
            ctx.stub.setEvent('VerifyMismatch', Buffer.from(JSON.stringify({
                credHash,
                callerID,
                timestamp,
                txID,
                reason: 'Credential hash not found on ledger'
            })));

            return JSON.stringify({
                '@context': 'https://schema.org/',
                '@type':    'EducationalOccupationalCredential',
                isValid:    false,
                credHash,
                message:    'Credential not found on ledger.',
                verificationLog: { result:'NOT_FOUND', timestamp, callerID }
            });
        }

        const c = JSON.parse(raw.toString());
        const isActive = c.status === 'ACTIVE';

        if (!isActive) {
            // ── REVOKED CREDENTIAL ────────────────────────────────────────────
            await this._logVerification(ctx, {
                credHash,
                result:    'REVOKED',
                callerID,
                timestamp,
                txID,
                alert:     true,
                alertMsg:  `Revoked credential verification attempted`
            });

            ctx.stub.setEvent('VerifyMismatch', Buffer.from(JSON.stringify({
                credHash,
                callerID,
                timestamp,
                txID,
                reason: `Credential is ${c.status}`
            })));
        } else {
            // ── SUCCESSFUL VERIFICATION ───────────────────────────────────────
            await this._logVerification(ctx, {
                credHash,
                result:    'VERIFIED',
                callerID,
                timestamp,
                txID,
                alert:     false
            });
        }

        return JSON.stringify({
            '@context':         'https://schema.org/',
            '@type':            'EducationalOccupationalCredential',
            identifier:         c.credentialID,
            credentialHash:     credHash,
            isValid:            isActive,
            credentialStatus:   c.status,
            credentialCategory: 'micro-credential',
            recognizedBy:       c.issuerID,
            educationalProgram: c.program,
            competencyRequired: c.courses_completed,
            dateCreated:        c.issuedAt,
            eligibilityScore:   c.eligibility_score,
            scoreBreakdown:     c.score_breakdown,
            ipfsCID:            c.ipfs_cid,
            postQuantumSigned:  c.pq_signature !== null,
            pqAlgorithm:        c.pq_algorithm,
            revokedAt:          c.revokedAt,
            revocationReason:   c.revocationReason,
            verificationLog:    { result: isActive ? 'VERIFIED' : c.status, timestamp, callerID }
        });
    }

    // ── Get Verification Log (Admin/Institution only) ─────────────────────────
    // Item 3: Exposes verification history including mismatches
    async getVerificationLog(ctx, limit) {
        this._assertRole(ctx, [ROLES.ADMIN, ROLES.INSTITUTION]);
        const maxResults = parseInt(limit||'50');
        const results    = [];
        const it = await ctx.stub.getStateByRange('VERIFYLOG~', 'VERIFYLOG~\uFFFF');
        let r    = await it.next();
        while (!r.done && results.length < maxResults) {
            results.push(JSON.parse(r.value.value.toString()));
            r = await it.next();
        }
        // Sort by timestamp descending (most recent first)
        results.sort((a,b) => b.timestamp.localeCompare(a.timestamp));
        return JSON.stringify({
            count:   results.length,
            entries: results,
            alerts:  results.filter(e => e.alert).length
        });
    }

    // ── Get Mismatch Alerts (Admin only) ──────────────────────────────────────
    async getMismatchAlerts(ctx) {
        this._assertRole(ctx, [ROLES.ADMIN]);
        const results = [];
        const it = await ctx.stub.getStateByRange('VERIFYLOG~', 'VERIFYLOG~\uFFFF');
        let r    = await it.next();
        while (!r.done) {
            const entry = JSON.parse(r.value.value.toString());
            if (entry.alert) results.push(entry);
            r = await it.next();
        }
        results.sort((a,b) => b.timestamp.localeCompare(a.timestamp));
        return JSON.stringify({
            alertCount: results.length,
            alerts:     results.slice(0, 20)
        });
    }

    // ── Get all credentials for a student ─────────────────────────────────────
    async getStudentCredentials(ctx, studentID) {
        this._assertRole(ctx, [ROLES.STUDENT, ROLES.INSTITUTION, ROLES.ADMIN]);
        const results = [];
        const it      = await ctx.stub.getStateByPartialCompositeKey(
            'student~hash', [studentID]
        );
        let r = await it.next();
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
        const c           = JSON.parse(raw.toString());
        c.status          = 'REVOKED';
        c.revokedAt       = new Date().toISOString();
        c.revocationReason = reason||'No reason provided';
        await ctx.stub.putState(`CRED~${credHash}`, Buffer.from(JSON.stringify(c)));
        ctx.stub.setEvent('CredentialRevoked', Buffer.from(JSON.stringify({
            credHash, reason: c.revocationReason
        })));
        await this._log(ctx, c.studentID, 'REVOKED', reason);
        return JSON.stringify({ success:true, credHash, status:'REVOKED' });
    }

    // ── Program Analytics ──────────────────────────────────────────────────────
    async getProgramAnalytics(ctx) {
        this._assertRole(ctx, [ROLES.INSTITUTION, ROLES.ADMIN]);
        let total=0, active=0, revoked=0, scoreSum=0, pqSigned=0, ipfsLinked=0;
        const courseCounts = {};
        FCSS_COURSES.forEach(c => courseCounts[c]=0);

        const it = await ctx.stub.getStateByRange('CRED~', 'CRED~\uFFFF');
        let r    = await it.next();
        while (!r.done) {
            const c = JSON.parse(r.value.value.toString());
            total++;
            if (c.status==='ACTIVE')  { active++;  scoreSum+=c.eligibility_score; }
            if (c.status==='REVOKED')   revoked++;
            if (c.pq_signature)         pqSigned++;
            if (c.ipfs_cid)             ipfsLinked++;
            (c.courses_completed||[]).forEach(code => {
                if (courseCounts[code] !== undefined) courseCounts[code]++;
            });
            r = await it.next();
        }

        // Note: averageGPA removed — GPA is off-chain (FERPA protected)
        return JSON.stringify({
            program:          PROGRAM,
            generatedAt:      new Date().toISOString(),
            totalIssued:      total,
            activeCount:      active,
            revokedCount:     revoked,
            pqSignedCount:    pqSigned,
            ipfsLinkedCount:  ipfsLinked,
            averageScore:     active>0 ? Math.round(scoreSum/active*10000)/10000 : 0,
            coursePopularity: courseCounts,
            scoringConfig:    { w1:W1, w2:W2, w3:W3, threshold:THRESHOLD },
            pqCryptography:   'CRYSTALS-Dilithium3 (FIPS 204 / ML-DSA-65)',
            dataModel: {
                note: 'GPA and student PII stored off-chain in IPFS per FERPA requirements'
            }
        });
    }

    // ── Helpers ────────────────────────────────────────────────────────────────
    _assertRole(ctx, allowed) {
        let role;
        try { role = ctx.clientIdentity.getAttributeValue('role'); }
        catch(e) { throw new Error('Cannot read caller role.'); }
        if (!role || !allowed.includes(role))
            throw new Error(`Role '${role}' not permitted. Need: [${allowed.join(',')}]`);
    }

    _getCallerID(ctx) {
        try { return ctx.clientIdentity.getID(); }
        catch(e) { return 'unknown'; }
    }

    async _log(ctx, subject, action, detail) {
        await ctx.stub.putState(
            `LOG~${ctx.stub.getTxID()}`,
            Buffer.from(JSON.stringify({
                subject, action, detail,
                txID:      ctx.stub.getTxID(),
                timestamp: new Date().toISOString(),
            }))
        );
    }

    // Item 3: Separate verification log with alert flag
    async _logVerification(ctx, entry) {
        const key = `VERIFYLOG~${entry.timestamp}~${ctx.stub.getTxID()}`;
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(entry)));
    }
}

module.exports = CertChain;
