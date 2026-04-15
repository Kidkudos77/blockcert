'use strict';
/**
 * BlockCert — REST API
 * All credential responses in JSON-LD (schema.org) for interoperability.
 *
 * GET  /health
 * POST /issue
 * GET  /verify/:hash
 * GET  /student/:id
 * POST /revoke
 * GET  /analytics
 */
const express    = require('express');
const bodyParser = require('body-parser');
const { getContract } = require('../wallet/wallet_setup');

const app  = express();
const PORT = process.env.PORT || 3000;
app.use(bodyParser.json());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin',  '*');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

app.get('/health', (_, res) =>
    res.json({ status:'ok', system:'BlockCert', program:'FAMU-FCSS',
               pqCryptography:'CRYSTALS-Dilithium3' }));

app.post('/issue', async (req, res) => {
    const { studentID, callerID, nlpPayload } = req.body;
    if (!studentID||!callerID||!nlpPayload)
        return res.status(400).json({ error:'Missing: studentID, callerID, nlpPayload' });
    if ((nlpPayload.bert_confidence||0) < 0.60)
        return res.status(422).json({
            error:'BERT confidence too low for automated issuance.',
            score: nlpPayload.bert_confidence, message:'Manual review required.'
        });
    try {
        const { contract, gateway } = await getContract(callerID);
        const result = await contract.submitTransaction(
            'issueMicroCredential', studentID, JSON.stringify(nlpPayload));
        await gateway.disconnect();
        const parsed = JSON.parse(result.toString());
        return res.status(parsed.success ? 201 : 422).json(parsed);
    } catch(e) { return res.status(500).json({ error:e.message }); }
});

app.get('/verify/:hash', async (req, res) => {
    const callerID = req.query.as || 'public-verifier';
    try {
        const { contract, gateway } = await getContract(callerID);
        const result = await contract.evaluateTransaction('verifyCredential', req.params.hash);
        await gateway.disconnect();
        res.setHeader('Content-Type', 'application/ld+json');
        return res.status(200).json(JSON.parse(result.toString()));
    } catch(e) { return res.status(500).json({ error:e.message }); }
});

app.get('/student/:id', async (req, res) => {
    const callerID = req.query.as || req.params.id;
    try {
        const { contract, gateway } = await getContract(callerID);
        const result = await contract.evaluateTransaction('getStudentCredentials', req.params.id);
        await gateway.disconnect();
        res.setHeader('Content-Type', 'application/ld+json');
        return res.status(200).json(JSON.parse(result.toString()));
    } catch(e) { return res.status(500).json({ error:e.message }); }
});

app.post('/revoke', async (req, res) => {
    const { credHash, reason, callerID } = req.body;
    if (!credHash||!callerID) return res.status(400).json({ error:'credHash and callerID required.' });
    try {
        const { contract, gateway } = await getContract(callerID);
        const result = await contract.submitTransaction('revokeCredential', credHash, reason||'');
        await gateway.disconnect();
        return res.status(200).json(JSON.parse(result.toString()));
    } catch(e) { return res.status(500).json({ error:e.message }); }
});

app.get('/analytics', async (req, res) => {
    if (!req.query.as) return res.status(401).json({ error:'?as=<callerID> required.' });
    try {
        const { contract, gateway } = await getContract(req.query.as);
        const result = await contract.evaluateTransaction('getProgramAnalytics');
        await gateway.disconnect();
        return res.status(200).json(JSON.parse(result.toString()));
    } catch(e) { return res.status(403).json({ error:e.message }); }
});

app.listen(PORT, () => {
    console.log(`BlockCert API → http://localhost:${PORT}`);
    console.log('Routes: /health | POST /issue | GET /verify/:hash | GET /student/:id | POST /revoke | GET /analytics');
});
module.exports = app;
