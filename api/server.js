'use strict';
const express    = require('express');
const bodyParser = require('body-parser');
const cors       = require('cors');
const fs         = require('fs');
const path       = require('path');
const auth       = require('./auth');
const { getContract } = require('../wallet/wallet_setup');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (origin.includes('.ngrok') || origin.includes('github.io') || origin.includes('localhost'))
      return cb(null, true);
    cb(new Error('CORS: ' + origin));
  },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true,
  optionsSuccessStatus: 200,
}));

app.use(bodyParser.json({ limit: '1mb' }));
app.use((req,_,next)=>{ console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`); next(); });

app.get('/health', (_,res) => res.json({
  status:'ok', system:'BlockCert', program:'FAMU-FCSS',
  pqCryptography:'CRYSTALS-Dilithium3', timestamp:new Date().toISOString(), version:'2.0'
}));

app.post('/auth/login', (req,res) => {
  const {userID,password} = req.body;
  if (!userID||!password) return res.status(400).json({ok:false,error:'userID and password required.'});
  const result = auth.login(userID, password);
  return res.status(result.ok?200:401).json(result);
});

app.post('/auth/logout', (req,res) => {
  auth.logout((req.headers.authorization||'').replace('Bearer ',''));
  return res.json({ok:true});
});

app.post('/auth/register', (req,res) => {
  const result = auth.register(req.body);
  return res.status(result.ok?201:400).json(result);
});

app.post('/auth/change-password', auth.requireAuth(), (req,res) => {
  const {currentPassword,newPassword} = req.body;
  if (!currentPassword||!newPassword||newPassword.length<8)
    return res.status(400).json({ok:false,error:'currentPassword and newPassword (min 8 chars) required.'});
  const verify = auth.login(req.session.userID, currentPassword);
  if (!verify.ok) return res.status(401).json({ok:false,error:'Current password incorrect.'});
  const store = JSON.parse(fs.readFileSync(path.join(__dirname,'users.json'),'utf8'));
  const user  = store.users.find(u=>u.userID===req.session.userID);
  if (!user) return res.status(404).json({ok:false,error:'User not found.'});
  user.passwordHash = auth.hashPassword(newPassword);
  fs.writeFileSync(path.join(__dirname,'users.json'), JSON.stringify(store,null,2));
  return res.json({ok:true,message:'Password updated.'});
});

app.get('/admin/pending', auth.requireAuth(['admin']), (_,res) => {
  const pending = auth.getPendingRegistrations();
  return res.json({ok:true,pending,count:pending.length});
});

app.post('/admin/approve/:userID', auth.requireAuth(['admin']), (req,res) => {
  const token = (req.headers.authorization||'').replace('Bearer ','');
  return res.json(auth.approveUser(token, req.params.userID));
});

app.post('/admin/reject/:userID', auth.requireAuth(['admin']), (req,res) => {
  const token = (req.headers.authorization||'').replace('Bearer ','');
  return res.json(auth.rejectUser(token, req.params.userID, req.body.reason));
});

app.get('/admin/users', auth.requireAuth(['admin']), (req,res) => {
  const token = (req.headers.authorization||'').replace('Bearer ','');
  return res.json(auth.listUsers(token));
});

app.post('/issue', auth.requireAuth(['institution','admin']), async (req,res) => {
  const {studentID,nlpPayload} = req.body;
  if (!studentID||!nlpPayload) return res.status(400).json({error:'Missing: studentID, nlpPayload'});
  if ((nlpPayload.bert_confidence||0)<0.60)
    return res.status(422).json({error:'BERT confidence too low.',score:nlpPayload.bert_confidence});
  try {
    const {contract,gateway} = await getContract(req.session.fabricID);
    const result = await contract.submitTransaction('issueMicroCredential',studentID,JSON.stringify(nlpPayload));
    await gateway.disconnect();
    const parsed = JSON.parse(result.toString());
    return res.status(parsed.success?201:422).json(parsed);
  } catch(e) { return res.status(500).json({error:e.message}); }
});

app.get('/verify/:hash', auth.requireAuth(), async (req,res) => {
  try {
    const {contract,gateway} = await getContract(req.session.fabricID);
    const result = await contract.evaluateTransaction('verifyCredential',req.params.hash);
    await gateway.disconnect();
    res.setHeader('Content-Type','application/ld+json');
    return res.json(JSON.parse(result.toString()));
  } catch(e) { return res.status(500).json({error:e.message}); }
});

app.get('/student/:id', auth.requireAuth(), async (req,res) => {
  const sess=req.session;
  if (sess.role==='student'&&sess.userID!==req.params.id)
    return res.status(403).json({error:'Students can only access their own credentials.'});
  try {
    const {contract,gateway} = await getContract(sess.fabricID);
    const result = await contract.evaluateTransaction('getStudentCredentials',req.params.id);
    await gateway.disconnect();
    return res.json(JSON.parse(result.toString()));
  } catch(e) { return res.status(500).json({error:e.message}); }
});

app.post('/revoke', auth.requireAuth(['institution','admin']), async (req,res) => {
  const {credHash,reason} = req.body;
  if (!credHash) return res.status(400).json({error:'credHash required.'});
  try {
    const {contract,gateway} = await getContract(req.session.fabricID);
    const result = await contract.submitTransaction('revokeCredential',credHash,reason||'');
    await gateway.disconnect();
    return res.json(JSON.parse(result.toString()));
  } catch(e) { return res.status(500).json({error:e.message}); }
});

app.get('/analytics', auth.requireAuth(['institution','admin']), async (req,res) => {
  try {
    const {contract,gateway} = await getContract(req.session.fabricID);
    const result = await contract.evaluateTransaction('getProgramAnalytics');
    await gateway.disconnect();
    return res.json(JSON.parse(result.toString()));
  } catch(e) { return res.status(403).json({error:e.message}); }
});

app.use((err,_req,res,_next) => {
  if (err.message?.startsWith('CORS')) return res.status(403).json({error:err.message});
  console.error(err);
  return res.status(500).json({error:'Internal server error.'});
});

app.listen(PORT, () => {
  console.log(`\n  BlockCert API v2  →  http://localhost:${PORT}`);
  console.log('  POST /auth/login  |  POST /auth/register');
  console.log('  GET  /health      |  POST /issue\n');
});

module.exports = app;
