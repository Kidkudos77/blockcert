'use strict';
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const USERS_FILE = path.join(__dirname, 'users.json');
const sessions   = new Map();
const TTL        = 8 * 60 * 60 * 1000;

function loadUsers(){ try{ return JSON.parse(fs.readFileSync(USERS_FILE,'utf8')); }catch{ return {users:[]}; } }
function saveUsers(s){ fs.writeFileSync(USERS_FILE, JSON.stringify(s,null,2)); }
function hashPw(pw){ return crypto.createHash('sha256').update(pw+'blockcert-salt').digest('hex'); }
function genToken(){ return crypto.randomBytes(32).toString('hex'); }
function getFabricID(role,uid){ return role==='admin'?'admin':role==='institution'?'famu-institution':role==='employer'?'public-verifier':uid; }

function login(userID,password){
  const store=loadUsers(), u=store.users.find(x=>x.userID===userID);
  if(!u) return {ok:false,error:'Account not found.'};
  if(u.status==='pending') return {ok:false,error:'Account pending admin approval.'};
  if(u.status==='rejected') return {ok:false,error:'Account not approved. Contact admin.'};
  if(u.passwordHash!==hashPw(password)) return {ok:false,error:'Incorrect password.'};
  const token=genToken();
  sessions.set(token,{userID:u.userID,role:u.role,name:u.name,fabricID:getFabricID(u.role,u.userID),exp:Date.now()+TTL});
  return {ok:true,token,userID:u.userID,role:u.role,name:u.name,fabricID:getFabricID(u.role,u.userID)};
}
function logout(token){ sessions.delete(token); return {ok:true}; }
function getSession(token){
  if(!token) return null;
  const s=sessions.get(token);
  if(!s) return null;
  if(s.exp<Date.now()){ sessions.delete(token); return null; }
  return s;
}
function register(data){
  const {userID,name,email,password,role,reason}=data;
  if(!userID||!name||!email||!password||!role) return {ok:false,error:'Missing required fields.'};
  if(!['student','institution','employer'].includes(role)) return {ok:false,error:'Invalid role.'};
  if(password.length<8) return {ok:false,error:'Password must be at least 8 characters.'};
  const store=loadUsers();
  if(store.users.find(u=>u.userID===userID)) return {ok:false,error:'Account with this ID already exists.'};
  store.users.push({userID,name,email,passwordHash:hashPw(password),role,reason:reason||'',status:'pending',createdAt:new Date().toISOString()});
  saveUsers(store);
  return {ok:true,message:'Registration submitted. Awaiting admin approval.'};
}
function getPendingRegistrations(){
  return loadUsers().users.filter(u=>u.status==='pending').map(u=>({userID:u.userID,name:u.name,email:u.email,role:u.role,reason:u.reason,createdAt:u.createdAt,status:u.status}));
}
function approveUser(token,targetID){
  const sess=getSession(token);
  if(!sess||sess.role!=='admin') return {ok:false,error:'Admin only.'};
  const store=loadUsers(), u=store.users.find(x=>x.userID===targetID);
  if(!u) return {ok:false,error:'User not found.'};
  u.status='active'; u.approvedAt=new Date().toISOString(); u.approvedBy=sess.userID;
  saveUsers(store); return {ok:true,message:`${targetID} approved.`};
}
function rejectUser(token,targetID,reason){
  const sess=getSession(token);
  if(!sess||sess.role!=='admin') return {ok:false,error:'Admin only.'};
  const store=loadUsers(), u=store.users.find(x=>x.userID===targetID);
  if(!u) return {ok:false,error:'User not found.'};
  u.status='rejected'; u.rejectedAt=new Date().toISOString(); u.rejectReason=reason||'';
  saveUsers(store); return {ok:true,message:`${targetID} rejected.`};
}
function listUsers(token){
  const sess=getSession(token);
  if(!sess||sess.role!=='admin') return {ok:false,error:'Admin only.'};
  return {ok:true,users:loadUsers().users.map(u=>({userID:u.userID,name:u.name,email:u.email,role:u.role,status:u.status,createdAt:u.createdAt}))};
}
function requireAuth(roles){
  return (req,res,next)=>{
    const token=(req.headers.authorization||'').replace('Bearer ','');
    const sess=getSession(token);
    if(!sess) return res.status(401).json({error:'Unauthorized. Please log in.'});
    if(roles&&!roles.includes(sess.role)) return res.status(403).json({error:`Access denied. Required: ${roles.join(' or ')}`});
    req.session=sess; next();
  };
}
module.exports={login,logout,getSession,register,getPendingRegistrations,approveUser,rejectUser,listUsers,requireAuth,hashPassword:hashPw};
