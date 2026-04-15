'use strict';
/**
 * BlockCert — Wallet & Identity Manager
 * Role embedded in X.509 certificate → read by chaincode _assertRole()
 * Roles: admin | institution | student | verifier
 */
const { Wallets, Gateway } = require('fabric-network');
const FabricCA             = require('fabric-ca-client');
const fs                   = require('fs');
const path                 = require('path');

const WALLET_DIR   = path.join(__dirname, '..', 'wallet', 'store');
const CONN_PROFILE = path.join(__dirname, '..', 'config', 'connection.json');
const CHANNEL      = 'blockcertchannel';
const CHAINCODE    = 'blockcert';
const MSP_ID       = 'FAMUMsp';
const CA_HOST      = 'ca.famu.edu';

function loadProfile() {
    if (!fs.existsSync(CONN_PROFILE))
        throw new Error(`Connection profile not found: ${CONN_PROFILE}`);
    return JSON.parse(fs.readFileSync(CONN_PROFILE, 'utf8'));
}

async function getWallet() {
    return Wallets.newFileSystemWallet(WALLET_DIR);
}

async function enrollAdmin() {
    const ccp = loadProfile(); const wallet = await getWallet();
    if (await wallet.get('admin')) { console.log('Admin already enrolled.'); return; }
    const caInfo = ccp.certificateAuthorities[CA_HOST];
    const ca     = new FabricCA(caInfo.url, { trustedRoots:caInfo.tlsCACerts.pem, verify:false }, caInfo.caName);
    const enroll = await ca.enroll({ enrollmentID:'admin', enrollmentSecret:'adminpw' });
    await wallet.put('admin', {
        credentials: { certificate:enroll.certificate, privateKey:enroll.key.toBytes() },
        mspId:MSP_ID, type:'X.509'
    });
    console.log('Admin enrolled.');
}

async function registerUser({ userID, role, affiliation='famu.fcss' }) {
    const VALID = ['admin','institution','student','verifier'];
    if (!VALID.includes(role)) throw new Error(`Invalid role: ${role}`);
    const ccp = loadProfile(); const wallet = await getWallet();
    if (await wallet.get(userID)) { console.log(`${userID} already enrolled.`); return; }
    const adminId = await wallet.get('admin');
    if (!adminId) throw new Error('Enroll admin first.');
    const caInfo  = ccp.certificateAuthorities[CA_HOST];
    const ca      = new FabricCA(caInfo.url, { trustedRoots:caInfo.tlsCACerts.pem, verify:false }, caInfo.caName);
    const provider = wallet.getProviderRegistry().getProvider(adminId.type);
    const adminUser = await provider.getUserContext(adminId, 'admin');
    const secret = await ca.register({
        affiliation, enrollmentID:userID, role:'client',
        attrs:[
            { name:'role',    value:role,        ecert:true },
            { name:'program', value:'FAMU-FCSS',  ecert:true },
        ],
    }, adminUser);
    const enroll = await ca.enroll({
        enrollmentID:userID, enrollmentSecret:secret,
        attr_reqs:[{ name:'role', optional:false }],
    });
    await wallet.put(userID, {
        credentials: { certificate:enroll.certificate, privateKey:enroll.key.toBytes() },
        mspId:MSP_ID, type:'X.509'
    });
    console.log(`Enrolled ${userID} (role: ${role})`);
}

async function getContract(userID) {
    const ccp = loadProfile(); const wallet = await getWallet();
    if (!await wallet.get(userID)) throw new Error(`Identity '${userID}' not found.`);
    const gateway = new Gateway();
    await gateway.connect(ccp, { wallet, identity:userID, discovery:{ enabled:true, asLocalhost:true } });
    const contract = (await gateway.getNetwork(CHANNEL)).getContract(CHAINCODE);
    return { contract, gateway };
}

module.exports = { enrollAdmin, registerUser, getContract };
