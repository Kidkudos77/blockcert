'use strict';
/** CertChain — IPFS Off-Chain Storage
 *  Full document → IPFS. Only SHA-256 hash → ledger.
 *  Integrity verified by re-hashing on retrieval.
 */
const { create } = require('ipfs-http-client');
const crypto     = require('crypto');
const fs         = require('fs');

const ipfs = create({ host:'localhost', port:5001, protocol:'http' });

async function storeDocument(obj) {
    const content = JSON.stringify(obj);
    const sha256  = crypto.createHash('sha256').update(content).digest('hex');
    const result  = await ipfs.add(content, { pin:true });
    return { cid:result.path, sha256Hash:sha256 };
}

async function retrieveDocument(cid, expectedHash) {
    const chunks = [];
    for await (const chunk of ipfs.cat(cid)) chunks.push(chunk);
    const content  = Buffer.concat(chunks).toString();
    const computed = crypto.createHash('sha256').update(content).digest('hex');
    if (computed !== expectedHash) return { verified:false, document:null };
    return { verified:true, document:JSON.parse(content) };
}

async function storeFile(filePath) {
    const buf    = fs.readFileSync(filePath);
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const result = await ipfs.add(buf, { pin:true });
    return { cid:result.path, sha256Hash:sha256 };
}

module.exports = { storeDocument, retrieveDocument, storeFile };
