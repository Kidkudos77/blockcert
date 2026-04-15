"""
BlockCert — Post-Quantum Cryptographic Layer
==============================================
CRYSTALS-Dilithium signatures on top of Hyperledger Fabric credential hashing.

Thesis contribution:
  No micro-credentialing paper in the reviewed literature addresses
  post-quantum cryptography. BlockCert adds CRYSTALS-Dilithium3 —
  a NIST Post-Quantum Cryptography standard — to sign credential hashes
  before on-chain storage, making issued credentials cryptographically
  valid against future quantum computing attacks.

Scope clarification (important for thesis writing):
  This layer signs the credential hash at issuance time.
  It does NOT replace Hyperledger Fabric's internal consensus cryptography.
  It adds a forward-looking signature that verifiers can check independently
  of the Fabric network.

Install:
  pip install dilithium-py

References:
  NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
  Dilithium: Ducas et al., "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme"
"""

import json, hashlib, os
from datetime import datetime

try:
    from dilithium_py.dilithium import Dilithium3
    PQ_AVAILABLE = True
except ImportError:
    PQ_AVAILABLE = False
    print('WARNING: dilithium-py not installed. Run: pip install dilithium-py')
    print('Post-quantum signatures will be skipped until installed.')


class PostQuantumSigner:
    """
    Signs BlockCert credential hashes using CRYSTALS-Dilithium3.

    Each instance generates a fresh keypair.
    In production, the institution's keypair is generated once,
    the private key stored securely (HSM or encrypted vault),
    and the public key published for verifier use.
    """

    def __init__(self, key_dir: str = 'quantum/keys'):
        if not PQ_AVAILABLE:
            self.available = False
            return

        self.available = True
        self.key_dir   = key_dir
        os.makedirs(key_dir, exist_ok=True)

        pk_path = os.path.join(key_dir, 'dilithium3.pk')
        sk_path = os.path.join(key_dir, 'dilithium3.sk')

        if os.path.exists(pk_path) and os.path.exists(sk_path):
            # Load existing keypair
            with open(pk_path, 'rb') as f: self.pk = f.read()
            with open(sk_path, 'rb') as f: self.sk = f.read()
            print('Post-quantum keypair loaded from disk.')
        else:
            # Generate new keypair
            self.pk, self.sk = Dilithium3.keygen()
            with open(pk_path, 'wb') as f: f.write(self.pk)
            with open(sk_path, 'wb') as f: f.write(self.sk)
            print('New post-quantum keypair generated and saved.')

    def sign_credential(self, credential_dict: dict) -> dict:
        """
        Signs a credential object with Dilithium3.

        Returns a PQ signature bundle that is stored alongside
        the credential (on IPFS) and referenced on-chain.

        The SHA-256 hash is what Hyperledger Fabric stores on-chain.
        The Dilithium signature provides the post-quantum proof layer.
        """
        if not self.available:
            return {
                'pq_available':  False,
                'message':       'Install dilithium-py to enable post-quantum signatures.',
            }

        content  = json.dumps(credential_dict, sort_keys=True).encode('utf-8')
        sha256   = hashlib.sha256(content).hexdigest()

        # Sign the SHA-256 hash bytes with Dilithium3
        sig = Dilithium3.sign(self.sk, bytes.fromhex(sha256))

        return {
            'pq_available':  True,
            'sha256_hash':   sha256,
            'pq_signature':  sig.hex(),
            'pq_algorithm':  'CRYSTALS-Dilithium3',
            'pq_public_key': self.pk.hex(),
            'signed_at':     datetime.utcnow().isoformat() + 'Z',
            'nist_standard': 'FIPS 204 (ML-DSA)',
        }

    def verify_signature(self, credential_dict: dict, pq_sig_hex: str,
                         pk_hex: str = None) -> dict:
        """
        Verifies a Dilithium3 signature on a credential.
        Can use the instance's public key or a provided external key.
        """
        if not self.available:
            return {'verified': False, 'reason': 'dilithium-py not installed.'}

        pk = bytes.fromhex(pk_hex) if pk_hex else self.pk

        try:
            content  = json.dumps(credential_dict, sort_keys=True).encode('utf-8')
            sha256   = hashlib.sha256(content).hexdigest()
            verified = Dilithium3.verify(pk, bytes.fromhex(sha256),
                                         bytes.fromhex(pq_sig_hex))
            return {
                'verified':     verified,
                'sha256_hash':  sha256,
                'algorithm':    'CRYSTALS-Dilithium3',
            }
        except Exception as e:
            return {'verified': False, 'reason': str(e)}

    def get_public_key_hex(self) -> str:
        """Returns the public key as hex string for distribution to verifiers."""
        return self.pk.hex() if self.available else ''


# ── Module-level singleton (one signer per deployment) ───────────────────────
_signer = None

def get_signer(key_dir: str = 'quantum/keys') -> PostQuantumSigner:
    global _signer
    if _signer is None:
        _signer = PostQuantumSigner(key_dir=key_dir)
    return _signer


if __name__ == '__main__':
    signer = PostQuantumSigner()

    test_cred = {
        'credentialID':    'BLOCKCERT-FAMU10001-abc123',
        'studentID':       'FAMU10001',
        'program':         'FAMU-FCSS',
        'eligibility_score': 0.84,
        'issuedAt':        datetime.utcnow().isoformat(),
    }

    print('\n=== Signing credential ===')
    sig_bundle = signer.sign_credential(test_cred)
    print(json.dumps({k: v[:32]+'...' if isinstance(v,str) and len(v)>32 else v
                      for k,v in sig_bundle.items()}, indent=2))

    print('\n=== Verifying signature ===')
    result = signer.verify_signature(test_cred, sig_bundle['pq_signature'])
    print(json.dumps(result, indent=2))
