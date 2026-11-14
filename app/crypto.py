import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def generate_keypairs() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    priv_b = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

    pub_b = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv_b).decode(), base64.b64encode(pub_b).decode()

def canonical(payload: dict) -> bytes:
    return json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()

def sign(private_key_b64: str, payload: dict) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    signature = private_key.sign(canonical(payload))
    return base64.b64encode(signature).decode()

def verify(public_key_b64: str, payload: dict, signature_b64: str) -> bool:
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    try:
        public_key.verify(base64.b64decode(signature_b64), canonical(payload))
        return True
    except InvalidSignature:
        return False

