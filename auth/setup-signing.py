"""Generate gateway private and runner public keys once; never display keys."""
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

root = Path(__file__).resolve().parent / ".runtime"
root.mkdir(mode=0o700, exist_ok=True)
private = root / "gateway-signing.pem"
if private.exists():
    key = serialization.load_pem_private_key(private.read_bytes(), password=None)
else:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
public = root / "gateway-verify.pem"
public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo))
print("Gateway signing key preserved/generated; public verification key updated. Keys were not printed.")
