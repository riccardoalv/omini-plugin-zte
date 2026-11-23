"""The cryptography of the ZTE web interface (as its JavaScript does it).

- **Login**: the password is sent as ``sha256(password + random)``, the random
  number coming from ``login_token`` just before.
- **Integrity check**: every change (a POST) carries a ``Check`` header, the
  hex SHA-256 of the whole body encrypted with the device's RSA public key
  (PKCS#1 v1.5, base64). The key is the same on every unit of this firmware
  family; it is in the web interface's own code.
- **Secret fields** (Wi-Fi passwords) travel encrypted: AES-256-CBC with zero
  padding, the key the SHA-256 of a random 16-digit string and the IV the first
  16 bytes of the SHA-256 of another, and both strings sent RSA-encrypted in
  the ``encode`` field (``key+iv``). Secret values the device sends back are
  encrypted the same way with the page's session token as key and the token
  reversed as IV.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# From the web interface (asyEncode in its JavaScript).
PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodPTerkUVCYmv28SOfRV
7UKHVujx/HjCUTAWy9l0L5H0JV0LfDudTdMNPEKloZsNam3YrtEnq6jqMLJV4ASb
1d6axmIgJ636wyTUS99gj4BKs6bQSTUSE8h/QkUYv4gEIt3saMS0pZpd90y6+B/9
hZxZE/RKU8e+zgRqp1/762TB7vcjtjOwXRDEL0w71Jk9i8VUQ59MR1Uj5E8X3WIc
fYSK5RWBkMhfaTRM6ozS9Bqhi40xlSOb3GBxCmliCifOJNLoO9kFoWgAIw5hkSIb
GH+4Csop9Uy8VvmmB+B3ubFLN35qIa5OG5+SDXn4L7FeAA5lRiGxRi8tsWrtew8w
nwIDAQAB
-----END PUBLIC KEY-----"""


def public_key(pem: bytes = PUBLIC_KEY) -> RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    assert isinstance(key, RSAPublicKey)
    return key


def login_hash(password: str, random: str) -> str:
    return hashlib.sha256((password + random).encode()).hexdigest()


def rsa_b64(key: RSAPublicKey, text: str) -> str:
    return base64.b64encode(key.encrypt(text.encode(), padding.PKCS1v15())).decode()


def check_header(key: RSAPublicKey, body: str) -> str:
    return rsa_b64(key, hashlib.sha256(body.encode()).hexdigest())


def _cipher(key: str, iv: str) -> Cipher:
    k = hashlib.sha256(key.encode()).digest()
    v = hashlib.sha256(iv.encode()).digest()[:16]
    return Cipher(algorithms.AES(k), modes.CBC(v))


def aes_encrypt(text: str, key: str, iv: str) -> str:
    data = text.encode()
    data += b"\0" * (-len(data) % 16)
    e = _cipher(key, iv).encryptor()
    return base64.b64encode(e.update(data) + e.finalize()).decode()


def aes_decrypt(value: str, key: str, iv: str) -> str:
    d = _cipher(key, iv).decryptor()
    raw = d.update(base64.b64decode(value)) + d.finalize()
    return raw.rstrip(b"\0").decode()


def random_digits(n: int = 16) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(n))
