import os
import base64
from typing import Union, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, password)
    except Exception:
        return False

def derive_key(password: Union[str, bytes], salt: bytes) -> bytes:
    if isinstance(password, str):
        password = password.encode()
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID
    )

def derive_encryption_key(password: Union[str, bytes], salt: bytes | None = None) -> Tuple[bytes, bytes]:
    if isinstance(password, str):
        password = password.encode()
    if salt is None:
        salt = os.urandom(ARGON2_SALT_LEN)
    key = derive_key(password, salt)
    return key, salt

def encrypt_secret(password: Union[str, bytes], data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode()
    if isinstance(password, str):
        password = password.encode()
    salt = os.urandom(ARGON2_SALT_LEN)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, data, None)
    return base64.b64encode(salt + nonce + ct).decode()

def decrypt_secret(password: Union[str, bytes], enc: str) -> str:
    if isinstance(password, str):
        password = password.encode()
    raw = base64.b64decode(enc)
    salt, nonce, ct = raw[:ARGON2_SALT_LEN], raw[ARGON2_SALT_LEN:ARGON2_SALT_LEN+12], raw[ARGON2_SALT_LEN+12:]
    key = derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None).decode()
