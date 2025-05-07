import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
salt = os.urandom(16)
# derive
kdf = Argon2id(
    salt=salt,
    length=32,
    iterations=1,
    lanes=4,
    memory_cost=64 * 1024,
    ad=None,
    secret=None,
)
key = kdf.derive(b"my great password")
# verify
kdf = Argon2id(
    salt=salt,
    length=32,
    iterations=1,
    lanes=4,
    memory_cost=64 * 1024,
    ad=None,
    secret=None,
)
kdf.verify(b"my great paasdssword", key)