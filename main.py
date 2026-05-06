"""
E2EE reference design: server stores passphrase-encrypted private keys.

Same architecture as before, but every step is logged so you can see
which side of the wire is doing what.

  [CLIENT alice]  = code running locally on Alice's machine
  [SERVER]        = code running on the server (sees only what's logged)
  [WIRE alice->server]  = data crossing the network in that direction

If you only read the [SERVER] and [WIRE] lines, that's the attacker's view.
"""

import os
import secrets
from dataclasses import dataclass, field

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


# ---------------------------------------------------------------------------
# Tiny logging helper
# ---------------------------------------------------------------------------

def log(tag: str, msg: str) -> None:
    colors = {
        "CLIENT": "\033[36m",   # cyan
        "SERVER": "\033[33m",   # yellow
        "WIRE":   "\033[35m",   # magenta
        "STEP":   "\033[1;32m", # bold green
    }
    reset = "\033[0m"
    kind = tag.split()[0]
    color = colors.get(kind, "")
    print(f"{color}[{tag}]{reset} {msg}")


def step(title: str) -> None:
    print()
    log("STEP", f"━━ {title} ━━")


def short(b: bytes, n: int = 12) -> str:
    """Truncated hex for readability."""
    h = b.hex()
    return h if len(h) <= n * 2 else f"{h[:n]}…({len(b)}B)"


# ---------------------------------------------------------------------------
# Crypto primitives
# ---------------------------------------------------------------------------

ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_PARALLELISM = 4
ARGON2_OUTPUT_LEN = 64


def derive_keys(passphrase: str, salt: bytes, who: str) -> tuple[bytes, bytes]:
    log(f"CLIENT {who}", f"running Argon2id on passphrase + salt={short(salt)}")
    log(f"CLIENT {who}", f"  params: t={ARGON2_TIME_COST}, m={ARGON2_MEMORY_KIB} KiB, p={ARGON2_PARALLELISM}")
    raw = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_OUTPUT_LEN,
        type=Type.ID,
    )
    auth_key, wrap_key = raw[:32], raw[32:]
    log(f"CLIENT {who}", f"  -> auth_key = {short(auth_key)}  (will be sent to server)")
    log(f"CLIENT {who}", f"  -> wrap_key = {short(wrap_key)}  (STAYS LOCAL, never sent)")
    return auth_key, wrap_key


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def derive_message_key(shared_secret: bytes, context: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=context,
    ).derive(shared_secret)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


@dataclass
class UserRecord:
    salt: bytes
    auth_key_hash: bytes
    encrypted_private_key: bytes
    public_key: bytes


@dataclass
class Server:
    users: dict[str, UserRecord] = field(default_factory=dict)
    inbox: dict[str, list[tuple[str, bytes]]] = field(default_factory=dict)

    def register(self, username, salt, auth_key, encrypted_private_key, public_key):
        log("WIRE client->server", f"REGISTER user={username!r}")
        log("WIRE client->server", f"  salt={short(salt)} auth_key={short(auth_key)}")
        log("WIRE client->server", f"  encrypted_priv={short(encrypted_private_key)} public_key={short(public_key)}")

        if username in self.users:
            raise ValueError("username taken")

        log("SERVER", "hashing auth_key with SHA-256 before storing")
        digest = hashes.Hash(hashes.SHA256())
        digest.update(auth_key)
        auth_hash = digest.finalize()

        self.users[username] = UserRecord(
            salt=salt,
            auth_key_hash=auth_hash,
            encrypted_private_key=encrypted_private_key,
            public_key=public_key,
        )
        self.inbox[username] = []
        log("SERVER", f"stored record for {username!r}; cannot read their private key")

    def get_salt(self, username):
        log("WIRE client->server", f"GET_SALT user={username!r}")
        salt = self.users[username].salt
        log("WIRE server->client", f"  -> salt={short(salt)}")
        return salt

    def login(self, username, auth_key):
        log("WIRE client->server", f"LOGIN user={username!r} auth_key={short(auth_key)}")
        rec = self.users[username]
        digest = hashes.Hash(hashes.SHA256())
        digest.update(auth_key)
        if not secrets.compare_digest(digest.finalize(), rec.auth_key_hash):
            log("SERVER", "auth_key hash MISMATCH — rejecting")
            raise PermissionError("bad credentials")
        log("SERVER", "auth_key hash matches; returning encrypted_private_key blob")
        log("WIRE server->client", f"  -> encrypted_priv={short(rec.encrypted_private_key)}")
        return rec.encrypted_private_key

    def get_public_key(self, username):
        log("WIRE client->server", f"GET_PUBKEY user={username!r}")
        pub = self.users[username].public_key
        log("WIRE server->client", f"  -> public_key={short(pub)}")
        return pub

    def deliver(self, sender, recipient, ciphertext):
        log("WIRE client->server", f"DELIVER from={sender!r} to={recipient!r} ct={short(ciphertext)}")
        log("SERVER", f"queuing ciphertext in {recipient!r}'s inbox (cannot decrypt it)")
        self.inbox[recipient].append((sender, ciphertext))

    def fetch(self, username):
        log("WIRE client->server", f"FETCH user={username!r}")
        msgs, self.inbox[username] = self.inbox[username], []
        log("WIRE server->client", f"  -> {len(msgs)} message(s)")
        return msgs


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class Client:
    def __init__(self, username, server):
        self.username = username
        self.server = server
        self._private_key: X25519PrivateKey | None = None

    def register(self, passphrase):
        log(f"CLIENT {self.username}", f"register() called with passphrase (length={len(passphrase)})")
        log(f"CLIENT {self.username}", "generating random 16-byte salt")
        salt = os.urandom(16)

        auth_key, wrap_key = derive_keys(passphrase, salt, self.username)

        log(f"CLIENT {self.username}", "generating fresh X25519 keypair")
        priv = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        log(f"CLIENT {self.username}", f"  private_key (RAW, never leaves device) = {short(priv_bytes)}")
        log(f"CLIENT {self.username}", f"  public_key  (will be uploaded)         = {short(pub_bytes)}")

        log(f"CLIENT {self.username}", "wrapping private_key with AES-GCM under wrap_key (AAD=username)")
        encrypted_priv = aead_encrypt(wrap_key, priv_bytes, aad=self.username.encode())
        log(f"CLIENT {self.username}", f"  encrypted_priv = {short(encrypted_priv)}")

        self.server.register(self.username, salt, auth_key, encrypted_priv, pub_bytes)
        self._private_key = priv
        log(f"CLIENT {self.username}", "registration complete; private key held in RAM")

    def login(self, passphrase):
        log(f"CLIENT {self.username}", "login() called — fetching salt from server")
        salt = self.server.get_salt(self.username)

        auth_key, wrap_key = derive_keys(passphrase, salt, self.username)

        log(f"CLIENT {self.username}", "sending auth_key to server to retrieve encrypted private key")
        encrypted_priv = self.server.login(self.username, auth_key)

        log(f"CLIENT {self.username}", "decrypting private_key locally with wrap_key")
        priv_bytes = aead_decrypt(wrap_key, encrypted_priv, aad=self.username.encode())
        log(f"CLIENT {self.username}", f"  recovered private_key = {short(priv_bytes)}")
        self._private_key = X25519PrivateKey.from_private_bytes(priv_bytes)
        log(f"CLIENT {self.username}", "login complete; private key held in RAM")

    def send(self, recipient, message):
        assert self._private_key, "log in first"
        log(f"CLIENT {self.username}", f"send() to {recipient!r}: {message!r}")
        log(f"CLIENT {self.username}", f"fetching {recipient!r}'s public key")
        recipient_pub = X25519PublicKey.from_public_bytes(self.server.get_public_key(recipient))

        log(f"CLIENT {self.username}", f"performing X25519 ECDH(my_priv, {recipient}_pub)")
        shared = self._private_key.exchange(recipient_pub)
        log(f"CLIENT {self.username}", f"  shared_secret = {short(shared)}")

        ctx = f"{self.username}->{recipient}".encode()
        log(f"CLIENT {self.username}", f"deriving message key via HKDF(shared, info={ctx!r})")
        key = derive_message_key(shared, ctx)
        log(f"CLIENT {self.username}", f"  message_key = {short(key)}")

        log(f"CLIENT {self.username}", "encrypting plaintext with AES-GCM")
        ciphertext = aead_encrypt(key, message.encode())
        self.server.deliver(self.username, recipient, ciphertext)

    def inbox(self):
        assert self._private_key, "log in first"
        log(f"CLIENT {self.username}", "checking inbox")
        out = []
        for sender, ciphertext in self.server.fetch(self.username):
            log(f"CLIENT {self.username}", f"got ciphertext from {sender!r}; computing decryption key")
            sender_pub = X25519PublicKey.from_public_bytes(self.server.get_public_key(sender))
            shared = self._private_key.exchange(sender_pub)
            ctx = f"{sender}->{self.username}".encode()
            key = derive_message_key(shared, ctx)
            log(f"CLIENT {self.username}", f"  message_key = {short(key)} (matches what {sender} computed)")
            plaintext = aead_decrypt(key, ciphertext).decode()
            log(f"CLIENT {self.username}", f"  decrypted: {plaintext!r}")
            out.append((sender, plaintext))
        return out


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    server = Server()

    step("Alice registers")
    alice = Client("alice", server)
    alice.register("correct horse battery staple")

    step("Bob registers")
    bob = Client("bob", server)
    bob.register("hunter2-but-much-longer")

    step("Alice sends Bob a message")
    alice.send("bob", "hi bob — server can't read this")

    step("Bob logs in on a fresh device and reads inbox")
    bob_new_device = Client("bob", server)
    bob_new_device.login("hunter2-but-much-longer")
    bob_new_device.inbox()

    step("What the server actually has on disk for Alice")
    rec = server.users["alice"]
    print(f"  salt                  = {rec.salt.hex()}")
    print(f"  auth_key_hash         = {rec.auth_key_hash.hex()}")
    print(f"  encrypted_private_key = {rec.encrypted_private_key.hex()}")
    print(f"  public_key            = {rec.public_key.hex()}")
    print("  ^ none of this lets the server read Alice's messages")

    step("Wrong passphrase attempt")
    try:
        Client("alice", server).login("wrong passphrase")
    except PermissionError as e:
        log("CLIENT alice", f"login rejected as expected: {e}")