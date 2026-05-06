# e2ee-notes

Tiny experiment: a private notes web app where the server only ever sees
ciphertext. Rust on the backend, vanilla JS in the browser, all crypto
client-side.

Companion writeup: [Storing Private Keys on Servers](https://www.v0id.me/posts/storing-private-keys-on-servers).

## What the server stores

For each user, only:

- `salt` — random 16 bytes
- `auth_key_hash` — `SHA-256(auth_key)` where `auth_key` came out of Argon2id
- `notes` — list of opaque base64 blobs

Hit <http://localhost:3000/api/_debug/dump> while the server is running to
see exactly that — there's no hidden second copy.

## What the browser does

1. `Argon2id(passphrase, salt)` → 64 bytes
2. Split: first 32 = `auth_key` (sent to server), last 32 = `wrap_key`
   (never leaves the browser)
3. Each note: `AES-GCM(wrap_key, random_nonce, plaintext)` →
   `nonce || ciphertext`, base64'd, uploaded

`wrap_key` only exists in browser memory. If the server is fully compromised
or subpoenaed, an attacker has the salt, the SHA-256 of `auth_key`, and a
pile of AES-GCM ciphertext. Recovering plaintext requires brute-forcing the
passphrase through Argon2id (`t=3, m=64MiB, p=4`) — slow on purpose.

## Run it

```sh
cargo run --release
# open http://localhost:3000
```

Env vars: `PORT` (default `3000`), `DB_PATH` (default `data.json`).

Data persists to a JSON file. Delete it to wipe state.

## API (so you can poke at it)

| method | path                    | body                                              |
| ------ | ----------------------- | ------------------------------------------------- |
| POST   | `/api/register`         | `{ username, salt, auth_key_hex }`                |
| GET    | `/api/salt/:username`   | —                                                 |
| POST   | `/api/login`            | `{ username, auth_key_hex }` → `{ token }`        |
| POST   | `/api/notes`            | `{ token }` → `{ notes: [{ id, blob, created }] }`|
| POST   | `/api/notes/add`        | `{ token, blob }`                                 |
| DELETE | `/api/notes/:id`        | `{ token }`                                       |
| GET    | `/api/_debug/dump`      | full DB (proves nothing private is stored)        |

## What this is NOT

- Not a finished product. Sessions live in memory; restart = log out. No
  password change, no account recovery, no rate limiting, no CSRF token.
- Not audited. It's a one-evening experiment to make the Python reference
  tangible in a browser.
- Not magic. If you pick `password123` as your passphrase, Argon2id will not
  save you.
