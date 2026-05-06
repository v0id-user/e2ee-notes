// Browser-side E2EE for the notes app.
// Argon2id(passphrase, salt) -> 64 bytes -> [auth_key (32B) | wrap_key (32B)].
// auth_key goes to the server; wrap_key never leaves this browser.
// Notes are AES-GCM(wrap_key, nonce, plaintext) before upload.

import { argon2id } from "https://esm.sh/hash-wasm@4.11.0";

const ARGON2 = { iterations: 3, memorySize: 64 * 1024, parallelism: 4, hashLength: 64 };

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

const session = { token: null, username: null, wrapKey: null };

// ---------- helpers ----------

const toHex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

const toB64 = (buf) => {
  const a = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s);
};

const fromB64 = (s) => {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

const setStatus = (text, kind = "") => {
  const el = $("status");
  el.textContent = text;
  el.className = kind;
};

async function api(path, body, method = "POST") {
  const res = await fetch(path, {
    method,
    headers: body ? { "content-type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function deriveKeys(passphrase, saltBytes) {
  const raw = await argon2id({
    password: passphrase,
    salt: saltBytes,
    ...ARGON2,
    outputType: "binary",
  });
  return {
    authKey: raw.slice(0, 32),
    wrapKey: await crypto.subtle.importKey(
      "raw",
      raw.slice(32, 64),
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    ),
  };
}

async function encryptNote(plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    session.wrapKey,
    enc.encode(plaintext),
  );
  const blob = new Uint8Array(nonce.length + ct.byteLength);
  blob.set(nonce, 0);
  blob.set(new Uint8Array(ct), nonce.length);
  return toB64(blob);
}

async function decryptNote(blobB64) {
  const blob = fromB64(blobB64);
  const nonce = blob.slice(0, 12);
  const ct = blob.slice(12);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      session.wrapKey,
      ct,
    );
    return dec.decode(pt);
  } catch {
    return "[failed to decrypt]";
  }
}

// ---------- flows ----------

async function register() {
  const username = $("username").value.trim();
  const passphrase = $("passphrase").value;
  if (!username || !passphrase) return setStatus("need username + passphrase", "err");

  setStatus("deriving keys (this is intentionally slow)...");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const { authKey, wrapKey } = await deriveKeys(passphrase, salt);

  await api("/api/register", {
    username,
    salt: toB64(salt),
    auth_key_hex: toHex(authKey),
  });

  // server has nothing private; log straight in to grab a session token.
  const { token } = await api("/api/login", { username, auth_key_hex: toHex(authKey) });
  session.token = token;
  session.username = username;
  session.wrapKey = wrapKey;
  setStatus("registered + logged in", "ok");
  showApp();
  await refreshNotes();
}

async function login() {
  const username = $("username").value.trim();
  const passphrase = $("passphrase").value;
  if (!username || !passphrase) return setStatus("need username + passphrase", "err");

  setStatus("deriving keys (this is intentionally slow)...");
  const { salt } = await api(`/api/salt/${encodeURIComponent(username)}`, null, "GET");
  const { authKey, wrapKey } = await deriveKeys(passphrase, fromB64(salt));

  const { token } = await api("/api/login", { username, auth_key_hex: toHex(authKey) });
  session.token = token;
  session.username = username;
  session.wrapKey = wrapKey;
  setStatus("logged in", "ok");
  showApp();
  await refreshNotes();
}

function logout() {
  session.token = null;
  session.username = null;
  session.wrapKey = null;
  $("app").hidden = true;
  $("auth").hidden = false;
  $("passphrase").value = "";
  $("notes").innerHTML = "";
  setStatus("logged out");
}

function showApp() {
  $("auth").hidden = true;
  $("app").hidden = false;
  $("who").textContent = session.username;
}

async function refreshNotes() {
  const { notes } = await api("/api/notes", { token: session.token });
  notes.sort((a, b) => b.created - a.created);
  const ul = $("notes");
  ul.innerHTML = "";
  for (const n of notes) {
    const text = await decryptNote(n.blob);
    const li = document.createElement("li");
    const body = document.createElement("div");
    body.className = "body";
    body.textContent = text;
    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = new Date(n.created * 1000).toLocaleString();
    body.appendChild(meta);
    const del = document.createElement("button");
    del.className = "danger";
    del.textContent = "delete";
    del.onclick = () => deleteNote(n.id);
    li.appendChild(body);
    li.appendChild(del);
    ul.appendChild(li);
  }
}

async function addNote() {
  const text = $("note-input").value;
  if (!text.trim()) return;
  const blob = await encryptNote(text);
  await api("/api/notes/add", { token: session.token, blob });
  $("note-input").value = "";
  await refreshNotes();
}

async function deleteNote(id) {
  await api(`/api/notes/${id}`, { token: session.token }, "DELETE");
  await refreshNotes();
}

function wrap(fn) {
  return async (...a) => {
    try {
      await fn(...a);
    } catch (e) {
      console.error(e);
      setStatus(e.message || String(e), "err");
    }
  };
}

$("register-btn").onclick = wrap(register);
$("login-btn").onclick = wrap(login);
$("logout-btn").onclick = logout;
$("add-btn").onclick = wrap(addNote);
