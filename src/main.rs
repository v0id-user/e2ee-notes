// E2EE notes server.
// Stores only ciphertext + an Argon2id-derived auth_key hash.
// All crypto (Argon2id, AES-GCM) happens in the browser.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;
use tower_http::services::ServeDir;
use uuid::Uuid;

#[derive(Default, Serialize, Deserialize, Clone)]
struct Db {
    users: HashMap<String, User>,
}

#[derive(Serialize, Deserialize, Clone)]
struct User {
    salt: String,           // base64 (browser format)
    auth_key_hash: String,  // hex of SHA-256(auth_key)
    notes: Vec<Note>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Note {
    id: String,
    blob: String, // base64 ciphertext (nonce || AES-GCM(ct))
    created: u64,
}

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Db>>,
    sessions: Arc<Mutex<HashMap<String, String>>>,
    db_path: String,
}

async fn save(state: &AppState) {
    let snapshot = state.db.lock().unwrap().clone();
    let json = serde_json::to_string_pretty(&snapshot).unwrap();
    let _ = tokio::fs::write(&state.db_path, json).await;
}

async fn load(path: &str) -> Db {
    match tokio::fs::read_to_string(path).await {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Db::default(),
    }
}

fn err(code: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (code, Json(serde_json::json!({ "error": msg })))
}

fn auth(state: &AppState, token: &str) -> Option<String> {
    state.sessions.lock().unwrap().get(token).cloned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[derive(Deserialize)]
struct RegisterReq {
    username: String,
    salt: String,
    auth_key_hex: String,
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if req.username.is_empty() || req.username.len() > 64 {
        return Err(err(StatusCode::BAD_REQUEST, "bad username"));
    }
    let auth_key = hex::decode(&req.auth_key_hex)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad auth_key_hex"))?;
    let hash = sha256_hex(&auth_key);

    {
        let mut db = state.db.lock().unwrap();
        if db.users.contains_key(&req.username) {
            return Err(err(StatusCode::CONFLICT, "username taken"));
        }
        db.users.insert(
            req.username.clone(),
            User {
                salt: req.salt,
                auth_key_hash: hash,
                notes: vec![],
            },
        );
    }
    save(&state).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn get_salt(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let db = state.db.lock().unwrap();
    let user = db
        .users
        .get(&username)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such user"))?;
    Ok(Json(serde_json::json!({ "salt": user.salt })))
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    auth_key_hex: String,
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let auth_key = hex::decode(&req.auth_key_hex)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad auth_key_hex"))?;
    let computed = sha256_hex(&auth_key);

    let stored = {
        let db = state.db.lock().unwrap();
        db.users
            .get(&req.username)
            .map(|u| u.auth_key_hash.clone())
    };
    let stored = stored.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "bad credentials"))?;

    if computed.as_bytes().ct_eq(stored.as_bytes()).unwrap_u8() != 1 {
        return Err(err(StatusCode::UNAUTHORIZED, "bad credentials"));
    }

    let token = Uuid::new_v4().to_string();
    state
        .sessions
        .lock()
        .unwrap()
        .insert(token.clone(), req.username);
    Ok(Json(serde_json::json!({ "token": token })))
}

#[derive(Deserialize)]
struct TokenReq {
    token: String,
}

async fn list_notes(
    State(state): State<AppState>,
    Json(req): Json<TokenReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let username = auth(&state, &req.token)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "bad token"))?;
    let db = state.db.lock().unwrap();
    let user = db
        .users
        .get(&username)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such user"))?;
    Ok(Json(serde_json::json!({ "notes": user.notes })))
}

#[derive(Deserialize)]
struct AddNoteReq {
    token: String,
    blob: String,
}

async fn add_note(
    State(state): State<AppState>,
    Json(req): Json<AddNoteReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let username = auth(&state, &req.token)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "bad token"))?;
    let id = Uuid::new_v4().to_string();
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    {
        let mut db = state.db.lock().unwrap();
        let user = db
            .users
            .get_mut(&username)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such user"))?;
        user.notes.push(Note {
            id: id.clone(),
            blob: req.blob,
            created,
        });
    }
    save(&state).await;
    Ok(Json(serde_json::json!({ "id": id, "created": created })))
}

#[derive(Deserialize)]
struct DeleteNoteReq {
    token: String,
}

async fn delete_note(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<DeleteNoteReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let username = auth(&state, &req.token)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "bad token"))?;
    {
        let mut db = state.db.lock().unwrap();
        let user = db
            .users
            .get_mut(&username)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such user"))?;
        let before = user.notes.len();
        user.notes.retain(|n| n.id != id);
        if user.notes.len() == before {
            return Err(err(StatusCode::NOT_FOUND, "note not found"));
        }
    }
    save(&state).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn debug_dump(State(state): State<AppState>) -> impl IntoResponse {
    // Everything the server knows. The whole point: even given all of this,
    // an attacker still cannot read a note without brute-forcing a passphrase.
    let db = state.db.lock().unwrap().clone();
    let sessions: Vec<_> = state
        .sessions
        .lock()
        .unwrap()
        .iter()
        .map(|(t, u)| serde_json::json!({ "token": t, "username": u }))
        .collect();

    let total_notes: usize = db.users.values().map(|u| u.notes.len()).sum();
    let total_blob_bytes: usize = db
        .users
        .values()
        .flat_map(|u| u.notes.iter())
        .map(|n| n.blob.len())
        .sum();
    let on_disk_size = tokio::fs::metadata(&state.db_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);

    Json(serde_json::json!({
        "config": {
            "db_path": state.db_path,
            "on_disk_bytes": on_disk_size,
            "auth_key_hash_algo": "SHA-256",
            "expected_browser_argon2id": {
                "iterations": 3,
                "memory_kib": 64 * 1024,
                "parallelism": 4,
                "output_len_bytes": 64,
                "split": "first 32B = auth_key (sent), last 32B = wrap_key (kept in browser)"
            },
            "expected_browser_aead": "AES-GCM, 12-byte random nonce, blob = nonce || ciphertext (base64)"
        },
        "stats": {
            "user_count": db.users.len(),
            "session_count": sessions.len(),
            "note_count": total_notes,
            "ciphertext_bytes_total": total_blob_bytes,
        },
        "users": db.users,
        "sessions": sessions,
        "note": "this endpoint dumps every byte the server holds. nothing here is enough to read a note."
    }))
}

#[tokio::main]
async fn main() {
    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "data.json".into());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    let state = AppState {
        db: Arc::new(Mutex::new(load(&db_path).await)),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        db_path,
    };

    let app = Router::new()
        .route("/api/register", post(register))
        .route("/api/salt/:username", get(get_salt))
        .route("/api/login", post(login))
        .route("/api/notes", post(list_notes))
        .route("/api/notes/add", post(add_note))
        .route("/api/notes/:id", delete(delete_note))
        .route("/api/_debug/dump", get(debug_dump))
        .fallback_service(ServeDir::new("static"))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
