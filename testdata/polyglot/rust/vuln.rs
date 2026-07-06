// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Never compiled; exists only to be scanned by semgrep (p/rust, in standard).
//
// Labels: PLANT(id, min-profile, CWE) = a plant the recall eval asserts caught
// at that profile; PLANT-GAP = a real weakness NO curated profile catches, so
// it is honest documentation (docs/coverage.md Known gaps), never a silent
// miss. p/rust is thin (a handful of rules); the gaps below say so.

use std::process::Command;

fn take_input() -> String {
    // PLANT(rust-untrusted-input, min-profile=standard, CWE-807): p/rust flags
    // a security decision driven by untrusted process arguments.
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "admin" {
        return std::env::args().nth(2).unwrap_or_default();
    }
    mode
}

fn sqli(user_input: &str) {
    // PLANT-GAP: SQL injection via format! into the query (CWE-89) — p/rust
    // has no taint rule for rusqlite; uncaught by every profile.
    let query = format!("SELECT * FROM users WHERE name = '{}'", user_input);
    let conn = rusqlite::Connection::open("app.db").unwrap();
    conn.execute(&query, []).unwrap();
}

fn cmdi(user_input: &str) {
    // PLANT-GAP: OS command injection via sh -c with concatenated input
    // (CWE-78) — uncaught.
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("echo {}", user_input))
        .output()
        .unwrap();
    let _ = out;
}

fn weak_hash(user_input: &str) {
    // PLANT-GAP: MD5 over sensitive input (CWE-328) — uncaught.
    let digest = md5::compute(user_input.as_bytes());
    let _ = digest;
}

fn insecure_tls() {
    // PLANT-GAP: TLS certificate verification disabled (CWE-295) — uncaught.
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let _ = client.get("https://internal.example").send();
}

fn unsafe_mem(user_input: &str) {
    // PLANT(rust-unsafe-fn, min-profile=standard, CWE-242): p/rust flags the
    // use of an inherently dangerous construct — a raw-pointer deref in an
    // unsafe block reading past the slice bound.
    let bytes = user_input.as_bytes();
    unsafe {
        let p = bytes.as_ptr();
        let _v = *p.add(bytes.len());
    }
}

fn main() {
    let input = take_input();
    sqli(&input);
    cmdi(&input);
    weak_hash(&input);
    insecure_tls();
    unsafe_mem(&input);
}
