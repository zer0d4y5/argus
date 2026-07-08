// Safe-code plants for the FP measurement eval.
use std::process::Command;

// PLANT-FP(rust-safe-cmdi, CWE-78): no shell, argument passed directly.
fn run(user: &str) { Command::new("echo").arg(user).output().unwrap(); }

// PLANT-FP(rust-safe-sqli, CWE-89): parameterized query, no format!.
fn lookup(name: &str) { let _q = sqlx::query("SELECT * FROM users WHERE name = $1").bind(name); }

// PLANT-FP(rust-safe-secret, CWE-798): loaded from the environment.
fn key() -> String { std::env::var("AWS_ACCESS_KEY_ID").unwrap() }
