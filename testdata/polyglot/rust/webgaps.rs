// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Web-gap classes caught by argus/curated rules the registry packs miss.
use std::process::Command;

fn cmdi(user: &str) {
    // PLANT(rust-shell-cmdi, min-profile=standard, CWE-78): shell command built from input (argus/curated)
    Command::new("sh").arg("-c").arg(format!("echo {}", user)).output().unwrap();
}

fn sqli(name: &str) {
    // PLANT(rust-sqli-format, min-profile=standard, CWE-89): SQL built with format! (argus/curated)
    let _q = sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", name));
}

fn secret() {
    // PLANT(rust-hardcoded-key, min-profile=standard, CWE-798): hardcoded AWS access key (argus/curated)
    let key = "AKIAIOSFODNN7ABCDEF9";
    println!("{}", key);
}
