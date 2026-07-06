// Safe-code plants for the FP measurement eval (see fp/safe.py header).
// PLANT-FP(id, CWE) marks the correct, non-vulnerable form of a weakness
// class — flagging it is a measured false positive.

const crypto = require('crypto');
const { execFile } = require('child_process');

function safeQuery(db, name) {
  // PLANT-FP(js-safe-sql, CWE-89): parameterized query, value is bound.
  return db.query('SELECT * FROM users WHERE name = $1', [name]);
}

function safeExec() {
  // PLANT-FP(js-safe-exec, CWE-78): execFile with a constant argument array,
  // no shell interpolation.
  return execFile('ls', ['-la'], () => {});
}

function safeHash(data) {
  // PLANT-FP(js-safe-hash, CWE-328): SHA-256 is a strong hash.
  return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = { safeQuery, safeExec, safeHash };
