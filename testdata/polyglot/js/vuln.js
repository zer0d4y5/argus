// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
const express = require('express');
const { exec } = require('child_process');
const app = express();

// Mock database object for demonstration purposes
const db = {
  query: (sql, callback) => {
    console.log(`Executing SQL: ${sql}`);
    if (callback) callback(null, { rows: [] });
  }
};

// (1) SQL injection: build a query string with string concatenation of user input and pass to db.query. (CWE-89)
app.get('/user', (req, res) => {
  const userId = req.query.id;
  // PLANT-GAP: SQL injection via string concatenation (CWE-89) — mock db object defeats taint rules; caught by no profile
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  db.query(query, (err, result) => {
    if (err) return res.status(500).send('Error');
    res.json(result);
  });
});

// (2) OS command injection: require("child_process").exec with a string concatenating user input. (CWE-78)
app.get('/ping', (req, res) => {
  const host = req.query.host;
  // PLANT(js-cmdi, min-profile=standard, CWE-78): OS command injection via exec with concatenated input
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    if (error) return res.send(stderr);
    res.send(stdout);
  });
});

// (3) Code injection: eval() of user-supplied input. (CWE-95)
app.get('/calc', (req, res) => {
  const expression = req.query.expr;
  // PLANT(js-eval, min-profile=fast, CWE-95): arbitrary code execution via eval
  try {
    const result = eval(expression);
    res.json({ result });
  } catch (e) {
    res.status(400).send('Invalid expression');
  }
});

// (4) Server-side XSS/reflected: res.send() an HTML string containing unescaped user input. (CWE-79)
app.get('/greet', (req, res) => {
  const name = req.query.name;
  // PLANT(js-xss, min-profile=standard, CWE-79): reflected XSS via unescaped user input in HTML response
  res.send(`<h1>Hello, ${name}!</h1>`);
});

module.exports = app;
