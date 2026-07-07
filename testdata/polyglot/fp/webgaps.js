// Safe-code plants for the FP measurement eval.
const axios = require("axios");
const fs = require("fs");
const path = require("path");

// PLANT-FP(js-safe-ssrf, CWE-918): constant, hard-coded URL.
const a = axios.get("https://api.internal.example.com/status");

// PLANT-FP(js-safe-path, CWE-22): basename strips directory traversal.
const b = fs.readFileSync(path.basename(req.query.file));

// PLANT-FP(js-safe-redirect, CWE-601): constant redirect target.
function go(res) { res.redirect("/dashboard"); }
