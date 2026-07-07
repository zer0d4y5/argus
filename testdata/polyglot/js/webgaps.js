// Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
// Web-gap classes caught by argus/curated rules the registry packs miss.
const axios = require("axios");
const fs = require("fs");

app.get("/proxy", (req, res) => {
  // PLANT(js-ssrf-web, min-profile=standard, CWE-918): request to a request-controlled URL (argus/curated)
  return axios.get(req.query.url);
});

app.get("/file", (req, res) => {
  // PLANT(js-path-web, min-profile=standard, CWE-22): fs read from unsanitized request input (argus/curated)
  return fs.readFileSync(req.query.file);
});

app.get("/go", (req, res) => {
  // PLANT(js-open-redirect, min-profile=standard, CWE-601): redirect to a request-controlled target (argus/curated)
  res.redirect(req.query.next);
});
