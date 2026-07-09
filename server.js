/**
 * E2E test server with intentional vulnerabilities for Constantine pipeline.
 * DO NOT use in production.
 */

const http = require("http");
const { exec } = require("child_process");
const { execSync } = require("child_process");

const PORT = 3000;

// Intentional: Command injection — user input passed to exec (CWE-78)
function handlePing(req, res, url) {
  const u = new URL(url, "http://localhost");
  const host = u.searchParams.get("host") || "127.0.0.1";
  const cmd = `ping -c 3 ${host}`;
  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      res.writeHead(500);
      res.end("Ping failed: " + err.message);
      return;
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(stdout || stderr);
  });
}

// Intentional: Sync command execution with user-controlled input (CWE-78)
function handleWhoami(req, res, url) {
  const u = new URL(url, "http://localhost");
  const user = u.searchParams.get("user") || "";
  const result = execSync("id " + user, { encoding: "utf-8" });
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end(result);
}

const server = http.createServer((req, res) => {
  const url = "http://localhost" + req.url;
  if (req.url.startsWith("/ping")) {
    handlePing(req, res, url);
    return;
  }
  if (req.url.startsWith("/whoami")) {
    handleWhoami(req, res, url);
    return;
  }
  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log("E2E vulnerable app listening on port", PORT);
});
