// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();

// --- STATIC ASSETS ---
// Serve everything in /public at root (/runtime.js, /styles.css, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// --- LOAD KEYS ---
const PRIVATE_PEM = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'), 'utf8');
const PUBLIC_PEM = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'), 'utf8');

// --- MASTER FLO FILE ---
const MASTER_FLO_PATH = path.join(__dirname, 'home.flo');
if (!fs.existsSync(MASTER_FLO_PATH)) {
  console.error('❌ Missing master FLO file: home.flo');
  process.exit(1);
}

// --- FLO COMPILER ---
function compileFLOtoHTML(floSource, context = {}) {
  let html = floSource.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, v) => context[v] || '');
  return html
    .replace(/<flo:page[^>]*title="([^"]+)"[^>]*>/g, '<div class="flo-page" data-title="$1">')
    .replace(/<\/flo:page>/g, '</div>')
    .replace(/<flo:header>/g, '<header class="flo-header">').replace(/<\/flo:header>/g, '</header>')
    .replace(/<flo:nav>/g, '<nav class="flo-nav">').replace(/<\/flo:nav>/g, '</nav>')
    .replace(/<flo:logo>/g, '<div class="flo-logo">').replace(/<\/flo:logo>/g, '</div>')
    .replace(/<flo:main>/g, '<main class="flo-main">').replace(/<\/flo:main>/g, '</main>')
    .replace(/<flo:card[^>]*title="([^"]+)"[^>]*>/g, '<section class="flo-card" data-title="$1">')
    .replace(/<\/flo:card>/g, '</section>')
    .replace(/<flo:footer>/g, '<footer class="flo-footer">').replace(/<\/flo:footer>/g, '</footer>')
    .replace(/<flo:link href="([^"]+)"[^>]*>(.*?)<\/flo:link>/g, '<a href="$1" class="flo-link">$2</a>');
}

// --- SIGN FLO ---
function signString(privatePem, str) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(str, 'utf8');
  return signer.sign(privatePem, 'base64');
}

// --- SHELL BUILDER ---
function buildShell(floSource) {
  const signatureBase64 = signString(PRIVATE_PEM, floSource);
  const floB64 = Buffer.from(floSource, 'utf8').toString('base64');

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>FLO Master</title>
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self';">
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  <!-- Encoded FLO payload -->
  <script id="flo-payload" type="application/flo+base64">${floB64}</script>
  <script id="flo-signature" type="application/flo-signature">${signatureBase64}</script>
  <script id="flo-public-pem" type="application/flo-public-pem">${PUBLIC_PEM}</script>
  <script src="/runtime.js" defer></script>
</body>
</html>`;
}

// --- ROUTES ---

// Serve only .flo files under /flocode/
app.get('/flocode/:file', (req, res) => {
  const file = req.params.file;

  // Reject anything that isn’t a .flo file
  if (!file.endsWith('.flo')) {
    return res.status(404).send('Not a FLO file');
  }

  // For now, always serve the master FLO file
  const floSource = fs.readFileSync(MASTER_FLO_PATH, 'utf8');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(buildShell(floSource));
});

// Root -> serve master FLO page
app.get('/', (req, res) => {
  const floSource = fs.readFileSync(MASTER_FLO_PATH, 'utf8');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(buildShell(floSource));
});

// Optional SSR (SEO/debugging)
app.get('/ssr', (req, res) => {
  const floSource = fs.readFileSync(MASTER_FLO_PATH, 'utf8');
  const html = compileFLOtoHTML(floSource, { user: 'Scholar (SSR)' });
  res.send(`<!doctype html><html><head><meta charset="utf-8"><title>FLO SSR</title></head><body>${html}</body></html>`);
});

// --- START SERVER ---
const PORT = process.env.PORT || 30006;
app.listen(PORT, () => console.log(`🚀 FLO demo server running: http://localhost:${PORT}`));
