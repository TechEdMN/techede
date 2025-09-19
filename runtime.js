/* public/runtime.js
   Minimal FLO client runtime:
   - reads base64 FLO blob and signature from the shell
   - imports server public key (PEM)
   - verifies signature using WebCrypto
   - compiles FLO -> HTML (same rules as server)
   - renders into document.body
*/

(async function () {
  // Helpers ----------------------------------------------------------------

  function pemToArrayBuffer(pem) {
    // remove PEM header/footer and newlines, base64-decode
    const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----/, '')
                   .replace(/-----END PUBLIC KEY-----/, '')
                   .replace(/\s+/g, '');
    const binaryDer = atob(b64);
    const len = binaryDer.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binaryDer.charCodeAt(i);
    return bytes.buffer;
  }

  async function importPublicKey(pem) {
    const spki = pemToArrayBuffer(pem);
    return crypto.subtle.importKey(
      'spki',
      spki,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['verify']
    );
  }

  async function verifySignature(publicKey, signatureB64, dataStr) {
    const sigBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));
    const enc = new TextEncoder().encode(dataStr);
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, sigBytes, enc);
  }

  // FLO client compile (mirror of server's mapping) -------------------------
  function clientCompileFLO(src, context = {}) {
    // Very small deterministic transform. Avoid innerHTML where possible.
    // For this demo we produce HTML strings, but sanitize or use DOM APIs for production.
    let html = src;
    // interpolate variables {{ var }}
    html = html.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, v) => {
      return context[v] !== undefined ? String(context[v]) : '';
    });

    // simple flo tag -> html mapping (keep one-to-one and deterministic)
    html = html
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

    return html;
  }

  // Main runtime flow ------------------------------------------------------
  try {
    const payloadEl = document.getElementById('flo-payload');
    const sigEl = document.getElementById('flo-signature');
    const pubPemEl = document.getElementById('flo-public-pem');

    if (!payloadEl || !sigEl || !pubPemEl) {
      document.body.innerHTML = '<pre style="color:red">FLO runtime: missing payload or signature or public key.</pre>';
      return;
    }

    const floB64 = payloadEl.textContent.trim();
    const sigB64 = sigEl.textContent.trim();
    const pubPem = pubPemEl.textContent.trim();

    const floSource = atob(floB64);

    // Import public key and verify
    const publicKey = await importPublicKey(pubPem);
    const ok = await verifySignature(publicKey, sigB64, floSource);

    if (!ok) {
      document.body.innerHTML = '<pre style="color:red">FLO integrity check failed. Rendering aborted.</pre>';
      return;
    }

    // Trusted: compile and render
    const context = { user: 'Scholar' }; // Example: server could embed a JSON context
    const html = clientCompileFLO(floSource, context);

    // Render using DOM APIs to avoid some innerHTML pitfalls.
    // For this demo we replace body safely by parsing to a template and then moving nodes.
    const temp = document.createElement('template');
    temp.innerHTML = html;
    // clear body then append children
    document.body.innerHTML = '';
    Array.from(temp.content.childNodes).forEach(n => document.body.appendChild(n));

    // Optional: add a small banner to indicate verification success
    const note = document.createElement('div');
    note.style.fontSize = '12px';
    note.style.opacity = '0.7';
    note.style.position = 'fixed';
    note.style.right = '8px';
    note.style.bottom = '8px';
    note.textContent = 'FLO verified ✔';
    document.body.appendChild(note);

  } catch (err) {
    console.error('FLO runtime error:', err);
    document.body.innerHTML = '<pre style="color:red">FLO runtime error: see console.</pre>';
  }
})();
