// ============================================================
// Self-Hosted Ultra-Premium Image Host + ImgBB-Style Custom API
// Storage: Backblaze B2 (Private) | DB: Cloudflare D1 | Cache: Edge
// ============================================================

const COOKIE_NAME = 'pv_admin_session';
const MIME_EXT_MAP = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
  'image/svg+xml': 'svg',
  'image/avif': 'avif',
};

// ---------- Utility & Auth Helpers ----------
function randomId(length = 8) {
  const chars = 'abcdefghijkmnpqrstuvwxyz23456789';
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let res = '';
  for (let i = 0; i < length; i++) res += chars[bytes[i] % chars.length];
  return res;
}

function randomSecret(prefix = 'pv_') {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return prefix + Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

async function hmacHex(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function createSessionToken(password) {
  const payload = String(Date.now() + 1000 * 60 * 60 * 24 * 7);
  const sig = await hmacHex(payload, password);
  return `${payload}.${sig}`;
}

async function verifySessionToken(token, password) {
  if (!token || !password) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [payload, sig] = parts;
  const exp = Number(payload);
  if (!Number.isFinite(exp) || Date.now() > exp) return false;
  const expected = await hmacHex(payload, password);
  if (sig.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

function getCookie(req, name = COOKIE_NAME) {
  const header = req.headers.get('cookie');
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return undefined;
}

function buildCookie(value, maxAge) {
  return `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${maxAge}`;
}

async function isAdminReq(req, env) {
  return verifySessionToken(getCookie(req), (env.ADMIN_PASSWORD || '').trim());
}

// ---------- Pure WebCrypto AWS S3 v4 Signer (for Backblaze B2) ----------
async function sha256Hex(data) {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hmacRaw(keyData, msg) {
  const rawKey = typeof keyData === 'string' ? new TextEncoder().encode(keyData) : keyData;
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
}

async function b2SignedFetch(env, method, filename, bodyBytes = null, contentType = null) {
  const endpoint = (env.B2_ENDPOINT || '').replace(/^https?:\/\//i, '').replace(/\/+$/, '').trim();
  const bucket = (env.B2_BUCKET || '').trim();
  const keyId = (env.B2_KEY_ID || '').trim();
  const appKey = (env.B2_APP_KEY || '').trim();
  const region = endpoint.split('.')[1] || 'us-west-004';

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const canonicalUri = `/${bucket}/${filename}`;
  const payloadHash = bodyBytes
    ? await sha256Hex(bodyBytes)
    : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const canonicalHeaders = `host:${endpoint}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = `${method}\n${canonicalUri}\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${await sha256Hex(canonicalRequest)}`;

  const kDate = await hmacRaw('AWS4' + appKey, dateStamp);
  const kRegion = await hmacRaw(kDate, region);
  const kService = await hmacRaw(kRegion, 's3');
  const kSigning = await hmacRaw(kService, 'aws4_request');
  const sigBytes = await hmacRaw(kSigning, stringToSign);
  const signature = Array.from(sigBytes).map((b) => b.toString(16).padStart(2, '0')).join('');

  const headers = {
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
    Authorization: `AWS4-HMAC-SHA256 Credential=${keyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
  if (contentType) headers['Content-Type'] = contentType;

  return fetch(`https://${endpoint}${canonicalUri}`, {
    method,
    headers,
    body: bodyBytes,
  });
}

// ---------- D1 Database Helpers ----------
async function getSettings(db) {
  const { results } = await db.prepare('SELECT key, value FROM settings').all();
  const map = {};
  for (const r of results) map[r.key] = r.value;
  return {
    site_name: map.site_name || 'PixelVault',
    public_upload: map.public_upload || '0',
    max_size_mb: map.max_size_mb || '15',
    allowed_mimes: map.allowed_mimes || 'image/jpeg,image/png,image/webp,image/gif,image/svg+xml,image/avif',
  };
}

// ---------- Response Helpers ----------
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
};

function jsonRes(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function htmlRes(html, status = 200, extraHeaders = {}) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', ...extraHeaders },
  });
}

// ---------- Ultra-Premium Layout & Views ----------
function layoutHtml({ title, siteName, isAdmin, body }) {
  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(title)} — ${escapeHtml(siteName)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          fontFamily: {
            sans: ['"Plus Jakarta Sans"', 'system-ui', '-apple-system', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'monospace']
          }
        }
      }
    };
  </script>
  <style>
    * { font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif; }
    code, pre, .font-mono { font-family: 'JetBrains Mono', monospace !important; }
    body {
      background-color: #05070e;
      background-image:
        radial-gradient(ellipse 80% 50% at 50% -15%, rgba(99, 102, 241, 0.22), transparent),
        radial-gradient(ellipse 50% 40% at 85% 10%, rgba(168, 85, 247, 0.12), transparent),
        radial-gradient(ellipse 50% 40% at 10% 30%, rgba(6, 182, 212, 0.08), transparent);
      min-height: 100vh;
    }
    .bg-grid {
      background-size: 36px 36px;
      background-image: linear-gradient(to right, rgba(255,255,255,0.025) 1px, transparent 1px),
                        linear-gradient(to bottom, rgba(255,255,255,0.025) 1px, transparent 1px);
    }
    .glass-card {
      background: linear-gradient(180deg, rgba(255,255,255,0.045) 0%, rgba(255,255,255,0.02) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 255, 255, 0.08);
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.07);
    }
    .btn-primary {
      background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #4f46e5 100%);
      background-size: 200% auto;
      box-shadow: 0 8px 25px -5px rgba(99, 102, 241, 0.45), inset 0 1px 0 rgba(255,255,255,0.25);
      transition: all 0.25s ease;
    }
    .btn-primary:hover { background-position: right center; transform: translateY(-1px); box-shadow: 0 12px 30px -5px rgba(99, 102, 241, 0.6); }
    .checkerboard {
      background-color: #0b0e17;
      background-image: linear-gradient(45deg, #131826 25%, transparent 25%),
                        linear-gradient(-45deg, #131826 25%, transparent 25%),
                        linear-gradient(45deg, transparent 75%, #131826 75%),
                        linear-gradient(-45deg, transparent 75%, #131826 75%);
      background-size: 20px 20px;
      background-position: 0 0, 0 10px, 10px -10px, -10px 0px;
    }
    @keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
    .shimmer-bar {
      background: linear-gradient(90deg, #6366f1, #a855f7, #06b6d4, #6366f1);
      background-size: 200% 100%;
      animation: shimmer 2s linear infinite;
    }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #05070e; }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 99px; }
  </style>
</head>
<body class="text-slate-100 antialiased selection:bg-indigo-500/30 selection:text-indigo-200 bg-grid flex flex-col">
  <header class="sticky top-0 z-40 border-b border-white/[0.07] bg-[#05070e]/75 backdrop-blur-xl">
    <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
      <a href="/" class="flex items-center gap-3 group">
        <div class="relative w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 via-violet-500 to-cyan-500 p-[1px] shadow-lg shadow-indigo-500/25 group-hover:scale-105 transition">
          <div class="w-full h-full rounded-[11px] bg-[#090c18] flex items-center justify-center">
            <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
          </div>
        </div>
        <div>
          <span class="font-bold text-base sm:text-lg tracking-tight text-white">${escapeHtml(siteName)}</span>
          <span class="hidden sm:inline-block ml-2 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/25">Vault</span>
        </div>
      </a>
      <nav class="flex items-center gap-2">
        <a href="/" class="px-3.5 py-1.5 rounded-xl text-xs sm:text-sm font-medium text-slate-300 hover:text-white hover:bg-white/[0.06] transition">Upload</a>
        <a href="/admin" class="px-4 py-1.5 rounded-xl text-xs sm:text-sm font-semibold transition ${
          isAdmin
            ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/35 shadow-sm shadow-indigo-500/10'
            : 'bg-white/[0.06] text-slate-100 hover:bg-white/[0.12] border border-white/10'
        }">
          ${isAdmin ? 'Dashboard' : 'Admin Login'}
        </a>
      </nav>
    </div>
  </header>

  <main class="max-w-6xl w-full mx-auto px-4 py-8 sm:py-10 flex-1">${body}</main>

  <footer class="border-t border-white/[0.06] py-6 text-center text-xs text-slate-500">
    <div class="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
      <span>${escapeHtml(siteName)} • Private Self-Hosted Image Cloud</span>
      <span class="text-slate-600">Zero Third-Party Host • Edge Cached • Permanent Storage</span>
    </div>
  </footer>

  <!-- Global Toast -->
  <div id="pvToast" class="fixed bottom-5 left-1/2 -translate-x-1/2 z-50 pointer-events-none opacity-0 translate-y-3 transition-all duration-300">
    <div class="px-4 py-2.5 rounded-full bg-[#11172a]/95 border border-indigo-500/40 shadow-2xl shadow-indigo-500/20 backdrop-blur-xl flex items-center gap-2 text-xs font-semibold text-white">
      <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
      <span id="pvToastText">Done!</span>
    </div>
  </div>
  <script>
    function showToast(msg) {
      var el = document.getElementById('pvToast');
      var txt = document.getElementById('pvToastText');
      if (!el || !txt) return;
      txt.textContent = msg;
      el.classList.remove('opacity-0', 'translate-y-3');
      el.classList.add('opacity-100', 'translate-y-0');
      clearTimeout(window._pvToastTimer);
      window._pvToastTimer = setTimeout(function() {
        el.classList.add('opacity-0', 'translate-y-3');
        el.classList.remove('opacity-100', 'translate-y-0');
      }, 2200);
    }
  </script>
</body>
</html>`;
}

function renderHome(settings, isAdmin) {
  const canUpload = isAdmin || settings.public_upload === '1';
  const body = `
    <div class="max-w-3xl mx-auto">
      <div class="text-center mb-8 sm:mb-10">
        <div class="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/[0.04] border border-white/10 text-xs font-medium text-slate-300 mb-5 shadow-inner">
          <span class="relative flex h-2 w-2">
            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-400"></span>
          </span>
          <span>Permanent Cloud Storage • Direct CDN • Built-in API</span>
        </div>
        <h1 class="text-3xl sm:text-5xl font-extrabold tracking-tight leading-tight">
          <span class="bg-gradient-to-b from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">Host & Deliver Images</span><br />
          <span class="bg-gradient-to-r from-indigo-400 via-violet-400 to-cyan-400 bg-clip-text text-transparent">Without Limits or Expiry</span>
        </h1>
        <p class="text-slate-400 mt-4 text-sm sm:text-base max-w-xl mx-auto">
          Drop files below or press <kbd class="px-2 py-0.5 rounded-md bg-white/10 border border-white/10 text-slate-200 text-xs font-mono">Ctrl + V</kbd> to upload screenshots & get instant direct embed links.
        </p>
      </div>

      ${
        !canUpload
          ? `<div class="glass-card rounded-3xl p-8 sm:p-10 text-center max-w-lg mx-auto">
              <div class="w-14 h-14 mx-auto rounded-2xl bg-amber-500/10 border border-amber-500/25 flex items-center justify-center text-amber-400 mb-4">
                <svg class="w-7 h-7" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h2 class="text-xl font-bold text-white mb-2">Private Vault Mode Active</h2>
              <p class="text-slate-400 text-sm mb-6">Public uploads are locked to protect your 10 GB storage. Sign in as Admin to upload or manage files.</p>
              <a href="/admin" class="inline-flex items-center gap-2 px-6 py-3 rounded-xl btn-primary font-semibold text-sm text-white">
                Unlock Admin Upload →
              </a>
            </div>`
          : `<div class="glass-card rounded-3xl p-5 sm:p-8">
              <div class="flex flex-wrap items-center justify-between gap-3 mb-5 pb-4 border-b border-white/[0.07]">
                <div class="flex items-center gap-2 text-xs text-slate-400">
                  <span class="px-2.5 py-1 rounded-lg bg-white/[0.04] border border-white/[0.07] font-medium text-slate-300">Max ${escapeHtml(settings.max_size_mb)} MB</span>
                  <span class="hidden sm:inline text-slate-500">• Multi-file queue ready</span>
                </div>
                <label class="inline-flex items-center gap-2.5 cursor-pointer select-none">
                  <div class="relative">
                    <input id="webpToggle" type="checkbox" class="sr-only peer" />
                    <div class="w-10 h-5 bg-white/10 rounded-full peer peer-checked:bg-indigo-600 transition border border-white/10"></div>
                    <div class="absolute left-0.5 top-0.5 w-4 h-4 bg-white rounded-full transition peer-checked:translate-x-5 shadow"></div>
                  </div>
                  <span class="text-xs font-medium text-slate-300">Auto-Optimize WebP</span>
                </label>
              </div>

              <div id="dropzone" class="group relative border-2 border-dashed border-white/15 hover:border-indigo-400/70 rounded-2xl p-8 sm:p-12 text-center cursor-pointer transition-all duration-300 bg-black/20 hover:bg-indigo-500/[0.04]">
                <input id="fileInput" type="file" accept="image/*" multiple class="hidden" />
                <div class="w-16 h-16 mx-auto rounded-2xl bg-gradient-to-br from-indigo-500/20 to-violet-500/20 border border-indigo-400/25 flex items-center justify-center text-indigo-300 mb-4 group-hover:scale-110 transition duration-300 shadow-lg shadow-indigo-500/10">
                  <svg class="w-8 h-8" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                  </svg>
                </div>
                <p class="text-base sm:text-lg font-bold text-white">Drop your images here or tap to browse</p>
                <p class="text-xs text-slate-400 mt-1.5">Instant permanent URLs • Zero compression loss</p>
                <div class="flex flex-wrap justify-center gap-1.5 mt-5">
                  ${['PNG', 'JPG', 'WEBP', 'GIF', 'SVG', 'AVIF']
                    .map((ext) => `<span class="px-2 py-0.5 rounded-md bg-white/[0.05] border border-white/[0.07] text-[10px] font-mono text-slate-400">${ext}</span>`)
                    .join('')}
                </div>
              </div>

              <div id="progressWrap" class="hidden mt-5">
                <div class="flex justify-between text-xs font-medium text-slate-300 mb-2">
                  <span id="progressLabel">Uploading...</span>
                  <span id="progressPct" class="font-mono text-indigo-300">0%</span>
                </div>
                <div class="w-full h-2 rounded-full bg-white/10 overflow-hidden">
                  <div id="progressBar" class="h-full shimmer-bar w-0 transition-all duration-300 rounded-full"></div>
                </div>
              </div>
              <div id="errorBox" class="hidden mt-4 p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-medium"></div>
            </div>

            <div id="results" class="mt-8 space-y-4"></div>

            <script>
              (function() {
                var dropzone = document.getElementById('dropzone');
                var fileInput = document.getElementById('fileInput');
                var progressWrap = document.getElementById('progressWrap');
                var progressBar = document.getElementById('progressBar');
                var progressLabel = document.getElementById('progressLabel');
                var progressPct = document.getElementById('progressPct');
                var errorBox = document.getElementById('errorBox');
                var results = document.getElementById('results');
                var webpToggle = document.getElementById('webpToggle');

                dropzone.onclick = function() { fileInput.click(); };
                fileInput.onchange = function(e) {
                  if (e.target.files && e.target.files.length) handleFiles(e.target.files);
                  fileInput.value = '';
                };
                dropzone.ondragover = function(e) { e.preventDefault(); dropzone.classList.add('border-indigo-400', 'bg-indigo-500/10'); };
                dropzone.ondragleave = function() { dropzone.classList.remove('border-indigo-400', 'bg-indigo-500/10'); };
                dropzone.ondrop = function(e) {
                  e.preventDefault();
                  dropzone.classList.remove('border-indigo-400', 'bg-indigo-500/10');
                  if (e.dataTransfer.files && e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
                };
                window.addEventListener('paste', function(e) {
                  var items = (e.clipboardData || {}).items || [];
                  var files = [];
                  for (var i = 0; i < items.length; i++) {
                    if (items[i].type && items[i].type.indexOf('image') === 0) {
                      var f = items[i].getAsFile();
                      if (f) files.push(f);
                    }
                  }
                  if (files.length) handleFiles(files);
                });

                function optimizeToWebP(file) {
                  return new Promise(function(resolve) {
                    if (!webpToggle.checked || file.type === 'image/gif' || file.type === 'image/svg+xml' || file.type === 'image/webp') return resolve(file);
                    var img = new Image();
                    var url = URL.createObjectURL(file);
                    img.onload = function() {
                      var canvas = document.createElement('canvas');
                      canvas.width = img.width; canvas.height = img.height;
                      canvas.getContext('2d').drawImage(img, 0, 0);
                      canvas.toBlob(function(blob) {
                        URL.revokeObjectURL(url);
                        if (!blob || blob.size >= file.size) return resolve(file);
                        var dot = file.name.lastIndexOf('.');
                        var base = dot > 0 ? file.name.slice(0, dot) : file.name;
                        resolve(new File([blob], base + '.webp', { type: 'image/webp' }));
                      }, 'image/webp', 0.86);
                    };
                    img.onerror = function() { URL.revokeObjectURL(url); resolve(file); };
                    img.src = url;
                  });
                }

                async function handleFiles(fileList) {
                  errorBox.classList.add('hidden');
                  var files = Array.from(fileList);
                  progressWrap.classList.remove('hidden');
                  for (var i = 0; i < files.length; i++) {
                    progressLabel.textContent = 'Encrypting & uploading ' + (i + 1) + ' of ' + files.length + '...';
                    var pct = Math.round(((i + 0.35) / files.length) * 100);
                    progressBar.style.width = pct + '%';
                    progressPct.textContent = pct + '%';
                    try {
                      var processed = await optimizeToWebP(files[i]);
                      var fd = new FormData();
                      fd.append('image', processed);
                      var res = await fetch('/api/v1/upload', { method: 'POST', body: fd });
                      var json = await res.json();
                      if (!res.ok || !json.success) throw new Error(json.error || 'Upload failed');
                      renderResultCard(json.data);
                      showToast('Image uploaded permanently!');
                    } catch (err) {
                      errorBox.textContent = err.message || 'Upload failed';
                      errorBox.classList.remove('hidden');
                    }
                  }
                  progressBar.style.width = '100%';
                  progressPct.textContent = '100%';
                  progressLabel.textContent = 'All uploads completed!';
                  setTimeout(function() { progressWrap.classList.add('hidden'); progressBar.style.width = '0%'; }, 1600);
                }

                function makeLinkRow(title, value) {
                  var row = document.createElement('div');
                  row.className = 'flex items-center gap-2';
                  var lbl = document.createElement('span');
                  lbl.className = 'w-20 sm:w-24 text-[11px] font-medium text-slate-400 shrink-0';
                  lbl.textContent = title;
                  var inp = document.createElement('input');
                  inp.type = 'text'; inp.readOnly = true; inp.value = value;
                  inp.className = 'w-full bg-black/50 border border-white/10 rounded-xl px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500/50';
                  inp.onclick = function() { inp.select(); };
                  var btn = document.createElement('button');
                  btn.type = 'button';
                  btn.className = 'px-3.5 py-2 rounded-xl bg-white/10 hover:bg-indigo-600 text-xs font-semibold text-white shrink-0 transition';
                  btn.textContent = 'Copy';
                  btn.onclick = function() {
                    navigator.clipboard.writeText(value);
                    showToast(title + ' copied!');
                    btn.textContent = 'Copied';
                    setTimeout(function() { btn.textContent = 'Copy'; }, 1400);
                  };
                  row.appendChild(lbl); row.appendChild(inp); row.appendChild(btn);
                  return row;
                }

                function renderResultCard(data) {
                  var card = document.createElement('div');
                  card.className = 'glass-card rounded-2xl p-4 sm:p-5 flex flex-col sm:flex-row gap-4 items-start';
                  var thumb = document.createElement('a');
                  thumb.href = data.viewer_url; thumb.target = '_blank';
                  thumb.className = 'w-full sm:w-36 h-36 rounded-xl overflow-hidden checkerboard border border-white/10 shrink-0 block group';
                  var im = document.createElement('img');
                  im.src = data.direct_url; im.className = 'w-full h-full object-cover group-hover:scale-105 transition duration-300';
                  thumb.appendChild(im);

                  var info = document.createElement('div');
                  info.className = 'flex-1 w-full space-y-2.5';
                  var head = document.createElement('div');
                  head.className = 'flex items-center justify-between gap-2 pb-1';
                  var name = document.createElement('div');
                  name.className = 'text-sm font-bold text-white truncate';
                  name.textContent = data.original_name;
                  var badge = document.createElement('a');
                  badge.href = data.viewer_url; badge.target = '_blank';
                  badge.className = 'px-2.5 py-1 rounded-lg bg-indigo-500/15 border border-indigo-500/30 text-[11px] font-semibold text-indigo-300 hover:bg-indigo-500/25 shrink-0 transition';
                  badge.textContent = 'Viewer Page ↗';
                  head.appendChild(name); head.appendChild(badge);

                  info.appendChild(head);
                  info.appendChild(makeLinkRow('Direct URL', data.direct_url));
                  info.appendChild(makeLinkRow('Viewer URL', data.viewer_url));
                  info.appendChild(makeLinkRow('HTML Code', '<img src="' + data.direct_url + '" alt="' + data.original_name + '" />'));
                  info.appendChild(makeLinkRow('Markdown', '![' + data.original_name + '](' + data.direct_url + ')'));
                  card.appendChild(thumb); card.appendChild(info);
                  results.prepend(card);
                }
              })();
            </script>`
      }
    </div>`;
  return layoutHtml({ title: 'Upload Images', siteName: settings.site_name, isAdmin, body });
}

function renderViewer(img, origin, settings, isAdmin) {
  const directUrl = `${origin}/i/${img.filename}`;
  const viewerUrl = `${origin}/v/${img.id}`;
  const links = [
    ['Direct Image URL', directUrl],
    ['Viewer Page URL', viewerUrl],
    ['HTML Embed', `<img src="${directUrl}" alt="${img.original_name}" />`],
    ['Markdown', `![${img.original_name}](${directUrl})`],
    ['BBCode', `[img]${directUrl}[/img]`],
  ];
  const body = `
    <div class="max-w-4xl mx-auto space-y-6">
      <div class="glass-card rounded-3xl p-4 sm:p-7">
        <div class="flex flex-wrap items-center justify-between gap-4 mb-5">
          <div class="min-w-0">
            <h1 class="text-lg sm:text-2xl font-bold text-white break-all">${escapeHtml(img.original_name)}</h1>
            <div class="flex flex-wrap items-center gap-2 mt-2">
              <span class="px-2.5 py-0.5 rounded-md bg-indigo-500/15 border border-indigo-500/25 text-[11px] font-mono text-indigo-300">${escapeHtml(img.mime_type)}</span>
              <span class="px-2.5 py-0.5 rounded-md bg-white/[0.06] text-[11px] font-medium text-slate-300">${formatBytes(img.size_bytes)}</span>
              <span class="px-2.5 py-0.5 rounded-md bg-white/[0.06] text-[11px] font-medium text-slate-300">${img.views} views</span>
              <span class="px-2.5 py-0.5 rounded-md bg-white/[0.06] text-[11px] text-slate-400">${new Date(img.created_at).toLocaleDateString()}</span>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <button type="button" onclick="toggleBg()" class="px-3.5 py-2 rounded-xl bg-white/[0.06] hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-200 transition">Toggle Grid</button>
            <a href="${directUrl}" download="${escapeHtml(img.original_name)}" class="px-4 py-2 rounded-xl btn-primary text-xs font-semibold text-white">Download</a>
            <a href="${directUrl}" target="_blank" class="px-4 py-2 rounded-xl bg-white/10 hover:bg-white/15 text-xs font-semibold text-slate-100 transition">Raw ↗</a>
          </div>
        </div>
        <div id="previewStage" class="rounded-2xl checkerboard border border-white/10 p-3 sm:p-6 flex items-center justify-center min-h-[280px] transition">
          <img src="${directUrl}" alt="${escapeHtml(img.original_name)}" class="max-h-[72vh] w-auto rounded-lg object-contain shadow-2xl" />
        </div>
      </div>

      <div class="glass-card rounded-3xl p-5 sm:p-6 space-y-3">
        <div class="flex items-center justify-between mb-1">
          <h2 class="text-sm font-bold text-white">Direct Embed & Share Codes</h2>
          <span class="text-[11px] text-slate-400">Works in HTML, Apps, Forums & Markdown</span>
        </div>
        ${links
          .map(
            ([label, val]) => `
          <div class="flex flex-col sm:flex-row sm:items-center gap-2">
            <span class="sm:w-36 text-xs font-medium text-slate-400 shrink-0">${label}</span>
            <div class="flex-1 flex gap-2">
              <input type="text" readonly value="${escapeHtml(val)}" onclick="this.select()" class="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500/50" />
              <button type="button" data-copy="${escapeHtml(val)}" onclick="cpVal(this)" class="px-4 py-2 rounded-xl bg-white/10 hover:bg-indigo-600 text-xs font-semibold text-white shrink-0 transition">Copy</button>
            </div>
          </div>`
          )
          .join('')}
      </div>
    </div>
    <script>
      function cpVal(btn) {
        navigator.clipboard.writeText(btn.getAttribute('data-copy'));
        showToast('Copied to clipboard!');
        btn.textContent = 'Copied';
        setTimeout(function() { btn.textContent = 'Copy'; }, 1500);
      }
      function toggleBg() {
        var st = document.getElementById('previewStage');
        st.classList.toggle('checkerboard');
        st.classList.toggle('bg-black/70');
      }
    </script>`;
  return layoutHtml({ title: img.original_name, siteName: settings.site_name, isAdmin, body });
}

function renderLogin(settings, errorMsg = '') {
  const body = `
    <div class="max-w-md mx-auto mt-10 sm:mt-16">
      <div class="glass-card rounded-3xl p-8">
        <div class="w-12 h-12 mx-auto mb-4 rounded-2xl bg-indigo-500/15 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
        </div>
        <h1 class="text-2xl font-bold text-center text-white mb-1.5">Admin Access</h1>
        <p class="text-slate-400 text-xs text-center mb-6">Sign in to manage hosted images, site settings, and API keys.</p>
        ${errorMsg ? `<div class="mb-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs text-center font-medium">${escapeHtml(errorMsg)}</div>` : ''}
        <form method="POST" action="/api/admin/login" class="space-y-4">
          <input type="password" name="password" required autofocus placeholder="Enter Master Password" class="w-full bg-black/50 border border-white/15 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500" />
          <button type="submit" class="w-full py-3 rounded-xl btn-primary font-semibold text-sm text-white">Unlock Dashboard →</button>
        </form>
      </div>
    </div>`;
  return layoutHtml({ title: 'Admin Login', siteName: settings.site_name, isAdmin: false, body });
}

function renderAdmin(settings, origin) {
  const body = `
    <div class="space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 class="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">Command Center</h1>
          <p class="text-xs sm:text-sm text-slate-400 mt-0.5">Manage permanent media assets, storage quota, settings, and API keys.</p>
        </div>
        <div class="flex items-center gap-2">
          <a href="/" class="px-4 py-2 rounded-xl btn-primary text-xs font-semibold text-white">+ Upload New</a>
          <form method="POST" action="/api/admin/logout">
            <button type="submit" class="px-4 py-2 rounded-xl bg-white/[0.06] hover:bg-rose-500/20 border border-white/10 text-xs font-semibold text-slate-300 hover:text-rose-300 transition">Logout</button>
          </form>
        </div>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div class="glass-card rounded-2xl p-5">
          <div class="flex items-center justify-between">
            <p class="text-xs font-medium text-slate-400">Hosted Images</p>
            <span class="px-2 py-0.5 rounded-md bg-indigo-500/15 text-indigo-300 text-[10px] font-semibold">PERMANENT</span>
          </div>
          <p id="statCount" class="text-3xl font-extrabold text-white mt-2">—</p>
        </div>
        <div class="glass-card rounded-2xl p-5">
          <div class="flex items-center justify-between">
            <p class="text-xs font-medium text-slate-400">Cloud Storage (10 GB Free)</p>
            <span id="statPct" class="text-[11px] font-mono text-cyan-300">0%</span>
          </div>
          <p id="statStorage" class="text-3xl font-extrabold text-white mt-2">—</p>
          <div class="w-full h-1.5 rounded-full bg-white/10 mt-3 overflow-hidden">
            <div id="storageBar" class="h-full bg-gradient-to-r from-indigo-500 to-cyan-400 rounded-full transition-all duration-500" style="width:0%"></div>
          </div>
        </div>
        <div class="glass-card rounded-2xl p-5">
          <div class="flex items-center justify-between">
            <p class="text-xs font-medium text-slate-400">Total Viewer Hits</p>
            <span class="px-2 py-0.5 rounded-md bg-emerald-500/15 text-emerald-300 text-[10px] font-semibold">LIVE</span>
          </div>
          <p id="statViews" class="text-3xl font-extrabold text-white mt-2">—</p>
        </div>
      </div>

      <!-- Segmented Tabs -->
      <div class="inline-flex p-1 rounded-2xl bg-white/[0.04] border border-white/[0.08] gap-1">
        <button type="button" onclick="switchTab('gallery')" id="tab-gallery" class="px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 text-white shadow transition">Images Gallery</button>
        <button type="button" onclick="switchTab('api')" id="tab-api" class="px-4 py-2 rounded-xl text-xs font-semibold text-slate-300 hover:text-white transition">API Keys & Docs</button>
        <button type="button" onclick="switchTab('settings')" id="tab-settings" class="px-4 py-2 rounded-xl text-xs font-semibold text-slate-300 hover:text-white transition">Site Settings</button>
      </div>

      <!-- Gallery Panel -->
      <section id="panel-gallery" class="space-y-4">
        <div class="flex flex-wrap gap-2">
          <input id="searchInput" type="text" placeholder="Search by filename or ID..." class="flex-1 min-w-[200px] sm:max-w-sm bg-black/50 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500" />
          <button type="button" onclick="loadImages()" class="px-5 py-2.5 rounded-xl bg-white/10 hover:bg-white/15 border border-white/10 text-xs font-semibold text-white transition">Search</button>
        </div>
        <div id="galleryGrid" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4"></div>
      </section>

      <!-- API Keys & Docs Panel -->
      <section id="panel-api" class="hidden space-y-6">
        <div class="glass-card rounded-3xl p-5 sm:p-6 space-y-4">
          <div>
            <h2 class="text-base font-bold text-white">Create API Key</h2>
            <p class="text-xs text-slate-400 mt-0.5">Connect external mobile apps, websites, or automation scripts directly to your host.</p>
          </div>
          <div class="flex flex-wrap gap-2">
            <input id="newKeyName" type="text" placeholder="e.g., My Android App / Blog" class="flex-1 min-w-[220px] bg-black/50 border border-white/15 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500" />
            <button type="button" onclick="createKey()" class="px-5 py-2.5 rounded-xl btn-primary text-xs font-semibold text-white">+ Generate Key</button>
          </div>
          <div id="keysList" class="space-y-2.5 pt-2"></div>
        </div>

        <div class="glass-card rounded-3xl p-5 sm:p-6 space-y-4">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 class="text-base font-bold text-white">Developer API Documentation</h2>
              <p class="text-xs text-slate-400 mt-0.5">Endpoint: <code class="text-indigo-300 font-mono">POST ${escapeHtml(origin)}/api/v1/upload?key=YOUR_API_KEY</code></p>
            </div>
            <div class="inline-flex p-1 rounded-xl bg-black/40 border border-white/10 gap-1">
              <button type="button" onclick="switchDoc('js')" id="doc-tab-js" class="px-3 py-1 rounded-lg text-[11px] font-semibold bg-indigo-600 text-white">JavaScript</button>
              <button type="button" onclick="switchDoc('curl')" id="doc-tab-curl" class="px-3 py-1 rounded-lg text-[11px] font-semibold text-slate-400 hover:text-white">cURL</button>
              <button type="button" onclick="switchDoc('py')" id="doc-tab-py" class="px-3 py-1 rounded-lg text-[11px] font-semibold text-slate-400 hover:text-white">Python</button>
            </div>
          </div>
          <pre id="doc-js" class="bg-black/60 border border-white/10 rounded-2xl p-4 text-xs font-mono text-sky-300 overflow-x-auto">const fd = new FormData();
fd.append('image', fileInput.files[0]);

const res = await fetch('${escapeHtml(origin)}/api/v1/upload?key=YOUR_API_KEY', {
  method: 'POST',
  body: fd
});
const data = await res.json();
// data.data.direct_url  &  data.data.viewer_url</pre>
          <pre id="doc-curl" class="hidden bg-black/60 border border-white/10 rounded-2xl p-4 text-xs font-mono text-emerald-300 overflow-x-auto">curl -X POST "${escapeHtml(origin)}/api/v1/upload?key=YOUR_API_KEY" \\
  -F "image=@/path/to/photo.png"</pre>
          <pre id="doc-py" class="hidden bg-black/60 border border-white/10 rounded-2xl p-4 text-xs font-mono text-amber-300 overflow-x-auto">import requests
res = requests.post(
    "${escapeHtml(origin)}/api/v1/upload?key=YOUR_API_KEY",
    files={"image": open("photo.png", "rb")}
)
print(res.json()["data"]["direct_url"])</pre>
        </div>
      </section>

      <!-- Settings Panel -->
      <section id="panel-settings" class="hidden">
        <div class="glass-card rounded-3xl p-6 sm:p-7 max-w-xl space-y-4">
          <h2 class="text-base font-bold text-white">Website Configuration</h2>
          <div>
            <label class="block text-xs font-medium text-slate-400 mb-1.5">Website Brand Name</label>
            <input id="setSiteName" type="text" value="${escapeHtml(settings.site_name)}" class="w-full bg-black/50 border border-white/15 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-indigo-500" />
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-400 mb-1.5">Upload Access Mode</label>
            <select id="setPublicUpload" class="w-full bg-black/50 border border-white/15 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-indigo-500">
              <option value="0" ${settings.public_upload === '0' ? 'selected' : ''}>Private (Only Admin & API Keys — Recommended)</option>
              <option value="1" ${settings.public_upload === '1' ? 'selected' : ''}>Public (Anyone visiting homepage can upload)</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-400 mb-1.5">Max File Size Limit (MB)</label>
            <input id="setMaxSize" type="number" min="1" max="50" value="${escapeHtml(settings.max_size_mb)}" class="w-full bg-black/50 border border-white/15 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-indigo-500" />
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-400 mb-1.5">Allowed Image MIME Types</label>
            <input id="setMimes" type="text" value="${escapeHtml(settings.allowed_mimes)}" class="w-full bg-black/50 border border-white/15 rounded-xl px-4 py-2.5 text-xs font-mono text-white focus:outline-none focus:border-indigo-500" />
          </div>
          <button type="button" onclick="saveSettings()" class="px-6 py-2.5 rounded-xl btn-primary text-xs font-semibold text-white">Save Changes</button>
        </div>
      </section>
    </div>

    <script>
      function fmtBytes(b) {
        if (!b) return '0 B';
        var u = ['B','KB','MB','GB'], i = Math.floor(Math.log(b)/Math.log(1024));
        return (b/Math.pow(1024, i)).toFixed(2) + ' ' + u[i];
      }
      function switchTab(name) {
        ['gallery','api','settings'].forEach(function(t) {
          document.getElementById('panel-' + t).classList.toggle('hidden', t !== name);
          document.getElementById('tab-' + t).className = t === name
            ? 'px-4 py-2 rounded-xl text-xs font-semibold bg-indigo-600 text-white shadow transition'
            : 'px-4 py-2 rounded-xl text-xs font-semibold text-slate-300 hover:text-white transition';
        });
        if (name === 'api') loadKeys();
      }
      function switchDoc(lang) {
        ['js','curl','py'].forEach(function(l) {
          document.getElementById('doc-' + l).classList.toggle('hidden', l !== lang);
          document.getElementById('doc-tab-' + l).className = l === lang
            ? 'px-3 py-1 rounded-lg text-[11px] font-semibold bg-indigo-600 text-white'
            : 'px-3 py-1 rounded-lg text-[11px] font-semibold text-slate-400 hover:text-white';
        });
      }
      async function loadImages() {
        var q = document.getElementById('searchInput').value || '';
        var res = await fetch('/api/admin/images?q=' + encodeURIComponent(q));
        var data = await res.json();
        document.getElementById('statCount').textContent = data.total;
        document.getElementById('statStorage').textContent = fmtBytes(data.totalBytes);
        document.getElementById('statViews').textContent = data.totalViews;
        var pct = Math.min(100, ((data.totalBytes || 0) / (10 * 1024 * 1024 * 1024)) * 100);
        document.getElementById('statPct').textContent = pct.toFixed(2) + '%';
        document.getElementById('storageBar').style.width = Math.max(pct, data.totalBytes ? 2 : 0) + '%';

        var grid = document.getElementById('galleryGrid');
        grid.innerHTML = '';
        if (!data.images.length) { grid.innerHTML = '<p class="col-span-full text-sm text-slate-500 py-12 text-center">No images found.</p>'; return; }
        data.images.forEach(function(img) {
          var directUrl = window.location.origin + '/i/' + img.filename;
          var card = document.createElement('div'); card.className = 'glass-card rounded-2xl overflow-hidden flex flex-col group';
          var a = document.createElement('a'); a.href = '/v/' + img.id; a.target = '_blank'; a.className = 'relative h-40 checkerboard block overflow-hidden';
          var im = document.createElement('img'); im.src = directUrl; im.loading = 'lazy'; im.className = 'w-full h-full object-cover group-hover:scale-105 transition duration-300';
          var badge = document.createElement('span');
          badge.className = 'absolute top-2 right-2 px-2 py-0.5 rounded-md bg-black/70 backdrop-blur border border-white/10 text-[10px] font-mono uppercase text-slate-200';
          badge.textContent = img.source;
          a.appendChild(im); a.appendChild(badge);

          var meta = document.createElement('div'); meta.className = 'p-3 space-y-2 flex-1 flex flex-col justify-between';
          var t = document.createElement('div'); t.className = 'text-xs font-semibold text-white truncate'; t.textContent = img.original_name;
          var s = document.createElement('div'); s.className = 'text-[11px] text-slate-400 flex justify-between'; s.textContent = fmtBytes(img.size_bytes) + ' • ' + img.views + ' views';
          var act = document.createElement('div'); act.className = 'flex gap-1.5 pt-1';
          var cp = document.createElement('button'); cp.className = 'flex-1 py-1.5 rounded-xl bg-white/[0.08] hover:bg-indigo-600 text-[11px] font-semibold text-white transition'; cp.textContent = 'Copy URL';
          cp.onclick = function() { navigator.clipboard.writeText(directUrl); showToast('Direct URL copied!'); cp.textContent = 'Copied'; setTimeout(function(){ cp.textContent='Copy URL'; }, 1200); };
          var del = document.createElement('button'); del.className = 'px-2.5 py-1.5 rounded-xl bg-rose-500/15 hover:bg-rose-600 text-rose-300 hover:text-white text-[11px] font-semibold transition'; del.textContent = 'Delete';
          del.onclick = async function() { if (!confirm('Delete permanently?')) return; await fetch('/api/admin/images/' + img.id, { method: 'DELETE' }); showToast('Image deleted'); loadImages(); };
          act.appendChild(cp); act.appendChild(del); meta.appendChild(t); meta.appendChild(s); meta.appendChild(act);
          card.appendChild(a); card.appendChild(meta); grid.appendChild(card);
        });
      }
      async function loadKeys() {
        var res = await fetch('/api/admin/keys'); var data = await res.json();
        var list = document.getElementById('keysList'); list.innerHTML = '';
        if (!data.keys.length) { list.innerHTML = '<p class="text-xs text-slate-500">No API keys created yet.</p>'; return; }
        data.keys.forEach(function(k) {
          var row = document.createElement('div'); row.className = 'flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-2xl bg-black/45 border border-white/10';
          var left = document.createElement('div');
          var n = document.createElement('div'); n.className = 'text-xs font-bold text-white'; n.textContent = k.name + '  •  ' + k.upload_count + ' uploads';
          var v = document.createElement('div'); v.className = 'text-[11px] font-mono text-indigo-300 mt-1 break-all'; v.textContent = k.api_key;
          left.appendChild(n); left.appendChild(v);
          var btns = document.createElement('div'); btns.className = 'flex gap-2';
          var cp = document.createElement('button'); cp.className = 'px-3 py-1.5 rounded-xl bg-white/10 hover:bg-indigo-600 text-xs font-semibold transition'; cp.textContent = 'Copy';
          cp.onclick = function() { navigator.clipboard.writeText(k.api_key); showToast('API Key copied!'); cp.textContent = 'Copied'; setTimeout(function(){ cp.textContent='Copy'; }, 1200); };
          var rm = document.createElement('button'); rm.className = 'px-3 py-1.5 rounded-xl bg-rose-500/15 hover:bg-rose-600 text-rose-300 hover:text-white text-xs font-semibold transition'; rm.textContent = 'Revoke';
          rm.onclick = async function() { if (!confirm('Revoke this key?')) return; await fetch('/api/admin/keys/' + k.id, { method: 'DELETE' }); showToast('API Key revoked'); loadKeys(); };
          btns.appendChild(cp); btns.appendChild(rm); row.appendChild(left); row.appendChild(btns); list.appendChild(row);
        });
      }
      async function createKey() {
        var name = document.getElementById('newKeyName').value.trim() || 'App Key';
        await fetch('/api/admin/keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name }) });
        document.getElementById('newKeyName').value = '';
        showToast('New API Key generated!');
        loadKeys();
      }
      async function saveSettings() {
        var res = await fetch('/api/admin/settings', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            site_name: document.getElementById('setSiteName').value.trim(),
            public_upload: document.getElementById('setPublicUpload').value,
            max_size_mb: document.getElementById('setMaxSize').value,
            allowed_mimes: document.getElementById('setMimes').value.trim()
          })
        });
        showToast(res.ok ? 'Settings saved!' : 'Error saving settings');
      }
      document.getElementById('searchInput').onkeydown = function(e) { if (e.key === 'Enter') loadImages(); };
      loadImages();
    </script>`;
  return layoutHtml({ title: 'Dashboard', siteName: settings.site_name, isAdmin: true, body });
}

// ---------- Main Router ----------
export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const origin = url.origin;

    try {
      // 1. Home
      if (path === '/' && request.method === 'GET') {
        const settings = await getSettings(env.DB);
        return htmlRes(renderHome(settings, await isAdminReq(request, env)));
      }

      // 2. Direct Image Route (/i/filename)
      if (path.startsWith('/i/') && request.method === 'GET') {
        const filename = path.slice(3);
        if (!filename) return new Response('Not found', { status: 404 });

        const cacheKey = new Request(url.toString(), { method: 'GET' });
        const cache = caches.default;
        const cached = await cache.match(cacheKey);
        if (cached) return cached;

        const record = await env.DB.prepare('SELECT * FROM images WHERE filename = ?').bind(filename).first();
        if (!record) return new Response('Image not found', { status: 404 });

        const b2Res = await b2SignedFetch(env, 'GET', filename);
        if (!b2Res.ok || !b2Res.body) return new Response('Image unavailable', { status: 404 });

        const headers = new Headers();
        headers.set('Content-Type', record.mime_type);
        headers.set('Cache-Control', 'public, max-age=31536000, immutable');
        headers.set('Access-Control-Allow-Origin', '*');
        headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
        headers.set('Content-Security-Policy', 'sandbox');

        const res = new Response(b2Res.body, { status: 200, headers });
        ctx.waitUntil(cache.put(cacheKey, res.clone()));
        return res;
      }

      // 3. Viewer Page (/v/id)
      if (path.startsWith('/v/') && request.method === 'GET') {
        const id = path.slice(3);
        const img = await env.DB.prepare('SELECT * FROM images WHERE id = ?').bind(id).first();
        if (!img) return new Response('Image not found', { status: 404 });
        ctx.waitUntil(env.DB.prepare('UPDATE images SET views = views + 1 WHERE id = ?').bind(id).run());
        const settings = await getSettings(env.DB);
        return htmlRes(renderViewer(img, origin, settings, await isAdminReq(request, env)));
      }

      // 4. Upload API (Web + External ImgBB-style API)
      if (path === '/api/v1/upload' && request.method === 'POST') {
        const settings = await getSettings(env.DB);
        const isAdmin = await isAdminReq(request, env);
        const authHeader = request.headers.get('authorization') || '';
        const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        let providedKey = request.headers.get('x-api-key') || bearer || url.searchParams.get('key') || '';

        let authorized = isAdmin || settings.public_upload === '1';
        let source = 'web';

        const verifyKey = async (k) => {
          const row = await env.DB.prepare('SELECT id FROM api_keys WHERE api_key = ?').bind(k).first();
          if (!row) return false;
          await env.DB.prepare('UPDATE api_keys SET upload_count = upload_count + 1, last_used_at = ? WHERE id = ?')
            .bind(new Date().toISOString(), row.id)
            .run();
          return true;
        };

        if (providedKey) {
          if (!(await verifyKey(providedKey))) return jsonRes({ success: false, status: 401, error: 'Invalid API key' }, 401);
          authorized = true;
          source = 'api';
        }

        let bytes, mimeType = '', originalName = 'image.png';
        const ctype = request.headers.get('content-type') || '';

        if (ctype.includes('multipart/form-data')) {
          const form = await request.formData();
          const formKey = form.get('key');
          if (!providedKey && typeof formKey === 'string' && formKey) {
            if (!(await verifyKey(formKey))) return jsonRes({ success: false, status: 401, error: 'Invalid API key' }, 401);
            authorized = true;
            source = 'api';
          }
          if (!authorized) return jsonRes({ success: false, status: 401, error: 'Unauthorized' }, 401);

          const file = form.get('image');
          if (!file || typeof file === 'string') return jsonRes({ success: false, status: 400, error: 'Missing image file' }, 400);
          originalName = file.name || 'upload.png';
          mimeType = file.type;
          bytes = new Uint8Array(await file.arrayBuffer());
        } else if (ctype.includes('application/json')) {
          if (!authorized) return jsonRes({ success: false, status: 401, error: 'Unauthorized' }, 401);
          const body = await request.json();
          if (!body.image) return jsonRes({ success: false, status: 400, error: 'Missing image base64' }, 400);
          let b64 = body.image;
          const m = b64.match(/^data:(image\/[a-zA-Z0-9+.-]+);base64,(.+)$/);
          if (m) { mimeType = m[1]; b64 = m[2]; } else { mimeType = 'image/png'; }
          originalName = body.name || `upload.${MIME_EXT_MAP[mimeType] || 'png'}`;
          bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
        } else {
          return jsonRes({ success: false, status: 400, error: 'Use multipart/form-data or application/json' }, 400);
        }

        const allowed = settings.allowed_mimes.split(',').map((s) => s.trim().toLowerCase());
        if (!allowed.includes((mimeType || '').toLowerCase())) {
          return jsonRes({ success: false, status: 400, error: `Unsupported image type: ${mimeType}` }, 400);
        }
        const maxBytes = Number(settings.max_size_mb || '15') * 1024 * 1024;
        if (!bytes.byteLength || bytes.byteLength > maxBytes) {
          return jsonRes({ success: false, status: 400, error: `Max size is ${settings.max_size_mb} MB` }, 400);
        }

        const id = randomId(8);
        const ext = MIME_EXT_MAP[mimeType.toLowerCase()] || 'png';
        const filename = `${id}.${ext}`;
        const deleteToken = randomSecret('del_');
        const createdAt = new Date().toISOString();

        const putRes = await b2SignedFetch(env, 'PUT', filename, bytes, mimeType);
        if (!putRes.ok) {
          return jsonRes({ success: false, status: 500, error: `Storage error (${putRes.status}): ${await putRes.text()}` }, 500);
        }

        await env.DB.prepare(
          'INSERT INTO images (id, filename, original_name, mime_type, size_bytes, delete_token, source, views, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)'
        ).bind(id, filename, originalName, mimeType, bytes.byteLength, deleteToken, source, createdAt).run();

        return jsonRes({
          success: true,
          status: 200,
          data: {
            id,
            filename,
            original_name: originalName,
            mime: mimeType,
            size: bytes.byteLength,
            direct_url: `${origin}/i/${filename}`,
            viewer_url: `${origin}/v/${id}`,
            delete_url: `${origin}/api/v1/delete/${id}?token=${deleteToken}`,
            created_at: createdAt,
          },
        });
      }

      // 5. Token Delete API
      if (path.startsWith('/api/v1/delete/')) {
        const id = path.slice('/api/v1/delete/'.length);
        const token = url.searchParams.get('token');
        const img = await env.DB.prepare('SELECT * FROM images WHERE id = ?').bind(id).first();
        if (!img) return jsonRes({ success: false, error: 'Not found' }, 404);
        if (!token || token !== img.delete_token) return jsonRes({ success: false, error: 'Invalid token' }, 403);
        await b2SignedFetch(env, 'DELETE', img.filename);
        await env.DB.prepare('DELETE FROM images WHERE id = ?').bind(id).run();
        return jsonRes({ success: true });
      }

      // 6. Admin Login / Logout / Dashboard
      if (path === '/admin' && request.method === 'GET') {
        const settings = await getSettings(env.DB);
        if (!(await isAdminReq(request, env))) return htmlRes(renderLogin(settings));
        return htmlRes(renderAdmin(settings, origin));
      }

      if (path === '/api/admin/login' && request.method === 'POST') {
        const form = await request.formData();
        const pass = form.get('password');
        const settings = await getSettings(env.DB);
        if (typeof pass !== 'string' || pass !== (env.ADMIN_PASSWORD || '').trim()) {
          return htmlRes(renderLogin(settings, 'Wrong password!'), 401);
        }
        const token = await createSessionToken(pass);
        return new Response(null, {
          status: 302,
          headers: { Location: '/admin', 'Set-Cookie': buildCookie(token, 60 * 60 * 24 * 7) },
        });
      }

      if (path === '/api/admin/logout' && request.method === 'POST') {
        return new Response(null, {
          status: 302,
          headers: { Location: '/admin', 'Set-Cookie': buildCookie('', 0) },
        });
      }

      // Admin Protected APIs
      if (path.startsWith('/api/admin/')) {
        if (!(await isAdminReq(request, env))) return jsonRes({ error: 'Unauthorized' }, 401);

        if (path === '/api/admin/images' && request.method === 'GET') {
          const q = (url.searchParams.get('q') || '').trim();
          const listRes = q
            ? await env.DB.prepare('SELECT * FROM images WHERE original_name LIKE ? OR id LIKE ? ORDER BY created_at DESC LIMIT 60').bind(`%${q}%`, `%${q}%`).all()
            : await env.DB.prepare('SELECT * FROM images ORDER BY created_at DESC LIMIT 60').all();
          const stats = await env.DB.prepare('SELECT COUNT(*) as total, COALESCE(SUM(size_bytes),0) as totalBytes, COALESCE(SUM(views),0) as totalViews FROM images').first();
          return jsonRes({ images: listRes.results, total: stats.total || 0, totalBytes: stats.totalBytes || 0, totalViews: stats.totalViews || 0 });
        }

        if (path.startsWith('/api/admin/images/') && request.method === 'DELETE') {
          const id = path.slice('/api/admin/images/'.length);
          const img = await env.DB.prepare('SELECT * FROM images WHERE id = ?').bind(id).first();
          if (!img) return jsonRes({ error: 'Not found' }, 404);
          await b2SignedFetch(env, 'DELETE', img.filename);
          await env.DB.prepare('DELETE FROM images WHERE id = ?').bind(id).run();
          return jsonRes({ success: true });
        }

        if (path === '/api/admin/keys' && request.method === 'GET') {
          const res = await env.DB.prepare('SELECT * FROM api_keys ORDER BY created_at DESC').all();
          return jsonRes({ keys: res.results });
        }

        if (path === '/api/admin/keys' && request.method === 'POST') {
          const body = await request.json();
          const id = randomId(8);
          const apiKey = randomSecret('pv_key_');
          await env.DB.prepare('INSERT INTO api_keys (id, name, api_key, upload_count, created_at) VALUES (?, ?, ?, 0, ?)')
            .bind(id, (body.name || 'My App').slice(0, 50), apiKey, new Date().toISOString())
            .run();
          return jsonRes({ success: true, apiKey });
        }

        if (path.startsWith('/api/admin/keys/') && request.method === 'DELETE') {
          const id = path.slice('/api/admin/keys/'.length);
          await env.DB.prepare('DELETE FROM api_keys WHERE id = ?').bind(id).run();
          return jsonRes({ success: true });
        }

        if (path === '/api/admin/settings' && request.method === 'PUT') {
          const body = await request.json();
          const updates = [
            ['site_name', body.site_name || 'PixelVault'],
            ['public_upload', body.public_upload === '1' ? '1' : '0'],
            ['max_size_mb', String(body.max_size_mb || '15')],
            ['allowed_mimes', String(body.allowed_mimes || 'image/jpeg,image/png,image/webp,image/gif')],
          ];
          await env.DB.batch(
            updates.map(([k, v]) =>
              env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(k, v)
            )
          );
          return jsonRes({ success: true });
        }
      }

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      return jsonRes({ success: false, error: err.message || 'Server error' }, 500);
    }
  },
};
