#!/usr/bin/env bash
# =============================================================================
# RustHost Static Stress Test Fixture Generator
# =============================================================================
# Usage:  ./scripts/generate-static-stress-site.sh [OUTPUT_DIR]
# Default output: <repo-root>/test-sites/static-stress/
#
# Optional deps (gracefully skipped if absent):
#   ffmpeg   – mp4, webm, mp3, ogg, webp, gif
#   python3  – png (stdlib), wav (stdlib), pdf (stdlib)
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." 2>/dev/null && pwd || pwd)"
OUT="${1:-${REPO_ROOT}/test-sites/static-stress}"

# ── Tracking ──────────────────────────────────────────────────────────────────
GEN_COUNT=0
declare -a SKIPPED=()

# ── Logging ───────────────────────────────────────────────────────────────────
log()   { printf '\e[32m[GEN]\e[0m  %s\n'    "$*"; }
info()  { printf '\e[34m[INFO]\e[0m %s\n'    "$*"; }
warn()  { printf '\e[33m[WARN]\e[0m %s\n'    "$*" >&2; }
skip()  { SKIPPED+=("$1"); printf '\e[33m[SKIP]\e[0m %s\n' "$1"; }
wrote() { GEN_COUNT=$((GEN_COUNT+1)); printf '  \e[36m→\e[0m %s\n' "$1"; }
die()   { printf '\e[31m[ERR]\e[0m  %s\n'    "$*" >&2; exit 1; }

# ── Tool Detection ────────────────────────────────────────────────────────────
HAS_FFMPEG=0; HAS_PYTHON=0

if command -v ffmpeg &>/dev/null; then
    HAS_FFMPEG=1
    log "ffmpeg: $(ffmpeg -version 2>&1 | head -1 | sed 's/ffmpeg version //')"
else
    warn "ffmpeg not found — mp4, webm, mp3, ogg, webp, gif will be skipped"
fi

if command -v python3 &>/dev/null; then
    HAS_PYTHON=1
    log "python3: $(python3 --version 2>&1)"
else
    warn "python3 not found — png, wav, pdf generation will be skipped"
fi

# ── Directory Setup ───────────────────────────────────────────────────────────
log "Cleaning output dir: $OUT"
rm -rf "$OUT"
mkdir -p \
    "$OUT/assets/css" \
    "$OUT/assets/js" \
    "$OUT/assets/json" \
    "$OUT/assets/images/nested/deep" \
    "$OUT/assets/video" \
    "$OUT/assets/audio" \
    "$OUT/assets/pdf" \
    "$OUT/assets/downloads" \
    "$OUT/pages/deep/path/nested"

# =============================================================================
# §1  PYTHON HELPERS  (inline scripts, all stdlib)
# =============================================================================

# Generate a solid-colour PNG using only Python stdlib (zlib + struct)
_py_make_png() {
    local path="$1" w="$2" h="$3" r="${4:-128}" g="${5:-128}" b="${6:-128}"
    python3 - "$path" "$w" "$h" "$r" "$g" "$b" <<'PYEOF'
import sys, zlib, struct
path,w,h,r,g,b = sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]),int(sys.argv[5]),int(sys.argv[6])
def chunk(tag,data):
    c=zlib.crc32(tag+data)&0xffffffff
    return struct.pack('>I',len(data))+tag+data+struct.pack('>I',c)
hdr=b'\x89PNG\r\n\x1a\n'
ihdr=chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0))
raw=b''.join(b'\x00'+bytes([r,g,b])*w for _ in range(h))
idat=chunk(b'IDAT',zlib.compress(raw,9))
iend=chunk(b'IEND',b'')
with open(path,'wb') as f: f.write(hdr+ihdr+idat+iend)
PYEOF
}

# Generate a gradient PNG (left→right hue shift) for more visual interest
_py_make_gradient_png() {
    local path="$1" w="$2" h="$3"
    python3 - "$path" "$w" "$h" <<'PYEOF'
import sys, zlib, struct, math
path,w,h = sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
def chunk(tag,data):
    c=zlib.crc32(tag+data)&0xffffffff
    return struct.pack('>I',len(data))+tag+data+struct.pack('>I',c)
def hsv(h,s=0.8,v=0.9):
    h=h%360; c=v*s; x=c*(1-abs((h/60)%2-1)); m=v-c
    if h<60: r,g,b=c,x,0
    elif h<120: r,g,b=x,c,0
    elif h<180: r,g,b=0,c,x
    elif h<240: r,g,b=0,x,c
    elif h<300: r,g,b=x,0,c
    else: r,g,b=c,0,x
    return int((r+m)*255),int((g+m)*255),int((b+m)*255)
hdr=b'\x89PNG\r\n\x1a\n'
ihdr=chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0))
rows=b''
for y in range(h):
    row=b'\x00'
    for x in range(w):
        hue=360*x/w; sat=0.6+0.4*(y/h); val=0.85
        r,g,b=hsv(hue,sat,val)
        row+=bytes([r,g,b])
    rows+=row
idat=chunk(b'IDAT',zlib.compress(rows,6))
iend=chunk(b'IEND',b'')
with open(path,'wb') as f: f.write(hdr+ihdr+idat+iend)
PYEOF
}

# Generate a minimal valid PDF using only Python stdlib
_py_make_pdf() {
    local path="$1" title="${2:-RustHost Test PDF}"
    python3 - "$path" "$title" <<'PYEOF'
import sys
path,title=sys.argv[1],sys.argv[2]

body=(
    "BT\n/F1 22 Tf\n72 720 Td\n("+title+") Tj\n"
    "0 -36 Td /F1 13 Tf\n(RustHost Static Stress Test Fixture) Tj\n"
    "0 -22 Td\n(This PDF tests MIME handling, range requests,) Tj\n"
    "0 -22 Td\n(inline embedding, and download behaviour.) Tj\n"
    "0 -22 Td\n(Generated deterministically without external tools.) Tj\n"
    "0 -40 Td /F1 10 Tf (Page 1 of 1) Tj\nET\n"
)
objs=[None,
    "<</Type/Catalog/Pages 2 0 R>>",
    "<</Type/Pages/Kids[3 0 R]/Count 1>>",
    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
    "/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>",
    "<</Length "+str(len(body.encode()))+">>",
    "<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>",
]
parts=[b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
offs=[None]
for i in range(1,len(objs)):
    offs.append(len(b"".join(parts)))
    s=f"{i} 0 obj\n{objs[i]}\n"
    if i==4: s+=f"stream\n{body}endstream\n"
    s+="endobj\n"
    parts.append(s.encode())
xoff=len(b"".join(parts))
n=len(objs)
xref=f"xref\n0 {n}\n0000000000 65535 f \n"
for i in range(1,n): xref+=f"{offs[i]:010d} 00000 n \n"
trailer=f"trailer\n<</Size {n}/Root 1 0 R>>\nstartxref\n{xoff}\n%%EOF\n"
with open(path,'wb') as f:
    f.write(b"".join(parts)+xref.encode()+trailer.encode())
PYEOF
}

# Generate a sine-wave WAV using only Python stdlib (wave module)
_py_make_wav() {
    local path="$1" freq="${2:-440}" dur="${3:-2}"
    python3 - "$path" "$freq" "$dur" <<'PYEOF'
import sys,wave,struct,math
path,freq,dur=sys.argv[1],float(sys.argv[2]),float(sys.argv[3])
sr=22050; n=int(sr*dur); amp=18000
with wave.open(path,'w') as wf:
    wf.setnchannels(1); wf.setsampwidth(2); wf.setframerate(sr)
    for i in range(n):
        fade=min(1.0,min(i,n-i)/(sr*0.05))
        v=int(amp*fade*math.sin(2*math.pi*freq*i/sr))
        wf.writeframes(struct.pack('<h',v))
PYEOF
}

# =============================================================================
# §2  CSS
# =============================================================================
log "Writing CSS..."
cat > "$OUT/assets/css/stress.css" <<'CSS_EOF'
/* RustHost Static Stress Fixture – stress.css
   Tests: custom properties, sticky header, media queries,
   dark/light mode, background images, tables, pre/code */

:root {
  --color-bg:      #f4f5f7;
  --color-surface: #ffffff;
  --color-text:    #1a1a2e;
  --color-muted:   #6c757d;
  --color-primary: #2563eb;
  --color-accent:  #7c3aed;
  --color-success: #16a34a;
  --color-warn:    #d97706;
  --color-danger:  #dc2626;
  --color-border:  #dee2e6;
  --radius:        6px;
  --shadow:        0 1px 4px rgba(0,0,0,.10);
  --font-mono:     'Courier New', Courier, monospace;
  --font-sans:     system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  --header-h:      54px;
}

@media (prefers-color-scheme: dark) {
  :root {
    --color-bg:      #0d0d1a;
    --color-surface: #16162a;
    --color-text:    #e4e4f0;
    --color-muted:   #8888aa;
    --color-border:  #2a2a44;
    --shadow:        0 1px 4px rgba(0,0,0,.35);
  }
}

*,*::before,*::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; font-size: 16px; }
body {
  font-family: var(--font-sans);
  background: var(--color-bg);
  color: var(--color-text);
  line-height: 1.65;
}

/* ── Sticky header (tests position:sticky + z-index) ─── */
.site-header {
  position: sticky;
  top: 0;
  z-index: 200;
  height: var(--header-h);
  background: var(--color-primary);
  color: #fff;
  display: flex;
  align-items: center;
  padding: 0 1.5rem;
  gap: 1.25rem;
  box-shadow: 0 2px 10px rgba(0,0,0,.25);
}
.site-header .brand { font-size: .95rem; font-weight: 700; flex: 1; letter-spacing: -.01em; }
.site-header .brand small { font-weight: 400; opacity: .7; font-size: .8em; }
.site-header nav { display: flex; gap: .25rem; flex-wrap: wrap; }
.site-header nav a {
  color: rgba(255,255,255,.85);
  text-decoration: none;
  padding: .2rem .6rem;
  border-radius: var(--radius);
  font-size: .8rem;
  transition: background .15s;
}
.site-header nav a:hover { background: rgba(255,255,255,.18); color: #fff; }

/* ── Container / sections ─── */
.container { max-width: 1080px; margin: 0 auto; padding: 2rem 1.5rem; }
.section { margin-bottom: 3.5rem; }
.section-title {
  font-size: 1.25rem;
  font-weight: 700;
  margin-bottom: 1.25rem;
  padding-bottom: .5rem;
  border-bottom: 2px solid var(--color-primary);
  color: var(--color-primary);
}

/* ── Status panel ─── */
.status-panel {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius);
  padding: 1.25rem 1.5rem;
  box-shadow: var(--shadow);
}
.status-panel h2 { font-size: .95rem; margin-bottom: .8rem; color: var(--color-accent); font-weight: 700; }
.status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
  gap: .45rem;
}
.status-item { display: flex; align-items: flex-start; gap: .5rem; font-size: .82rem; }
.status-dot {
  width: 9px; height: 9px; margin-top: .3em;
  border-radius: 50%; background: #888; flex-shrink: 0;
  transition: background .3s;
}
.status-dot.ok   { background: var(--color-success); }
.status-dot.fail { background: var(--color-danger); }
.status-dot.warn { background: var(--color-warn); }

/* ── Card grid (images etc.) ─── */
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(175px, 1fr));
  gap: 1rem;
}
.card {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius);
  padding: .85rem;
  box-shadow: var(--shadow);
  display: flex;
  flex-direction: column;
  gap: .4rem;
}
.card img { max-width: 100%; border-radius: 4px; display: block; min-height: 40px; background: var(--color-bg); }
.card .label { font-size: .72rem; color: var(--color-muted); word-break: break-all; }
.card .tag { font-size: .68rem; font-weight: 700; color: var(--color-accent); text-transform: uppercase; letter-spacing: .05em; }

/* ── Badges ─── */
.badge {
  font-size: .68rem; padding: .1em .45em;
  border-radius: 3px; font-weight: 700;
  vertical-align: middle; margin-left: .3em;
}
.badge-broken { background: var(--color-danger); color: #fff; }
.badge-ok     { background: var(--color-success); color: #fff; }
.badge-opt    { background: var(--color-warn); color: #fff; }
.link-broken  { color: var(--color-danger); text-decoration: line-through; opacity: .8; }

/* ── Media ─── */
video, audio { max-width: 100%; border-radius: var(--radius); display: block; }
video { background: #000; max-height: 240px; }

/* ── Tables ─── */
.table-wrap { overflow-x: auto; border-radius: var(--radius); box-shadow: var(--shadow); }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
thead th {
  background: var(--color-primary); color: #fff;
  padding: .6rem 1rem; text-align: left;
  font-weight: 600;
}
tbody tr:nth-child(even) { background: var(--color-bg); }
tbody tr:hover { background: rgba(37,99,235,.06); }
tbody td { padding: .5rem 1rem; border-bottom: 1px solid var(--color-border); }

/* ── Code / Pre ─── */
code {
  font-family: var(--font-mono);
  background: var(--color-bg);
  border: 1px solid var(--color-border);
  border-radius: 3px;
  padding: .1em .35em;
  font-size: .85em;
}
pre {
  font-family: var(--font-mono);
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-left: 4px solid var(--color-accent);
  border-radius: var(--radius);
  padding: 1rem 1.25rem;
  overflow-x: auto;
  font-size: .84rem;
  line-height: 1.55;
}

/* ── Forms ─── */
.form-row { margin-bottom: .8rem; }
label { display: block; font-size: .85rem; margin-bottom: .3rem; font-weight: 600; }
input[type=text], input[type=search], textarea, select {
  width: 100%; padding: .5rem .75rem;
  border: 1px solid var(--color-border);
  border-radius: var(--radius);
  background: var(--color-surface);
  color: var(--color-text);
  font-family: var(--font-sans);
  font-size: .9rem;
  outline: none;
  transition: border-color .15s, box-shadow .15s;
}
input:focus, textarea:focus, select:focus {
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px rgba(37,99,235,.15);
}
button {
  padding: .5rem 1.2rem;
  background: var(--color-primary); color: #fff;
  border: none; border-radius: var(--radius);
  cursor: pointer; font-size: .9rem; font-weight: 600;
  transition: opacity .15s, transform .1s;
}
button:hover { opacity: .88; transform: translateY(-1px); }
button:active { transform: translateY(0); }
#form-result {
  margin-top: .75rem; padding: .75rem 1rem;
  border-radius: var(--radius);
  background: var(--color-bg);
  border: 1px solid var(--color-border);
  font-size: .85rem; min-height: 2.5rem;
  font-family: var(--font-mono);
}

/* ── Search ─── */
.search-wrap { display: flex; gap: .5rem; margin-bottom: 1rem; }
.search-wrap input { flex: 1; }
#search-results { min-height: 60px; }
.search-item {
  padding: .45rem .25rem;
  border-bottom: 1px solid var(--color-border);
  font-size: .88rem;
}
.search-item:last-child { border-bottom: none; }
.search-item mark { background: rgba(37,99,235,.2); border-radius: 2px; }
.search-empty { color: var(--color-muted); font-style: italic; font-size: .88rem; }

/* ── Background image test ─── */
.bg-image-test {
  min-height: 130px;
  background-image: url('../images/background.png');
  background-size: cover; background-position: center;
  border-radius: var(--radius);
  display: flex; align-items: center; justify-content: center;
  color: #fff; font-weight: 700;
  text-shadow: 0 1px 6px rgba(0,0,0,.75);
  font-size: 1.05rem;
  border: 1px solid var(--color-border);
}

/* ── Dynamic image box ─── */
#dynamic-images { display: flex; gap: .75rem; flex-wrap: wrap; margin-top: .75rem; }
#dynamic-images img { border-radius: var(--radius); border: 1px solid var(--color-border); max-height: 80px; }

/* ── Hash anchors ─── */
.anchor-list { display: flex; flex-wrap: wrap; gap: .5rem; }
.anchor-list a {
  padding: .2rem .6rem; border-radius: var(--radius);
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  font-size: .82rem; text-decoration: none;
}
.anchor-list a:hover { border-color: var(--color-primary); }

/* ── Link list ─── */
.link-list { list-style: none; }
.link-list li { padding: .3rem 0; border-bottom: 1px solid var(--color-border); font-size: .9rem; }
.link-list li:last-child { border-bottom: none; }

/* ── Long text ─── */
.long-text p { margin-bottom: 1rem; }

/* ── Flex utilities ─── */
.flex       { display: flex; gap: .75rem; flex-wrap: wrap; align-items: flex-start; }
.flex-col   { display: flex; flex-direction: column; gap: .75rem; }
.row        { display: flex; gap: 1rem; flex-wrap: wrap; }
.col        { flex: 1 1 220px; }
.mt-1       { margin-top: .5rem; }
.mt-2       { margin-top: 1rem; }

/* ── Responsive ─── */
@media (max-width: 680px) {
  .site-header nav  { display: none; }
  .card-grid        { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); }
  .status-grid      { grid-template-columns: 1fr; }
  .row              { flex-direction: column; }
}
CSS_EOF
wrote "$OUT/assets/css/stress.css"

# =============================================================================
# §3  JAVASCRIPT
# =============================================================================
log "Writing JavaScript..."
cat > "$OUT/assets/js/stress.js" <<'JS_EOF'
/* RustHost Static Stress Fixture – stress.js
   Tests: DOMContentLoaded, localStorage, fetch, dynamic DOM,
          form handling, hash nav, client-side search */
'use strict';

// ── Utilities ────────────────────────────────────────────────────────────────
function el(selector, root = document) { return root.querySelector(selector); }
function els(selector, root = document) { return [...root.querySelectorAll(selector)]; }

function setStatus(id, state, text) {
    const item = el(`#status-${id}`);
    if (!item) return;
    const dot  = item.querySelector('.status-dot');
    const span = item.querySelector('.status-text');
    if (dot)  { dot.classList.remove('ok','fail','warn'); dot.classList.add(state); }
    if (span) span.textContent = text;
}

// ── DOMContentLoaded ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

    // 1. JS loaded
    setStatus('js', 'ok', 'JS executed ✓');

    // 2. Current time
    setStatus('time', 'ok', new Date().toLocaleTimeString());

    // 3. Viewport
    const vw = window.innerWidth, vh = window.innerHeight;
    setStatus('viewport', 'ok', `${vw} × ${vh} px`);

    // 4. User agent (truncated)
    const ua = navigator.userAgent;
    setStatus('useragent', 'ok', ua.length > 60 ? ua.slice(0, 57) + '…' : ua);

    // 5. localStorage
    try {
        const KEY = '_rh_stress_test_';
        localStorage.setItem(KEY, 'ok');
        const got = localStorage.getItem(KEY);
        localStorage.removeItem(KEY);
        setStatus('localstorage', got === 'ok' ? 'ok' : 'warn',
                  got === 'ok' ? 'localStorage R/W OK ✓' : 'localStorage read mismatch');
    } catch (e) {
        setStatus('localstorage', 'fail', `localStorage blocked: ${e.message}`);
    }

    // 6. fetch local JSON
    fetch('assets/json/data.json')
        .then(r => {
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return r.json();
        })
        .then(d => setStatus('fetch', 'ok', `fetch OK → "${d.name}" (${d.items} items)`))
        .catch(e => setStatus('fetch', 'fail', `fetch failed: ${e.message} — serve with a static server`));

    // 7. Dynamic image insertion
    const dynBox = el('#dynamic-images');
    if (dynBox) {
        const imgs = [
            { src: 'assets/images/small.png',           alt: 'small png' },
            { src: 'assets/images/photo.webp',          alt: 'webp' },
            { src: 'assets/images/animation.gif',       alt: 'gif' },
        ];
        imgs.forEach(({ src, alt }) => {
            const img = document.createElement('img');
            img.src = src; img.alt = alt; img.title = src;
            img.onerror = () => { img.alt = `[missing: ${alt}]`; img.style.opacity = '.4'; };
            dynBox.appendChild(img);
        });
        setStatus('dynamic-img', 'ok', `${imgs.length} images injected dynamically`);
    }

    // 8. Dynamic link creation
    const dynLinks = el('#dynamic-links');
    if (dynLinks) {
        [
            ['assets/downloads/sample.txt', 'sample.txt (dynamic link)'],
            ['assets/json/data.json',        'data.json (dynamic link)'],
        ].forEach(([href, text]) => {
            const a = document.createElement('a');
            a.href = href; a.textContent = text; a.className = 'dynamic-link';
            dynLinks.appendChild(a); dynLinks.appendChild(document.createTextNode(' '));
        });
    }

    // 9. Form handling (no network submit)
    const form = el('#stress-form');
    if (form) {
        form.addEventListener('submit', e => {
            e.preventDefault();
            const data = Object.fromEntries(new FormData(form).entries());
            el('#form-result').textContent = `Submitted: ${JSON.stringify(data, null, 2)}`;
        });
    }

    // 10. Hash navigation listener
    window.addEventListener('hashchange', () => {
        const hash = location.hash;
        setStatus('hash', 'ok', `hash changed → ${hash || '(none)'}`);
    });
    if (location.hash) setStatus('hash', 'ok', `current hash: ${location.hash}`);

    // 11. Client-side search/filter
    const searchInput = el('#search-input');
    const searchResults = el('#search-results');
    const searchData = [
        { title: 'PNG Image',       path: 'assets/images/small.png',            category: 'image' },
        { title: 'JPEG Image',      path: 'assets/images/medium.jpg',           category: 'image' },
        { title: 'WebP Image',      path: 'assets/images/photo.webp',           category: 'image' },
        { title: 'GIF Animation',   path: 'assets/images/animation.gif',        category: 'image' },
        { title: 'SVG Vector',      path: 'assets/images/vector.svg',           category: 'image' },
        { title: 'MP4 Video',       path: 'assets/video/test.mp4',              category: 'video' },
        { title: 'WebM Video',      path: 'assets/video/test.webm',             category: 'video' },
        { title: 'WAV Audio',       path: 'assets/audio/test.wav',              category: 'audio' },
        { title: 'MP3 Audio',       path: 'assets/audio/test.mp3',              category: 'audio' },
        { title: 'OGG Audio',       path: 'assets/audio/test.ogg',              category: 'audio' },
        { title: 'PDF Document',    path: 'assets/pdf/test.pdf',                category: 'pdf'   },
        { title: 'CSV Download',    path: 'assets/downloads/data.csv',          category: 'download' },
        { title: 'JSON Data',       path: 'assets/json/data.json',              category: 'json'  },
        { title: 'Binary File',     path: 'assets/downloads/test.bin',          category: 'download' },
        { title: 'No Extension',    path: 'assets/downloads/no-extension',      category: 'download' },
        { title: 'Hash Nav Page',   path: 'pages/hash-nav.html',                category: 'page'  },
        { title: 'Long Page',       path: 'pages/long-page.html',               category: 'page'  },
        { title: 'Table Heavy',     path: 'pages/table-heavy.html',             category: 'page'  },
        { title: 'Unicode Page',    path: 'pages/unicode.html',                 category: 'page'  },
        { title: 'Nested Page',     path: 'pages/deep/path/nested/page.html',   category: 'page'  },
    ];

    function renderSearch(query) {
        if (!searchResults) return;
        const q = query.trim().toLowerCase();
        if (!q) { searchResults.innerHTML = '<p class="search-empty">Type to search assets…</p>'; return; }
        const matches = searchData.filter(d =>
            d.title.toLowerCase().includes(q) ||
            d.path.toLowerCase().includes(q) ||
            d.category.toLowerCase().includes(q)
        );
        if (!matches.length) {
            searchResults.innerHTML = `<p class="search-empty">No results for "${q}"</p>`;
            return;
        }
        searchResults.innerHTML = matches.map(d => {
            const t = d.title.replace(new RegExp(q,'gi'), m => `<mark>${m}</mark>`);
            return `<div class="search-item"><a href="${d.path}">${t}</a>
                    <span class="badge badge-opt">${d.category}</span>
                    <small style="color:var(--color-muted);display:block">${d.path}</small></div>`;
        }).join('');
    }

    if (searchInput) {
        searchInput.addEventListener('input', () => renderSearch(searchInput.value));
        renderSearch('');
    }

    // 12. Resize observer for live viewport stat
    if (typeof ResizeObserver !== 'undefined') {
        new ResizeObserver(() => {
            setStatus('viewport', 'ok', `${window.innerWidth} × ${window.innerHeight} px`);
        }).observe(document.body);
    }

}); // end DOMContentLoaded
JS_EOF
wrote "$OUT/assets/js/stress.js"

# =============================================================================
# §4  JSON DATA
# =============================================================================
log "Writing JSON..."
cat > "$OUT/assets/json/data.json" <<'JSON_EOF'
{
  "name": "RustHost Stress Fixture",
  "version": "1.0.0",
  "description": "Local JSON file for fetch() testing",
  "generated": "deterministic",
  "items": 20,
  "categories": ["image", "video", "audio", "pdf", "download", "page"],
  "unicode": "日本語 • Ñoño • Ψ • 🦀",
  "nested": {
    "level1": {
      "level2": {
        "level3": "deep nesting test"
      }
    }
  },
  "array_of_objects": [
    { "id": 1, "mime": "image/png",  "ext": "png"  },
    { "id": 2, "mime": "image/jpeg", "ext": "jpg"  },
    { "id": 3, "mime": "image/webp", "ext": "webp" },
    { "id": 4, "mime": "video/mp4",  "ext": "mp4"  },
    { "id": 5, "mime": "audio/wav",  "ext": "wav"  }
  ]
}
JSON_EOF
wrote "$OUT/assets/json/data.json"

# =============================================================================
# §5  SVG (hand-written)
# =============================================================================
log "Writing SVG..."
cat > "$OUT/assets/images/vector.svg" <<'SVG_EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 300" width="400" height="300">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%"   stop-color="#2563eb"/>
      <stop offset="100%" stop-color="#7c3aed"/>
    </linearGradient>
    <linearGradient id="fg" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%"   stop-color="#ffffff" stop-opacity="0.9"/>
      <stop offset="100%" stop-color="#ffffff" stop-opacity="0.6"/>
    </linearGradient>
  </defs>
  <rect width="400" height="300" fill="url(#bg)" rx="12"/>
  <!-- Crab emoji stand-in: simple SVG crab shape -->
  <text x="200" y="130" text-anchor="middle" font-size="72" font-family="serif">🦀</text>
  <text x="200" y="175" text-anchor="middle" font-size="22" font-weight="bold"
        font-family="system-ui,sans-serif" fill="url(#fg)">RustHost</text>
  <text x="200" y="200" text-anchor="middle" font-size="13"
        font-family="system-ui,sans-serif" fill="rgba(255,255,255,.7)">Static Stress Fixture</text>
  <text x="200" y="265" text-anchor="middle" font-size="10"
        font-family="monospace" fill="rgba(255,255,255,.5)">image/svg+xml • inline SVG test</text>
  <!-- Decorative circles -->
  <circle cx="40"  cy="40"  r="28" fill="rgba(255,255,255,.08)"/>
  <circle cx="360" cy="260" r="40" fill="rgba(255,255,255,.06)"/>
  <circle cx="370" cy="30"  r="18" fill="rgba(255,255,255,.10)"/>
</svg>
SVG_EOF
wrote "$OUT/assets/images/vector.svg"

# =============================================================================
# §6  PNG IMAGES  (Python stdlib, no external deps)
# =============================================================================
log "Generating PNG images..."

if [ "$HAS_PYTHON" -eq 1 ] || [ "$HAS_FFMPEG" -eq 1 ]; then
    if [ "$HAS_PYTHON" -eq 1 ]; then
        _py_make_png       "$OUT/assets/images/small.png"              64   48  37  99 235   # blue
        _py_make_png       "$OUT/assets/images/poster.png"            320  180  15  15  30   # dark (video poster)
        _py_make_png       "$OUT/assets/images/favicon-src.png"        64   64  37  99 235
        _py_make_gradient_png "$OUT/assets/images/medium.png"         400  300
        _py_make_gradient_png "$OUT/assets/images/large.png"          800  500
        _py_make_gradient_png "$OUT/assets/images/background.png"     512  256
        _py_make_png       "$OUT/assets/images/nested/deep/photo.png" 200  150 124  58 237   # purple
    else
        # ffmpeg fallback
        for spec in "small.png:64:48:#2563eb" "poster.png:320:180:#0f0f1e" \
                    "medium.png:400:300:#7c3aed" "large.png:800:500:#16a34a" \
                    "background.png:512:256:#2563eb" "nested/deep/photo.png:200:150:#7c3aed"; do
            IFS=':' read -r fname w h col <<< "$spec"
            ffmpeg -y -f lavfi -i "color=c=${col}:s=${w}x${h}:d=1" \
                   -frames:v 1 "$OUT/assets/images/$fname" -loglevel error
            wrote "$OUT/assets/images/$fname"
        done
    fi

    # Files with special names
    cp "$OUT/assets/images/small.png" "$OUT/assets/images/image with spaces.png"
    wrote "$OUT/assets/images/image with spaces.png"
    cp "$OUT/assets/images/medium.png" "$OUT/assets/images/photo.JPG"   # uppercase ext, wrong mime test
    wrote "$OUT/assets/images/photo.JPG"

    for f in small.png medium.png large.png background.png poster.png nested/deep/photo.png; do
        wrote "$OUT/assets/images/$f"
    done
else
    skip "PNG images (no python3 or ffmpeg)"
fi

# =============================================================================
# §7  JPEG  (ffmpeg)
# =============================================================================
log "Generating JPEG..."
if [ "$HAS_FFMPEG" -eq 1 ]; then
    ffmpeg -y -f lavfi \
        -i "color=c=#e85d04:s=320x240:d=1" \
        -frames:v 1 -q:v 3 \
        "$OUT/assets/images/medium.jpg" -loglevel error
    wrote "$OUT/assets/images/medium.jpg"
else
    skip "JPEG (ffmpeg not available)"
fi

# =============================================================================
# §8  WebP  (ffmpeg)
# =============================================================================
log "Generating WebP..."
if [ "$HAS_FFMPEG" -eq 1 ]; then
    ffmpeg -y -f lavfi \
        -i "color=c=#06b6d4:s=200x150:d=1" \
        -frames:v 1 -vf "format=rgba" \
        "$OUT/assets/images/photo.webp" -loglevel error
    wrote "$OUT/assets/images/photo.webp"
else
    skip "WebP (ffmpeg not available)"
fi

# =============================================================================
# §9  GIF  (ffmpeg)
# =============================================================================
log "Generating GIF..."
if [ "$HAS_FFMPEG" -eq 1 ]; then
    # Animated gradient: hue rotate over 2s, 10fps, 120x90
    ffmpeg -y -f lavfi \
        -i "color=c=#ff4800:s=120x90:d=2,hue=h='t*180'" \
        -vf "fps=8,scale=120:90:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" \
        "$OUT/assets/images/animation.gif" -loglevel error
    wrote "$OUT/assets/images/animation.gif"
else
    skip "GIF (ffmpeg not available)"
fi

# =============================================================================
# §10  ICO / Favicon  (Python)
# =============================================================================
log "Generating favicon.ico..."
if [ "$HAS_PYTHON" -eq 1 ]; then
    python3 - "$OUT/favicon.ico" <<'PYEOF'
import sys, zlib, struct

# Embed a minimal 16x16 PNG inside a .ico container
def make_png16(r,g,b):
    def chunk(tag,data):
        c=zlib.crc32(tag+data)&0xffffffff
        return struct.pack('>I',len(data))+tag+data+struct.pack('>I',c)
    rows=b''.join(b'\x00'+bytes([r,g,b,255])*16 for _ in range(16))
    ihdr=chunk(b'IHDR',struct.pack('>IIBBBBB',16,16,8,6,0,0,0))
    idat=chunk(b'IDAT',zlib.compress(rows,9))
    iend=chunk(b'IEND',b'')
    return b'\x89PNG\r\n\x1a\n'+ihdr+idat+iend

png=make_png16(37,99,235)   # #2563eb blue

# ICO format: header + dir entry + image data
ico_header=struct.pack('<HHH',0,1,1)          # reserved, type=1 (ICO), count=1
img_offset=6+16                                # header(6) + 1 dir entry(16)
ico_dir   =struct.pack('<BBBBHHII',
    16,16,          # width, height
    0,              # color count (0=256+)
    0,              # reserved
    1,              # color planes
    32,             # bits per pixel
    len(png),       # image data size
    img_offset      # image data offset
)
with open(sys.argv[1],'wb') as f:
    f.write(ico_header+ico_dir+png)
PYEOF
    wrote "$OUT/favicon.ico"
else
    skip "favicon.ico (no python3)"
fi

# =============================================================================
# §11  VIDEO  (ffmpeg)
# =============================================================================
log "Generating video..."
if [ "$HAS_FFMPEG" -eq 1 ]; then
    # MP4 H.264 – colour bars, 4 seconds, tiny bitrate
    ffmpeg -y -f lavfi \
        -i "testsrc=duration=4:size=320x180:rate=15" \
        -c:v libx264 -preset ultrafast -crf 35 \
        -movflags +faststart -an \
        "$OUT/assets/video/test.mp4" -loglevel error
    wrote "$OUT/assets/video/test.mp4"

    # WebM VP9 – same source
    ffmpeg -y -f lavfi \
        -i "testsrc=duration=4:size=320x180:rate=15" \
        -c:v libvpx-vp9 -b:v 200k -an \
        "$OUT/assets/video/test.webm" -loglevel error
    wrote "$OUT/assets/video/test.webm"

    # Video with spaces in filename
    cp "$OUT/assets/video/test.mp4" "$OUT/assets/video/video with spaces.mp4"
    wrote "$OUT/assets/video/video with spaces.mp4"
else
    skip "MP4 video (ffmpeg not available)"
    skip "WebM video (ffmpeg not available)"
fi

# =============================================================================
# §12  AUDIO  (WAV via Python; MP3+OGG via ffmpeg)
# =============================================================================
log "Generating audio..."

# WAV – always attempted via Python
if [ "$HAS_PYTHON" -eq 1 ]; then
    _py_make_wav "$OUT/assets/audio/test.wav" 440 3
    wrote "$OUT/assets/audio/test.wav"
elif [ "$HAS_FFMPEG" -eq 1 ]; then
    ffmpeg -y -f lavfi -i "sine=frequency=440:duration=3" \
           -ar 22050 -ac 1 "$OUT/assets/audio/test.wav" -loglevel error
    wrote "$OUT/assets/audio/test.wav"
else
    skip "WAV audio"
fi

if [ "$HAS_FFMPEG" -eq 1 ] && [ -f "$OUT/assets/audio/test.wav" ]; then
    # MP3
    ffmpeg -y -i "$OUT/assets/audio/test.wav" -c:a libmp3lame -b:a 64k \
           "$OUT/assets/audio/test.mp3" -loglevel error
    wrote "$OUT/assets/audio/test.mp3"

    # OGG/Opus
    ffmpeg -y -i "$OUT/assets/audio/test.wav" -c:a libopus -b:a 32k \
           "$OUT/assets/audio/test.ogg" -loglevel error
    wrote "$OUT/assets/audio/test.ogg"
else
    skip "MP3 audio (ffmpeg not available or WAV missing)"
    skip "OGG audio (ffmpeg not available or WAV missing)"
fi

# =============================================================================
# §13  PDF
# =============================================================================
log "Generating PDF..."
if [ "$HAS_PYTHON" -eq 1 ]; then
    _py_make_pdf "$OUT/assets/pdf/test.pdf"     "RustHost Stress Test PDF"
    wrote "$OUT/assets/pdf/test.pdf"
    _py_make_pdf "$OUT/assets/pdf/document with spaces.pdf" "PDF With Spaces In Filename"
    wrote "$OUT/assets/pdf/document with spaces.pdf"
else
    skip "PDF (no python3)"
fi

# =============================================================================
# §14  DOWNLOAD ASSETS
# =============================================================================
log "Generating download assets..."

cat > "$OUT/assets/downloads/sample.txt" <<'TXT_EOF'
RustHost Static Stress Fixture – sample.txt
============================================
This plain text file tests text/plain MIME type serving.

Content-Type should be: text/plain (or text/plain; charset=utf-8)

Lines: 10
Unicode check: café, naïve, 日本語, Ψ, 🦀
TXT_EOF
wrote "$OUT/assets/downloads/sample.txt"

cat > "$OUT/assets/downloads/data.csv" <<'CSV_EOF'
id,name,category,mime_type,size_bytes,expected_behavior
1,small.png,image,image/png,512,inline
2,medium.jpg,image,image/jpeg,4096,inline
3,test.mp4,video,video/mp4,16384,inline
4,test.wav,audio,audio/wav,8192,inline
5,test.pdf,pdf,application/pdf,1024,inline-or-download
6,data.csv,download,text/csv,256,download
7,test.bin,download,application/octet-stream,256,download
8,no-extension,download,,256,download
CSV_EOF
wrote "$OUT/assets/downloads/data.csv"

cat > "$OUT/assets/downloads/data.xml" <<'XML_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<stress-fixture version="1.0">
  <meta>
    <generator>RustHost Stress Test Generator</generator>
    <description>XML test file for MIME type validation</description>
  </meta>
  <assets>
    <asset id="1" type="image" mime="image/png">small.png</asset>
    <asset id="2" type="video" mime="video/mp4">test.mp4</asset>
    <asset id="3" type="audio" mime="audio/wav">test.wav</asset>
    <unicode>日本語 • café • Ψ • 🦀</unicode>
  </assets>
</stress-fixture>
XML_EOF
wrote "$OUT/assets/downloads/data.xml"

# Binary-ish test file (random-looking bytes)
python3 -c "
import struct, math
data = b'RHBIN\x01\x00'  # magic
for i in range(120):
    data += struct.pack('>H', int(abs(math.sin(i*0.3))*65535))
with open('$OUT/assets/downloads/test.bin','wb') as f: f.write(data)
"
wrote "$OUT/assets/downloads/test.bin"

# File with no extension
cat > "$OUT/assets/downloads/no-extension" <<'NOEXT_EOF'
This file has no extension.
Servers should serve it as application/octet-stream or text/plain.
NOEXT_EOF
wrote "$OUT/assets/downloads/no-extension"

# File with uppercase extension
cat > "$OUT/assets/downloads/README.TXT" <<'UPCASE_EOF'
README.TXT — uppercase extension test
Servers should serve .TXT as text/plain just as .txt.
UPCASE_EOF
wrote "$OUT/assets/downloads/README.TXT"

# File with spaces in filename
cat > "$OUT/assets/downloads/file with spaces.txt" <<'SPACES_EOF'
This file's path contains spaces.
Requesting it requires percent-encoding: file%20with%20spaces.txt
SPACES_EOF
wrote "$OUT/assets/downloads/file with spaces.txt"

# Nested files several dirs deep
mkdir -p "$OUT/assets/downloads/level1/level2/level3"
cat > "$OUT/assets/downloads/level1/level2/level3/deep-file.txt" <<'DEEP_EOF'
Deeply nested file — tests directory traversal and relative path resolution.
Path: assets/downloads/level1/level2/level3/deep-file.txt
DEEP_EOF
wrote "$OUT/assets/downloads/level1/level2/level3/deep-file.txt"

# =============================================================================
# §15  PDF EMBED TEST PAGE
# =============================================================================
log "Writing PDF embed test page..."
cat > "$OUT/assets/pdf/pdf-embed-test.html" <<'PDFEMBED_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PDF Embed Test – RustHost Stress</title>
<link rel="stylesheet" href="../../assets/css/stress.css">
</head>
<body>
<header class="site-header">
  <span class="brand">RustHost Stress <small>/ PDF Embed Test</small></span>
  <nav><a href="../../index.html">← Home</a></nav>
</header>
<div class="container">
  <h1 class="section-title">PDF Embedding Tests</h1>

  <div class="section">
    <h2 class="section-title" style="font-size:1rem">1. &lt;iframe&gt; embed</h2>
    <iframe src="test.pdf" width="100%" height="480"
            style="border:1px solid var(--color-border);border-radius:var(--radius);">
      Your browser does not support iframes.
    </iframe>
  </div>

  <div class="section">
    <h2 class="section-title" style="font-size:1rem">2. &lt;object&gt; embed</h2>
    <object data="test.pdf" type="application/pdf" width="100%" height="480"
            style="border:1px solid var(--color-border);border-radius:var(--radius);">
      <p>PDF not supported. <a href="test.pdf">Download test.pdf</a></p>
    </object>
  </div>

  <div class="section">
    <h2 class="section-title" style="font-size:1rem">3. &lt;embed&gt; tag</h2>
    <embed src="test.pdf" type="application/pdf" width="100%" height="400"
           style="border:1px solid var(--color-border);border-radius:var(--radius);">
  </div>

  <div class="section">
    <h2 class="section-title" style="font-size:1rem">4. Links</h2>
    <ul class="link-list">
      <li><a href="test.pdf">test.pdf – direct link</a></li>
      <li><a href="document%20with%20spaces.pdf">document with spaces.pdf – percent-encoded link</a></li>
      <li><a href="missing.pdf" class="link-broken">missing.pdf <span class="badge badge-broken">EXPECTED BROKEN</span></a></li>
    </ul>
  </div>
</div>
</body>
</html>
PDFEMBED_EOF
wrote "$OUT/assets/pdf/pdf-embed-test.html"

# =============================================================================
# §16  EDGE-CASE SUBPAGES
# =============================================================================
log "Writing edge-case subpages..."

# ── Hash navigation ──
cat > "$OUT/pages/hash-nav.html" <<'HASHNAV_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hash Navigation Test – RustHost Stress</title>
<link rel="stylesheet" href="../assets/css/stress.css">
<style>
  .anchor-block { min-height: 180px; padding: 2rem; border: 1px solid var(--color-border);
                  border-radius: var(--radius); margin-bottom: 1rem;
                  display: flex; align-items: center; justify-content: center;
                  font-size: 1.5rem; font-weight: 700; color: var(--color-muted);
                  background: var(--color-surface); }
  :target { outline: 3px solid var(--color-primary); outline-offset: 4px; }
</style>
</head>
<body>
<header class="site-header">
  <span class="brand">RustHost Stress <small>/ Hash Navigation</small></span>
  <nav>
    <a href="../index.html">← Home</a>
    <a href="#section-a">#A</a>
    <a href="#section-b">#B</a>
    <a href="#section-c">#C</a>
    <a href="#bottom">#Bottom</a>
  </nav>
</header>
<div class="container">
  <h1 class="section-title">Hash / Fragment Navigation Test</h1>
  <p class="mt-1">Tests: URL fragment targeting, <code>:target</code> CSS, <code>scroll-behavior:smooth</code>,
     <code>hashchange</code> JS event, back/forward navigation.</p>

  <div class="anchor-list mt-2">
    <a href="#section-a">#section-a</a>
    <a href="#section-b">#section-b</a>
    <a href="#section-c">#section-c</a>
    <a href="#item-1">#item-1</a>
    <a href="#item-5">#item-5</a>
    <a href="#bottom">#bottom</a>
    <a href="#"># (root)</a>
    <a href="#nonexistent">#nonexistent (missing anchor)</a>
  </div>

  <div id="section-a" class="anchor-block mt-2">§ A — First Section</div>

  <ul class="link-list">
    <li id="item-1"><strong>#item-1</strong> — anchor on list item 1</li>
    <li id="item-2"><strong>#item-2</strong> — anchor on list item 2</li>
    <li id="item-3"><strong>#item-3</strong> — anchor on list item 3</li>
    <li id="item-4"><strong>#item-4</strong> — anchor on list item 4</li>
    <li id="item-5"><strong>#item-5</strong> — anchor on list item 5</li>
  </ul>

  <div id="section-b" class="anchor-block mt-2">§ B — Second Section</div>
  <p>After scrolling here, the URL should show <code>#section-b</code>.
     Using browser back should restore the previous hash.</p>

  <div id="section-c" class="anchor-block mt-2">§ C — Third Section</div>
  <p>External link back to index with hash:
     <a href="../index.html#js-stress">index.html#js-stress</a></p>

  <div id="bottom" class="anchor-block mt-2" style="min-height:80px">↓ Bottom anchor</div>
  <p class="mt-2"><a href="#section-a">↑ Back to top (#section-a)</a></p>
</div>
<script>
  document.addEventListener('DOMContentLoaded',()=>{
    const info=document.createElement('div');
    info.style.cssText='position:fixed;bottom:1rem;right:1rem;background:var(--color-surface);border:1px solid var(--color-border);padding:.5rem .85rem;border-radius:6px;font-size:.8rem;z-index:999;box-shadow:0 2px 8px rgba(0,0,0,.15)';
    info.textContent='hash: '+(location.hash||'(none)');
    document.body.appendChild(info);
    window.addEventListener('hashchange',()=>{ info.textContent='hash: '+location.hash; });
  });
</script>
</body>
</html>
HASHNAV_EOF
wrote "$OUT/pages/hash-nav.html"

# ── Long page ──
{
cat <<'LONG_OPEN'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Long Page – RustHost Stress</title>
<link rel="stylesheet" href="../assets/css/stress.css">
</head>
<body>
<header class="site-header">
  <span class="brand">RustHost Stress <small>/ Long Page</small></span>
  <nav><a href="../index.html">← Home</a></nav>
</header>
<div class="container">
<h1 class="section-title">Long Page – Scroll and Anchor Test</h1>
<p>Tests: long-content layout, sticky header, many anchors, scroll performance.</p>
<div class="anchor-list mt-2">
LONG_OPEN
for i in $(seq 1 30); do
    printf '<a href="#anchor-%d">#%d</a>\n' "$i" "$i"
done
cat <<'LONG_BODY'
</div>
<div class="long-text mt-2">
LONG_BODY
for i in $(seq 1 30); do
    cat <<ANCHOR_BLOCK
<h2 id="anchor-${i}" style="margin:2rem 0 .5rem;padding-top:1rem;border-top:1px solid var(--color-border)">
  § ${i} — Section heading ${i}
</h2>
<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt
ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco
laboris nisi ut aliquip ex ea commodo consequat. Section ${i} tests anchor ${i} resolution.</p>
<p>Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat
nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia
deserunt mollit anim id est laborum. <a href="#anchor-1">↑ Top</a> | <a href="#anchor-$((i < 30 ? i+1 : 1))">Next →</a></p>
ANCHOR_BLOCK
done
cat <<'LONG_CLOSE'
</div>
</div>
</body>
</html>
LONG_CLOSE
} > "$OUT/pages/long-page.html"
wrote "$OUT/pages/long-page.html"

# ── Table-heavy page ──
{
cat <<'TABLE_OPEN'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Table Heavy – RustHost Stress</title>
<link rel="stylesheet" href="../assets/css/stress.css">
</head>
<body>
<header class="site-header">
  <span class="brand">RustHost Stress <small>/ Table Heavy</small></span>
  <nav><a href="../index.html">← Home</a></nav>
</header>
<div class="container">
<h1 class="section-title">Table-Heavy Page</h1>
<p>Tests: wide tables, overflow-x scroll, sticky header while scrolling wide content.</p>

<h2 class="section-title" style="font-size:1rem;margin-top:2rem">Asset Manifest Table (50 rows)</h2>
<div class="table-wrap">
<table>
<thead>
  <tr><th>#</th><th>Filename</th><th>Category</th><th>MIME Type</th><th>Expected Behavior</th><th>Size (approx)</th><th>Notes</th></tr>
</thead>
<tbody>
TABLE_OPEN
MIMES=("image/png" "image/jpeg" "image/webp" "image/gif" "image/svg+xml" "video/mp4" "video/webm" "audio/wav" "audio/mpeg" "audio/ogg" "application/pdf" "text/plain" "text/csv" "text/xml" "application/json" "application/octet-stream" "application/wasm" "text/html" "font/woff2" "image/ico")
CATS=("image" "image" "image" "image" "image" "video" "video" "audio" "audio" "audio" "pdf" "download" "download" "download" "json" "download" "download" "page" "font" "image")
BEHS=("inline" "inline" "inline" "inline" "inline" "inline" "inline" "inline" "download" "inline" "inline-or-download" "inline" "download" "inline" "inline" "download" "download" "inline" "download" "inline")
for i in $(seq 1 50); do
    idx=$(( (i-1) % 20 ))
    mime="${MIMES[$idx]}"
    cat="${CATS[$idx]}"
    beh="${BEHS[$idx]}"
    size=$(( (i * 137 + 512) % 65536 + 256 ))
    printf '<tr><td>%d</td><td><code>asset_%03d.%s</code></td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%d B</td><td>Row %d stress test</td></tr>\n' \
        "$i" "$i" "$(echo "$mime" | cut -d/ -f2)" "$cat" "$mime" "$beh" "$size" "$i"
done
cat <<'TABLE_CLOSE'
</tbody>
</table>
</div>
</div>
</body>
</html>
TABLE_CLOSE
} > "$OUT/pages/table-heavy.html"
wrote "$OUT/pages/table-heavy.html"

# ── Unicode page ──
cat > "$OUT/pages/unicode.html" <<'UNICODE_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unicode Test – RustHost Stress</title>
<link rel="stylesheet" href="../assets/css/stress.css">
</head>
<body>
<header class="site-header">
  <span class="brand">RustHost Stress <small>/ Unicode</small></span>
  <nav><a href="../index.html">← Home</a></nav>
</header>
<div class="container">
<h1 class="section-title">Unicode / Encoding Test</h1>
<p>Tests: UTF-8 response headers, multi-byte characters, emoji, RTL, special HTML entities.</p>

<div class="section">
  <h2 class="section-title" style="font-size:1rem">Emoji</h2>
  <p style="font-size:2rem;line-height:2">🦀 🦭 🐻 🌍 🚀 🎵 🔥 ⚡ 🎯 💡 🏴‍☠️ 🇯🇵 🇩🇪 🇺🇦</p>
</div>

<div class="section">
  <h2 class="section-title" style="font-size:1rem">Latin Extended</h2>
  <p>café • naïve • résumé • Ñoño • façade • über • Ångström • voilà</p>
  <p>Ø Å æ Þ ð ý ĝ ĥ ŝ ĵ ĉ ĝ — Czech: Příliš žluťoučký kůň</p>
</div>

<div class="section">
  <h2 class="section-title" style="font-size:1rem">CJK</h2>
  <p lang="ja">日本語テスト：吾輩は猫である。名前はまだ無い。</p>
  <p lang="zh">中文测试：春眠不觉晓，处处闻啼鸟。</p>
  <p lang="ko">한국어 테스트: 내가 그의 이름을 불러 주기 전에는</p>
</div>

<div class="section">
  <h2 class="section-title" style="font-size:1rem">RTL (Arabic / Hebrew)</h2>
  <p dir="rtl" lang="ar" style="font-size:1.2rem">مرحباً بالعالم — اختبار الترميز UTF-8</p>
  <p dir="rtl" lang="he" style="font-size:1.2rem">שלום עולם — בדיקת קידוד</p>
</div>

<div class="section">
  <h2 class="section-title" style="font-size:1rem">Greek / Cyrillic / Math</h2>
  <p>Greek: α β γ δ ε ζ η θ ι κ λ μ ν ξ ο π ρ σ τ υ φ χ ψ ω</p>
  <p>Cyrillic: А Б В Г Д Е Ж З И Й К Л М Н О П Р С Т У Ф Х Ц Ч Ш Щ Ъ Ы Ь Э Ю Я</p>
  <p>Math: ∀ ∂ ∃ ∅ ∇ ∈ ∉ ∋ ∏ ∑ − ∕ ∗ √ ∝ ∞ ∠ ∧ ∨ ∩ ∪ ∫ ∴ ∼ ≅ ≈ ≠ ≡ ≤ ≥</p>
</div>

<div class="section">
  <h2 class="section-title" style="font-size:1rem">URL-sensitive characters (display only)</h2>
  <pre>Reserved: : / ? # [ ] @ ! $ & ' ( ) * + , ; =
Unreserved: A-Z a-z 0-9 - _ . ~
Percent-encoded space: %20
Non-ASCII in URL: /path/日本語 (may need encoding)
Null byte in URL: /path/%00 (server should handle safely)</pre>
</div>

<div class="section">
  <h2 class="section-title" style="font-size:1rem">HTML Entities</h2>
  <p>&lt;p&gt; &amp;amp; &quot;quoted&quot; &apos;apostrophe&apos; &copy; &reg; &trade; &mdash; &ndash; &hellip;</p>
  <p>Non-breaking: A&nbsp;B&nbsp;C&nbsp;(should not break)</p>
</div>
</div>
</body>
</html>
UNICODE_EOF
wrote "$OUT/pages/unicode.html"

# ── File with spaces in name ──
cat > "$OUT/pages/file with spaces.html" <<'SPACES_HTML_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Filename With Spaces – RustHost Stress</title>
<link rel="stylesheet" href="../assets/css/stress.css">
</head>
<body>
<header class="site-header">
  <span class="brand">RustHost Stress <small>/ Spaces in filename</small></span>
  <nav><a href="../index.html">← Home</a></nav>
</header>
<div class="container">
  <h1 class="section-title">File With Spaces in Name Test</h1>
  <p>This file itself is named <code>file with spaces.html</code>.</p>
  <p>Linking to it requires percent-encoding: <code>pages/file%20with%20spaces.html</code></p>
  <p>The server should decode <code>%20</code> and serve this file correctly.</p>
  <p><a href="../index.html">← Back to index</a></p>
</div>
</body>
</html>
SPACES_HTML_EOF
wrote "$OUT/pages/file with spaces.html"

# ── Deeply nested page ──
cat > "$OUT/pages/deep/path/nested/page.html" <<'DEEP_HTML_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deep Nested Page – RustHost Stress</title>
<link rel="stylesheet" href="../../../../assets/css/stress.css">
</head>
<body>
<header class="site-header">
  <span class="brand">RustHost Stress <small>/ Deep Nested</small></span>
  <nav><a href="../../../../index.html">← Home</a></nav>
</header>
<div class="container">
  <h1 class="section-title">Deeply Nested Page</h1>
  <p>This file is at <code>pages/deep/path/nested/page.html</code> (4 directories deep).</p>
  <p>All relative paths in this file use <code>../../../../</code> to reach the root.</p>
  <ul class="link-list">
    <li><a href="../../../../assets/css/stress.css">../../../../assets/css/stress.css</a> (CSS — should be loaded above)</li>
    <li><a href="../../../../assets/images/small.png">../../../../assets/images/small.png</a></li>
    <li><a href="../../../../index.html">../../../../index.html</a> (root)</li>
    <li><a href="../../../hash-nav.html">../../../hash-nav.html</a> (go up one, then pages/)</li>
    <li><a href="./page.html">./page.html</a> (self-link)</li>
  </ul>
  <h2 class="section-title" style="font-size:1rem;margin-top:2rem">Relative image test</h2>
  <img src="../../../../assets/images/small.png" alt="small.png via relative path" style="border:1px solid var(--color-border);border-radius:4px">
</div>
</body>
</html>
DEEP_HTML_EOF
wrote "$OUT/pages/deep/path/nested/page.html"

# ── 404 example ──
cat > "$OUT/pages/404-example.html" <<'E404_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>404 Not Found – RustHost Stress</title>
<link rel="stylesheet" href="../assets/css/stress.css">
<style>
  .error-hero { text-align:center; padding: 4rem 1rem; }
  .error-code { font-size: 6rem; font-weight:900; color:var(--color-danger); line-height:1; }
  .error-msg  { font-size: 1.5rem; margin: .5rem 0; }
</style>
</head>
<body>
<header class="site-header">
  <span class="brand">RustHost Stress <small>/ 404 Example</small></span>
  <nav><a href="../index.html">← Home</a></nav>
</header>
<div class="container">
  <div class="error-hero">
    <div class="error-code">404</div>
    <div class="error-msg">Not Found</div>
    <p style="color:var(--color-muted)">
      This is a static example of a 404 page.<br>
      It is reachable at <code>pages/404-example.html</code> — so it is not actually a 404.<br>
      To test RustHost's real 404 handling, request a path that does not exist.
    </p>
    <p class="mt-2"><a href="../index.html">← Return home</a></p>
  </div>
</div>
</body>
</html>
E404_EOF
wrote "$OUT/pages/404-example.html"

# =============================================================================
# §17  BASELINE PAGE
# =============================================================================
log "Writing baseline.html..."
cat > "$OUT/baseline.html" <<'BASELINE_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Baseline Report – RustHost Stress</title>
<link rel="stylesheet" href="assets/css/stress.css">
</head>
<body>
<header class="site-header">
  <span class="brand">RustHost Stress <small>/ Baseline Report</small></span>
  <nav>
    <a href="index.html">← Home</a>
  </nav>
</header>
<div class="container">
  <h1 class="section-title">Baseline: What a Healthy RustHost Run Looks Like</h1>
  <p>Use this page as a reference when manually testing RustHost against the stress fixture.
     Open browser DevTools → Network tab and Console tab while checking each item.</p>

  <div class="section">
    <h2 class="section-title">✅ Expected: No Errors</h2>
    <ul class="link-list">
      <li>Console shows <strong>zero errors</strong>, except for assets explicitly marked <span class="badge badge-broken">EXPECTED BROKEN</span></li>
      <li>No mixed-content warnings (fixture is entirely local)</li>
      <li>No CORS errors (all assets are same-origin)</li>
      <li>Network tab shows all non-broken assets returning <strong>2xx</strong></li>
    </ul>
  </div>

  <div class="section">
    <h2 class="section-title">🟢 MIME Type Expectations</h2>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Extension</th><th>Expected Content-Type</th><th>Browser behavior</th></tr></thead>
      <tbody>
        <tr><td><code>.html</code></td><td><code>text/html; charset=utf-8</code></td><td>Renders</td></tr>
        <tr><td><code>.css</code></td><td><code>text/css</code></td><td>Applied as stylesheet</td></tr>
        <tr><td><code>.js</code></td><td><code>text/javascript</code> or <code>application/javascript</code></td><td>Executed</td></tr>
        <tr><td><code>.json</code></td><td><code>application/json</code></td><td>Displayed or download</td></tr>
        <tr><td><code>.png</code></td><td><code>image/png</code></td><td>Renders inline</td></tr>
        <tr><td><code>.jpg</code> / <code>.jpeg</code></td><td><code>image/jpeg</code></td><td>Renders inline</td></tr>
        <tr><td><code>.webp</code></td><td><code>image/webp</code></td><td>Renders inline (modern browsers)</td></tr>
        <tr><td><code>.gif</code></td><td><code>image/gif</code></td><td>Renders/animates inline</td></tr>
        <tr><td><code>.svg</code></td><td><code>image/svg+xml</code></td><td>Renders inline</td></tr>
        <tr><td><code>.ico</code></td><td><code>image/x-icon</code> or <code>image/vnd.microsoft.icon</code></td><td>Favicon in tab</td></tr>
        <tr><td><code>.mp4</code></td><td><code>video/mp4</code></td><td>Video player</td></tr>
        <tr><td><code>.webm</code></td><td><code>video/webm</code></td><td>Video player</td></tr>
        <tr><td><code>.wav</code></td><td><code>audio/wav</code> or <code>audio/x-wav</code></td><td>Audio player</td></tr>
        <tr><td><code>.mp3</code></td><td><code>audio/mpeg</code></td><td>Audio player</td></tr>
        <tr><td><code>.ogg</code></td><td><code>audio/ogg</code></td><td>Audio player</td></tr>
        <tr><td><code>.pdf</code></td><td><code>application/pdf</code></td><td>PDF viewer or download</td></tr>
        <tr><td><code>.csv</code></td><td><code>text/csv</code></td><td>Download</td></tr>
        <tr><td><code>.xml</code></td><td><code>text/xml</code> or <code>application/xml</code></td><td>Displayed</td></tr>
        <tr><td><code>.bin</code></td><td><code>application/octet-stream</code></td><td>Download prompt</td></tr>
        <tr><td>(no ext)</td><td><code>application/octet-stream</code> or <code>text/plain</code></td><td>Download or display</td></tr>
        <tr><td><code>.TXT</code> (uppercase)</td><td>Same as <code>.txt</code> — <code>text/plain</code></td><td>Displayed</td></tr>
      </tbody>
    </table>
    </div>
  </div>

  <div class="section">
    <h2 class="section-title">🟡 Expected Broken Assets</h2>
    <p>These are <strong>intentionally missing</strong>. RustHost should return <strong>404</strong> for each.</p>
    <ul class="link-list">
      <li><span class="link-broken">assets/images/broken-reference.png</span> <span class="badge badge-broken">EXPECTED 404</span></li>
      <li><span class="link-broken">assets/pdf/missing.pdf</span> <span class="badge badge-broken">EXPECTED 404</span></li>
      <li><span class="link-broken">assets/images/does-not-exist.jpg</span> <span class="badge badge-broken">EXPECTED 404</span></li>
      <li><span class="link-broken">pages/nonexistent-page.html</span> <span class="badge badge-broken">EXPECTED 404</span></li>
    </ul>
  </div>

  <div class="section">
    <h2 class="section-title">📋 Manual Checklist</h2>
    <ul class="link-list">
      <li>☐ Status panel on <a href="index.html">index.html</a> shows all green dots</li>
      <li>☐ <code>fetch()</code> status dot shows "fetch OK" — requires serving over HTTP (not file://)</li>
      <li>☐ Images render in the image grid; broken image shows alt text</li>
      <li>☐ <code>&lt;video controls&gt;</code> renders and plays MP4 and/or WebM</li>
      <li>☐ <code>&lt;audio controls&gt;</code> renders and plays WAV, MP3, and/or OGG</li>
      <li>☐ PDF link opens in browser viewer or prompts download</li>
      <li>☐ PDF iframe/object on embed test page shows content or fallback</li>
      <li>☐ Dark mode stylesheet activates if OS dark mode is on</li>
      <li>☐ Sticky header stays visible while scrolling <a href="pages/long-page.html">long-page.html</a></li>
      <li>☐ Hash links on <a href="pages/hash-nav.html">hash-nav.html</a> scroll smoothly to anchors</li>
      <li>☐ Table overflows with horizontal scroll on <a href="pages/table-heavy.html">table-heavy.html</a></li>
      <li>☐ Unicode characters render correctly on <a href="pages/unicode.html">unicode.html</a></li>
      <li>☐ Nested page at <a href="pages/deep/path/nested/page.html">pages/deep/path/nested/page.html</a> loads CSS correctly</li>
      <li>☐ <code>pages/file%20with%20spaces.html</code> serves correctly when percent-encoded</li>
      <li>☐ <code>assets/downloads/file%20with%20spaces.txt</code> downloads correctly</li>
      <li>☐ <code>assets/downloads/README.TXT</code> (uppercase) served as text/plain</li>
      <li>☐ Background image visible in CSS background-image test box on index.html</li>
      <li>☐ Client-side search on index.html filters the asset list</li>
      <li>☐ Form submit on index.html shows submitted data (no network request)</li>
      <li>☐ Network tab shows <strong>no</strong> external requests to CDNs, fonts, analytics</li>
    </ul>
  </div>

  <div class="section">
    <h2 class="section-title">🔴 Failure Diagnosis</h2>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Symptom</th><th>Likely Cause</th></tr></thead>
      <tbody>
        <tr><td>CSS not applied</td><td>Wrong MIME for .css, or relative path resolution bug</td></tr>
        <tr><td>JS status panel blank</td><td>JS blocked, wrong MIME for .js, or syntax error</td></tr>
        <tr><td>fetch() failed (not file://)</td><td>CORS, wrong path, or server rejected the JSON request</td></tr>
        <tr><td>Images show broken icon</td><td>Wrong MIME, path with spaces not decoded, or missing file</td></tr>
        <tr><td>Video/audio no controls</td><td>Wrong MIME type; browser won't play unrecognised MIME</td></tr>
        <tr><td>PDF downloads instead of viewing</td><td>Content-Disposition: attachment set; or browser lacks viewer</td></tr>
        <tr><td>Uppercase .TXT served wrong MIME</td><td>Case-insensitive MIME lookup not implemented</td></tr>
        <tr><td>Spaces in filename → 404</td><td>Server not decoding %20 in URL path</td></tr>
        <tr><td>Nested CSS broken</td><td>Relative path resolution from deep directories</td></tr>
        <tr><td>Range requests broken</td><td>Video/audio may stutter or fail to seek; check Accept-Ranges header</td></tr>
      </tbody>
    </table>
    </div>
  </div>
</div>
</body>
</html>
BASELINE_EOF
wrote "$OUT/baseline.html"

# =============================================================================
# §18  MAIN INDEX PAGE
# =============================================================================
log "Writing index.html..."
cat > "$OUT/index.html" <<'INDEX_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RustHost Static Stress Fixture</title>
<link rel="icon" href="favicon.ico">
<link rel="stylesheet" href="assets/css/stress.css">
</head>
<body>

<header class="site-header">
  <span class="brand">🦀 RustHost <small>Static Stress Fixture v1.0</small></span>
  <nav>
    <a href="#css-stress">CSS</a>
    <a href="#js-stress">JS</a>
    <a href="#images">Images</a>
    <a href="#video">Video</a>
    <a href="#audio">Audio</a>
    <a href="#pdf">PDF</a>
    <a href="#downloads">Downloads</a>
    <a href="#forms">Forms</a>
    <a href="#search">Search</a>
    <a href="#edge-cases">Edge Cases</a>
    <a href="baseline.html">Baseline ↗</a>
  </nav>
</header>

<div class="container">

  <!-- ═══════════════════════════════ STATUS PANEL ════════════════════════ -->
  <div class="status-panel">
    <h2>⚡ Live Status Panel <small style="font-weight:400;color:var(--color-muted)">(populated by stress.js)</small></h2>
    <div class="status-grid">
      <div class="status-item" id="status-js">
        <span class="status-dot warn"></span>
        <span class="status-text">Waiting for JS…</span>
      </div>
      <div class="status-item" id="status-time">
        <span class="status-dot"></span>
        <span class="status-text">—</span>
      </div>
      <div class="status-item" id="status-viewport">
        <span class="status-dot"></span>
        <span class="status-text">—</span>
      </div>
      <div class="status-item" id="status-useragent">
        <span class="status-dot"></span>
        <span class="status-text">—</span>
      </div>
      <div class="status-item" id="status-localstorage">
        <span class="status-dot warn"></span>
        <span class="status-text">Checking localStorage…</span>
      </div>
      <div class="status-item" id="status-fetch">
        <span class="status-dot warn"></span>
        <span class="status-text">Fetching data.json…</span>
      </div>
      <div class="status-item" id="status-dynamic-img">
        <span class="status-dot warn"></span>
        <span class="status-text">Inserting images…</span>
      </div>
      <div class="status-item" id="status-hash">
        <span class="status-dot"></span>
        <span class="status-text">hash: (none yet)</span>
      </div>
    </div>
  </div>

  <!-- ═══════════════════════════════ CSS STRESS ══════════════════════════ -->
  <div class="section" id="css-stress">
    <h2 class="section-title">§1 CSS Stress</h2>
    <p>If this page is styled (sticky header, colour variables, dark/light mode) the CSS loaded correctly.</p>

    <div class="row mt-2">
      <div class="col">
        <h3 style="margin-bottom:.5rem;font-size:.95rem">Custom properties</h3>
        <div style="display:flex;gap:.5rem;flex-wrap:wrap">
          <div style="width:40px;height:40px;background:var(--color-primary);border-radius:4px;title='--color-primary'"></div>
          <div style="width:40px;height:40px;background:var(--color-accent);border-radius:4px"></div>
          <div style="width:40px;height:40px;background:var(--color-success);border-radius:4px"></div>
          <div style="width:40px;height:40px;background:var(--color-warn);border-radius:4px"></div>
          <div style="width:40px;height:40px;background:var(--color-danger);border-radius:4px"></div>
        </div>
      </div>
      <div class="col">
        <h3 style="margin-bottom:.5rem;font-size:.95rem">Background image (relative CSS path)</h3>
        <div class="bg-image-test">background.png via CSS url('../images/background.png')</div>
      </div>
    </div>

    <div class="mt-2">
      <h3 style="margin-bottom:.5rem;font-size:.95rem">Pre / code blocks</h3>
      <pre>GET /assets/css/stress.css HTTP/1.1
Host: localhost:3000
Accept: text/css,*/*;q=0.1

HTTP/1.1 200 OK
Content-Type: text/css; charset=utf-8
Cache-Control: public, max-age=3600</pre>
    </div>

    <div class="row mt-2">
      <div class="col">
        <h3 style="margin-bottom:.5rem;font-size:.95rem">Small table</h3>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Key</th><th>Value</th></tr></thead>
            <tbody>
              <tr><td>Font</td><td><code>system-ui</code></td></tr>
              <tr><td>Radius</td><td><code>6px</code></td></tr>
              <tr><td>Header height</td><td><code>54px</code></td></tr>
              <tr><td>Dark mode</td><td><code>prefers-color-scheme</code></td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- ═══════════════════════════════ JS STRESS ═══════════════════════════ -->
  <div class="section" id="js-stress">
    <h2 class="section-title">§2 JavaScript Stress</h2>
    <p>See status panel above for JS results. Dynamic elements below are injected by <code>stress.js</code>.</p>
    <div class="mt-1">
      <strong style="font-size:.85rem">Dynamically inserted images:</strong>
      <div id="dynamic-images"></div>
    </div>
    <div class="mt-1">
      <strong style="font-size:.85rem">Dynamically created links:</strong>
      <p id="dynamic-links" style="font-size:.9rem;margin-top:.3rem"></p>
    </div>
  </div>

  <!-- ═══════════════════════════════ IMAGES ══════════════════════════════ -->
  <div class="section" id="images">
    <h2 class="section-title">§3 Image Assets</h2>
    <div class="card-grid">

      <div class="card">
        <img src="assets/images/small.png" alt="small PNG" loading="lazy">
        <span class="tag">PNG</span>
        <span class="label">small.png (64×48)</span>
      </div>

      <div class="card">
        <img src="assets/images/medium.png" alt="medium gradient PNG" loading="lazy">
        <span class="tag">PNG gradient</span>
        <span class="label">medium.png (400×300)</span>
      </div>

      <div class="card">
        <img src="assets/images/large.png" alt="large PNG" loading="lazy">
        <span class="tag">PNG large-dim</span>
        <span class="label">large.png (800×500)</span>
      </div>

      <div class="card">
        <img src="assets/images/medium.jpg" alt="JPEG" loading="lazy">
        <span class="tag">JPEG</span>
        <span class="label">medium.jpg</span>
      </div>

      <div class="card">
        <img src="assets/images/photo.webp" alt="WebP" loading="lazy">
        <span class="tag">WebP</span>
        <span class="label">photo.webp</span>
      </div>

      <div class="card">
        <img src="assets/images/animation.gif" alt="animated GIF" loading="lazy">
        <span class="tag">GIF animated</span>
        <span class="label">animation.gif</span>
      </div>

      <div class="card">
        <img src="assets/images/vector.svg" alt="SVG" loading="lazy">
        <span class="tag">SVG</span>
        <span class="label">vector.svg (hand-written)</span>
      </div>

      <div class="card">
        <img src="assets/images/image%20with%20spaces.png" alt="image with spaces in filename" loading="lazy">
        <span class="tag">Spaces in name</span>
        <span class="label">image with spaces.png (via %20)</span>
      </div>

      <div class="card">
        <img src="assets/images/photo.JPG" alt="uppercase extension" loading="lazy">
        <span class="tag">Uppercase .JPG</span>
        <span class="label">photo.JPG — server must handle uppercase ext</span>
      </div>

      <div class="card">
        <img src="assets/images/nested/deep/photo.png" alt="nested image" loading="lazy">
        <span class="tag">Nested path</span>
        <span class="label">nested/deep/photo.png</span>
      </div>

      <div class="card">
        <div class="bg-image-test" style="min-height:80px;font-size:.8rem">
          CSS background-image
        </div>
        <span class="tag">CSS bg-image</span>
        <span class="label">background.png via CSS</span>
      </div>

      <div class="card">
        <img src="assets/images/broken-reference.png" alt="[EXPECTED BROKEN]" loading="lazy"
             style="border:2px dashed var(--color-danger);padding:.5rem;opacity:.5">
        <span class="tag" style="color:var(--color-danger)">BROKEN</span>
        <span class="label broken">broken-reference.png <span class="badge badge-broken">EXPECTED BROKEN</span></span>
      </div>

    </div>
  </div>

  <!-- ═══════════════════════════════ VIDEO ═══════════════════════════════ -->
  <div class="section" id="video">
    <h2 class="section-title">§4 Video Assets</h2>
    <div class="row">
      <div class="col">
        <p style="font-size:.85rem;margin-bottom:.5rem"><strong>MP4 (H.264)</strong> — <code>video/mp4</code></p>
        <video controls poster="assets/images/poster.png" preload="metadata">
          <source src="assets/video/test.mp4" type="video/mp4">
          <p>MP4 not supported or missing.</p>
        </video>
        <p class="mt-1" style="font-size:.8rem">
          <a href="assets/video/test.mp4" download>⬇ Download test.mp4</a> |
          <a href="assets/video/video%20with%20spaces.mp4" download>⬇ video with spaces.mp4</a>
        </p>
      </div>
      <div class="col">
        <p style="font-size:.85rem;margin-bottom:.5rem"><strong>WebM (VP9)</strong> — <code>video/webm</code></p>
        <video controls preload="metadata">
          <source src="assets/video/test.webm" type="video/webm">
          <p>WebM not supported or missing.</p>
        </video>
        <p class="mt-1" style="font-size:.8rem">
          <a href="assets/video/test.webm" download>⬇ Download test.webm</a>
        </p>
      </div>
    </div>
  </div>

  <!-- ═══════════════════════════════ AUDIO ═══════════════════════════════ -->
  <div class="section" id="audio">
    <h2 class="section-title">§5 Audio Assets</h2>
    <div class="flex-col">
      <div>
        <p style="font-size:.85rem;margin-bottom:.3rem"><strong>WAV</strong> — <code>audio/wav</code> (440 Hz sine, 3 s)</p>
        <audio controls src="assets/audio/test.wav" preload="metadata"></audio>
        <a href="assets/audio/test.wav" download style="font-size:.8rem;display:block;margin-top:.3rem">⬇ Download WAV</a>
      </div>
      <div>
        <p style="font-size:.85rem;margin-bottom:.3rem"><strong>MP3</strong> — <code>audio/mpeg</code></p>
        <audio controls src="assets/audio/test.mp3" preload="metadata"></audio>
        <a href="assets/audio/test.mp3" download style="font-size:.8rem;display:block;margin-top:.3rem">⬇ Download MP3</a>
      </div>
      <div>
        <p style="font-size:.85rem;margin-bottom:.3rem"><strong>OGG (Opus)</strong> — <code>audio/ogg</code></p>
        <audio controls src="assets/audio/test.ogg" preload="metadata"></audio>
        <a href="assets/audio/test.ogg" download style="font-size:.8rem;display:block;margin-top:.3rem">⬇ Download OGG</a>
      </div>
    </div>
  </div>

  <!-- ═══════════════════════════════ PDF ═════════════════════════════════ -->
  <div class="section" id="pdf">
    <h2 class="section-title">§6 PDF Assets</h2>
    <ul class="link-list">
      <li><a href="assets/pdf/test.pdf">assets/pdf/test.pdf</a> — direct link</li>
      <li><a href="assets/pdf/document%20with%20spaces.pdf">document with spaces.pdf</a> — filename with spaces</li>
      <li><a href="assets/pdf/pdf-embed-test.html">PDF embed test page →</a> (iframe / object / embed)</li>
      <li class="link-broken">assets/pdf/missing.pdf <span class="badge badge-broken">EXPECTED BROKEN</span></li>
    </ul>
  </div>

  <!-- ═══════════════════════════════ DOWNLOADS ═══════════════════════════ -->
  <div class="section" id="downloads">
    <h2 class="section-title">§7 Text &amp; Download Assets</h2>
    <ul class="link-list">
      <li><a href="assets/downloads/sample.txt">sample.txt</a> <span class="badge badge-ok">text/plain</span></li>
      <li><a href="assets/json/data.json">data.json</a> <span class="badge badge-ok">application/json</span></li>
      <li><a href="assets/downloads/data.csv">data.csv</a> <span class="badge badge-ok">text/csv</span></li>
      <li><a href="assets/downloads/data.xml">data.xml</a> <span class="badge badge-ok">text/xml</span></li>
      <li><a href="assets/downloads/test.bin">test.bin</a> <span class="badge badge-ok">octet-stream</span></li>
      <li><a href="assets/downloads/no-extension">no-extension</a> <span class="badge badge-opt">no ext</span></li>
      <li><a href="assets/downloads/README.TXT">README.TXT</a> <span class="badge badge-opt">uppercase .TXT</span></li>
      <li><a href="assets/downloads/file%20with%20spaces.txt">file with spaces.txt</a> <span class="badge badge-opt">%20 in path</span></li>
      <li><a href="assets/downloads/level1/level2/level3/deep-file.txt">level1/level2/level3/deep-file.txt</a> <span class="badge badge-opt">nested</span></li>
      <li><a href="assets/images/vector.svg">vector.svg</a> <span class="badge badge-ok">image/svg+xml</span></li>
    </ul>
  </div>

  <!-- ═══════════════════════════════ FORMS ════════════════════════════════ -->
  <div class="section" id="forms">
    <h2 class="section-title">§8 Form Handling (no network submit)</h2>
    <div style="max-width:480px">
      <div id="stress-form">
        <div class="form-row">
          <label for="f-name">Name</label>
          <input type="text" id="f-name" name="name" placeholder="Enter a name…">
        </div>
        <div class="form-row">
          <label for="f-option">Option</label>
          <select id="f-option" name="option">
            <option value="a">Option A</option>
            <option value="b">Option B</option>
            <option value="c">Option C</option>
          </select>
        </div>
        <div class="form-row">
          <label for="f-notes">Notes</label>
          <textarea id="f-notes" name="notes" rows="3" placeholder="Some notes…"></textarea>
        </div>
        <button type="button" onclick="
          const data = {
            name: document.getElementById('f-name').value,
            option: document.getElementById('f-option').value,
            notes: document.getElementById('f-notes').value
          };
          document.getElementById('form-result').textContent = 'Submitted: ' + JSON.stringify(data, null, 2);
        ">Submit (client-side only)</button>
        <div id="form-result"></div>
      </div>
    </div>
  </div>

  <!-- ═══════════════════════════════ SEARCH ══════════════════════════════ -->
  <div class="section" id="search">
    <h2 class="section-title">§9 Client-Side Search (JS-powered)</h2>
    <div class="search-wrap">
      <input type="search" id="search-input" placeholder="Search assets by name, path, or category…" autocomplete="off">
    </div>
    <div id="search-results"></div>
  </div>

  <!-- ═══════════════════════════════ EDGE CASES ══════════════════════════ -->
  <div class="section" id="edge-cases">
    <h2 class="section-title">§10 Path &amp; URL Edge Cases</h2>

    <h3 style="font-size:.95rem;margin:.75rem 0 .4rem">Subpages</h3>
    <ul class="link-list">
      <li><a href="pages/hash-nav.html">pages/hash-nav.html</a> — hash fragment navigation</li>
      <li><a href="pages/long-page.html">pages/long-page.html</a> — 30 sections, many anchors</li>
      <li><a href="pages/table-heavy.html">pages/table-heavy.html</a> — 50-row wide table</li>
      <li><a href="pages/unicode.html">pages/unicode.html</a> — UTF-8, emoji, RTL, CJK</li>
      <li><a href="pages/file%20with%20spaces.html">pages/file with spaces.html</a> — spaces in filename</li>
      <li><a href="pages/deep/path/nested/page.html">pages/deep/path/nested/page.html</a> — 4-level deep nesting</li>
      <li><a href="pages/404-example.html">pages/404-example.html</a> — static 404 example page</li>
      <li><a href="assets/pdf/pdf-embed-test.html">assets/pdf/pdf-embed-test.html</a> — PDF embedding test</li>
      <li><a href="baseline.html">baseline.html</a> — expected behaviour reference</li>
    </ul>

    <h3 style="font-size:.95rem;margin:.75rem 0 .4rem">URL variations</h3>
    <ul class="link-list">
      <li><a href="assets/images/small.png">assets/images/small.png</a> — normal path</li>
      <li><a href="assets/images/image%20with%20spaces.png">assets/images/image%20with%20spaces.png</a> — %20-encoded space</li>
      <li><a href="assets/images/photo.JPG">assets/images/photo.JPG</a> — uppercase extension</li>
      <li><a href="assets/json/data.json?v=1">assets/json/data.json?v=1</a> — query string on static asset</li>
      <li><a href="assets/images/vector.svg#title">assets/images/vector.svg#title</a> — fragment on static file</li>
      <li><a href="./assets/images/small.png">./assets/images/small.png</a> — explicit ./ relative path</li>
      <li><a href="assets/downloads/level1/level2/level3/deep-file.txt">assets/downloads/level1/level2/level3/deep-file.txt</a> — nested 3 deep</li>
    </ul>

    <h3 style="font-size:.95rem;margin:.75rem 0 .4rem">Intentionally broken links <span class="badge badge-broken">EXPECTED 404</span></h3>
    <ul class="link-list">
      <li class="link-broken"><a href="assets/images/does-not-exist.jpg" class="link-broken">assets/images/does-not-exist.jpg</a> <span class="badge badge-broken">EXPECTED 404</span></li>
      <li class="link-broken"><a href="pages/nonexistent-page.html" class="link-broken">pages/nonexistent-page.html</a> <span class="badge badge-broken">EXPECTED 404</span></li>
      <li class="link-broken"><a href="assets/pdf/missing.pdf" class="link-broken">assets/pdf/missing.pdf</a> <span class="badge badge-broken">EXPECTED 404</span></li>
      <li class="link-broken"><a href="assets/downloads/also-missing.bin" class="link-broken">assets/downloads/also-missing.bin</a> <span class="badge badge-broken">EXPECTED 404</span></li>
    </ul>

    <h3 style="font-size:.95rem;margin:.75rem 0 .4rem">Traversal examples (display only — not active links)</h3>
    <pre style="font-size:.8rem">
# These are shown as text only — never as clickable links.
# A correct server should reject or sanitise these:
GET /../../../etc/passwd          → should 400 or 403, never serve
GET /assets/../../secret          → should resolve safely within root
GET /%2e%2e%2f%2e%2e%2fetc/passwd → percent-encoded traversal attempt
    </pre>
  </div>

</div><!-- /container -->

<script src="assets/js/stress.js"></script>
</body>
</html>
INDEX_EOF
wrote "$OUT/index.html"

# =============================================================================
# §19  MANIFEST JSON
# =============================================================================
log "Generating stress-manifest.json..."
if [ "$HAS_PYTHON" -eq 1 ]; then
python3 - "$OUT" <<'MANIFEST_PY'
import sys, os, json, mimetypes

root = sys.argv[1]
mimetypes.init()

MIME_OVERRIDES = {
    '.JPG': 'image/jpeg', '.TXT': 'text/plain',
    '.webm': 'video/webm', '.ogg': 'audio/ogg',
    '.wav': 'audio/wav', '.bin': 'application/octet-stream',
}

def guess_behavior(mime, path):
    if not mime: return 'download'
    if mime.startswith('text/') or mime in ('application/json','image/svg+xml'): return 'inline'
    if mime.startswith('image/'): return 'inline'
    if mime.startswith('video/') or mime.startswith('audio/'): return 'inline'
    if mime == 'application/pdf': return 'inline-or-download'
    return 'download'

def is_broken_ref(path):
    return 'broken' in os.path.basename(path).lower() or 'missing' in os.path.basename(path).lower()

entries = []
for dirpath, _, files in os.walk(root):
    for fname in sorted(files):
        fpath = os.path.join(dirpath, fname)
        relpath = os.path.relpath(fpath, root)
        ext = os.path.splitext(fname)[1]
        size = os.path.getsize(fpath)
        mime = MIME_OVERRIDES.get(ext) or mimetypes.guess_type(fname)[0] or ''
        behavior = guess_behavior(mime, relpath)
        if is_broken_ref(fname): behavior = 'expected-broken'
        entries.append({
            'path': relpath.replace(os.sep, '/'),
            'size_bytes': size,
            'mime_type': mime,
            'expected_behavior': behavior,
        })

manifest = {
    'name': 'RustHost Static Stress Fixture',
    'version': '1.0.0',
    'generated': 'deterministic',
    'file_count': len(entries),
    'files': entries,
}
out_path = os.path.join(root, 'stress-manifest.json')
with open(out_path, 'w') as f:
    json.dump(manifest, f, indent=2)
print(f'  → {out_path} ({len(entries)} entries)')
MANIFEST_PY
    GEN_COUNT=$((GEN_COUNT+1))
else
    skip "stress-manifest.json (no python3)"
fi

# =============================================================================
# §20  SUMMARY
# =============================================================================
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  RustHost Static Stress Fixture — Generation Complete"
echo "════════════════════════════════════════════════════════════"
printf "  Output dir   : %s\n" "$OUT"
printf "  Files written: %d\n" "$GEN_COUNT"

if [ ${#SKIPPED[@]} -gt 0 ]; then
    echo ""
    echo "  Skipped (optional assets — tool not available):"
    for s in "${SKIPPED[@]}"; do
        printf "    - %s\n" "$s"
    done
fi

echo ""
echo "  To serve with RustHost (example):"
echo "    rusthost --root $OUT --port 3000"
echo "  Then open: http://localhost:3000"
echo ""
echo "  Baseline reference: http://localhost:3000/baseline.html"
echo "════════════════════════════════════════════════════════════"
