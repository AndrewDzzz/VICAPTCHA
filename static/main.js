let state = { captchaId: null, selectCount: 2, images: [], selected: new Set(), pow: null };

const grid = document.getElementById('grid');
const promptEl = document.getElementById('prompt');
const submitBtn = document.getElementById('submitBtn');
const refreshBtn = document.getElementById('refreshBtn');
const messageEl = document.getElementById('message');
const progress = document.getElementById('progress');
const progressText = document.getElementById('progressText');

function setMessage(text, kind) {
  messageEl.textContent = text || '';
  messageEl.className = 'message' + (kind ? ` ${kind}` : '');
}

function toggleSubmit() {
  // Always allow submit; backend will fail if count mismatches
  submitBtn.classList.add('enabled');
  submitBtn.disabled = false;
}

function renderGrid() {
  grid.innerHTML = '';
  state.images.forEach(img => {
    const tile = document.createElement('div');
    tile.className = 'tile';
    tile.addEventListener('click', () => onToggle(img.id, tile));
    const image = document.createElement('img');
    image.src = img.url;
    const check = document.createElement('div');
    check.className = 'check';
    check.textContent = '✓';
    tile.appendChild(image);
    tile.appendChild(check);
    grid.appendChild(tile);
  });
}

function onToggle(id, tile) {
  if (state.selected.has(id)) {
    state.selected.delete(id);
    tile.classList.remove('selected');
  } else {
    if (state.selected.size >= state.selectCount) return;
    state.selected.add(id);
    tile.classList.add('selected');
  }
  toggleSubmit();
}

async function loadCaptcha() {
  setMessage('');
  // submit is always enabled in this interaction model
  submitBtn.disabled = false;
  submitBtn.classList.add('enabled');
  state.selected.clear();
  try {
    const res = await fetch('/api/captcha');
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    state.captchaId = data.captcha_id;
    state.selectCount = data.select_count;
    state.images = data.images;
    state.pow = data.pow; // {challenge, difficulty, algo}
    promptEl.textContent = data.prompt;
    renderGrid();
    toggleSubmit();
  } catch (e) {
    setMessage(e.message || 'Failed to load captcha', 'error');
  }
}

async function sha256Hex(str) {
  const enc = new TextEncoder();
  const buf = enc.encode(str);
  const digest = await crypto.subtle.digest('SHA-256', buf);
  const bytes = Array.from(new Uint8Array(digest));
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function computePow(challenge, difficulty) {
  if (!challenge) throw new Error('Missing challenge');
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto not available');
  }
  let nonce = 0;
  const prefix = '0'.repeat(difficulty);
  while (true) {
    const candidate = `${challenge}:${nonce}`;
    const hash = await sha256Hex(candidate);
    if (hash.startsWith(prefix)) return { nonce: String(nonce), hash };
    if (nonce % 500 === 0) setMessage(`Computing proof... tried ${nonce} nonces`);
    nonce++;
    // yield to UI occasionally
    if (nonce % 2000 === 0) await new Promise(r => setTimeout(r, 0));
  }
}

async function precheck() {
  const body = {
    captcha_id: state.captchaId,
    selected_ids: Array.from(state.selected.values()),
  };
  const res = await fetch('/api/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  // api now always 200; check validity flags
  if (!data.valid) {
    throw new Error(data.error || 'Invalid or expired captcha.');
  }
  return data;
}

async function verify() {
  // No front-end guard on selection count; server will enforce
  const body = {
    captcha_id: state.captchaId,
    selected_ids: Array.from(state.selected.values()),
  };
  submitBtn.disabled = true;
  try {
    // 1) Precheck selections
    const check = await precheck();
    if (!check.correct) {
      setMessage('Selection incorrect. Please try again.', 'error');
      toggleSubmit();
      return;
    }
    // 2) Compute lightweight PoW (Python-only backend)
    const { challenge, difficulty } = check.pow || state.pow || {};
    if (!challenge) throw new Error('Challenge not ready');
    progress.classList.add('show');
    const pow = await computePow(challenge, difficulty || 4);
    body.pow = pow;
  } catch (e) {
    progress.classList.remove('show');
    // If precheck failed due to invalid captcha, auto refresh challenge
    const msg = e && e.message ? e.message : 'Precheck failed';
    setMessage(msg, 'error');
    if (/expired captcha/i.test(msg)) {
      await loadCaptcha();
    }
    toggleSubmit();
    return;
  }
  try {
    const res = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    progress.classList.remove('show');
    if (data.success) {
      setMessage('Verification successful!', 'success');
    } else {
      setMessage(data.error || 'Verification failed. Try another challenge.', 'error');
    }
  } catch (e) {
    progress.classList.remove('show');
    setMessage('Network error', 'error');
  }
  toggleSubmit();
}

submitBtn.addEventListener('click', verify);
refreshBtn.addEventListener('click', loadCaptcha);

loadCaptcha();


