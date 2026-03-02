// ── State ──
let loggedIn = false;
let appMode = 'cloud'; // 'local' or 'cloud' — set from /api/config
const sessions = new Map(); // id → { term, fitAddon, ws, info }
let activeSessionId = null;
let agentPollInterval = null;
let agentConnected = false;

// ── Desktop grid state ──
const GRID_SLOTS = 4;

// ── Playbook state ──
let playbooks = [];
let selectedPlaybookId = null;
let editingPlaybookId = null;
let focusedSessionId = null;
const isDesktop = () => window.innerWidth > 1024;

const API = '';
const WS_BASE = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;

// ── E2EE Crypto ──
const E2EE_SALT = new TextEncoder().encode('automaite-e2ee-v1');
const E2EE_INFO = new TextEncoder().encode('aes-key');
const e2eeKeys = new Map(); // session_id → CryptoKey

async function deriveE2EEKey(deviceSecret) {
  const ikm = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(deviceSecret),
    'HKDF', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: E2EE_SALT, info: E2EE_INFO },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt', 'decrypt']
  );
}

async function e2eeEncrypt(key, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, key, encoded
  );
  // nonce (12) + ciphertext + tag (16) — tag is appended by SubtleCrypto
  const result = new Uint8Array(12 + ciphertext.byteLength);
  result.set(nonce, 0);
  result.set(new Uint8Array(ciphertext), 12);
  return result;
}

async function e2eeDecrypt(key, blob) {
  // blob = nonce (12) + ciphertext + tag (16)
  const nonce = blob.slice(0, 12);
  const ciphertext = blob.slice(12);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce }, key, ciphertext
  );
  return new Uint8Array(plaintext);
}

// ── HMAC Re-Auth ──
async function tryHmacReAuth() {
  const deviceId = localStorage.getItem('automaite_device_id');
  const deviceSecret = localStorage.getItem('automaite_device_secret');
  if (!deviceId || !deviceSecret) return false;
  try {
    const timestamp = Math.floor(Date.now() / 1000);
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(deviceSecret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(String(timestamp)));
    const hmac = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
    const res = await fetch(API + '/api/auth/device', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId, timestamp, hmac }),
    });
    if (res.ok) {
      loggedIn = true;
      showApp();
      return true;
    }
  } catch (e) {
    console.warn('HMAC re-auth failed:', e);
  }
  return false;
}

// ── DOM refs ──
const loginScreen  = document.getElementById('login-screen');
const appScreen    = document.getElementById('app-screen');
const loginError   = document.getElementById('login-error');
const tabBar       = document.getElementById('tab-bar');
const termContainer= document.getElementById('terminal-container');
const noSessions   = document.getElementById('no-sessions');
const agentDot     = document.getElementById('agent-status');
const modalOverlay = document.getElementById('modal-overlay');
const btnNew       = document.getElementById('btn-new-session');

// ── Init ──
(async () => {
  // Fetch mode from server
  try {
    const configRes = await fetch(API + '/api/config');
    const config = await configRes.json();
    appMode = config.mode || 'cloud';
  } catch {
    appMode = 'cloud';
  }

  // Check if already authenticated
  try {
    const res = await fetch(API + '/api/me', { credentials: 'same-origin' });
    if (res.ok) {
      loggedIn = true;
      showApp();
      return;
    }
  } catch {}

  // Try silent HMAC re-auth if we have stored device credentials
  if (appMode === 'local' && await tryHmacReAuth()) return;

  if (appMode === 'local') {
    const params = new URLSearchParams(location.search);

    // Check for skip_login param (mobile WebView sets cookie natively)
    if (params.has('skip_login')) {
      loggedIn = true;
      showApp();
      return;
    }

    // Check for ?pair=TOKEN (user scanned QR code)
    const pairToken = params.get('pair');
    if (pairToken) {
      await handleQRPairing(pairToken);
      return;
    }

    // Show a simplified login screen for local mode
    loginScreen.style.display = 'flex';
    document.getElementById('google-btn-container').innerHTML =
      '<div style="color: var(--text-dim); font-size: 13px; text-align: center;">' +
      'Scan the QR code from the desktop app to connect,<br>' +
      'or open this page from a paired device.' +
      '</div>';
  } else {
    // Cloud mode
    loginScreen.style.display = 'flex';
    if (navigator.userAgent.includes('AutomaiteApp')) {
      // WebView — GIS doesn't work here, open browser for auth
      document.getElementById('google-btn-container').innerHTML =
        '<button id="app-signin-btn" style="' +
        'background: #7c3aed; color: white; border: none; border-radius: 8px; ' +
        'padding: 12px 32px; font-size: 15px; cursor: pointer; font-weight: 500;' +
        '">Sign in with Google</button>';
      document.getElementById('app-signin-btn').addEventListener('click', () => {
        if (window.AutomaiteApp && window.AutomaiteApp.openInBrowser) {
          window.AutomaiteApp.openInBrowser(location.origin + '/app-login.html');
        } else {
          window.open(location.origin + '/app-login.html', '_blank');
        }
      });
      // Show app version
      const vMatch = navigator.userAgent.match(/AutomaiteApp\/(\S+)/);
      if (vMatch) {
        const vEl = document.createElement('div');
        vEl.style.cssText = 'color: #555; font-size: 11px; margin-top: 16px;';
        vEl.textContent = 'App v' + vMatch[1];
        document.getElementById('google-btn-container').appendChild(vEl);
      }
    } else {
      loadGoogleSignIn();
    }
  }
})();

// ── QR Pairing (local mode) ──
async function handleQRPairing(pairToken) {
  loginScreen.style.display = 'flex';
  loginError.textContent = '';
  document.getElementById('google-btn-container').innerHTML =
    '<div style="color: var(--text-dim); font-size: 13px; text-align: center;">Pairing...</div>';

  // Generate a device ID (persisted in localStorage for re-auth)
  let deviceId = localStorage.getItem('automaite_device_id');
  if (!deviceId) {
    deviceId = crypto.randomUUID();
    localStorage.setItem('automaite_device_id', deviceId);
  }

  const deviceName = navigator.userAgent.split(/[()]/)[1] || 'Phone Browser';

  try {
    const res = await fetch(API + '/api/pair', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({
        pairing_token: pairToken,
        device_id: deviceId,
        device_name: deviceName,
      }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      loginError.textContent = data.detail || 'Pairing failed';
      document.getElementById('google-btn-container').innerHTML =
        '<div style="color: var(--text-dim); font-size: 13px; text-align: center;">' +
        'Scan a fresh QR code to try again.</div>';
      return;
    }

    const data = await res.json();

    // Store device_secret for future HMAC auth
    localStorage.setItem('automaite_device_secret', data.device_secret);

    // Clean up URL (remove ?pair= param)
    history.replaceState(null, '', '/');

    // JWT cookie was set by the server — proceed to app
    loggedIn = true;
    showApp();
  } catch (err) {
    loginError.textContent = 'Connection error: ' + err.message;
  }
}

// ── Google Sign-In (cloud mode) ──
function loadGoogleSignIn() {
  // Dynamically load the Google Sign-In script
  const script = document.createElement('script');
  script.src = 'https://accounts.google.com/gsi/client';
  script.async = true;
  script.defer = true;
  script.onload = () => initGoogleSignIn();
  document.head.appendChild(script);
}

async function initGoogleSignIn() {
  try {
    const [configRes, nonceRes] = await Promise.all([
      fetch(API + '/api/config'),
      fetch(API + '/api/nonce'),
    ]);
    const config = await configRes.json();
    const { nonce } = await nonceRes.json();
    // Wait for GIS library to load
    function tryInit() {
      if (typeof google !== 'undefined' && google.accounts) {
        google.accounts.id.initialize({
          client_id: config.google_client_id,
          nonce: nonce,
          callback: (response) => handleGoogleLogin(response, nonce),
        });
        google.accounts.id.renderButton(
          document.getElementById('google-btn-container'),
          { theme: 'filled_black', size: 'large', width: 300, text: 'signin_with' }
        );
      } else {
        setTimeout(tryInit, 100);
      }
    }
    tryInit();
  } catch {
    loginError.textContent = 'Failed to load sign-in';
  }
}

async function handleGoogleLogin(response, nonce) {
  loginError.textContent = '';
  try {
    const res = await fetch(API + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ credential: response.credential, nonce }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      loginError.textContent = data.detail || 'Login failed';
      return;
    }
    loggedIn = true;
    showApp();
  } catch (err) {
    loginError.textContent = 'Connection error';
  }
}

async function showApp() {
  loginScreen.style.display = 'none';
  appScreen.classList.add('active');
  // Create desktop agent status dot
  if (!document.getElementById('desktop-agent-status')) {
    const dot = document.createElement('div');
    dot.id = 'desktop-agent-status';
    appScreen.appendChild(dot);
  }
  pollAgentStatus();
  agentPollInterval = setInterval(pollAgentStatus, 5000);
  connectPhoneWS();
  await loadSessions();
}

async function logout() {
  try {
    await fetch(API + '/api/logout', { method: 'POST', credentials: 'same-origin' });
  } catch {}
  loggedIn = false;
  sessions.forEach(s => { if (s.ws) s.ws.close(); s.term.dispose(); });
  sessions.clear();
  clearInterval(agentPollInterval);
  appScreen.classList.remove('active');
  loginScreen.style.display = 'flex';
  if (appMode === 'cloud') {
    initGoogleSignIn();
  }
}

async function apiFetch(path, opts = {}) {
  const res = await fetch(API + path, {
    ...opts,
    credentials: 'same-origin',
    headers: { ...opts.headers, 'Content-Type': 'application/json' },
  });
  if (res.status === 401) {
    // Try silent HMAC re-auth before giving up
    if (appMode === 'local' && await tryHmacReAuth()) {
      // Retry the original request with fresh cookie
      return fetch(API + path, {
        ...opts,
        credentials: 'same-origin',
        headers: { ...opts.headers, 'Content-Type': 'application/json' },
      });
    }
    logout();
    throw new Error('Unauthorized');
  }
  return res;
}

// ── Agent status ──
async function pollAgentStatus() {
  try {
    const res = await apiFetch('/api/agent-status');
    const data = await res.json();
    agentConnected = data.connected;
    agentDot.className = data.connected ? 'connected' : '';
    agentDot.title = data.connected ? 'Agent connected' : 'Agent disconnected';
    const desktopDot = document.getElementById('desktop-agent-status');
    if (desktopDot) desktopDot.className = data.connected ? 'connected' : '';
    updateNoSessionsView();
  } catch {}
}

function updateNoSessionsView() {
  if (sessions.size > 0) return;
  const ns = document.getElementById('no-sessions');
  if (!ns) return;
  const connectedEmpty = document.getElementById('connected-empty');
  const setup = document.getElementById('setup-guide');
  if (agentConnected) {
    if (connectedEmpty) connectedEmpty.style.display = '';
    if (setup) setup.style.display = 'none';
  } else {
    if (connectedEmpty) connectedEmpty.style.display = 'none';
    if (setup) setup.style.display = '';
  }
}

// ── Sessions ──
async function loadSessions() {
  try {
    const res = await apiFetch('/api/sessions');
    const list = await res.json();
    list.forEach(info => {
      if (!sessions.has(info.session_id)) {
        createTerminalSession(info);
      }
    });
    updateUI();
  } catch {}
}

const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);

function createTerminalSession(info) {
  const term = new Terminal({
    theme: {
      background: '#0a0a0f',
      foreground: '#e4e4e7',
      cursor: '#7c3aed',
      selectionBackground: 'rgba(124,58,237,0.3)',
      black: '#09090b',
      red: '#ef4444',
      green: '#22c55e',
      yellow: '#eab308',
      blue: '#3b82f6',
      magenta: '#a855f7',
      cyan: '#06b6d4',
      white: '#e4e4e7',
    },
    fontFamily: "'JetBrains Mono', 'Cascadia Code', 'Fira Code', monospace",
    fontSize: isMobile ? 12 : 14,
    cursorBlink: true,
    allowProposedApi: true,
    scrollback: 5000,
  });

  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);

  // Try WebGL, fall back silently
  try {
    const webglAddon = new WebglAddon.WebglAddon();
    webglAddon.onContextLoss(() => webglAddon.dispose());
    term.loadAddon(webglAddon);
  } catch {}

  // Create wrapper div
  const wrapper = document.createElement('div');
  wrapper.className = 'term-wrapper';
  wrapper.id = 'term-' + info.session_id;

  // Tile header (always in DOM, hidden on mobile via CSS)
  const header = document.createElement('div');
  header.className = 'tile-header';
  const labelSpan = document.createElement('span');
  labelSpan.className = 'tile-label';
  labelSpan.textContent = info.label;
  header.appendChild(labelSpan);
  const closeBtn = document.createElement('button');
  closeBtn.className = 'tile-close';
  closeBtn.textContent = '\u00d7';
  closeBtn.addEventListener('click', (e) => { e.stopPropagation(); killSession(info.session_id); });
  header.appendChild(closeBtn);
  wrapper.appendChild(header);

  // Term body
  const termBody = document.createElement('div');
  termBody.className = 'term-body';
  wrapper.appendChild(termBody);

  termContainer.appendChild(wrapper);
  term.open(termBody);

  // Click-to-focus (desktop)
  wrapper.addEventListener('mousedown', () => {
    if (isDesktop()) focusTile(info.session_id);
  });

  // Editable tile name on double-click
  labelSpan.addEventListener('dblclick', (e) => {
    e.stopPropagation();
    const input = document.createElement('input');
    input.className = 'tile-label-input';
    input.value = info.label;
    labelSpan.style.display = 'none';
    header.insertBefore(input, closeBtn);
    input.focus();
    input.select();
    const commit = () => {
      if (input._committed) return;
      input._committed = true;
      const val = input.value.trim() || info.label;
      info.label = val;
      labelSpan.textContent = val;
      labelSpan.style.display = '';
      input.remove();
      updateTabs();
    };
    input.addEventListener('blur', commit);
    input.addEventListener('keydown', (ke) => {
      if (ke.key === 'Enter') { ke.preventDefault(); input.blur(); }
      if (ke.key === 'Escape') { input.value = info.label; input.blur(); }
    });
  });

  // Only focus (open keyboard) on a deliberate tap, not while scrolling
  // Ignore taps on input-bar / special-keys so Send button works on first tap
  let touchMoved = false;
  wrapper.addEventListener('touchstart', () => { touchMoved = false; }, { passive: true });
  wrapper.addEventListener('touchmove', () => { touchMoved = true; }, { passive: true });
  wrapper.addEventListener('touchend', (e) => {
    if (!touchMoved && !e.target.closest('#input-bar') && !e.target.closest('#special-keys')) {
      document.getElementById('term-input').focus();
    }
  }, { passive: true });

  // Faster scrolling — 2x speed (scroll 6 lines instead of default 3)
  wrapper.addEventListener('wheel', (e) => {
    const lines = Math.sign(e.deltaY) * 6;
    term.scrollLines(lines);
    e.preventDefault();
  }, { passive: false });

  // Fit after a tick, then scroll to bottom in the NEXT frame
  // (DOM needs to settle after fit before scroll position is reliable)
  requestAnimationFrame(() => {
    fitAddon.fit();
    requestAnimationFrame(() => term.scrollToBottom());
  });

  // WebSocket — cookie auth sent automatically on upgrade
  const ws = connectTerminalWS(info.session_id, term);

  const session = { term, fitAddon, ws, info, wrapper, _retries: 0 };
  sessions.set(info.session_id, session);

  // Handle input — always look up the CURRENT ws from the session object
  // so reconnected sockets work without re-binding
  term.onData(async (data) => {
    const cur = sessions.get(info.session_id);
    if (cur && cur.ws && cur.ws.readyState === WebSocket.OPEN) {
      const e2eeKey = e2eeKeys.get(info.session_id);
      if (e2eeKey) {
        // E2EE: encrypt input and send as base64
        const encrypted = await e2eeEncrypt(e2eeKey, data);
        const b64 = btoa(String.fromCharCode(...encrypted));
        cur.ws.send(JSON.stringify({ type: 'input', data: b64 }));
      } else {
        cur.ws.send(JSON.stringify({ type: 'input', data }));
      }
    }
  });

  // Handle resize — same pattern
  term.onResize(({ cols, rows }) => {
    const cur = sessions.get(info.session_id);
    if (cur && cur.ws && cur.ws.readyState === WebSocket.OPEN) {
      cur.ws.send(JSON.stringify({ type: 'resize', cols, rows }));
    }
  });

  return session;
}

// Heartbeat interval (ms) — if no message received within this window, reconnect
const WS_HEARTBEAT_INTERVAL = 30000;
const WS_HEARTBEAT_TIMEOUT = 45000;
const WS_RECONNECT_MAX = 30000;

function connectTerminalWS(sessionId, term) {
  const url = WS_BASE + '/ws/terminal/' + sessionId;
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';

  let lastMessageAt = Date.now();
  let heartbeatTimer = null;

  // Heartbeat: periodically check if we've heard from the server.
  // If not, the connection is half-open — force close to trigger reconnect.
  function startHeartbeat() {
    stopHeartbeat();
    heartbeatTimer = setInterval(() => {
      if (Date.now() - lastMessageAt > WS_HEARTBEAT_TIMEOUT) {
        // Connection is likely dead — force close
        stopHeartbeat();
        try { ws.close(); } catch {}
      }
    }, WS_HEARTBEAT_INTERVAL);
  }

  function stopHeartbeat() {
    if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
  }

  ws.onopen = () => {
    // Reset retry counter on successful connect
    const s = sessions.get(sessionId);
    if (s) s._retries = 0;
    lastMessageAt = Date.now();
    startHeartbeat();
  };

  ws.onmessage = async (evt) => {
    lastMessageAt = Date.now();
    if (evt.data instanceof ArrayBuffer) {
      const bytes = new Uint8Array(evt.data);
      // Check for status message (prefixed with 0x00)
      if (bytes.length > 0 && bytes[0] === 0) {
        try {
          const msg = JSON.parse(new TextDecoder().decode(bytes.slice(1)));
          if (msg.type === 'status') {
            const s = sessions.get(sessionId);
            if (s) {
              s.info.status = msg.status;
              if (msg.status === 'exited' && msg.reason) {
                showAgentError(msg.reason, msg.command || '');
              }
            }
            updateTabs();
          }
        } catch {}
        return;
      }
      // E2EE: decrypt output if we have a key for this session
      const e2eeKey = e2eeKeys.get(sessionId);
      if (e2eeKey) {
        try {
          const decrypted = await e2eeDecrypt(e2eeKey, bytes);
          term.write(decrypted);
        } catch (e) {
          console.warn('E2EE decrypt failed:', e);
          term.write(bytes);  // fallback to raw (e.g. buffered pre-E2EE data)
        }
      } else {
        term.write(bytes);
      }
    }
  };

  ws.onclose = () => {
    stopHeartbeat();
    const s = sessions.get(sessionId);
    if (s && sessions.has(sessionId)) {
      // Exponential backoff: 1s → 2s → 4s → ... → 30s max
      const delay = Math.min(1000 * Math.pow(2, s._retries || 0), WS_RECONNECT_MAX);
      s._retries = (s._retries || 0) + 1;
      setTimeout(() => {
        if (sessions.has(sessionId)) {
          s.ws = connectTerminalWS(sessionId, term);
        }
      }, delay);
    }
  };

  ws.onerror = () => {
    // onerror is always followed by onclose — just let onclose handle it
  };

  return ws;
}

function switchToSession(id) {
  if (isDesktop()) { focusTile(id); return; }
  if (activeSessionId === id) return;
  activeSessionId = id;

  sessions.forEach((s, sid) => {
    const isActive = sid === id;
    s.wrapper.classList.toggle('active', isActive);
    if (isActive) {
      requestAnimationFrame(() => {
        s.fitAddon.fit();
        requestAnimationFrame(() => {
          s.term.scrollToBottom();
          if (isDesktop()) s.term.focus();
          else document.getElementById('term-input').focus();
        });
      });
    }
  });

  updateTabs();
}

async function killSession(id) {
  try {
    await apiFetch('/api/sessions/' + id, { method: 'DELETE' });
  } catch {}
  const s = sessions.get(id);
  if (s) {
    if (s.ws) s.ws.close();
    s.term.dispose();
    s.wrapper.remove();
    sessions.delete(id);
    e2eeKeys.delete(id);
  }
  if (isDesktop()) {
    if (focusedSessionId === id) {
      const remaining = [...sessions.keys()];
      focusedSessionId = remaining.length > 0 ? remaining[remaining.length - 1] : null;
      if (focusedSessionId) focusTile(focusedSessionId);
    }
  } else {
    if (activeSessionId === id) {
      const remaining = [...sessions.keys()];
      activeSessionId = remaining.length > 0 ? remaining[remaining.length - 1] : null;
      if (activeSessionId) switchToSession(activeSessionId);
    }
  }
  updateUI();
}

// ── UI Updates ──
function updateUI() {
  if (isDesktop()) {
    updateGrid();
    if (sessions.size > 0 && !focusedSessionId) {
      focusTile([...sessions.keys()][0]);
    }
  } else {
    noSessions.style.display = sessions.size === 0 ? 'flex' : 'none';
    updateTabs();
    if (sessions.size > 0 && !activeSessionId) {
      switchToSession([...sessions.keys()][0]);
    }
  }
}

function updateTabs() {
  if (isDesktop()) return;
  tabBar.innerHTML = '';
  sessions.forEach((s, id) => {
    const tab = document.createElement('div');
    tab.className = 'tab' + (id === activeSessionId ? ' active' : '');
    const label = document.createElement('span');
    label.textContent = s.info.label;
    tab.appendChild(label);

    const close = document.createElement('span');
    close.className = 'close-tab';
    close.textContent = '\u00d7';
    close.onclick = (e) => { e.stopPropagation(); killSession(id); };
    tab.appendChild(close);

    tab.onclick = () => switchToSession(id);
    tabBar.appendChild(tab);
  });

  // Scroll active tab into view
  const activeTab = tabBar.querySelector('.tab.active');
  if (activeTab) activeTab.scrollIntoView({ inline: 'center', behavior: 'smooth' });
}

// ── Desktop grid functions ──
function focusTile(id) {
  if (!isDesktop()) { switchToSession(id); return; }
  focusedSessionId = id;
  sessions.forEach((s, sid) => {
    s.wrapper.classList.toggle('focused', sid === id);
  });
  const s = sessions.get(id);
  if (s) s.term.focus();
}

function updateGrid() {
  if (!isDesktop()) return;
  // Remove existing empty slots
  termContainer.querySelectorAll('.grid-slot-empty').forEach(el => el.remove());
  if (sessions.size === 0) {
    noSessions.style.display = 'flex';
    return;
  }
  noSessions.style.display = 'none';
  // Add empty slots
  const emptyCount = Math.max(0, GRID_SLOTS - sessions.size);
  for (let i = 0; i < emptyCount; i++) {
    const slot = document.createElement('div');
    slot.className = 'grid-slot-empty';
    slot.innerHTML = '<span>+</span>';
    slot.addEventListener('click', openModal);
    termContainer.appendChild(slot);
  }
  // Fit all terminals
  requestAnimationFrame(() => {
    sessions.forEach(s => s.fitAddon.fit());
  });
  updateTileHeaders();
}

function syncViewMode() {
  if (isDesktop()) {
    // Mobile → Desktop
    focusedSessionId = focusedSessionId || activeSessionId;
    sessions.forEach(s => {
      s.wrapper.classList.remove('active');
    });
    termContainer.querySelectorAll('.grid-slot-empty').forEach(el => el.remove());
    updateGrid();
    if (focusedSessionId) focusTile(focusedSessionId);
  } else {
    // Desktop → Mobile
    activeSessionId = activeSessionId || focusedSessionId;
    sessions.forEach(s => {
      s.wrapper.classList.remove('focused');
    });
    termContainer.querySelectorAll('.grid-slot-empty').forEach(el => el.remove());
    if (activeSessionId) {
      // Force re-apply mobile active state
      sessions.forEach((s, sid) => {
        s.wrapper.classList.toggle('active', sid === activeSessionId);
      });
    }
    updateTabs();
    if (activeSessionId) {
      const s = sessions.get(activeSessionId);
      if (s) requestAnimationFrame(() => s.fitAddon.fit());
    }
  }
}

function updateTileHeaders() {
  sessions.forEach((s) => {
    const label = s.wrapper.querySelector('.tile-label');
    if (label) label.textContent = s.info.label;
  });
}

// ── Swipe ──
let touchStartX = 0;
let touchStartY = 0;
termContainer.addEventListener('touchstart', (e) => {
  if (e.touches.length === 1) {
    touchStartX = e.touches[0].clientX;
    touchStartY = e.touches[0].clientY;
  }
}, { passive: true });

termContainer.addEventListener('touchend', (e) => {
  if (e.changedTouches.length === 1) {
    const dx = e.changedTouches[0].clientX - touchStartX;
    const dy = e.changedTouches[0].clientY - touchStartY;
    if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy) * 1.5) {
      const ids = [...sessions.keys()];
      const idx = ids.indexOf(activeSessionId);
      if (dx < 0 && idx < ids.length - 1) switchToSession(ids[idx + 1]); // swipe left → next
      if (dx > 0 && idx > 0) switchToSession(ids[idx - 1]); // swipe right → prev
    }
  }
}, { passive: true });

// ── Playbooks ──

async function fetchPlaybooks() {
  try {
    const res = await apiFetch('/api/playbooks');
    playbooks = await res.json();
  } catch { playbooks = []; }
}

function renderPlaybookChips() {
  const container = document.getElementById('playbook-chips');
  container.innerHTML = '';
  // "None" chip
  const none = document.createElement('button');
  none.className = 'playbook-chip chip-none' + (selectedPlaybookId === null ? ' selected' : '');
  none.textContent = 'None';
  none.addEventListener('click', () => {
    selectedPlaybookId = null;
    renderPlaybookChips();
    hidePlaybookPreview();
  });
  container.appendChild(none);
  // Playbook chips
  playbooks.forEach(pb => {
    const chip = document.createElement('button');
    chip.className = 'playbook-chip' + (selectedPlaybookId === pb.id ? ' selected' : '');
    chip.textContent = pb.name;
    chip.addEventListener('click', () => {
      selectedPlaybookId = pb.id;
      renderPlaybookChips();
      applyPlaybookToModal(pb);
      if (pb.instructions) showPlaybookPreview(pb);
      else hidePlaybookPreview();
    });
    container.appendChild(chip);
  });
  // "+" chip to create new
  const add = document.createElement('button');
  add.className = 'playbook-chip';
  add.textContent = '+';
  add.addEventListener('click', () => openPlaybookEditor(null));
  container.appendChild(add);
}

function applyPlaybookToModal(pb) {
  const cfg = pb.agent_config || {};
  // Select agent type
  selectAgent(pb.agent_type || 'claude');
  // Apply agent-specific config
  if (pb.agent_type === 'claude') {
    setGroupSelection('claude-model', cfg.model || 'claude-opus-4-6');
    setGroupSelection('claude-perms', cfg.perms || 'regular');
    setGroupSelection('claude-effort', cfg.effort || 'high');
  } else if (pb.agent_type === 'gemini') {
    setGroupSelection('gemini-model', cfg.model || 'auto');
    setGroupSelection('gemini-approval', cfg.approval || 'default');
  } else if (pb.agent_type === 'codex') {
    setGroupSelection('codex-approval', cfg.approval || 'suggest');
  }
}

function setGroupSelection(groupName, value) {
  const group = document.querySelector(`[data-group="${groupName}"]`);
  if (!group) return;
  group.querySelectorAll('.option-btn').forEach(b => {
    b.classList.toggle('selected', b.dataset.value === value);
  });
}

function showPlaybookPreview(pb) {
  const el = document.getElementById('playbook-preview');
  const text = document.getElementById('playbook-preview-text');
  text.textContent = pb.instructions.length > 200
    ? pb.instructions.substring(0, 200) + '...'
    : pb.instructions;
  el.style.display = '';
}

function hidePlaybookPreview() {
  document.getElementById('playbook-preview').style.display = 'none';
}

// ── Playbook Editor ──

function openPlaybookEditor(id) {
  editingPlaybookId = id;
  const overlay = document.getElementById('playbook-editor-overlay');
  const title = document.getElementById('pb-editor-title');
  const deleteBtn = document.getElementById('pb-delete');

  if (id) {
    const pb = playbooks.find(p => p.id === id);
    if (!pb) return;
    title.textContent = 'Edit Playbook';
    document.getElementById('pb-name').value = pb.name;
    selectEditorAgent(pb.agent_type || 'claude');
    const cfg = pb.agent_config || {};
    if (pb.agent_type === 'claude') {
      setGroupSelection('pb-claude-model', cfg.model || 'claude-opus-4-6');
      setGroupSelection('pb-claude-perms', cfg.perms || 'regular');
      setGroupSelection('pb-claude-effort', cfg.effort || 'high');
    } else if (pb.agent_type === 'gemini') {
      setGroupSelection('pb-gemini-model', cfg.model || 'auto');
      setGroupSelection('pb-gemini-approval', cfg.approval || 'default');
    } else if (pb.agent_type === 'codex') {
      setGroupSelection('pb-codex-approval', cfg.approval || 'suggest');
    }
    document.getElementById('pb-instructions').value = pb.instructions || '';
    deleteBtn.style.display = '';
  } else {
    title.textContent = 'New Playbook';
    document.getElementById('pb-name').value = '';
    selectEditorAgent('claude');
    document.getElementById('pb-instructions').value = '';
    deleteBtn.style.display = 'none';
  }
  overlay.classList.add('active');
}

function closePlaybookEditor() {
  document.getElementById('playbook-editor-overlay').classList.remove('active');
  editingPlaybookId = null;
}

function selectEditorAgent(agent) {
  const sel = document.getElementById('pb-agent-select');
  sel.querySelectorAll('.option-btn').forEach(b => b.classList.toggle('selected', b.dataset.value === agent));
  document.getElementById('pb-claude-options').style.display = agent === 'claude' ? '' : 'none';
  document.getElementById('pb-gemini-options').style.display = agent === 'gemini' ? '' : 'none';
  document.getElementById('pb-codex-options').style.display = agent === 'codex' ? '' : 'none';
}

function getEditorSelectedAgent() {
  const sel = document.getElementById('pb-agent-select').querySelector('.selected');
  return sel ? sel.dataset.value : 'claude';
}

function getEditorSelected(groupName) {
  const group = document.querySelector(`[data-group="${groupName}"]`);
  if (!group) return null;
  const sel = group.querySelector('.selected');
  return sel ? sel.dataset.value : null;
}

function collectEditorConfig() {
  const agent = getEditorSelectedAgent();
  const config = {};
  if (agent === 'claude') {
    config.model = getEditorSelected('pb-claude-model') || 'claude-opus-4-6';
    config.perms = getEditorSelected('pb-claude-perms') || 'regular';
    config.effort = getEditorSelected('pb-claude-effort') || 'high';
  } else if (agent === 'gemini') {
    config.model = getEditorSelected('pb-gemini-model') || 'auto';
    config.approval = getEditorSelected('pb-gemini-approval') || 'default';
  } else if (agent === 'codex') {
    config.approval = getEditorSelected('pb-codex-approval') || 'suggest';
  }
  return config;
}

// Editor agent selection clicks
document.getElementById('pb-agent-select').addEventListener('click', (e) => {
  const btn = e.target.closest('.option-btn');
  if (!btn) return;
  selectEditorAgent(btn.dataset.value);
});

// Editor option group clicks (pb-prefixed groups)
document.querySelectorAll('#playbook-editor .option-group[data-group]').forEach(group => {
  group.addEventListener('click', (e) => {
    const btn = e.target.closest('.option-btn');
    if (!btn) return;
    group.querySelectorAll('.option-btn').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');
  });
});

// Editor save
document.getElementById('pb-save').addEventListener('click', async () => {
  const name = document.getElementById('pb-name').value.trim();
  if (!name) { alert('Name is required'); return; }
  const agent = getEditorSelectedAgent();
  const config = collectEditorConfig();
  const instructions = document.getElementById('pb-instructions').value;
  const body = { name, agent_type: agent, agent_config: config, instructions };

  try {
    if (editingPlaybookId) {
      await apiFetch('/api/playbooks/' + editingPlaybookId, {
        method: 'PUT',
        body: JSON.stringify(body),
      });
    } else {
      await apiFetch('/api/playbooks', {
        method: 'POST',
        body: JSON.stringify(body),
      });
    }
    await fetchPlaybooks();
    renderPlaybookChips();
    closePlaybookEditor();
  } catch (err) {
    alert('Save failed: ' + err.message);
  }
});

// Editor delete
document.getElementById('pb-delete').addEventListener('click', async () => {
  if (!editingPlaybookId) return;
  if (!confirm('Delete this playbook?')) return;
  try {
    await apiFetch('/api/playbooks/' + editingPlaybookId, { method: 'DELETE' });
    if (selectedPlaybookId === editingPlaybookId) selectedPlaybookId = null;
    await fetchPlaybooks();
    renderPlaybookChips();
    closePlaybookEditor();
  } catch (err) {
    alert('Delete failed: ' + err.message);
  }
});

// Editor cancel
document.getElementById('pb-cancel').addEventListener('click', closePlaybookEditor);

// Close editor on overlay click
document.getElementById('playbook-editor-overlay').addEventListener('click', (e) => {
  if (e.target === document.getElementById('playbook-editor-overlay')) closePlaybookEditor();
});

// "Manage Playbooks" link — open editor for first playbook or new
document.getElementById('btn-manage-playbooks').addEventListener('click', () => {
  if (playbooks.length > 0) {
    openPlaybookEditor(playbooks[0].id);
  } else {
    openPlaybookEditor(null);
  }
});

// ── Playbook instruction injection ──

function sendInputToSession(sessionId, text) {
  const s = sessions.get(sessionId);
  if (!s || !s.ws || s.ws.readyState !== WebSocket.OPEN) return false;
  const e2eeKey = e2eeKeys.get(sessionId);
  if (e2eeKey) {
    e2eeEncrypt(e2eeKey, text).then(encrypted => {
      const b64 = btoa(String.fromCharCode(...encrypted));
      s.ws.send(JSON.stringify({ type: 'input', data: b64 }));
    });
  } else {
    s.ws.send(JSON.stringify({ type: 'input', data: text }));
  }
  return true;
}

function schedulePlaybookInput(sessionId, instructions) {
  // Wait for WS to be open, then send after a delay so the agent has time to initialize
  const maxWait = 10000;
  const start = Date.now();
  const check = () => {
    const s = sessions.get(sessionId);
    if (!s) return;
    if (s.ws && s.ws.readyState === WebSocket.OPEN) {
      // Wait 1.5s for the agent to finish starting up
      setTimeout(() => {
        sendInputToSession(sessionId, instructions + '\r');
      }, 1500);
      return;
    }
    if (Date.now() - start < maxWait) {
      setTimeout(check, 200);
    }
  };
  check();
}

// ── Modal ──
btnNew.addEventListener('click', openModal);
document.getElementById('btn-launch-agent').addEventListener('click', openModal);
document.getElementById('modal-cancel').addEventListener('click', closeModal);

async function openModal() {
  if (!agentConnected) {
    alert('No desktop agent connected.\n\nDownload and run the Automaite Desktop app on your computer to connect.\nGet it at automaite.ca');
    return;
  }
  if (isDesktop() && sessions.size >= GRID_SLOTS) {
    alert('Maximum ' + GRID_SLOTS + ' sessions on desktop. Close a session first.');
    return;
  }
  modalOverlay.classList.add('active');
  fetchAgentStatus();
  selectAgent('claude');
  selectedPlaybookId = null;
  // Fetch and render playbook chips
  await fetchPlaybooks();
  renderPlaybookChips();
  hidePlaybookPreview();
  // In local mode, fetch and display agent install status
  if (appMode === 'local') {
    fetchAgentStatus();
  }
}

function closeModal() {
  modalOverlay.classList.remove('active');
}

// Close modal on overlay click
modalOverlay.addEventListener('click', (e) => {
  if (e.target === modalOverlay) closeModal();
});

// ── Agent Install Status ──
async function fetchAgentStatus() {
  const statusDiv = document.getElementById('agent-install-status');
  const listDiv = document.getElementById('agent-status-list');
  try {
    const res = await apiFetch('/api/agents');
    const agents = await res.json();
    listDiv.innerHTML = '';
    agents.forEach(agent => {
      const item = document.createElement('div');
      item.className = 'agent-status-item';
      item.style.cssText = 'padding:8px 0;border-bottom:1px solid var(--border);font-size:13px;';
      if (agent.installed) {
        item.innerHTML = '<span style="color:#4ade80">\u2713</span> ' +
          '<strong>' + agent.display_name + '</strong>' +
          ' <span style="color:var(--text-dim);font-size:11px">' + (agent.version || '') + '</span>';
      } else {
        item.innerHTML = '<span style="color:#f87171">\u2717</span> ' +
          '<strong>' + agent.display_name + '</strong>' +
          ' <span style="color:#f87171;font-size:11px">not installed</span>' +
          '<div style="font-size:11px;color:var(--text-dim);margin-top:4px;line-height:1.5">' +
          'Install: <code style="background:var(--bg);padding:2px 6px;border-radius:4px">' + (agent.install_cmd || '') + '</code>' +
          '<br>' + (agent.auth_instructions || '') +
          '</div>';
      }
      listDiv.appendChild(item);
    });
    statusDiv.style.display = '';

    // Update agent buttons - dim unavailable ones
    const agentBtns = document.querySelectorAll('#agent-select .option-btn');
    agentBtns.forEach(btn => {
      const agentName = btn.dataset.value;
      const agentInfo = agents.find(a => a.name === agentName);
      if (agentInfo && !agentInfo.installed) {
        btn.style.opacity = '0.4';
        btn.title = agentInfo.display_name + ' not installed';
      } else {
        btn.style.opacity = '1';
        btn.title = '';
      }
    });
  } catch (e) {
    statusDiv.style.display = 'none';
  }
}

// Agent selection
const agentSelect = document.getElementById('agent-select');
agentSelect.addEventListener('click', (e) => {
  const btn = e.target.closest('.option-btn');
  if (!btn) return;
  selectAgent(btn.dataset.value);
});

function selectAgent(agent) {
  agentSelect.querySelectorAll('.option-btn').forEach(b => b.classList.toggle('selected', b.dataset.value === agent));
  document.getElementById('claude-options').style.display = agent === 'claude' ? '' : 'none';
  document.getElementById('gemini-options').style.display = agent === 'gemini' ? '' : 'none';
  document.getElementById('codex-options').style.display = agent === 'codex' ? '' : 'none';
}

// Option group selection
document.querySelectorAll('.option-group[data-group]').forEach(group => {
  group.addEventListener('click', (e) => {
    const btn = e.target.closest('.option-btn');
    if (!btn) return;
    group.querySelectorAll('.option-btn').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');
  });
});

function getSelected(groupName) {
  const group = document.querySelector(`[data-group="${groupName}"]`);
  if (!group) return null;
  const sel = group.querySelector('.selected');
  return sel ? sel.dataset.value : null;
}

function getSelectedAgent() {
  const sel = agentSelect.querySelector('.selected');
  return sel ? sel.dataset.value : 'claude';
}

// Build command
function buildCommand() {
  const agent = getSelectedAgent();

  if (agent === 'claude') {
    const model = getSelected('claude-model') || 'claude-opus-4-6';
    const perms = getSelected('claude-perms') || 'regular';
    const effort = getSelected('claude-effort') || 'high';

    let cmd = `claude --model ${model}`;
    if (perms === 'dangerous') cmd += ' --dangerously-skip-permissions';
    if (effort === 'high') cmd += ' --effort high';
    return { command: cmd, label: `Claude ${model.includes('opus') ? 'Opus' : 'Sonnet'}` };
  }

  if (agent === 'gemini') {
    const model = getSelected('gemini-model') || 'auto';
    const approval = getSelected('gemini-approval') || 'default';

    let cmd = 'gemini';
    if (model !== 'auto') cmd += ` --model ${model}`;
    if (approval === 'auto-edit') cmd += ' --auto-edit';
    else if (approval === 'yolo') cmd += ' --yolo';
    return { command: cmd, label: `Gemini ${model}` };
  }

  if (agent === 'codex') {
    const approval = getSelected('codex-approval') || 'suggest';

    let cmd = 'codex';
    if (approval === 'auto-edit') cmd += ' --approval-mode auto-edit';
    else if (approval === 'full-auto') cmd += ' --full-auto';
    return { command: cmd, label: 'Codex' };
  }

  return { command: agent, label: agent };
}

// Launch
document.getElementById('modal-launch').addEventListener('click', async () => {
  const agent = getSelectedAgent();
  const { command, label } = buildCommand();

  // Capture pending instructions from selected playbook BEFORE closing modal
  let pendingInstructions = null;
  if (selectedPlaybookId) {
    const pb = playbooks.find(p => p.id === selectedPlaybookId);
    if (pb && pb.instructions) pendingInstructions = pb.instructions;
  }

  // Get terminal dimensions from a hidden probe
  const cols = 80;
  const rows = 24;

  // E2EE: if we have a device_secret from pairing, enable encryption
  const deviceId = localStorage.getItem('automaite_device_id') || '';
  const deviceSecret = localStorage.getItem('automaite_device_secret') || '';
  const useE2EE = appMode === 'local' && !!deviceId && !!deviceSecret;

  const body = { agent_type: agent, command, label, cols, rows };
  if (useE2EE) {
    body.device_id = deviceId;
    body.e2ee = true;
  }

  try {
    const res = await apiFetch('/api/sessions', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      const err = new Error(errData.detail || 'Failed to create session');
      err.status = res.status;
      throw err;
    }
    const info = await res.json();

    // Derive and store E2EE key for this session
    if (useE2EE) {
      const key = await deriveE2EEKey(deviceSecret);
      e2eeKeys.set(info.session_id, key);
    }

    const s = createTerminalSession(info);
    switchToSession(info.session_id);
    updateUI();
    closeModal();

    // Send playbook instructions after session is ready
    if (pendingInstructions) {
      schedulePlaybookInput(info.session_id, pendingInstructions);
    }
  } catch (err) {
    if (err.status === 402 || (err.message && err.message.includes('402'))) {
      showSubscribeScreen();
    } else if (err.status === 503) {
      alert('Desktop Agent Offline\n\n' + err.message);
    } else {
      alert('Failed to launch: ' + err.message);
    }
  }
});


function showAgentError(reason, command) {
  var title = 'Session Failed';
  var body = '';
  var base = command.replace(/\\/g, '/').split('/').pop().replace(/\.(cmd|bat|exe)$/i, '').toLowerCase();

  if (reason === 'not_found') {
    var instructions = {
      'claude': 'Install Claude Code:\n  npm install -g @anthropic-ai/claude-code\n\nThen run "claude" once to sign in via your browser,\nor add your Anthropic API key in Settings (gear icon).',
      'claudereal': 'Install Claude Code:\n  npm install -g @anthropic-ai/claude-code\n\nThen run "claude" once to sign in via your browser,\nor add your Anthropic API key in Settings (gear icon).',
      'gemini': 'Install Gemini CLI:\n  npm install -g @google/gemini-cli\n\nThen add your Gemini API key in Settings (gear icon).\nGet a key at ai.google.dev',
      'geminireal': 'Install Gemini CLI:\n  npm install -g @google/gemini-cli\n\nThen add your Gemini API key in Settings (gear icon).\nGet a key at ai.google.dev',
      'codex': 'Install Codex CLI:\n  npm install -g @openai/codex\n\nThen run "codex" once to sign in via your browser,\nor add your OpenAI API key in Settings (gear icon).',
      'codexreal': 'Install Codex CLI:\n  npm install -g @openai/codex\n\nThen run "codex" once to sign in via your browser,\nor add your OpenAI API key in Settings (gear icon).',
    };
    title = base.replace('real','') + ' not found';
    title = title.charAt(0).toUpperCase() + title.slice(1);
    body = instructions[base] || ('The agent "' + command + '" was not found on your desktop.\nMake sure it is installed and on your PATH.');
  } else if (reason === 'not_allowed') {
    body = 'The command "' + command + '" is not in the allowed list.\nCheck your agent configuration.';
  } else if (reason === 'spawn_failed') {
    body = 'Failed to start "' + command + '".\nThe agent may not be properly installed.';
  } else {
    return;
  }
  alert(title + '\n\n' + body);
}

// ── Input bar ──
const termInput = document.getElementById('term-input');
const sendBtn = document.getElementById('send-btn');

async function sendInput(text, addNewline = false) {
  const targetId = isDesktop() ? focusedSessionId : activeSessionId;
  if (!targetId) return false;
  const s = sessions.get(targetId);
  if (!s || !s.ws || s.ws.readyState !== WebSocket.OPEN) return false;
  const payload = text + (addNewline ? '\r' : '');
  try {
    const e2eeKey = e2eeKeys.get(targetId);
    if (e2eeKey) {
      const encrypted = await e2eeEncrypt(e2eeKey, payload);
      const b64 = btoa(String.fromCharCode(...encrypted));
      s.ws.send(JSON.stringify({ type: 'input', data: b64 }));
    } else {
      s.ws.send(JSON.stringify({ type: 'input', data: payload }));
    }
    return true;
  } catch {
    return false;
  }
}

sendBtn.textContent = 'Enter';
sendBtn.addEventListener('click', async () => {
  const sent = await sendInput(termInput.value, true);
  if (sent) {
    termInput.value = '';
    sendBtn.textContent = 'Enter';
  }
  termInput.focus();
});

termInput.addEventListener('keydown', async (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    const sent = await sendInput(termInput.value, true);
    if (sent) {
      termInput.value = '';
      sendBtn.textContent = 'Enter';
    }
  }
});

termInput.addEventListener('input', () => {
  sendBtn.textContent = termInput.value.length > 0 ? 'Send' : 'Enter';
});

// Special key mapping — HTML data attributes can't hold real control chars,
// so we map readable names to the actual byte sequences here.
const SPECIAL_KEYS = {
  'enter': '\r',
  'tab': '\t',
  'up': '\x1b[A',
  'down': '\x1b[B',
};

// Special keys — click is reliable on both desktop and mobile
// (touch-action: manipulation in CSS removes the 300ms tap delay)
document.getElementById('special-keys').addEventListener('click', (e) => {
  const btn = e.target.closest('.skey');
  if (!btn) return;
  e.preventDefault();
  const seq = SPECIAL_KEYS[btn.dataset.key] || btn.dataset.key;
  sendInput(seq);
  if (isDesktop() && activeSessionId) {
    const s = sessions.get(activeSessionId);
    if (s) s.term.focus();
  } else {
    document.getElementById('term-input').focus();
  }
});

// ── Keyboard shortcuts ──
document.addEventListener('keydown', (e) => {
  // Ctrl+T: new session
  if (e.ctrlKey && e.key === 't') {
    e.preventDefault();
    openModal();
    return;
  }
  // Desktop-only shortcuts
  if (!isDesktop()) return;
  const ids = [...sessions.keys()];
  if (ids.length === 0) return;
  // Ctrl+Shift+Tab or Alt+ArrowLeft: focus previous
  if ((e.ctrlKey && e.shiftKey && e.key === 'Tab') || (e.altKey && e.key === 'ArrowLeft')) {
    e.preventDefault();
    const idx = ids.indexOf(focusedSessionId);
    const prev = (idx - 1 + ids.length) % ids.length;
    focusTile(ids[prev]);
    return;
  }
  // Ctrl+Tab or Alt+ArrowRight: focus next
  if ((e.ctrlKey && e.key === 'Tab') || (e.altKey && e.key === 'ArrowRight')) {
    e.preventDefault();
    const idx = ids.indexOf(focusedSessionId);
    const next = (idx + 1) % ids.length;
    focusTile(ids[next]);
    return;
  }
});

// ── Reconnect on app resume (visibility change) ──
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && loggedIn) {
    // Force-close and reconnect ALL WebSockets — after backgrounding,
    // connections are often half-open even if readyState says OPEN
    sessions.forEach((s, sid) => {
      s._retries = 0; // Reset backoff on user-initiated resume
      try { if (s.ws) s.ws.close(); } catch {}
      s.ws = connectTerminalWS(sid, s.term);
    });
    // Refresh agent status
    pollAgentStatus();
    // Sync session list with server (remove sessions that server cleaned up)
    syncSessions();
    // Refit terminals, but only scroll the focused/active one to bottom
    requestAnimationFrame(() => {
      sessions.forEach(s => s.fitAddon.fit());
      requestAnimationFrame(() => {
        const targetId = isDesktop() ? focusedSessionId : activeSessionId;
        const s = targetId && sessions.get(targetId);
        if (s) s.term.scrollToBottom();
      });
    });
  }
});

async function syncSessions() {
  try {
    const res = await apiFetch('/api/sessions');
    const serverSessions = await res.json();
    const serverIds = new Set(serverSessions.map(s => s.session_id));
    // Remove local sessions that no longer exist on server
    sessions.forEach((s, sid) => {
      if (!serverIds.has(sid)) {
        if (s.ws) try { s.ws.close(); } catch {}
        s.term.dispose();
        s.wrapper.remove();
        sessions.delete(sid);
        e2eeKeys.delete(sid);
      }
    });
    // Add server sessions we don't have locally
    serverSessions.forEach(info => {
      if (!sessions.has(info.session_id)) {
        createTerminalSession(info);
      }
    });
    updateUI();
  } catch {}
}

// ── Global resize handler (replaces per-session handlers) ──
let _resizeTimer = null;
let _lastDesktopState = isDesktop();
window.addEventListener('resize', () => {
  if (_resizeTimer) clearTimeout(_resizeTimer);
  _resizeTimer = setTimeout(() => {
    const nowDesktop = isDesktop();
    if (nowDesktop !== _lastDesktopState) {
      _lastDesktopState = nowDesktop;
      syncViewMode();
    }
    if (nowDesktop) {
      sessions.forEach(s => s.fitAddon.fit());
    } else if (activeSessionId) {
      const s = sessions.get(activeSessionId);
      if (s) s.fitAddon.fit();
    }
  }, 100);
});

// ── Mobile: refit terminal and reposition input bar when virtual keyboard opens/closes ──
if (window.visualViewport) {
  let _vpRAF = null;
  const repositionInputBar = () => {
    const vv = window.visualViewport;
    // Clamp offset so it never goes negative during keyboard animation
    const offset = Math.max(0, window.innerHeight - vv.height - vv.offsetTop);
    document.getElementById('input-bar').style.bottom = offset + 'px';
    document.getElementById('special-keys').style.bottom = (offset + 46) + 'px';
    // Update app-screen height immediately (not in a separate timeout)
    document.getElementById('app-screen').style.height = vv.height + 'px';
    // Refit the active terminal to match the new viewport
    if (activeSessionId) {
      const s = sessions.get(activeSessionId);
      if (s) s.fitAddon.fit();
    }
  };
  const scheduleReposition = () => {
    if (isDesktop()) return;
    if (_vpRAF) cancelAnimationFrame(_vpRAF);
    _vpRAF = requestAnimationFrame(repositionInputBar);
  };
  window.visualViewport.addEventListener('scroll', scheduleReposition);
  window.visualViewport.addEventListener('resize', scheduleReposition);
}

// ── Settings / API Keys UI ──
const settingsOverlay = document.getElementById('settings-overlay');
const settingsStatus = document.getElementById('settings-status');

document.getElementById('btn-settings').addEventListener('click', openSettings);
document.getElementById('settings-close').addEventListener('click', closeSettings);
document.getElementById('settings-save').addEventListener('click', saveKeys);
settingsOverlay.addEventListener('click', (e) => { if (e.target === settingsOverlay) closeSettings(); });

// Toggle show/hide for key inputs
document.querySelectorAll('.key-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.for);
    if (input.type === 'password') { input.type = 'text'; btn.textContent = 'Hide'; }
    else { input.type = 'password'; btn.textContent = 'Show'; }
  });
});

async function openSettings() {
  settingsOverlay.classList.add('active');
  settingsStatus.textContent = '';
  settingsStatus.className = '';
  // Load existing keys
  try {
    const res = await apiFetch('/api/settings/keys');
    const data = await res.json();
    document.getElementById('key-anthropic').value = '';
    document.getElementById('key-gemini').value = '';
    document.getElementById('key-openai').value = '';
    document.getElementById('key-anthropic').placeholder = data.keys.ANTHROPIC_API_KEY || 'sk-ant-...';
    document.getElementById('key-gemini').placeholder = data.keys.GEMINI_API_KEY || 'AIza...';
    document.getElementById('key-openai').placeholder = data.keys.OPENAI_API_KEY || 'sk-...';
  } catch {}
}

function closeSettings() {
  settingsOverlay.classList.remove('active');
}

async function saveKeys() {
  const keys = {};
  const anthropic = document.getElementById('key-anthropic').value.trim();
  const gemini = document.getElementById('key-gemini').value.trim();
  const openai = document.getElementById('key-openai').value.trim();
  if (anthropic) keys.ANTHROPIC_API_KEY = anthropic;
  if (gemini) keys.GEMINI_API_KEY = gemini;
  if (openai) keys.OPENAI_API_KEY = openai;

  if (Object.keys(keys).length === 0) {
    settingsStatus.textContent = 'Enter at least one key to save';
    settingsStatus.className = 'error';
    return;
  }

  try {
    const res = await apiFetch('/api/settings/keys', {
      method: 'POST',
      body: JSON.stringify({ keys }),
    });
    if (res.ok) {
      settingsStatus.textContent = 'Keys saved successfully!';
      settingsStatus.className = 'success';
      // Reload placeholders
      setTimeout(() => openSettings(), 500);
    } else {
      const err = await res.json().catch(() => ({}));
      settingsStatus.textContent = err.detail || 'Failed to save';
      settingsStatus.className = 'error';
    }
  } catch (e) {
    settingsStatus.textContent = 'Connection error';
    settingsStatus.className = 'error';
  }
}

// ── Subscription Gating ──
let userSubscribed = false;

async function checkSubscription() {
  try {
    const res = await apiFetch('/api/subscription');
    const data = await res.json();
    userSubscribed = data.active;
    return data;
  } catch {
    return { active: false };
  }
}

function showSubscribeScreen() {
  // Hide main app, show subscribe prompt
  document.getElementById('terminal-container').style.display = 'none';
  document.getElementById('tab-bar').style.display = 'none';
  document.getElementById('btn-new-session').style.display = 'none';
  document.getElementById('special-keys').style.display = 'none';
  document.getElementById('input-bar').style.display = 'none';

  // Create subscribe overlay if not exists
  if (!document.getElementById('subscribe-prompt')) {
    const div = document.createElement('div');
    div.id = 'subscribe-prompt';
    div.innerHTML = `
      <div style="text-align:center; padding:2rem; max-width:400px; margin:auto;">
        <h2 style="margin-bottom:0.5rem;">Subscribe to Automaite</h2>
        <p style="color:#888; margin-bottom:1.5rem; line-height:1.5;">
          Get remote terminal access to AI coding agents from your phone.<br>
          <strong>$10/month</strong> — cancel anytime.
        </p>
        <p style="color:#666; font-size:0.85rem; margin-bottom:1.5rem;">
          Requires your own AI subscription (Claude Pro, Gemini, or OpenAI).
        </p>
        <button id="btn-subscribe" style="
          background: #7c3aed; color: white; border: none; padding: 0.75rem 2rem;
          border-radius: 8px; font-size: 1rem; cursor: pointer; font-weight: 600;
        ">Subscribe — $10/month</button>
        <div id="subscribe-status" style="margin-top:1rem; color:#888; font-size:0.85rem;"></div>
        <div style="margin-top:1.5rem; font-size:0.75rem; color:#666;">
          By subscribing you agree to our
          <a href="https://automaite.ca/terms" target="_blank" style="color:#7c3aed;">Terms of Service</a> and
          <a href="https://automaite.ca/privacy" target="_blank" style="color:#7c3aed;">Privacy Policy</a>.
        </div>
      </div>
    `;
    document.getElementById('app-screen').appendChild(div);
    document.getElementById('btn-subscribe').addEventListener('click', async () => {
      document.getElementById('subscribe-status').textContent = 'Redirecting to checkout...';
      try {
        const res = await apiFetch('/api/subscribe', { method: 'POST' });
        const data = await res.json();
        if (data.url) window.location.href = data.url;
        else document.getElementById('subscribe-status').textContent = 'Error creating checkout session';
      } catch (e) {
        document.getElementById('subscribe-status').textContent = 'Connection error';
      }
    });
  }
  document.getElementById('subscribe-prompt').style.display = 'block';
}

function hideSubscribeScreen() {
  const el = document.getElementById('subscribe-prompt');
  if (el) el.style.display = 'none';
  document.getElementById('terminal-container').style.display = '';
  document.getElementById('tab-bar').style.display = '';
  document.getElementById('btn-new-session').style.display = '';
  document.getElementById('special-keys').style.display = '';
  document.getElementById('input-bar').style.display = '';
}

// Patch showApp to check subscription
const _originalShowApp = showApp;
showApp = async function() {
  await _originalShowApp();
  const subData = await checkSubscription();
  if (!subData.active) {
    showSubscribeScreen();
  } else {
    hideSubscribeScreen();
  }
};

// Check for ?subscribed=1 in URL (redirect from Stripe Checkout)
// Webhook race fix: if session_id is present, verify directly via Stripe API
(async function handleCheckoutReturn() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('subscribed') === '1') {
    const sessionId = params.get('session_id');
    window.history.replaceState({}, '', '/');
    if (sessionId) {
      // Verify the checkout session directly (don't wait for webhook)
      try {
        const res = await apiFetch('/api/subscription/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_id: sessionId }),
        });
        const data = await res.json();
        if (data.active) {
          userSubscribed = true;
          hideSubscribeScreen();
        }
      } catch (e) {
        console.error('Failed to verify checkout session:', e);
      }
    }
    // Also re-check subscription (covers case where webhook already fired)
    const subData = await checkSubscription();
    if (subData.active) {
      userSubscribed = true;
      hideSubscribeScreen();
    }
  }
})();

// ── Clean View Feature ──

// Global clean mode state
let globalCleanMode = false;

// ── ANSI stripping + agent speech extraction ──
function extractAgentSpeech(rawText) {
  if (!rawText) return '';

  // Strip all ANSI/VT escape sequences:
  // CSI sequences: ESC [ ... final-byte
  // OSC sequences: ESC ] ... ST (ST = ESC\ or BEL)
  // Other ESC sequences
  let text = rawText
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b[^[\]]/g, '')
    .replace(/\x1b/g, '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]/g, '');

  const lines = text.split('\n');
  const filteredLines = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip empty / whitespace-only
    if (trimmed === '') {
      filteredLines.push('');
      continue;
    }

    // Skip lines with box-drawing characters (UI chrome from Claude/tools)
    if (/[─│┌┐└┘├┤┬┴┼╭╮╰╯]/.test(trimmed)) continue;

    // Skip lines that are only repeated characters (dividers like ──────)
    if (/^(.)\1{3,}$/.test(trimmed)) continue;

    // Skip spinner characters
    if (/^[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]/.test(trimmed)) continue;

    // Skip tool call / file operation prefixes
    if (/^(Reading|Read |Wrote |Edit:|Bash:|Writing |Write |Listing |List |Glob:|Grep:|WebFetch:|WebSearch:|MCP |TodoWrite|TaskCreate|TaskUpdate|TaskGet|TaskList|NotebookEdit)/.test(trimmed)) continue;

    // Skip shell prompt indicators
    if (/^(\$ |❯ |> {1,3}\S)/.test(trimmed)) continue;

    // Skip tool result indicators (checkmarks, bullets, etc at start of line with indent)
    if (/^\s{0,3}[✓✗●○⎿⎾]/.test(line)) continue;

    // Skip diff header lines
    if (/^[+]{3}|^[-]{3}/.test(trimmed)) continue;

    // Skip diff hunk lines in context (adjacent +/- lines)
    if (/^[+\-]/.test(trimmed) && trimmed.length > 2) {
      const prevTrimmed = (lines[i-1] || '').trim();
      const nextTrimmed = (lines[i+1] || '').trim();
      if (/^[+\-]/.test(prevTrimmed) || /^[+\-]/.test(nextTrimmed)) {
        continue;
      }
    }

    // Skip lines that look like pure file paths (no spaces, starts with / or ~/ or ./ or letter:\)
    if (/^(\/|~\/|\.\/|[a-zA-Z]:\\)[\w\-./\\]+$/.test(trimmed)) continue;

    // Skip very short lines that are just non-alphanumeric crud
    if (trimmed.length <= 2 && /^[^a-zA-Z0-9]/.test(trimmed)) continue;

    // Keep the line
    filteredLines.push(line);
  }

  // Collapse multiple consecutive blank lines into a single blank line
  const collapsed = [];
  let blankCount = 0;
  for (const line of filteredLines) {
    if (line.trim() === '') {
      blankCount++;
      if (blankCount <= 1) collapsed.push('');
    } else {
      blankCount = 0;
      collapsed.push(line);
    }
  }

  // Trim leading/trailing blanks
  while (collapsed.length && collapsed[0].trim() === '') collapsed.shift();
  while (collapsed.length && collapsed[collapsed.length - 1].trim() === '') collapsed.pop();

  return collapsed.join('\n');
}

// ── Toggle clean/raw view for a single session ──
function setSessionCleanMode(sessionId, cleanMode) {
  const s = sessions.get(sessionId);
  if (!s) return;

  s.cleanMode = cleanMode;
  const termBody = s.wrapper.querySelector('.term-body');
  const cleanView = s.cleanView;
  const toggleBtn = s.wrapper.querySelector('.tile-toggle');

  if (cleanMode) {
    // Switch to clean view
    termBody.style.display = 'none';
    cleanView.style.display = 'block';
    if (toggleBtn) { toggleBtn.textContent = 'Raw'; toggleBtn.classList.add('active'); }
    // Render current content
    cleanView.textContent = extractAgentSpeech(s.rawOutput || '');
    // Scroll to bottom
    cleanView.scrollTop = cleanView.scrollHeight;
  } else {
    // Switch back to raw/xterm view
    termBody.style.display = '';
    cleanView.style.display = 'none';
    if (toggleBtn) { toggleBtn.textContent = '\u25C9'; toggleBtn.classList.remove('active'); }
    // Refit the terminal
    requestAnimationFrame(() => {
      if (s.fitAddon) s.fitAddon.fit();
    });
  }
}

// ── Monkey-patch createTerminalSession to inject clean view ──
const _origCreateTerminalSession = createTerminalSession;
createTerminalSession = function(info) {
  const session = _origCreateTerminalSession(info);

  // Add rawOutput buffer and clean mode state
  session.rawOutput = '';
  session.cleanMode = false;

  // Create cleanView div inside term-body (so absolute positioning works)
  const cleanView = document.createElement('div');
  cleanView.className = 'clean-view';
  cleanView.style.display = 'none';
  const termBody = session.wrapper.querySelector('.term-body');
  termBody.appendChild(cleanView);
  session.cleanView = cleanView;

  // Add per-tile toggle button in tile-header (desktop only, header exists on desktop)
  const header = session.wrapper.querySelector('.tile-header');
  if (header) {
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'tile-toggle';
    toggleBtn.title = 'Toggle clean view';
    toggleBtn.textContent = '\u25C9';
    // Insert before close button
    const closeBtn = header.querySelector('.tile-close');
    if (closeBtn) {
      header.insertBefore(toggleBtn, closeBtn);
    } else {
      header.appendChild(toggleBtn);
    }
    toggleBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      setSessionCleanMode(info.session_id, !session.cleanMode);
    });
  }

  // If globalCleanMode is active when session is created, apply it
  if (globalCleanMode) {
    // Defer to next tick so the session is fully set up first
    setTimeout(() => setSessionCleanMode(info.session_id, true), 0);
  }

  return session;
};

// ── Monkey-patch connectTerminalWS to capture rawOutput and update clean view ──
const _origConnectTerminalWS = connectTerminalWS;
connectTerminalWS = function(sessionId, term) {
  const ws = _origConnectTerminalWS(sessionId, term);

  // Wrap onmessage after the original has set it (next tick)
  setTimeout(() => {
    if (!ws || ws.readyState === WebSocket.CLOSED) return;
    const origOnMessage = ws.onmessage;
    let cleanViewUpdateTimer = null;

    ws.onmessage = async function(evt) {
      // Call original handler first so xterm gets its data
      if (origOnMessage) await origOnMessage.call(this, evt);

      // Capture data for rawOutput
      if (!(evt.data instanceof ArrayBuffer)) return;
      const bytes = new Uint8Array(evt.data);
      // Skip status messages (0x00 prefix)
      if (bytes.length > 0 && bytes[0] === 0) return;

      const cur = sessions.get(sessionId);
      if (!cur) return;

      // Decode text — if E2EE, re-decrypt; otherwise decode raw bytes
      let text;
      const e2eeKey = e2eeKeys.get(sessionId);
      if (e2eeKey) {
        try {
          const decrypted = await e2eeDecrypt(e2eeKey, bytes);
          text = new TextDecoder('utf-8', { fatal: false }).decode(decrypted);
        } catch {
          text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        }
      } else {
        text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      }

      cur.rawOutput = (cur.rawOutput || '') + text;

      // Throttled live update of clean view when in clean mode
      if (cur.cleanMode && cur.cleanView) {
        if (cleanViewUpdateTimer) return;
        cleanViewUpdateTimer = setTimeout(() => {
          cleanViewUpdateTimer = null;
          const latestSession = sessions.get(sessionId);
          if (latestSession && latestSession.cleanMode && latestSession.cleanView) {
            latestSession.cleanView.textContent = extractAgentSpeech(latestSession.rawOutput || '');
            latestSession.cleanView.scrollTop = latestSession.cleanView.scrollHeight;
          }
        }, 500);
      }
    };
  }, 0);

  return ws;
};

// ── Global toggle button handler ──
(function() {
  const btnGlobalToggle = document.getElementById('btn-toggle-view');
  if (!btnGlobalToggle) return;
  btnGlobalToggle.addEventListener('click', function() {
    globalCleanMode = !globalCleanMode;
    this.classList.toggle('active', globalCleanMode);
    sessions.forEach((s, sessionId) => {
      setSessionCleanMode(sessionId, globalCleanMode);
    });
  });
})();

// ── Phone WebSocket (vault credential requests) ──
let phoneWs = null;
let pendingVaultRequests = new Map(); // request_id -> {credential_name, reason, agent_id, session_id}
let activeVaultRequestId = null;

function connectPhoneWS() {
  if (phoneWs && phoneWs.readyState <= WebSocket.OPEN) return;
  const url = WS_BASE + '/ws/phone';
  phoneWs = new WebSocket(url);

  phoneWs.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      if (data.type === 'credential_request') {
        pendingVaultRequests.set(data.request_id, {
          credential_name: data.credential_name,
          reason: data.reason || '',
          agent_id: data.agent_id || 'agent',
          session_id: data.session_id || '',
          ttl_seconds: data.ttl_seconds || 300,
        });
        updateVaultButton();
        showVaultApproval(data.request_id);
      }
    } catch {}
  };

  phoneWs.onclose = () => {
    setTimeout(() => {
      if (loggedIn) connectPhoneWS();
    }, 5000);
  };

  phoneWs.onerror = () => {};
}

function updateVaultButton() {
  const btn = document.getElementById('btn-vault');
  if (!btn) return;
  btn.classList.toggle('has-pending', pendingVaultRequests.size > 0);
}

// ── Saved Credentials (localStorage, encrypted with device_secret) ──

function getSavedVaultCredentials() {
  try {
    return JSON.parse(localStorage.getItem('automaite_vault') || '{}');
  } catch { return {}; }
}

function setSavedVaultCredentials(creds) {
  localStorage.setItem('automaite_vault', JSON.stringify(creds));
}

async function saveVaultCredential(name, plaintext) {
  const deviceSecret = localStorage.getItem('automaite_device_secret');
  if (!deviceSecret) { alert('Vault not available -- link this device first via Vault > Device Key.'); return; }
  const key = await deriveE2EEKey(deviceSecret);
  const encrypted = await e2eeEncrypt(key, plaintext);
  const stored = btoa(String.fromCharCode(...encrypted));
  const creds = getSavedVaultCredentials();
  creds[name] = stored;
  setSavedVaultCredentials(creds);
}

async function loadVaultCredential(name) {
  const creds = getSavedVaultCredentials();
  const stored = creds[name];
  if (!stored) return null;
  const deviceSecret = localStorage.getItem('automaite_device_secret');
  if (!deviceSecret) return null;
  try {
    const bytes = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
    const key = await deriveE2EEKey(deviceSecret);
    const decrypted = await e2eeDecrypt(key, bytes);
    return new TextDecoder().decode(decrypted);
  } catch { return null; }
}

function listSavedVaultNames() {
  return Object.keys(getSavedVaultCredentials());
}

function deleteSavedVaultCredential(name) {
  const creds = getSavedVaultCredentials();
  delete creds[name];
  setSavedVaultCredentials(creds);
}

// ── Vault Approval UI ──

async function showVaultApproval(requestId) {
  const req = pendingVaultRequests.get(requestId);
  if (!req) return;
  activeVaultRequestId = requestId;
  document.getElementById('vault-agent-name').textContent = req.agent_id;
  document.getElementById('vault-cred-name').textContent = req.credential_name;
  document.getElementById('vault-reason').textContent = req.reason || 'Agent needs this credential';
  document.getElementById('vault-cred-input').value = '';
  document.getElementById('vault-remember-cb').checked = false;

  const savedMatch = document.getElementById('vault-saved-match');
  const useSavedBtn = document.getElementById('vault-use-saved');
  const savedValue = await loadVaultCredential(req.credential_name);
  if (savedValue) {
    const masked = savedValue.length > 6
      ? savedValue.slice(0, 3) + '***' + savedValue.slice(-3)
      : '******';
    useSavedBtn.textContent = 'Use saved (' + masked + ')';
    savedMatch.style.display = '';
    document.getElementById('vault-input-label').textContent = 'Or enter manually';
  } else {
    savedMatch.style.display = 'none';
    document.getElementById('vault-input-label').textContent = 'Value';
  }

  document.getElementById('vault-approval').style.display = '';
  document.getElementById('vault-list').style.display = 'none';
  document.getElementById('vault-overlay').classList.add('active');
}

async function approveWithValue(value) {
  const requestId = activeVaultRequestId;
  if (!requestId) return;
  const req = pendingVaultRequests.get(requestId);

  const deviceSecret = localStorage.getItem('automaite_device_secret');
  if (!deviceSecret) {
    alert('No vault key on this device. Open Vault > Device Key to link this device first.');
    return;
  }

  if (req && document.getElementById('vault-remember-cb').checked) {
    await saveVaultCredential(req.credential_name, value);
  }
  const key = await deriveE2EEKey(deviceSecret);
  const encrypted = await e2eeEncrypt(key, value);
  const encryptedB64 = btoa(String.fromCharCode(...encrypted));

  if (phoneWs && phoneWs.readyState === WebSocket.OPEN) {
    phoneWs.send(JSON.stringify({
      type: 'credential_response',
      request_id: requestId,
      encrypted_credential: encryptedB64,
    }));
  }

  pendingVaultRequests.delete(requestId);
  activeVaultRequestId = null;
  document.getElementById('vault-cred-input').value = '';
  updateVaultButton();
  closeVaultOverlay();
}

async function handleVaultApprove() {
  const input = document.getElementById('vault-cred-input');
  const value = input.value;
  if (!value) { input.focus(); return; }
  await approveWithValue(value);
}

async function handleVaultUseSaved() {
  const req = pendingVaultRequests.get(activeVaultRequestId);
  if (!req) return;
  const value = await loadVaultCredential(req.credential_name);
  if (!value) { alert('Saved credential could not be read'); return; }
  document.getElementById('vault-remember-cb').checked = false;
  await approveWithValue(value);
}

function handleVaultDeny() {
  const requestId = activeVaultRequestId;
  if (!requestId) return;

  if (phoneWs && phoneWs.readyState === WebSocket.OPEN) {
    phoneWs.send(JSON.stringify({
      type: 'credential_denied',
      request_id: requestId,
    }));
  }

  pendingVaultRequests.delete(requestId);
  activeVaultRequestId = null;
  updateVaultButton();
  closeVaultOverlay();
}

function closeVaultOverlay() {
  document.getElementById('vault-overlay').classList.remove('active');
  document.getElementById('vault-approval').style.display = 'none';
  document.getElementById('vault-list').style.display = 'none';
}

async function showVaultList() {
  document.getElementById('vault-approval').style.display = 'none';
  document.getElementById('vault-list').style.display = '';
  document.getElementById('vault-overlay').classList.add('active');

  const pendingDiv = document.getElementById('vault-pending-list');
  pendingDiv.innerHTML = '';
  pendingVaultRequests.forEach((req, id) => {
    const item = document.createElement('div');
    item.className = 'vault-pending-item';
    item.style.cursor = 'pointer';
    const makeField = (label, val) => {
      const f = document.createElement('div');
      f.className = 'vault-field';
      const l = document.createElement('label');
      l.textContent = label;
      const v = document.createElement('div');
      v.className = 'vault-value';
      v.textContent = val;
      f.appendChild(l);
      f.appendChild(v);
      return f;
    };
    item.appendChild(makeField('Credential', req.credential_name));
    item.appendChild(makeField('Agent', req.agent_id));
    item.addEventListener('click', () => showVaultApproval(id));
    pendingDiv.appendChild(item);
  });
  if (pendingVaultRequests.size === 0) {
    pendingDiv.innerHTML = '<div style="color:var(--text-dim);font-size:13px;padding:8px 0">No pending requests</div>';
  }

  const savedNames = listSavedVaultNames();
  if (savedNames.length > 0) {
    const savedSection = document.createElement('div');
    savedSection.innerHTML = '<div class="vault-section-label">Saved Credentials</div>';
    savedNames.forEach(name => {
      const row = document.createElement('div');
      row.className = 'vault-audit-item';
      const nameSpan = document.createElement('span');
      nameSpan.style.flex = '1';
      nameSpan.textContent = name;
      row.appendChild(nameSpan);
      const del = document.createElement('button');
      del.textContent = 'Remove';
      del.className = 'btn-danger';
      del.style.cssText = 'padding:4px 10px;font-size:11px';
      del.addEventListener('click', () => {
        if (confirm('Remove saved credential "' + name + '"?')) {
          deleteSavedVaultCredential(name);
          showVaultList();
        }
      });
      row.appendChild(del);
      savedSection.appendChild(row);
    });
    pendingDiv.after(savedSection);
  }

  const deviceSecret = localStorage.getItem('automaite_device_secret');
  const deviceSection = document.createElement('div');
  const deviceLabel = document.createElement('div');
  deviceLabel.className = 'vault-section-label';
  deviceLabel.textContent = 'Device Key';
  deviceSection.appendChild(deviceLabel);
  const deviceRow = document.createElement('div');
  deviceRow.className = 'vault-audit-item';
  deviceRow.style.cssText = 'flex-direction:column;align-items:flex-start;gap:8px';
  if (deviceSecret) {
    const desc = document.createElement('div');
    desc.textContent = 'Vault active. Reveal this key to link your laptop or another browser.';
    desc.style.cssText = 'font-size:13px;color:var(--text-dim)';
    const revealBtn = document.createElement('button');
    revealBtn.textContent = 'Reveal Key';
    revealBtn.className = 'btn-secondary';
    revealBtn.style.cssText = 'padding:4px 10px;font-size:11px';
    revealBtn.addEventListener('click', () => {
      if (!confirm('Show vault key? Anyone with this key can decrypt your saved credentials.')) return;
      const keyBox = document.createElement('div');
      keyBox.style.cssText = 'font-family:monospace;font-size:12px;word-break:break-all;background:var(--bg-2,#111);padding:8px;border-radius:4px;user-select:all;cursor:text';
      keyBox.textContent = deviceSecret;
      revealBtn.replaceWith(keyBox);
    });
    deviceRow.appendChild(desc);
    deviceRow.appendChild(revealBtn);
  } else {
    const desc = document.createElement('div');
    desc.textContent = 'No vault key on this device. Paste the key from your phone or another linked device to enable encrypted vault.';
    desc.style.cssText = 'font-size:13px;color:var(--text-dim)';
    const linkBtn = document.createElement('button');
    linkBtn.textContent = 'Link Device';
    linkBtn.className = 'btn-primary';
    linkBtn.style.cssText = 'padding:4px 10px;font-size:11px';
    linkBtn.addEventListener('click', () => {
      const key = prompt('Paste your vault key:');
      if (key && key.trim()) {
        localStorage.setItem('automaite_device_secret', key.trim());
        showVaultList();
      }
    });
    deviceRow.appendChild(desc);
    deviceRow.appendChild(linkBtn);
  }
  deviceSection.appendChild(deviceRow);
  const recentLabel = document.querySelector('#vault-list .vault-section-label');
  recentLabel.before(deviceSection);

  const auditDiv = document.getElementById('vault-audit-list');
  auditDiv.innerHTML = '<div style="color:var(--text-dim);font-size:13px">Loading...</div>';
  try {
    const res = await apiFetch('/api/vault/audit?limit=20');
    const entries = await res.json();
    auditDiv.innerHTML = '';
    if (entries.length === 0) {
      auditDiv.innerHTML = '<div style="color:var(--text-dim);font-size:13px">No activity yet</div>';
    }
    entries.forEach(e => {
      const item = document.createElement('div');
      item.className = 'vault-audit-item';
      const actionClass = e.action || 'requested';
      const time = new Date(e.timestamp * 1000).toLocaleTimeString();
      item.innerHTML = '<span class="vault-audit-action ' + actionClass + '">' + actionClass + '</span>'
        + '<span>' + e.credential_name + '</span>'
        + '<span style="margin-left:auto;color:var(--text-dim);font-size:11px">' + time + '</span>';
      auditDiv.appendChild(item);
    });
  } catch {
    auditDiv.innerHTML = '<div style="color:var(--text-dim);font-size:13px">Failed to load</div>';
  }
}

// Vault button click
document.getElementById('btn-vault').addEventListener('click', () => {
  if (pendingVaultRequests.size > 0) {
    const firstId = pendingVaultRequests.keys().next().value;
    showVaultApproval(firstId);
  } else {
    showVaultList();
  }
});

// Vault approve/deny/close handlers
document.getElementById('vault-approve').addEventListener('click', handleVaultApprove);
document.getElementById('vault-deny').addEventListener('click', handleVaultDeny);
document.getElementById('vault-use-saved').addEventListener('click', handleVaultUseSaved);
document.getElementById('vault-close').addEventListener('click', closeVaultOverlay);

document.getElementById('vault-overlay').addEventListener('click', (e) => {
  if (e.target === document.getElementById('vault-overlay')) closeVaultOverlay();
});

document.getElementById('vault-cred-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); handleVaultApprove(); }
});
