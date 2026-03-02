var params = new URLSearchParams(location.search);
var codeFromUrl = params.get('code');

function showApprovalUI() {
  document.getElementById('login-needed').style.display = 'none';
  if (codeFromUrl) {
    document.getElementById('code-display').style.display = 'block';
    document.getElementById('user-code').textContent = codeFromUrl;
  } else {
    document.getElementById('manual-entry').style.display = 'block';
  }
}

async function init() {
  try {
    var res = await fetch('/api/me', { credentials: 'same-origin' });
    if (!res.ok) throw new Error('not logged in');
    document.getElementById('loading').style.display = 'none';
    showApprovalUI();
  } catch (e) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('login-needed').style.display = 'block';
    loadGoogleSignIn();
  }
}

function loadGoogleSignIn() {
  var script = document.createElement('script');
  script.src = 'https://accounts.google.com/gsi/client';
  script.async = true;
  script.defer = true;
  script.onload = function() { initGoogleSignIn(); };
  document.head.appendChild(script);
}

async function initGoogleSignIn() {
  try {
    var results = await Promise.all([
      fetch('/api/config'),
      fetch('/api/nonce'),
    ]);
    var config = await results[0].json();
    var nonceData = await results[1].json();
    var nonce = nonceData.nonce;

    function tryInit() {
      if (typeof google !== 'undefined' && google.accounts) {
        google.accounts.id.initialize({
          client_id: config.google_client_id,
          nonce: nonce,
          callback: function(response) { handleGoogleLogin(response, nonce); },
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
  } catch (e) {
    document.getElementById('login-needed').innerHTML =
      '<div class="status error">Failed to load Google Sign-In. Try refreshing.</div>';
  }
}

async function handleGoogleLogin(response, nonce) {
  try {
    var res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ credential: response.credential, nonce: nonce }),
    });
    if (!res.ok) {
      var data = await res.json().catch(function() { return {}; });
      document.getElementById('login-needed').innerHTML =
        '<div class="status error">' + (data.detail || 'Login failed') + '</div>';
      return;
    }
    document.getElementById('login-needed').style.display = 'none';
    showApprovalUI();
  } catch (e) {
    document.getElementById('login-needed').innerHTML =
      '<div class="status error">Connection error. Try refreshing.</div>';
  }
}

async function approve() {
  var btn = document.getElementById('approve-btn');
  var status = document.getElementById('status');
  btn.disabled = true;
  btn.textContent = 'Connecting...';

  try {
    var res = await fetch('/api/agent/approve', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_code: codeFromUrl }),
    });
    if (!res.ok) {
      var err = await res.json().catch(function() { return {}; });
      throw new Error(err.detail || 'Failed to approve');
    }
    status.className = 'status success';
    status.textContent = 'Desktop connected! You can close this page.';
    btn.textContent = 'Connected';
  } catch (e) {
    status.className = 'status error';
    status.textContent = e.message;
    btn.disabled = false;
    btn.textContent = 'Connect This Computer';
  }
}

async function approveManual() {
  var code = document.getElementById('manual-code').value.trim();
  if (!code) return;
  var status = document.getElementById('manual-status');

  try {
    var res = await fetch('/api/agent/approve', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_code: code }),
    });
    if (!res.ok) {
      var err = await res.json().catch(function() { return {}; });
      throw new Error(err.detail || 'Invalid code');
    }
    status.className = 'status success';
    status.textContent = 'Desktop connected! You can close this page.';
  } catch (e) {
    status.className = 'status error';
    status.textContent = e.message;
  }
}

document.getElementById('approve-btn').addEventListener('click', approve);
document.getElementById('manual-approve-btn').addEventListener('click', approveManual);
document.getElementById('manual-code').addEventListener('input', function() {
  this.value = this.value.toUpperCase();
});

init();
