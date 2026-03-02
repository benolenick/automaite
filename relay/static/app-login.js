// Bridge page JS — runs in system browser, handles Google Sign-In,
// then hands off a one-time token to the app via deep link.

const statusEl = document.getElementById('status');
const errorEl = document.getElementById('error');

async function handleCredentialResponse(response) {
  statusEl.textContent = 'Signing in...';
  errorEl.textContent = '';

  try {
    // 1. Login with Google credential
    const loginRes = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ credential: response.credential, nonce: null }),
    });

    if (!loginRes.ok) {
      const data = await loginRes.json().catch(() => ({}));
      errorEl.textContent = data.detail || 'Login failed';
      statusEl.textContent = '';
      return;
    }

    statusEl.textContent = 'Transferring session to app...';

    // 2. Get one-time app token (authenticated via cookie set above)
    const tokenRes = await fetch('/api/app/token', {
      method: 'POST',
      credentials: 'same-origin',
    });

    if (!tokenRes.ok) {
      errorEl.textContent = 'Failed to create app token';
      statusEl.textContent = '';
      return;
    }

    const { token } = await tokenRes.json();

    // 3. Redirect to app via deep link
    statusEl.textContent = 'Opening app...';
    window.location.href = 'automaite://auth?token=' + token;

    // Fallback message if deep link doesn't fire
    setTimeout(() => {
      statusEl.textContent = 'If the app did not open, go back to the app manually.';
    }, 3000);

  } catch (err) {
    errorEl.textContent = 'Error: ' + err.message;
    statusEl.textContent = '';
  }
}

// Init Google Identity Services
async function init() {
  try {
    const configRes = await fetch('/api/config');
    const config = await configRes.json();

    function tryInit() {
      if (typeof google !== 'undefined' && google.accounts) {
        google.accounts.id.initialize({
          client_id: config.google_client_id,
          callback: handleCredentialResponse,
        });
        google.accounts.id.renderButton(
          document.getElementById('g-signin'),
          { theme: 'filled_black', size: 'large', width: 300, text: 'signin_with' }
        );
      } else {
        setTimeout(tryInit, 100);
      }
    }
    tryInit();
  } catch (err) {
    errorEl.textContent = 'Failed to load sign-in: ' + err.message;
  }
}

init();
