document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('loginForm');
  const usernameInput = document.getElementById('usernameInput');
  const passwordInput = document.getElementById('passwordInput');
  const togglePasswordBtn = document.getElementById('togglePasswordBtn');
  const eyeOpen = document.getElementById('eyeOpen');
  const eyeClosed = document.getElementById('eyeClosed');
  const loginSubmitBtn = document.getElementById('loginSubmitBtn');
  const loginBtnText = document.getElementById('loginBtnText');
  const loginSpinner = document.getElementById('loginSpinner');
  const loginAlert = document.getElementById('loginAlert');
  const csrfTokenInput = document.getElementById('csrfToken');

  const biometricPromptContainer = document.getElementById('biometricPromptContainer');
  const biometricLoginBtn = document.getElementById('biometricLoginBtn');
  const biometricBtnText = document.getElementById('biometricBtnText');

  let currentCsrfToken = '';

  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const themeColorMeta = document.getElementById('themeColorMeta');

  function applyTheme(isDark) {
    if (isDark) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('door_theme', 'dark');
      if (themeColorMeta) themeColorMeta.setAttribute('content', '#101828');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('door_theme', 'light');
      if (themeColorMeta) themeColorMeta.setAttribute('content', '#f9fafb');
    }
  }

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const isDark = document.documentElement.classList.contains('dark');
      applyTheme(!isDark);
    });
  }

  // 1. Získání CSRF tokenu
  async function initCsrf() {
    try {
      const res = await fetch('/api/csrf-token');
      if (res.ok) {
        const data = await res.json();
        currentCsrfToken = data.csrf_token || '';
        if (csrfTokenInput) {
          csrfTokenInput.value = currentCsrfToken;
        }
      }
    } catch (_) {}
  }

  // 2. Přepínač zobrazení hesla
  if (togglePasswordBtn) {
    togglePasswordBtn.addEventListener('click', () => {
      const isPassword = passwordInput.getAttribute('type') === 'password';
      if (isPassword) {
        passwordInput.setAttribute('type', 'text');
        eyeOpen.classList.add('hidden');
        eyeClosed.classList.remove('hidden');
      } else {
        passwordInput.setAttribute('type', 'password');
        eyeOpen.classList.remove('hidden');
        eyeClosed.classList.add('hidden');
      }
    });
  }

  function showAlert(msg, type = 'error') {
    loginAlert.classList.remove('hidden', 'border-emerald-200', 'bg-emerald-50', 'text-emerald-800', 'border-rose-200', 'bg-rose-50', 'text-rose-800', 'dark:border-rose-900', 'dark:bg-rose-950/30', 'dark:text-rose-300');
    if (type === 'error') {
      loginAlert.classList.add('border-rose-200', 'bg-rose-50', 'text-rose-800', 'dark:border-rose-900', 'dark:bg-rose-950/30', 'dark:text-rose-300');
    } else {
      loginAlert.classList.add('border-emerald-200', 'bg-emerald-50', 'text-emerald-800', 'dark:border-emerald-900', 'dark:bg-emerald-950/30', 'dark:text-emerald-300');
    }
    loginAlert.textContent = msg;
  }

  // 3. Přihlášení formulářem
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginAlert.classList.add('hidden');

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
      showAlert('Zadejte uživatelské jméno i heslo.');
      return;
    }

    loginSubmitBtn.disabled = true;
    loginBtnText.classList.add('hidden');
    loginSpinner.classList.remove('hidden');

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRF-Token': currentCsrfToken
        },
        body: JSON.stringify({
          username,
          password,
          csrf_token: currentCsrfToken
        })
      });

      const data = await res.json().catch(() => null);

      if (res.ok && data && data.success) {
        localStorage.setItem('door_last_username', username);
        window.location.href = '/';
      } else {
        const errorMsg = (data && data.message) ? data.message : 'Neplatné přihlašovací údaje.';
        showAlert(errorMsg);
        await initCsrf();
        loginSubmitBtn.disabled = false;
        loginBtnText.classList.remove('hidden');
        loginSpinner.classList.add('hidden');
        passwordInput.value = '';
        passwordInput.focus();
      }
    } catch (_) {
      showAlert('Chyba spojení se serverem.');
      loginSubmitBtn.disabled = false;
      loginBtnText.classList.remove('hidden');
      loginSpinner.classList.add('hidden');
    }
  });

  // 4. Biometrické přihlášení (WebAuthn)
  function base64urlToBuffer(base64url) {
    const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
    const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray.buffer;
  }

  function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function checkBiometricsAvailable() {
    if (window.PublicKeyCredential && biometricPromptContainer) {
      try {
        // Zkontrolovat, zda zařízení podporuje platformní autentizátor (otisk prstu / Face ID)
        const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        if (available) {
          biometricPromptContainer.classList.remove('hidden');
          // Na mobilu automaticky spustit biometrii pouze pokud už byla úspěšně použita
          const isBiometricsConfigured = localStorage.getItem('door_biometrics_enabled') === 'true';
          const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
          if (isMobile && isBiometricsConfigured) {
            setTimeout(() => triggerBiometricLogin(), 350);
          }
        }
      } catch (_) {
        // Fallback: zobrazit tlačítko pokud WebAuthn existuje
        biometricPromptContainer.classList.remove('hidden');
      }
    }
  }

  async function triggerBiometricLogin() {
    loginAlert.classList.add('hidden');
    if (biometricLoginBtn) biometricLoginBtn.disabled = true;
    if (biometricBtnText) biometricBtnText.textContent = 'Ověřuji otisk...';

    try {
      const savedUser = localStorage.getItem('door_biometrics_username') || localStorage.getItem('door_last_username') || '';

      const optRes = await fetch('/api/webauthn/login/options', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRF-Token': currentCsrfToken
        },
        body: JSON.stringify({ username: savedUser, csrf_token: currentCsrfToken })
      });

      if (!optRes.ok) throw new Error('Nelze inicializovat biometrické přihlášení.');

      const options = await optRes.json();
      options.challenge = base64urlToBuffer(options.challenge);
      if (options.allowCredentials && options.allowCredentials.length > 0) {
        options.allowCredentials = options.allowCredentials.map(cred => ({
          ...cred,
          id: base64urlToBuffer(cred.id)
        }));
      }

      const assertion = await navigator.credentials.get({ publicKey: options });
      if (!assertion) throw new Error('Ověření zrušeno.');

      const authData = {
        id: assertion.id,
        rawId: bufferToBase64url(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
          authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
          signature: bufferToBase64url(assertion.response.signature),
          userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null
        },
        csrf_token: currentCsrfToken
      };

      const verifyRes = await fetch('/api/webauthn/login/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRF-Token': currentCsrfToken
        },
        body: JSON.stringify(authData)
      });

      const verData = await verifyRes.json();
      if (verifyRes.ok && verData && verData.success) {
        window.location.href = '/';
      } else {
        throw new Error(verData.message || 'Ověření otisku selhalo.');
      }
    } catch (err) {
      if (err.name !== 'NotAllowedError') {
        showAlert('Biometrické ověření: ' + (err.message || err));
      }
    } finally {
      if (biometricLoginBtn) biometricLoginBtn.disabled = false;
      if (biometricBtnText) biometricBtnText.textContent = 'Přihlásit se otiskem prstu';
    }
  }

  if (biometricLoginBtn) {
    biometricLoginBtn.addEventListener('click', triggerBiometricLogin);
  }

  // Předvyplnění posledního uživatele
  const lastUser = localStorage.getItem('door_last_username');
  if (lastUser && usernameInput && !usernameInput.value) {
    usernameInput.value = lastUser;
  }

  // Kontrola, zda byl uživatel přesměrován kvůli deaktivovanému účtu
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('disabled') === '1') {
    showAlert('Váš účet byl deaktivován. Obraťte se na správce systému.');
  }

  initCsrf();
  checkBiometricsAvailable();
});
