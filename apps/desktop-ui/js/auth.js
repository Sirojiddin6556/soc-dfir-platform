/**
 * First-run setup and login dialog.
 *
 * The engine refuses every RPC call except health/auth.status/auth.setup/
 * auth.login without a valid session token, so the app must authenticate
 * before it loads any data.
 */

const TOKEN_KEY = 'soc_session_token';

export function getSessionToken() {
  try { return localStorage.getItem(TOKEN_KEY); } catch (_) { return null; }
}

export function setSessionToken(token) {
  try { localStorage.setItem(TOKEN_KEY, token); } catch (_) { /* storage unavailable */ }
}

export function clearSessionToken() {
  try { localStorage.removeItem(TOKEN_KEY); } catch (_) { /* storage unavailable */ }
}

/**
 * Resolves with the logged-in user once a valid session exists, showing the
 * setup or login form when needed.
 */
export async function ensureSession(ipc) {
  if (getSessionToken()) {
    try {
      const res = await ipc.call('auth.session', {});
      if (res && res.user) return res.user;
    } catch (err) {
      if (err.transport) throw err;
      clearSessionToken();
    }
  }
  const status = await ipc.call('auth.status', {});
  return showAuthDialog(ipc, status && status.setup_required ? 'setup' : 'login', status);
}

function showAuthDialog(ipc, mode, status) {
  const overlay = document.getElementById('authOverlay');
  const form = document.getElementById('authForm');
  const title = document.getElementById('authTitle');
  const hint = document.getElementById('authHint');
  const userRow = document.getElementById('authUserRow');
  const username = document.getElementById('authUsername');
  const password = document.getElementById('authPassword');
  const confirmRow = document.getElementById('authConfirmRow');
  const confirm = document.getElementById('authConfirm');
  const error = document.getElementById('authError');
  const submit = document.getElementById('authSubmit');
  const minLen = (status && status.min_password_length) || 8;

  if (mode === 'setup') {
    title.textContent = 'Первичная настройка';
    hint.textContent = `Задайте пароль владельца рабочей станции (не короче ${minLen} символов). Без него вход невозможен.`;
    userRow.hidden = true;
    confirmRow.hidden = false;
    password.autocomplete = 'new-password';
    submit.textContent = 'Сохранить и войти';
  } else {
    title.textContent = 'Вход';
    hint.textContent = 'Войдите, чтобы продолжить работу с кейсами.';
    userRow.hidden = false;
    confirmRow.hidden = true;
    password.autocomplete = 'current-password';
    submit.textContent = 'Войти';
  }
  error.textContent = '';
  overlay.hidden = false;
  (mode === 'setup' ? password : (username.value ? password : username)).focus();

  return new Promise((resolve) => {
    const onSubmit = async (e) => {
      e.preventDefault();
      error.textContent = '';
      if (mode === 'setup') {
        if (password.value.length < minLen) {
          error.textContent = `Пароль должен содержать не менее ${minLen} символов`;
          return;
        }
        if (password.value !== confirm.value) {
          error.textContent = 'Пароли не совпадают';
          return;
        }
      } else if (!username.value.trim() || !password.value) {
        error.textContent = 'Введите имя пользователя и пароль';
        return;
      }

      submit.disabled = true;
      try {
        const res = mode === 'setup'
          ? await ipc.call('auth.setup', { password: password.value })
          : await ipc.call('auth.login', { username: username.value.trim(), password: password.value });
        setSessionToken(res.session.token);
        password.value = '';
        confirm.value = '';
        overlay.hidden = true;
        form.removeEventListener('submit', onSubmit);
        resolve(res.user);
      } catch (err) {
        error.textContent = err.message || 'Ошибка входа';
        password.select();
      } finally {
        submit.disabled = false;
      }
    };
    form.addEventListener('submit', onSubmit);
  });
}

export async function logout(ipc) {
  try { await ipc.call('auth.logout', {}); } catch (_) { /* session may already be gone */ }
  clearSessionToken();
  window.location.reload();
}
