/**
 * Team Collaboration & Investigation-Aware Chat Module
 */
let appInstance = null;

let state = {
  currentUser: {
    username: 'sirojiddin',
    display_name: 'Сироҷиддин',
    role: 'Owner',
    department: 'SOC',
  },
  activeChannelId: null,
  channels: [],
  messages: [],
  presences: [],
  teams: [],
};

async function rpcCall(method, params = {}) {
  try {
    const token = (params && params.token) || (typeof localStorage !== 'undefined' ? localStorage.getItem('soc_session_token') : null);
    const finalParams = token ? { ...params, token } : { ...params };
    const res = await fetch('http://127.0.0.1:8080/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_version: 1, request_id: 'collab-' + Date.now(), method, params: finalParams }),
    });
    const data = await res.json();
    if (data.error) {
      if (data.error.status === 401 || data.error.code === 401) showLoginModal('Сессия недействительна. Пожалуйста, авторизуйтесь.');
      return null;
    }
    return data.result;
  } catch (err) {
    console.warn('[Collab] RPC error:', err);
    return null;
  }
}

export function showLoginModal(errorMsg = null) {
  const modal = document.getElementById('loginModal');
  const errEl = document.getElementById('loginErrorMsg');
  if (modal) modal.style.display = 'flex';
  if (errEl) {
    errEl.textContent = errorMsg || '';
    errEl.style.display = errorMsg ? 'block' : 'none';
  }
}

export function hideLoginModal() {
  const modal = document.getElementById('loginModal');
  const errEl = document.getElementById('loginErrorMsg');
  if (modal) modal.style.display = 'none';
  if (errEl) errEl.style.display = 'none';
}

export async function loadCollabData() {
  const channels = await rpcCall('chat.channels', {});
  if (channels && channels.length > 0) {
    state.channels = channels;
    state.activeChannelId = channels[channels.length - 1].id;
    await refreshMessages();
  }
  await refreshPresences();
  await refreshTeams();
  await refreshInvites();
}

export async function initCollaboration(app, ipc) {
  appInstance = app;
  bindUiEvents();

  let token = typeof localStorage !== 'undefined' ? localStorage.getItem('soc_session_token') : null;
  if (!token) {
    const auto = await rpcCall('auth.login', { username: 'sirojiddin', password: 'admin' });
    if (auto?.session) {
      token = auto.session.token;
      localStorage.setItem('soc_session_token', token);
      state.currentUser = auto.user;
    }
  }

  if (token) {
    const sessionRes = await rpcCall('auth.session', {});
    if (sessionRes?.valid && sessionRes.user) {
      state.currentUser = sessionRes.user;
      updateUserBadge();
      hideLoginModal();
      await loadCollabData();
    } else {
      showLoginModal();
    }
  } else {
    showLoginModal();
  }

  // Poll presence & messages periodically
  setInterval(async () => {
    const pane = document.getElementById('collabPane');
    if (pane && pane.style.display !== 'none' && localStorage.getItem('soc_session_token')) {
      await refreshMessages();
      await refreshPresences();
    }
  }, 4000);
}

function updateUserBadge() {
  const btn = document.getElementById('btnUserProfile');
  if (btn) {
    btn.innerHTML = `<span style="border-radius: 50%; width: 16px; height: 16px; background: var(--accent-primary); color: #fff; display: inline-flex; align-items: center; justify-content: center; font-size: 9px; font-weight: bold;">${state.currentUser.display_name.charAt(0)}</span> ${state.currentUser.display_name} <span class="badge badge-host" style="font-size: 9px;">${state.currentUser.role}</span>`;
  }
  const modalHeader = document.getElementById('profileDisplayNameHeader');
  if (modalHeader) {
    modalHeader.textContent = state.currentUser.display_name;
  }
}

async function refreshMessages() {
  if (!state.activeChannelId) return;
  const msgs = await rpcCall('chat.history', { channel_id: state.activeChannelId, limit: 50 });
  if (msgs) {
    state.messages = msgs;
    renderMessages();
  }
}

async function refreshPresences() {
  const presences = await rpcCall('presence.list', {});
  if (presences) {
    state.presences = presences;
    renderPresences();
  }
}

async function refreshTeams() {
  const teams = await rpcCall('team.list', {});
  if (teams) {
    state.teams = teams;
    renderTeams();
  }
}

function renderMessages() {
  const list = document.getElementById('collabMessagesList');
  if (!list) return;

  if (state.messages.length === 0) {
    list.innerHTML = `<div style="color: var(--text-muted); font-size: 11px; text-align: center; margin-top: 30px;">Сообщений пока нет. Начните обсуждение расследования!</div>`;
    return;
  }

  let html = '';
  for (const m of state.messages) {
    const timeStr = m.created_at ? new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
    const roleBadgeClass = m.author_role === 'Owner' || m.author_role === 'Lead' ? 'badge-attack' : 'badge-net';

    // Parse Mentions
    let formattedBody = m.body.replace(/@([a-zA-Z0-9_\u0400-\u04FF]+)/g, '<strong style="color: var(--accent-primary); background: rgba(56,139,253,0.15); padding: 1px 4px; border-radius: 3px;">@$1</strong>');

    // Investigation Entity Reference Pills
    let pillsHtml = '';
    if (m.references && m.references.length > 0) {
      const typeIcons = { Finding: '🔍', Process: '⚙️', Mitre: '🛡️', Cve: '⚠️' };
      const typeBadges = { Finding: 'badge-attack', Process: 'badge-proc', Mitre: 'badge-host', Cve: 'badge-critical' };
      pillsHtml = `<div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px;">` +
        m.references.map(ref => `<span class="badge ${typeBadges[ref.ref_type] || 'badge-net'}" style="cursor: pointer;" data-ref-type="${ref.ref_type.toLowerCase()}" data-ref-id="${ref.ref_id}">${typeIcons[ref.ref_type] || '📌'} ${ref.title || ref.ref_id}</span>`).join('') +
        `</div>`;
    }

    html += `
      <div style="background: var(--bg-canvas); border: 1px solid var(--border-muted); border-radius: 6px; padding: 8px 10px; font-size: 11px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <div style="display: flex; align-items: center; gap: 6px;">
            <strong style="color: var(--text-primary);">${m.author_name}</strong>
            <span class="badge ${roleBadgeClass}" style="font-size: 9px; padding: 1px 4px;">${m.author_role}</span>
          </div>
          <span style="color: var(--text-muted); font-size: 10px;">${timeStr}</span>
        </div>
        <div style="color: var(--text-secondary); line-height: 1.4; word-break: break-word;">${formattedBody}</div>
        ${pillsHtml}
      </div>
    `;
  }

  list.innerHTML = html;
  list.scrollTop = list.scrollHeight;

  // Bind clickable entity pills
  list.querySelectorAll('[data-ref-type]').forEach(el => {
    el.addEventListener('click', () => {
      const type = el.getAttribute('data-ref-type');
      const id = el.getAttribute('data-ref-id');
      handleEntityPillClick(type, id);
    });
  });
}

async function handleEntityPillClick(type, id) {
  if (!appInstance) return;
  const res = await rpcCall('entity.get', { type, id });
  if (res && res.found) {
    appInstance.inspectEntity({
      name: res.name || `${type.toUpperCase()} #${id}`,
      type: res.type || type,
      assertion: res.assertion || `Верифицированная запись из БД (${res.source})`,
      verification: `Статус: ${res.verification || 'Подтверждено в БД'}`,
      details: res.details || JSON.stringify(res.raw_data || {}, null, 2)
    });
  } else {
    appInstance.inspectEntity({
      name: `Сущность #${id} (${type})`,
      type: `Неподтвержденная сущность`,
      assertion: `Эпистемический статус: Факт/Улика не найдены в SQLite БД`,
      verification: `Статус: Не подтверждено (Отсутствует в CAS/Facts)`,
      details: `Запрос entity.get({ type: "${type}", id: "${id}" }) вернул отрицательный результат.\nСущность не зафиксирована в базе доказательств текущей сессии расследования.`
    });
  }
}

function renderPresences() {
  const list = document.getElementById('presenceMembersList');
  const countBadge = document.getElementById('onlineCountBadge');
  if (!list) return;

  const onlineCount = state.presences.filter(p => p.is_online).length;
  if (countBadge) countBadge.textContent = onlineCount;

  let html = '';
  for (const p of state.presences) {
    const dotColor = p.is_online ? 'var(--accent-success)' : 'var(--text-muted)';
    const statusText = p.status_text || (p.is_online ? 'В сети' : 'Не в сети');
    html += `
      <div style="display: flex; align-items: center; justify-content: space-between; background: var(--bg-canvas); border: 1px solid var(--border-muted); border-radius: 6px; padding: 6px 10px; font-size: 11px;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="color: ${dotColor}; font-size: 10px;">●</span>
          <div>
            <div style="font-weight: 700; color: var(--text-primary);">${p.display_name} <span style="font-weight: 400; color: var(--text-muted); font-size: 10px;">@${p.username}</span></div>
            <div style="font-size: 10px; color: var(--text-secondary);">${statusText}</div>
          </div>
        </div>
        <span class="badge ${p.is_online ? 'badge-proc' : 'badge-host'}" style="font-size: 9px;">${p.is_online ? 'ONLINE' : 'OFFLINE'}</span>
      </div>
    `;
  }
  list.innerHTML = html;
}

function renderTeams() {
  const list = document.getElementById('workspaceTeamsList');
  if (!list) return;

  let html = '';
  for (const t of state.teams) {
    html += `
      <div style="background: var(--bg-canvas); border: 1px solid var(--border-muted); border-radius: 6px; padding: 6px 10px; font-size: 11px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="color: var(--accent-primary);">${t.name}</strong>
          <span class="badge badge-net" style="font-size: 9px;">${t.member_count} уч.</span>
        </div>
        <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">${t.description}</div>
      </div>
    `;
  }
  list.innerHTML = html;
}

async function refreshInvites() {
  const c = document.getElementById('invitationsList');
  if (!c) return;
  const list = await rpcCall('invite.list', {});
  if (!list || list.length === 0) {
    c.innerHTML = `<div style="color: var(--text-muted); font-size: 10px; padding: 2px 0;">Нет активных приглашений</div>`;
    return;
  }
  c.innerHTML = list.map(inv => `
    <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-canvas); border: 1px solid var(--border-muted); border-radius: 4px; padding: 3px 6px; font-size: 10px;">
      <div>
        <strong style="color: var(--accent-primary); font-family: monospace;">${inv.code}</strong>
        <span class="badge badge-host" style="font-size: 8px;">${inv.role}</span>
        <div style="color: var(--text-muted); font-size: 9px;">Исп: ${inv.used_count}/${inv.max_uses} • ${inv.status}</div>
      </div>
      ${inv.status === 'Pending' ? `<button class="btn" style="padding: 1px 4px; font-size: 9px; border-color: var(--accent-critical); color: var(--accent-critical);" data-revoke-id="${inv.id}">Отозвать</button>` : ''}
    </div>
  `).join('');
  c.querySelectorAll('[data-revoke-id]').forEach(btn => {
    btn.addEventListener('click', async () => {
      await rpcCall('invite.revoke', { invite_id: btn.getAttribute('data-revoke-id') });
      await refreshInvites();
    });
  });
}

async function sendMessage() {
  const input = document.getElementById('collabChatInput');
  if (!input) return;
  const text = input.value.trim();
  if (!text) return;

  const res = await rpcCall('chat.send', {
    channel_id: state.activeChannelId,
    author_name: state.currentUser.display_name,
    author_role: state.currentUser.role,
    body: text,
  });

  if (res) {
    input.value = '';
    await refreshMessages();
  }
}

function bindUiEvents() {
  const btnToggle = document.getElementById('btnToggleTeamChat');
  const collabPane = document.getElementById('collabPane');
  const btnClose = document.getElementById('btnCloseCollab');
  const inspectorPane = document.getElementById('inspectorPane');

  if (btnToggle && collabPane) {
    btnToggle.addEventListener('click', () => {
      const isVisible = collabPane.style.display === 'flex';
      collabPane.style.display = isVisible ? 'none' : 'flex';
      if (!isVisible && inspectorPane) inspectorPane.style.display = 'none';
      if (!isVisible) refreshMessages();
    });
  }

  if (btnClose && collabPane) {
    btnClose.addEventListener('click', () => {
      collabPane.style.display = 'none';
    });
  }

  // Tabs switching
  const tabChat = document.getElementById('tabCaseChat');
  const tabPresence = document.getElementById('tabPresence');
  const chatView = document.getElementById('collabChatView');
  const presenceView = document.getElementById('collabPresenceView');

  if (tabChat && tabPresence && chatView && presenceView) {
    tabChat.addEventListener('click', () => {
      tabChat.className = 'btn btn-primary';
      tabPresence.className = 'btn';
      chatView.style.display = 'flex';
      presenceView.style.display = 'none';
    });

    tabPresence.addEventListener('click', () => {
      tabPresence.className = 'btn btn-primary';
      tabChat.className = 'btn';
      chatView.style.display = 'none';
      presenceView.style.display = 'flex';
      refreshPresences();
      refreshTeams();
    });
  }

  // Send message
  const btnSend = document.getElementById('btnCollabSend');
  const input = document.getElementById('collabChatInput');
  if (btnSend) btnSend.addEventListener('click', sendMessage);
  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });
  }

  // Quick entity insert helpers
  const btnFinding = document.getElementById('btnInsertFinding');
  const btnProcess = document.getElementById('btnInsertProcess');
  const btnMitre = document.getElementById('btnInsertMitre');

  if (btnFinding && input) {
    btnFinding.addEventListener('click', () => {
      input.value += (input.value ? ' ' : '') + '#finding-CORR-WIN-001e ';
      input.focus();
    });
  }
  if (btnProcess && input) {
    btnProcess.addEventListener('click', () => {
      input.value += (input.value ? ' ' : '') + '#process-4872 ';
      input.focus();
    });
  }
  if (btnMitre && input) {
    btnMitre.addEventListener('click', () => {
      input.value += (input.value ? ' ' : '') + '#T1059.001 ';
      input.focus();
    });
  }

  // User Profile Modal
  const btnProfile = document.getElementById('btnUserProfile');
  const profileModal = document.getElementById('userProfileModal');
  const btnCloseModal = document.getElementById('btnCloseProfileModal');
  const btnCancelModal = document.getElementById('btnCancelProfile');
  const btnSaveModal = document.getElementById('btnSaveProfile');

  if (btnProfile && profileModal) {
    btnProfile.addEventListener('click', () => {
      profileModal.style.display = 'flex';
    });
  }
  if (btnCloseModal && profileModal) {
    btnCloseModal.addEventListener('click', () => profileModal.style.display = 'none');
  }
  if (btnCancelModal && profileModal) {
    btnCancelModal.addEventListener('click', () => profileModal.style.display = 'none');
  }
  if (btnSaveModal && profileModal) {
    btnSaveModal.addEventListener('click', async () => {
      const name = document.getElementById('profileInputName')?.value || 'Сироҷиддин';
      const email = document.getElementById('profileInputEmail')?.value || 'sirojiddin@soc.local';
      const dept = document.getElementById('profileInputDept')?.value || 'SOC';
      const tz = document.getElementById('profileInputTz')?.value || 'Asia/Tashkent';

      await rpcCall('auth.update_profile', {
        user_id: state.currentUser.id,
        display_name: name,
        email,
        department: dept,
        timezone: tz,
        language: 'ru',
      });

      state.currentUser.display_name = name;
      state.currentUser.email = email;
      state.currentUser.department = dept;
      state.currentUser.timezone = tz;
      updateUserBadge();
      profileModal.style.display = 'none';
    });
  }

  // Logout action
  const btnLogout = document.getElementById('btnLogoutProfile');
  if (btnLogout && profileModal) {
    btnLogout.addEventListener('click', async () => {
      const token = typeof localStorage !== 'undefined' ? localStorage.getItem('soc_session_token') : null;
      if (token) {
        await rpcCall('auth.logout', { token });
      }
      localStorage.removeItem('soc_session_token');
      state.messages = [];
      state.channels = [];
      renderMessages();
      profileModal.style.display = 'none';
      showLoginModal();
    });
  }

  // Login form submission
  const btnSubmitLogin = document.getElementById('btnSubmitLogin');
  const loginUsername = document.getElementById('loginInputUsername');
  const loginPassword = document.getElementById('loginInputPassword');
  if (btnSubmitLogin) {
    const doLogin = async () => {
      const username = loginUsername?.value.trim() || '';
      const password = loginPassword?.value || '';
      if (!username || !password) {
        showLoginModal('Заполните имя пользователя и пароль');
        return;
      }
      const res = await rpcCall('auth.login', { username, password });
      if (res?.session) {
        localStorage.setItem('soc_session_token', res.session.token);
        state.currentUser = res.user;
        updateUserBadge();
        hideLoginModal();
        await loadCollabData();
      } else {
        showLoginModal('Неверный логин или пароль');
      }
    };
    btnSubmitLogin.addEventListener('click', doLogin);
    loginPassword?.addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });
  }

  document.getElementById('btnCreateInvite')?.addEventListener('click', async () => {
    const role = prompt('Роль (Analyst, Responder, Viewer, Lead):', 'Analyst') || 'Analyst';
    const res = await rpcCall('invite.create', { role, expires_hours: 24, max_uses: 1 });
    if (res?.code) { alert(`Код создан: ${res.code}\nРоль: ${role}`); await refreshInvites(); }
  });
  document.getElementById('btnJoinCode')?.addEventListener('click', async () => {
    const code = prompt('Введите код приглашения (например, 7K4P-X2MN):');
    if (!code) return;
    const res = await rpcCall('invite.accept', { code: code.trim() });
    if (res?.success) { alert(`Успешно! Роль: ${res.workspace_member?.role || 'Analyst'}`); await loadCollabData(); }
    else { alert('Не удалось принять приглашение.'); }
  });
}
