/**
 * 2N Access Unit M - Frontend Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  let currentUsername = '';
  let currentUserRole = '';
  let currentUserBypass = false;
  let isNetworkAllowed = false;
  let serverNetworkAllowed = false;
  let isProbeVerified = false;
  let isProbing = false;
  let isSending = false;
  let webUnlockBlocked = false;
  let csrfToken = '';
  let deviceIp = '';
  let devicePort = 443;
  let deviceProtocol = 'https';
  let vapidPublicKey = '';

  // UI elementy
  const sidebar = document.getElementById('sidebar');
  const sidebarBackdrop = document.getElementById('sidebarBackdrop');
  const openSidebarBtn = document.getElementById('openSidebarBtn');
  const closeSidebarBtn = document.getElementById('closeSidebarBtn');

  const navTabBtns = document.querySelectorAll('.nav-tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');
  let unitsStatusRefreshInterval = null;
  let ntpStatusRefreshInterval = null;
  const pageHeaderTitle = document.getElementById('pageHeaderTitle');

  const navHomeBtn = document.getElementById('navHomeBtn');
  const navLogsBtn = document.getElementById('navLogsBtn');
  const navInfoBtn = document.getElementById('navInfoBtn');
  const navUsersBtn = document.getElementById('navUsersBtn');
  const navKeysBtn = document.getElementById('navKeysBtn');
  const navUnitsBtn = document.getElementById('navUnitsBtn');
  const navPermanentBtn = document.getElementById('navPermanentBtn');
  const navScheduleBtn = document.getElementById('navScheduleBtn');
  const navGlobalSettingsBtn = document.getElementById('navGlobalSettingsBtn');
  const securityKeysList = document.getElementById('securityKeysList');
  const keyRegistrationModal = document.getElementById('securityKeyRegistrationModal');
  const openKeyRegistrationBtn = document.getElementById('openKeyRegistrationBtn');
  const closeKeyRegistrationBtn = document.getElementById('closeKeyRegistrationBtn');
  const beginKeyScanBtn = document.getElementById('beginKeyScanBtn');
  const cancelKeySetupBtn = document.getElementById('cancelKeySetupBtn');
  const keyScanStep = document.getElementById('keyScanStep');
  const keySetupStep = document.getElementById('keySetupStep');
  const keyScanMessage = document.getElementById('keyScanMessage');
  const keyScanCountdown = document.getElementById('keyScanCountdown');
  const keyScanAlert = document.getElementById('keyScanAlert');
  const keySetupAlert = document.getElementById('keySetupAlert');
  const securityKeyName = document.getElementById('securityKeyName');
  const securityKeyAction = document.getElementById('securityKeyAction');
  const securityKeyUnit = document.getElementById('securityKeyUnit');
  const securityKeyActionHelp = document.getElementById('securityKeyActionHelp');
  const saveSecurityKeyBtn = document.getElementById('saveSecurityKeyBtn');
  let keyScanPollTimer = null;
  let keyRegistrationActive = false;
  let keyStatusPolling = false;

  // Profil
  const userDropdownBtn = document.getElementById('userDropdownBtn');
  const userDropdownMenu = document.getElementById('userDropdownMenu');
  const userDropdownArrow = document.getElementById('userDropdownArrow');
  const userAvatarCircle = document.getElementById('userAvatarCircle');
  const headerUsername = document.getElementById('headerUsername');
  const headerUserRole = document.getElementById('headerUserRole');
  const dropdownUsernameFull = document.getElementById('dropdownUsernameFull');
  const logoutBtn = document.getElementById('logoutBtn');

  // Sidebar stav
  const sidebarStatusDot = document.getElementById('sidebarStatusDot');
  const sidebarStatusText = document.getElementById('sidebarStatusText');
  const sidebarAdminIpDisplay = document.getElementById('sidebarAdminIpDisplay');
  const sidebarSubtitle = document.getElementById('sidebarSubtitle');

  // Home prvky
  const doorWrapper = document.getElementById('doorWrapper');
  const doorBtn = document.getElementById('doorBtn');
  const svgLocked = document.getElementById('svgLocked');
  const svgBlockedCross = document.getElementById('svgBlockedCross');
  const svgUnlocked = document.getElementById('svgUnlocked');
  const svgSpinner = document.getElementById('svgSpinner');
  const doorBtnText = document.getElementById('doorBtnText');
  const doorBtnSubtext = document.getElementById('doorBtnSubtext');
  const doorStatusIndicator = document.getElementById('doorStatusIndicator');
  const doorStatusText = document.getElementById('doorStatusText');
  const networkBlockedCard = document.getElementById('networkBlockedCard');
  const retryProbeBtn = document.getElementById('retryProbeBtn');
  const tileClientIp = document.getElementById('tileClientIp');
  const tileNetworkStatus = document.getElementById('tileNetworkStatus');
  const legacyDoorCard = document.getElementById('legacyDoorCard');
  const unitControlsContainer = document.getElementById('unitControlsContainer');
  let userUnits = [];
  let unitTypes = [];
  let unitProbeVerified = new Set();
  let networkProbeQueued = false;

  // Logy
  const refreshLogsBtn = document.getElementById('refreshLogsBtn');
  const clearLogsBtn = document.getElementById('clearLogsBtn');
  const logsTableBody = document.getElementById('logsTableBody');
  const logSourceFilter = document.getElementById('logSourceFilter');

  // Informace
  const infoDeviceIp = document.getElementById('infoDeviceIp');
  const infoProtocolPort = document.getElementById('infoProtocolPort');
  const infoSwitchId = document.getElementById('infoSwitchId');
  const infoApiUser = document.getElementById('infoApiUser');
  const infoAuthType = document.getElementById('infoAuthType');
  const infoApiStatus = document.getElementById('infoApiStatus');
  const infoUnitSelect = document.getElementById('infoUnitSelect');
  const testConnectionBtn = document.getElementById('testConnectionBtn');
  const testConnectionBtnText = document.getElementById('testConnectionBtnText');
  const testConnAlert = document.getElementById('testConnAlert');
  const testConnMsg = document.getElementById('testConnMsg');
  const addUnitForm = document.getElementById('addUnitForm');
  const unitNameInput = document.getElementById('unitNameInput');
  const unitModelInput = document.getElementById('unitModelInput');
  const unitIpInput = document.getElementById('unitIpInput');
  const unitApiUserInput = document.getElementById('unitApiUserInput');
  const unitApiPasswordInput = document.getElementById('unitApiPasswordInput');
  const addUnitAlert = document.getElementById('addUnitAlert');
  const addUnitSubmitBtn = document.getElementById('addUnitSubmitBtn');
  const unitsList = document.getElementById('unitsList');
  const refreshUnitsBtn = document.getElementById('refreshUnitsBtn');
  const ntpSettingsForm = document.getElementById('ntpSettingsForm');
  const ntpServerInput = document.getElementById('ntpServerInput');
  const ntpSettingsAlert = document.getElementById('ntpSettingsAlert');
  const ntpStatus = document.getElementById('ntpStatus');
  const ntpLastSync = document.getElementById('ntpLastSync');
  const saveNtpBtn = document.getElementById('saveNtpBtn');
  const disableNtpBtn = document.getElementById('disableNtpBtn');
  const userUnitPreferences = document.getElementById('userUnitPreferences');
  const userUnitPreferencesAlert = document.getElementById('userUnitPreferencesAlert');
  const saveUserUnitsBtn = document.getElementById('saveUserUnitsBtn');

  // Správa uživatelů
  const openAddUserBtn = document.getElementById('openAddUserBtn');
  const cancelAddUserBtn = document.getElementById('cancelAddUserBtn');
  const addUserCard = document.getElementById('addUserCard');
  const addUserForm = document.getElementById('addUserForm');
  const newUsernameInput = document.getElementById('newUsername');
  const newPasswordInput = document.getElementById('newPassword');
  const newRoleSelect = document.getElementById('newRole');
  const newRoleAdminOption = document.getElementById('newRoleAdminOption');
  const newUserBypass = document.getElementById('newUserBypass');
  const newUserBypassWrapper = document.getElementById('newUserBypassWrapper');
  const addUserAlert = document.getElementById('addUserAlert');
  const usersListContainer = document.getElementById('usersListContainer');

  // Oprávnění uživatelů (Modal)
  const userPermissionsModal = document.getElementById('userPermissionsModal');
  const closePermModalBtn = document.getElementById('closePermModalBtn');
  const cancelPermModalBtn = document.getElementById('cancelPermModalBtn');
  const savePermModalBtn = document.getElementById('savePermModalBtn');
  const userPermissionsForm = document.getElementById('userPermissionsForm');
  const permUserId = document.getElementById('permUserId');
  const permModalUsernameDisplay = document.getElementById('permModalUsernameDisplay');
  const permModalRoleBadge = document.getElementById('permModalRoleBadge');
  const permRoleSelect = document.getElementById('permRoleSelect');
  const permBypassToggle = document.getElementById('permBypassToggle');
  const permCanUnlockToggle = document.getElementById('permCanUnlockToggle');
  const permCanUnlockWarning = document.getElementById('permCanUnlockWarning');
  const permUnitAccessSection = document.getElementById('permUnitAccessSection');
  const permUnitAccessList = document.getElementById('permUnitAccessList');
  const permPermanentToggle = document.getElementById('permPermanentToggle');
  const permPermanentConfigWrapper = document.getElementById('permPermanentConfigWrapper');
  const permPermanentDurationValue = document.getElementById('permPermanentDurationValue');
  const permDurationUnitMinutes = document.getElementById('permDurationUnitMinutes');
  const permDurationUnitHours = document.getElementById('permDurationUnitHours');
  const permDurationCalculatedHint = document.getElementById('permDurationCalculatedHint');
  const permDisabledToggle = document.getElementById('permDisabledToggle');
  const permDeactivatedBadge = document.getElementById('permDeactivatedBadge');

  const permNewPassword = document.getElementById('permNewPassword');
  const permUserNote = document.getElementById('permUserNote');
  const permModalAlert = document.getElementById('permModalAlert');
  const permLockedBanner = document.getElementById('permLockedBanner');
  const permLockedBannerText = document.getElementById('permLockedBannerText');
  const permUnlockAccountBtn = document.getElementById('permUnlockAccountBtn');
  const permModalDeleteBtn = document.getElementById('permModalDeleteBtn');
  const permModalDeleteRow = document.getElementById('permModalDeleteRow');
  // State for duration unit
  let permDurationUnitIsHours = false;

  // Položky bočního menu a správa jiných uživatelů
  const permMenuDefaultBtn = document.getElementById('permMenuDefaultBtn');
  const permMenuSelectAllBtn = document.getElementById('permMenuSelectAllBtn');
  const permMenuHomeOnlyBtn = document.getElementById('permMenuHomeOnlyBtn');
  const permMenu_home = document.getElementById('permMenu_home');
  const permMenu_logs = document.getElementById('permMenu_logs');
  const permMenu_info = document.getElementById('permMenu_info');
  const permMenu_users = document.getElementById('permMenu_users');
  const permMenu_permanent = document.getElementById('permMenu_permanent');
  const permMenu_schedule = document.getElementById('permMenu_schedule');
  const permMenu_keys = document.getElementById('permMenu_keys');
  const permCanManageUsersToggle = document.getElementById('permCanManageUsersToggle');
  const permManagementSubConfigWrapper = document.getElementById('permManagementSubConfigWrapper');
  const permManagementSection = document.getElementById('permManagementSection');
  const permMgmt_role = document.getElementById('permMgmt_role');
  const permMgmt_bypass = document.getElementById('permMgmt_bypass');
  const permMgmt_unlock = document.getElementById('permMgmt_unlock');
  const permMgmt_permanent = document.getElementById('permMgmt_permanent');
  const permMgmt_time = document.getElementById('permMgmt_time');
  const permMgmt_menu = document.getElementById('permMgmt_menu');
  const permMgmt_note = document.getElementById('permMgmt_note');
  const permMgmt_disabled = document.getElementById('permMgmt_disabled');
  const permMgmt_password = document.getElementById('permMgmt_password');
  const permMgmt_delete = document.getElementById('permMgmt_delete');

  // Globální proměnné pro menu a oprávnění
  let currentUserSidebarMenu = ['home'];
  let currentUserCanManageUsers = false;
  let currentUserManagePermissions = {};
  let currentUserId = null;

  // Nastavení
  const openSettingsBtn = document.getElementById('openSettingsBtn');
  const settingsModal = document.getElementById('settingsModal');
  const closeSettingsModalBtn = document.getElementById('closeSettingsModalBtn');
  const closeSettingsBottomBtn = document.getElementById('closeSettingsBottomBtn');

  // Režimy
  const themeToggleQuickBtn = document.getElementById('themeToggleQuickBtn');
  const themeLightBtn = document.getElementById('themeLightBtn');
  const themeDarkBtn = document.getElementById('themeDarkBtn');
  const themeColorMeta = document.getElementById('themeColorMeta');

  // Oznámení a otisk
  const pushNotificationToggle = document.getElementById('pushNotificationToggle');
  const pushNotificationStatusText = document.getElementById('pushNotificationStatusText');
  const testPushBtn = document.getElementById('testPushBtn');
  const biometricAuthToggle = document.getElementById('biometricAuthToggle');
  const biometricStatusText = document.getElementById('biometricStatusText');

  // Heslo
  const toggleChangePasswordCardBtn = document.getElementById('toggleChangePasswordCardBtn');
  const changePasswordForm = document.getElementById('changePasswordForm');
  const currentPasswordInput = document.getElementById('currentPasswordInput');
  const newPassInput = document.getElementById('newPassInput');
  const confirmPassInput = document.getElementById('confirmPassInput');
  const changePasswordAlert = document.getElementById('changePasswordAlert');
  const changePasswordSubmitBtn = document.getElementById('changePasswordSubmitBtn');

  // ==========================================================================
  // UPTIME KUMA STYL OZNÁMENÍ (TOAST NOTIFIKACE S ODPOČTEM)
  // ==========================================================================
  function showToast(message, type = 'success', durationMs = 3500) {
    const container = document.getElementById('kumaToastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `kuma-toast kuma-${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = `<svg class="w-5 h-5 text-white" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>`;
    } else if (type === 'error') {
      iconSvg = `<svg class="w-5 h-5 text-white" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/></svg>`;
    } else {
      iconSvg = `<svg class="w-5 h-5 text-white" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/></svg>`;
    }

    toast.innerHTML = `
      <div class="kuma-toast-body">
        <div class="kuma-toast-icon">${iconSvg}</div>
        <span>${message}</span>
      </div>
      <div class="kuma-toast-progress-track">
        <div class="kuma-toast-progress-bar" style="animation-duration: ${durationMs}ms;"></div>
      </div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-10px)';
      setTimeout(() => toast.remove(), 250);
    }, durationMs);
  }

  // ==========================================================================
  // MOTIV (DARK / LIGHT)
  // ==========================================================================
  function applyTheme(isDark) {
    if (isDark) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('door_theme', 'dark');
      if (themeColorMeta) themeColorMeta.setAttribute('content', '#101828');
      if (themeDarkBtn) {
        themeDarkBtn.className = 'px-2.5 py-1 font-semibold rounded-lg bg-white text-gray-900 shadow-xs dark:bg-gray-800 dark:text-white transition-all';
        themeLightBtn.className = 'px-2.5 py-1 font-semibold rounded-lg text-gray-600 hover:text-gray-900 dark:text-gray-300 transition-all';
      }
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('door_theme', 'light');
      if (themeColorMeta) themeColorMeta.setAttribute('content', '#f9fafb');
      if (themeLightBtn) {
        themeLightBtn.className = 'px-2.5 py-1 font-semibold rounded-lg bg-white text-gray-900 shadow-xs transition-all';
        themeDarkBtn.className = 'px-2.5 py-1 font-semibold rounded-lg text-gray-600 hover:text-gray-900 dark:text-gray-300 transition-all';
      }
    }
  }

  const savedTheme = localStorage.getItem('door_theme');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(savedTheme ? savedTheme === 'dark' : prefersDark);

  if (themeToggleQuickBtn) {
    themeToggleQuickBtn.addEventListener('click', () => {
      const isDark = document.documentElement.classList.contains('dark');
      applyTheme(!isDark);
    });
  }

  if (themeLightBtn) themeLightBtn.addEventListener('click', () => applyTheme(false));
  if (themeDarkBtn) themeDarkBtn.addEventListener('click', () => applyTheme(true));

  // ==========================================================================
  // SIDEBAR MOBILNÍ OVLÁDÁNÍ
  // ==========================================================================
  function openSidebar() {
    sidebar.classList.remove('-translate-x-full');
    sidebarBackdrop.classList.remove('hidden');
  }

  function closeSidebar() {
    sidebar.classList.add('-translate-x-full');
    sidebarBackdrop.classList.add('hidden');
  }

  if (openSidebarBtn) openSidebarBtn.addEventListener('click', openSidebar);
  if (closeSidebarBtn) closeSidebarBtn.addEventListener('click', closeSidebar);
  if (sidebarBackdrop) sidebarBackdrop.addEventListener('click', closeSidebar);

  // ==========================================================================
  // ZÁLOŽKY + URL ROUTING
  // ==========================================================================
  const tabTitles = {
    home: 'Home',
    logs: 'Log',
    info: 'Informace',
    units: 'Jednotky',
    users: 'Správa uživatelů',
    keys: 'Bezpečnostní klíče',
    permanent: 'Trvalé odemčení',
    schedule: 'Rozvrh',
    'global-settings': 'Globální nastavení'
  };

  // Mapování: interní tab-name → URL path segment
  const tabToPath = {
    home: '/home',
    logs: '/log',
    info: '/info',
    units: '/units',
    users: '/users',
    keys: '/keys',
    permanent: '/permanent',
    schedule: '/schedule',
    'global-settings': '/global-settings'
  };

  // Mapování: URL path segment → interní tab-name
  const pathToTab = {
    '/': 'home',
    '/home': 'home',
    '/log': 'logs',
    '/logs': 'logs',
    '/info': 'info',
    '/units': 'units',
    '/users': 'users',
    '/keys': 'keys',
    '/permanent': 'permanent',
    '/schedule': 'schedule',
    '/global-settings': 'global-settings'
  };

  /** Vrátí tab-name pro aktuální URL pathname, nebo 'home' jako fallback. */
  function tabFromCurrentPath() {
    return pathToTab[window.location.pathname] || 'home';
  }

  function updateSidebarNavVisibility() {
    const isElevated = (currentUserRole === 'admin' || currentUserRole === 'správce' || currentUserCanManageUsers);
    const menu = (currentUserSidebarMenu && Array.isArray(currentUserSidebarMenu) && currentUserSidebarMenu.length > 0)
      ? currentUserSidebarMenu
      : (isElevated ? ['home', 'logs', 'info', 'users', 'keys', 'permanent', 'schedule', 'global-settings'] : ['home']);

    if (navHomeBtn) {
      const show = menu.includes('home');
      navHomeBtn.classList.toggle('hidden', !show);
      navHomeBtn.style.display = show ? 'flex' : 'none';
    }
    if (navLogsBtn) {
      const show = menu.includes('logs');
      navLogsBtn.classList.toggle('hidden', !show);
      navLogsBtn.style.display = show ? 'flex' : 'none';
    }
    if (navInfoBtn) {
      const show = menu.includes('info');
      navInfoBtn.classList.toggle('hidden', !show);
      navInfoBtn.style.display = show ? 'flex' : 'none';
    }
    if (navUsersBtn) {
      const show = menu.includes('users');
      navUsersBtn.classList.toggle('hidden', !show);
      navUsersBtn.style.display = show ? 'flex' : 'none';
    }
    if (navUnitsBtn) {
      const show = currentUserRole === 'admin';
      navUnitsBtn.classList.toggle('hidden', !show);
      navUnitsBtn.style.display = show ? 'flex' : 'none';
    }
    if (navKeysBtn) {
      const show = menu.includes('keys') && isElevated;
      navKeysBtn.classList.toggle('hidden', !show);
      navKeysBtn.style.display = show ? 'flex' : 'none';
    }
    if (navPermanentBtn) {
      const show = menu.includes('permanent');
      navPermanentBtn.classList.toggle('hidden', !show);
      navPermanentBtn.style.display = show ? 'flex' : 'none';
    }
    if (navScheduleBtn) {
      const show = menu.includes('schedule');
      navScheduleBtn.classList.toggle('hidden', !show);
      navScheduleBtn.style.display = show ? 'flex' : 'none';
    }
    if (navGlobalSettingsBtn) {
      const show = currentUserRole === 'admin';
      navGlobalSettingsBtn.classList.toggle('hidden', !show);
      navGlobalSettingsBtn.style.display = show ? 'flex' : 'none';
    }
  }

  function setKeyAlert(element, message, isError = true) {
    if (!element) return;
    element.textContent = message;
    element.className = isError
      ? 'rounded-xl border border-rose-200 bg-rose-50 p-3 text-xs font-medium text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/30 dark:text-rose-300'
      : 'rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-xs font-medium text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-300';
    element.classList.remove('hidden');
  }

  function updateSecurityKeyActionHelp() {
    if (!securityKeyActionHelp || !securityKeyAction) return;
    const descriptions = {
      unlock: 'Přiložení karty krátce odemkne dveře.',
      ring: 'Přiložení karty spustí zvonění.',
      permanent_toggle: 'Každé přiložení střídá trvalé odemčení a uzamčení. Uzamknout lze také tlačítkem v aplikaci.',
      web_block_toggle: 'Každé přiložení zablokuje nebo znovu povolí odemykání přes web všem uživatelům.'
    };
    securityKeyActionHelp.textContent = descriptions[securityKeyAction.value] || '';
  }

  if (securityKeyAction) {
    securityKeyAction.addEventListener('change', updateSecurityKeyActionHelp);
  }

  async function loadSecurityKeys() {
    if (!securityKeysList) return;
    try {
      const res = await fetch('/api/security-keys');
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || 'Bezpečnostní klíče se nepodařilo načíst.');
      }

      securityKeysList.replaceChildren();
      if (!Array.isArray(data.keys) || data.keys.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'rounded-2xl border border-dashed border-gray-300 bg-white p-8 text-center text-sm text-gray-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-400';
        empty.textContent = 'Zatím není zaregistrován žádný bezpečnostní klíč.';
        securityKeysList.appendChild(empty);
        return;
      }

      data.keys.forEach(key => {
        const card = document.createElement('article');
        card.className = 'flex flex-col gap-3 rounded-2xl border border-gray-200/80 bg-white p-4 shadow-xs dark:border-gray-800 dark:bg-gray-900 sm:flex-row sm:items-center sm:justify-between';

        const details = document.createElement('div');
        const name = document.createElement('h3');
        name.className = 'text-sm font-bold text-gray-900 dark:text-white';
        name.textContent = key.name;
        const action = document.createElement('p');
        action.className = 'mt-1 text-xs text-gray-500 dark:text-gray-400';
        const actionLabels = {
          unlock: 'Odemknout dveře',
          ring: 'Spustit zvonění',
          permanent_toggle: 'Přepínat trvalé odemčení',
          web_block_toggle: 'Přepínat blokování webového odemykání'
        };
        action.textContent = `Funkce: ${actionLabels[key.action] || 'Neznámá funkce'} · Jednotka: ${key.unit_name || 'Všechny jednotky'}`;
        details.append(name, action);

        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'self-start rounded-xl border border-rose-200 px-3 py-1.5 text-xs font-semibold text-rose-700 hover:bg-rose-50 dark:border-rose-900/60 dark:text-rose-400 dark:hover:bg-rose-950/30 sm:self-auto';
        remove.textContent = 'Odstranit';
        remove.addEventListener('click', async () => {
          if (!window.confirm(`Opravdu odstranit klíč „${key.name}“?`)) return;
          remove.disabled = true;
          try {
            const response = await fetch(`/api/security-keys/${key.id}`, {
              method: 'DELETE',
              headers: authHeaders()
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.message || 'Klíč se nepodařilo odstranit.');
            showToast('Bezpečnostní klíč byl odstraněn.', 'success');
            loadSecurityKeys();
          } catch (error) {
            showToast(error.message || 'Chyba sítě při odstraňování klíče.', 'error');
            remove.disabled = false;
          }
        });

        card.append(details, remove);
        securityKeysList.appendChild(card);
      });
    } catch (error) {
      securityKeysList.textContent = error.message || 'Bezpečnostní klíče se nepodařilo načíst.';
      showToast(error.message || 'Chyba sítě při načítání klíčů.', 'error');
    }
  }

  function stopKeyScanPolling() {
    if (keyScanPollTimer) {
      clearInterval(keyScanPollTimer);
      keyScanPollTimer = null;
    }
  }

  async function pollKeyRegistration() {
    if (keyStatusPolling) return;
    keyStatusPolling = true;
    try {
      const res = await fetch('/api/security-keys/registration');
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Stav registrace se nepodařilo ověřit.');

      if (data.registered_in_lock) {
        stopKeyScanPolling();
        keyRegistrationActive = true;
        keyScanCountdown.classList.add('hidden');
        keyScanMessage.textContent = 'Tento klíč je již zaregistrován pro odemykání v nastavení zámku. Nelze ho přiřadit jako bezpečnostní klíč aplikace. Přiložte jinou kartu.';
        setKeyAlert(keyScanAlert, 'Karta byla načtena jako platná v zámku (valid=true), proto ji nelze přiřadit aplikaci.');
        beginKeyScanBtn.textContent = 'Zkusit jinou kartu';
        beginKeyScanBtn.classList.remove('hidden');
      } else if (data.captured) {
        stopKeyScanPolling();
        keyRegistrationActive = true;
        keyScanMessage.textContent = 'UID karty bylo načteno. Klíč není registrován v nastavení zámku (valid=false) a lze ho přiřadit aplikaci.';
        keyScanAlert.classList.add('hidden');
        keyScanStep.classList.add('hidden');
        keySetupStep.classList.remove('hidden');
        securityKeyName.focus();
      } else if (data.active) {
        keyRegistrationActive = true;
        keyScanCountdown.textContent = `Budete mít ještě ${data.remaining_seconds} s na přiložení k jednotce.`;
      } else {
        stopKeyScanPolling();
        keyRegistrationActive = false;
        keyScanCountdown.classList.add('hidden');
        keyScanMessage.textContent = 'Čas vypršel. Kartu se nepodařilo načíst, můžete registraci spustit znovu.';
        beginKeyScanBtn.textContent = 'Zkusit znovu';
        beginKeyScanBtn.classList.remove('hidden');
      }
    } catch (error) {
      setKeyAlert(keyScanAlert, error.message || 'Chyba při ověřování registrace.');
    } finally {
      keyStatusPolling = false;
    }
  }

  async function openKeyRegistration() {
    stopKeyScanPolling();
    keyRegistrationActive = false;
    keyScanStep.classList.remove('hidden');
    keySetupStep.classList.add('hidden');
    keyScanMessage.textContent = 'Stiskněte tlačítko a připravte čipovou kartu k přiložení k jednotce.';
    keyScanCountdown.classList.add('hidden');
    keyScanAlert.classList.add('hidden');
    keySetupAlert.classList.add('hidden');
    beginKeyScanBtn.textContent = 'Zaregistrovat nový klíč';
    beginKeyScanBtn.classList.remove('hidden');
    securityKeyName.value = '';
    securityKeyAction.value = 'unlock';
    if (securityKeyUnit) {
      try {
        const response = await fetch('/api/user/units', { cache: 'no-store' });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Jednotky se nepodařilo načíst.');
        securityKeyUnit.replaceChildren();
        const allOption = document.createElement('option');
        allOption.value = 'all';
        allOption.textContent = 'Všechny jednotky';
        securityKeyUnit.appendChild(allOption);
        (data.units || []).forEach(unit => {
          const option = document.createElement('option');
          option.value = String(unit.id);
          option.textContent = unit.name;
          securityKeyUnit.appendChild(option);
        });
        if (securityKeyUnit.options.length > 1) securityKeyUnit.value = String(data.units[0].id);
      } catch (error) {
        securityKeyUnit.replaceChildren();
        const option = document.createElement('option');
        option.value = '';
        option.textContent = error.message || 'Jednotky se nepodařilo načíst.';
        securityKeyUnit.appendChild(option);
        showToast(error.message || 'Jednotky se nepodařilo načíst.', 'error');
      }
    }
    updateSecurityKeyActionHelp();
    keyRegistrationModal.classList.remove('hidden');
    beginKeyScanBtn.focus();
  }

  async function closeKeyRegistration() {
    stopKeyScanPolling();
    keyRegistrationModal.classList.add('hidden');
    if (!keyRegistrationActive) return;
    keyRegistrationActive = false;
    try {
      const res = await fetch('/api/security-keys/registration', {
        method: 'DELETE',
        headers: authHeaders()
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        showToast(data.message || 'Registraci se nepodařilo zrušit.', 'error');
      }
    } catch (error) {
      showToast(error.message || 'Chyba sítě při rušení registrace.', 'error');
    }
  }

  if (openKeyRegistrationBtn) openKeyRegistrationBtn.addEventListener('click', openKeyRegistration);
  if (closeKeyRegistrationBtn) closeKeyRegistrationBtn.addEventListener('click', closeKeyRegistration);
  if (cancelKeySetupBtn) cancelKeySetupBtn.addEventListener('click', closeKeyRegistration);
  if (keyRegistrationModal) {
    keyRegistrationModal.addEventListener('click', event => {
      if (event.target === keyRegistrationModal) closeKeyRegistration();
    });
  }

  if (beginKeyScanBtn) {
    beginKeyScanBtn.addEventListener('click', async () => {
      beginKeyScanBtn.disabled = true;
      keyScanAlert.classList.add('hidden');
      try {
        const res = await fetch('/api/security-keys/registration', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ unit_id: securityKeyUnit.value })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message || 'Registraci se nepodařilo spustit.');

        keyRegistrationActive = true;
        beginKeyScanBtn.classList.add('hidden');
        keyScanMessage.textContent = 'Budete mít 15 vteřin na přiložení k jednotce.';
        keyScanCountdown.textContent = 'Zbývá 15 s.';
        keyScanCountdown.classList.remove('hidden');
        stopKeyScanPolling();
        keyScanPollTimer = setInterval(pollKeyRegistration, 500);
      } catch (error) {
        setKeyAlert(keyScanAlert, error.message || 'Chyba při zahájení registrace.');
      } finally {
        beginKeyScanBtn.disabled = false;
      }
    });
  }

  if (keySetupStep) {
    keySetupStep.addEventListener('submit', async event => {
      event.preventDefault();
      saveSecurityKeyBtn.disabled = true;
      keySetupAlert.classList.add('hidden');
      try {
        const res = await fetch('/api/security-keys', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            name: securityKeyName.value.trim(),
            action: securityKeyAction.value
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.message || 'Klíč se nepodařilo uložit.');

        keyRegistrationActive = false;
        keyRegistrationModal.classList.add('hidden');
        showToast('Bezpečnostní klíč byl úspěšně zaregistrován.', 'success');
        loadSecurityKeys();
      } catch (error) {
        setKeyAlert(keySetupAlert, error.message || 'Chyba při ukládání klíče.');
      } finally {
        saveSecurityKeyBtn.disabled = false;
      }
    });
  }

  function switchTab(tabName, { pushHistory = true } = {}) {
    const isElevated = (currentUserRole === 'admin' || currentUserRole === 'správce' || currentUserCanManageUsers);
    const isAdmin = currentUserRole === 'admin';
    const menu = (currentUserSidebarMenu && Array.isArray(currentUserSidebarMenu) && currentUserSidebarMenu.length > 0)
      ? currentUserSidebarMenu
      : (isElevated ? ['home', 'logs', 'info', 'users', 'keys', 'permanent', 'schedule', 'global-settings'] : ['home']);

    if (!menu.includes(tabName) && !(isAdmin && ['units', 'global-settings'].includes(tabName))) {
      showToast('Na tuto akci nemáte právo. Obraťte se na správce systému.', 'error');
      tabName = menu.includes('home') ? 'home' : (menu[0] || 'home');
    }
    if (tabName === 'units' && !isAdmin) {
      showToast('Správa jednotek je dostupná pouze administrátorovi.', 'error');
      tabName = menu.includes('home') ? 'home' : (menu[0] || 'home');
    }
    if (tabName === 'global-settings' && !isAdmin) {
      showToast('Globální nastavení je dostupné pouze administrátorovi.', 'error');
      tabName = menu.includes('home') ? 'home' : (menu[0] || 'home');
    }
    if (tabName === 'keys' && !isElevated) {
      showToast('Na tuto akci nemáte právo. Obraťte se na správce systému.', 'error');
      tabName = menu.includes('home') ? 'home' : (menu[0] || 'home');
    }

    if (pushHistory) {
      const targetPath = tabToPath[tabName] || '/home';
      if (window.location.pathname !== targetPath) {
        history.pushState({ tab: tabName }, '', targetPath);
      }
    }

    navTabBtns.forEach(btn => {
      const btnTab = btn.getAttribute('data-tab');
      if (btnTab === tabName) {
        btn.className = 'nav-tab-btn w-full flex items-center gap-3.5 rounded-xl px-3.5 py-2.5 text-sm font-medium transition-all text-white bg-brand-500 shadow-sm shadow-brand-500/30';
      } else {
        btn.className = 'nav-tab-btn w-full flex items-center gap-3.5 rounded-xl px-3.5 py-2.5 text-sm font-medium transition-all text-gray-600 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-white';
      }
    });

    tabPanes.forEach(pane => {
      if (pane.id === `tab-${tabName}`) {
        pane.classList.remove('hidden');
      } else {
        pane.classList.add('hidden');
      }
    });

    if (pageHeaderTitle) {
      pageHeaderTitle.textContent = tabTitles[tabName] || 'Home';
    }

    if (window.innerWidth < 1024) closeSidebar();

    if (tabName === 'logs') fetchLogs();
    if (tabName === 'info') loadConfig();
    if (tabName === 'units') {
      loadManagedUnits();
      if (!unitsStatusRefreshInterval) {
        unitsStatusRefreshInterval = window.setInterval(() => {
          if (window.location.pathname === tabToPath.units) loadManagedUnits();
        }, 15000);
      }
    }
    if (tabName === 'users') loadUsers();
    if (tabName === 'keys') loadSecurityKeys();
    if (tabName === 'permanent') {
      if (currentUserRole === 'admin' || currentUserRole === 'správce') {
        loadPermanentUsersTable();
      }
      fetchPermanentUnlockStatus();
    }
    if (tabName === 'schedule') {
      initScheduleTab();
    }
    if (tabName === 'global-settings') {
      loadGlobalSettings();
      if (!ntpStatusRefreshInterval) {
        ntpStatusRefreshInterval = window.setInterval(() => {
          if (window.location.pathname === tabToPath['global-settings']) loadGlobalSettings();
        }, 30000);
      }
    }
  }

  navTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      switchTab(btn.getAttribute('data-tab'));
    });
  });

  const sidebarLogoLink = document.getElementById('sidebarLogoLink');
  if (sidebarLogoLink) {
    sidebarLogoLink.addEventListener('click', (e) => {
      e.preventDefault();
      switchTab('home');
      if (window.innerWidth < 1024 && sidebar) {
        sidebar.classList.add('-translate-x-full');
        if (sidebarOverlay) sidebarOverlay.classList.add('hidden');
      }
    });
  }

  // Navigace tlačítky Zpět / Vpřed v prohlížeči
  window.addEventListener('popstate', (e) => {
    const tab = (e.state && e.state.tab) ? e.state.tab : tabFromCurrentPath();
    switchTab(tab, { pushHistory: false });
  });

  // ==========================================================================
  // UŽIVATELSKÝ DROPDOWN
  // ==========================================================================
  if (userDropdownBtn && userDropdownMenu) {
    userDropdownBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isHidden = userDropdownMenu.classList.contains('hidden');
      if (isHidden) {
        userDropdownMenu.classList.remove('hidden');
        userDropdownArrow.classList.add('rotate-180');
      } else {
        userDropdownMenu.classList.add('hidden');
        userDropdownArrow.classList.remove('rotate-180');
      }
    });

    document.addEventListener('click', (e) => {
      if (!userDropdownMenu.contains(e.target) && !userDropdownBtn.contains(e.target)) {
        userDropdownMenu.classList.add('hidden');
        userDropdownArrow.classList.remove('rotate-180');
      }
    });
  }

  // ==========================================================================
  // NASTAVENÍ MODÁL
  // ==========================================================================
  function openSettings() {
    userDropdownMenu.classList.add('hidden');
    userDropdownArrow.classList.remove('rotate-180');
    settingsModal.classList.remove('hidden');
    loadUserUnits();
  }

  function closeSettings() {
    settingsModal.classList.add('hidden');
    if (changePasswordForm) changePasswordForm.classList.add('hidden');
    if (changePasswordAlert) changePasswordAlert.classList.add('hidden');
  }

  if (openSettingsBtn) openSettingsBtn.addEventListener('click', openSettings);
  if (closeSettingsModalBtn) closeSettingsModalBtn.addEventListener('click', closeSettings);
  if (closeSettingsBottomBtn) closeSettingsBottomBtn.addEventListener('click', closeSettings);
  if (settingsModal) {
    settingsModal.addEventListener('click', (e) => {
      if (e.target === settingsModal) closeSettings();
    });
  }

  if (toggleChangePasswordCardBtn) {
    toggleChangePasswordCardBtn.addEventListener('click', () => {
      changePasswordForm.classList.toggle('hidden');
      if (changePasswordAlert) changePasswordAlert.classList.add('hidden');
    });
  }

  // ==========================================================================
  // CSRF & AUTH HEADERS
  // ==========================================================================
  function authHeaders(extraHeaders) {
    return Object.assign({
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-CSRF-Token': csrfToken
    }, extraHeaders || {});
  }

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

  // ==========================================================================
  // INICIALIZACE RELACE (/api/me)
  // ==========================================================================
  async function initSession() {
    try {
      const res = await fetch('/api/me');
      if (res.status === 401) {
        const errData = await res.json().catch(() => null);
        if (errData && errData.account_disabled) {
          window.location.href = '/login?disabled=1';
        } else {
          window.location.href = '/login';
        }
        return;
      }
      if (res.ok) {
        const data = await res.json();
        currentUserId = data.user_id || null;
        currentUsername = data.username || 'admin';
        currentUserRole = data.role || 'user';
        currentUserBypass = Boolean(data.network_bypass);
        serverNetworkAllowed = Boolean(data.network_allowed);
        isNetworkAllowed = serverNetworkAllowed;
        csrfToken = data.csrf_token || '';
        deviceIp = data.device_ip || '';
        devicePort = data.device_port || 443;
        deviceProtocol = data.device_protocol || 'https';
        vapidPublicKey = data.vapid_public_key || '';
        currentUserSidebarMenu = Array.isArray(data.sidebar_menu) ? data.sidebar_menu : ['home'];
        currentUserCanManageUsers = Boolean(data.can_manage_users);
        currentUserManagePermissions = (typeof data.manage_permissions === 'object' && data.manage_permissions !== null) ? data.manage_permissions : {};

        if (typeof data.permanent_unlock_allowed !== 'undefined') {
          permanentUserAllowed = Boolean(data.permanent_unlock_allowed);
          permanentUserMaxDuration = data.permanent_unlock_max_duration || 60;
          updatePermanentControlsVisibility();
        }

        if (headerUsername) headerUsername.textContent = currentUsername;
        if (headerUserRole) {
          if (currentUserRole === 'admin') {
            headerUserRole.textContent = 'Administrátor';
          } else if (currentUserRole === 'správce') {
            headerUserRole.textContent = 'Správce';
          } else {
            headerUserRole.textContent = 'Uživatel';
          }
        }
        if (dropdownUsernameFull) dropdownUsernameFull.textContent = currentUsername;

        const initial = currentUsername.charAt(0).toUpperCase() || 'U';
        if (userAvatarCircle) userAvatarCircle.textContent = initial;

        if (tileClientIp) tileClientIp.textContent = data.client_ip || '—';

        const isAdmin = (currentUserRole === 'admin');

        // Aktualizovat viditelnost bočního menu podle nastavení pro přihlášeného uživatele
        updateSidebarNavVisibility();

        // Zobrazení IP a detailů jednotky nesmí být nikde mimo záložku Informace
        if (sidebarAdminIpDisplay) {
          sidebarAdminIpDisplay.classList.add('hidden');
        }

        // Subtitle v sidebar nesmí zobrazovat Access Unit
        if (sidebarSubtitle) {
          sidebarSubtitle.textContent = 'Dálkové odemykání';
        }

        // Bypass přepínač při vytváření uživatele podle oprávnění
        const canEditBypass = isAdmin || Boolean(currentUserManagePermissions.can_edit_network_bypass);
        if (newUserBypassWrapper) {
          newUserBypassWrapper.style.display = canEditBypass ? 'flex' : 'none';
        }

        // Možnost vytvořit Administrátora má pouze administrátor
        if (newRoleAdminOption) {
          newRoleAdminOption.hidden = !isAdmin;
          newRoleAdminOption.disabled = !isAdmin;
        }

        // Zobraz záložku odpovídající aktuální URL (nebo první povolenou položku)
        const urlTab = tabFromCurrentPath();
        const effectiveMenu = (currentUserSidebarMenu && currentUserSidebarMenu.length > 0) ? currentUserSidebarMenu : ['home'];
        const initialTab = effectiveMenu.includes(urlTab) ? urlTab : (effectiveMenu[0] || 'home');
        switchTab(initialTab, { pushHistory: false });

        // Push notifikace stav (vázáno ke konkrétnímu zařízení / prohlížeči)
        let isDevicePushEnabled = false;
        if ('serviceWorker' in navigator && 'PushManager' in window) {
          try {
            const reg = await navigator.serviceWorker.getRegistration();
            if (reg) {
              const sub = await reg.pushManager.getSubscription();
              isDevicePushEnabled = Boolean(sub);
            }
          } catch (_) {}
        }
        if (pushNotificationToggle) pushNotificationToggle.checked = isDevicePushEnabled;
        if (pushNotificationStatusText) {
          pushNotificationStatusText.textContent = isDevicePushEnabled ? 'Stav: aktivní na tomto zařízení' : 'Stav: neaktivní';
        }
        if (testPushBtn) testPushBtn.classList.toggle('hidden', !isDevicePushEnabled);

        // Biometrie stav (vázáno ke konkrétnímu zařízení / prohlížeči)
        const isDeviceBioEnabled = (localStorage.getItem('door_biometrics_enabled') === 'true');
        if (biometricAuthToggle) biometricAuthToggle.checked = isDeviceBioEnabled;
        if (biometricStatusText) {
          biometricStatusText.textContent = isDeviceBioEnabled ? 'Stav: aktivní na tomto zařízení (otisk uložen)' : 'Stav: neaktivní';
        }

        updateNetworkUi(isNetworkAllowed);
        if (!currentUserBypass) {
          runNetworkProbe();
        }

        // Periodické ověřování stavu bypassu (každých 1,5 s) pro okamžitou synchronizaci mezi zařízeními
        async function pollStatus() {
          if (isSending) return;
          try {
            const pollRes = await fetch('/api/me');
            if (pollRes.status === 401) {
              const errData = await pollRes.json().catch(() => null);
              if (errData && errData.account_disabled) {
                window.location.href = '/login?disabled=1';
              } else {
                window.location.href = '/login';
              }
              return;
            }
            if (pollRes.ok) {
              const pollData = await pollRes.json();
              const newBypass = Boolean(pollData.network_bypass);
              const serverAllowed = Boolean(pollData.network_allowed);
              serverNetworkAllowed = serverAllowed;
              // Pokud je ověřena klientská sonda, síť je povolena i při přístupu přes tunel/proxy
              const effectiveAllowed = serverAllowed || isProbeVerified;

              // Pokud došlo ke změně bypassu nebo přístupu
              if (newBypass !== currentUserBypass || effectiveAllowed !== isNetworkAllowed) {
                const bypassRevoked = (currentUserBypass && !newBypass);
                currentUserBypass = newBypass;
                isNetworkAllowed = effectiveAllowed;
                updateNetworkUi(isNetworkAllowed);
                if (bypassRevoked) {
                  // Bypass byl odebrán – znovu ověřit lokální přítomnost v síti
                  isProbeVerified = false;
                  runNetworkProbe();
                } else if (!currentUserBypass && !isProbeVerified) {
                  runNetworkProbe();
                }
              }

              if (typeof pollData.permanent_unlock_allowed !== 'undefined') {
                const newPermAllowed = Boolean(pollData.permanent_unlock_allowed);
                const newPermDuration = pollData.permanent_unlock_max_duration || 60;
                if (newPermAllowed !== permanentUserAllowed || newPermDuration !== permanentUserMaxDuration) {
                  permanentUserAllowed = newPermAllowed;
                  permanentUserMaxDuration = newPermDuration;
                  updatePermanentControlsVisibility();
                }
              }
            }
          } catch (_) {}
        }

        if (!window.__statusPollInterval) {
          window.__statusPollInterval = setInterval(pollStatus, 1500);
          document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
              pollStatus();
            }
          });
          window.addEventListener('focus', pollStatus);
        }
      }
    } catch (e) {
      console.warn('Chyba relace:', e);
    }
  }

  // ==========================================================================
  // SÍŤOVÁ SONDA
  // ==========================================================================
  function updateNetworkUi(allowed) {
    if (allowed) {
      sidebarStatusDot.className = 'h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse';
      sidebarStatusText.textContent = currentUserBypass ? 'Bypass aktivní' : 'Síť Šešule ověřena';
      tileNetworkStatus.textContent = 'Přístup povolen';
      tileNetworkStatus.className = 'font-semibold text-emerald-600 dark:text-emerald-400';
      networkBlockedCard.classList.add('hidden');
      if (svgBlockedCross) svgBlockedCross.classList.add('hidden');

      if (webUnlockBlocked) {
        doorBtn.disabled = true;
        doorBtn.className = 'door-btn-orig blocked';
        doorWrapper.className = 'door-wrapper blocked';
        doorBtnText.textContent = 'WEB ZABLOKOVÁN';
        doorBtnSubtext.textContent = permanentUnlockActive
          ? 'Zámek zůstává trvale odemčen'
          : 'Přiložte bezpečnostní klíč k povolení';
        doorStatusIndicator.className = 'h-2 w-2 rounded-full bg-rose-500';
        doorStatusText.textContent = 'Webové odemykání zablokováno';
        if (svgLocked) svgLocked.classList.add('hidden');
        if (svgUnlocked) svgUnlocked.classList.toggle('hidden', !permanentUnlockActive);
        if (svgBlockedCross) svgBlockedCross.classList.toggle('hidden', permanentUnlockActive);
        renderHomeUnitCards();
        return;
      }

      if (permanentUnlockActive) {
        doorBtn.disabled = false;
        doorBtn.className = 'door-btn-orig permanent';
        doorWrapper.className = 'door-wrapper permanent';
        doorBtnText.textContent = 'TRVALE ODEMČENO';
        doorStatusIndicator.className = 'h-2 w-2 rounded-full bg-amber-500 animate-pulse';
        doorStatusText.textContent = 'Trvale odemčeno';
        if (svgLocked) svgLocked.classList.add('hidden');
        if (svgUnlocked) svgUnlocked.classList.remove('hidden');
      } else {
        doorBtn.disabled = false;
        doorBtn.className = 'door-btn-orig';
        doorWrapper.className = 'door-wrapper';
        doorBtnText.textContent = 'ODEMKNOUT';
        doorBtnSubtext.textContent = 'Stiskněte pro otevření';
        doorStatusIndicator.className = 'h-2 w-2 rounded-full bg-emerald-500';
        doorStatusText.textContent = 'Připraveno k odemčení';
        if (svgLocked) svgLocked.classList.remove('hidden');
        if (svgUnlocked) svgUnlocked.classList.add('hidden');
      }
    } else {
      sidebarStatusDot.className = 'h-2.5 w-2.5 rounded-full bg-rose-500';
      sidebarStatusText.textContent = 'Mimo síť Šešule';
      tileNetworkStatus.textContent = 'Mimo povolenou síť';
      tileNetworkStatus.className = 'font-semibold text-rose-600 dark:text-rose-400';
      networkBlockedCard.classList.remove('hidden');
      doorBtn.disabled = true;
      doorBtn.className = 'door-btn-orig blocked';
      doorWrapper.className = 'door-wrapper blocked';
      doorBtnText.textContent = 'BLOKOVÁNO';
      doorBtnSubtext.textContent = 'Bypass nepovolen';
      doorStatusIndicator.className = 'h-2 w-2 rounded-full bg-rose-500';
      doorStatusText.textContent = 'Odemykání blokováno';
      if (svgLocked) svgLocked.classList.add('hidden');
      if (svgUnlocked) svgUnlocked.classList.add('hidden');
      if (svgSpinner) svgSpinner.classList.add('hidden');
      if (svgBlockedCross) svgBlockedCross.classList.remove('hidden');
    }
    renderHomeUnitCards();
  }

  function renderHomeUnitCards() {
    if (!unitControlsContainer) return;
    const availableUnits = userUnits.filter(unit => unit.selected);
    if (userUnits.length === 0) {
      unitControlsContainer.classList.add('hidden');
      if (legacyDoorCard) legacyDoorCard.classList.remove('hidden');
      return;
    }

    unitControlsContainer.classList.remove('hidden');
    if (legacyDoorCard) legacyDoorCard.classList.add('hidden');
    unitControlsContainer.replaceChildren();

    if (availableUnits.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'rounded-2xl border border-gray-200 bg-white p-5 text-center text-sm text-gray-500 dark:border-gray-800 dark:bg-gray-900 dark:text-gray-400';
      empty.textContent = 'Nemáte vybranou žádnou jednotku. Výběr můžete změnit v Nastavení účtu.';
      unitControlsContainer.appendChild(empty);
      return;
    }

    availableUnits.forEach(unit => {
      const card = document.createElement('article');
      card.className = 'unit-control-card rounded-3xl border border-gray-200/80 bg-white p-4 shadow-xs dark:border-gray-800 dark:bg-gray-900';

      const heading = document.createElement('div');
      heading.className = 'mb-3 flex items-start justify-between gap-3 text-left';
      const details = document.createElement('div');
      details.className = 'min-w-0';
      const name = document.createElement('h2');
      name.className = 'truncate text-sm font-bold text-gray-900 dark:text-white';
      name.textContent = unit.name;
      const model = document.createElement('p');
      model.className = 'mt-0.5 truncate text-xs text-gray-500 dark:text-gray-400';
      model.textContent = unit.model;
      details.append(name, model);
      const status = document.createElement('span');
      status.className = `unit-connection-status${unit.connected ? ' is-connected' : ' is-offline'}`;
      status.textContent = unit.connected ? 'Připojeno' : 'Nedostupné';
      heading.append(details, status);

      const state = unit.permanent_state || {};
      const access = unit.access || {};
      const blocked = Boolean(unit.web_unlock_blocked);
      const networkAllowed = Boolean(access.network_bypass) || serverNetworkAllowed || unitProbeVerified.has(unit.id);
      const wrapper = document.createElement('div');
      wrapper.className = `door-wrapper${blocked ? ' blocked' : state.active ? ' permanent' : ''}`;
      const ring1 = document.createElement('div');
      const ring2 = document.createElement('div');
      const ring3 = document.createElement('div');
      ring1.className = ring2.className = ring3.className = 'door-ring';
      wrapper.append(ring1, ring2, ring3);

      const button = document.createElement('button');
      button.type = 'button';
      button.className = `door-btn-orig${blocked ? ' blocked' : state.active ? ' permanent' : ''}`;
      button.disabled = !access.can_unlock || !networkAllowed || blocked;
      button.setAttribute('aria-label', `Odemknout jednotku ${unit.name}`);
      button.title = blocked
        ? 'Webové odemykání je zablokováno bezpečnostním klíčem.'
        : (!access.can_unlock ? 'Nemáte oprávnění odemykat tuto jednotku.' : (!networkAllowed ? 'Odemykání není povoleno z této sítě.' : `Odemknout ${unit.name}`));

      const inner = document.createElement('div');
      inner.className = 'door-btn-inner';
      const iconWrap = document.createElement('div');
      iconWrap.className = 'door-icon-wrap';
      iconWrap.innerHTML = '<svg class="h-10 w-10 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
      const buttonText = document.createElement('span');
      buttonText.className = 'door-btn-text';
      buttonText.textContent = blocked ? 'BLOKOVÁNO' : state.active ? 'TRVALE ODEMČENO' : 'ODEMKNOUT';
      const subtext = document.createElement('span');
      subtext.className = 'door-btn-subtext';
      subtext.textContent = blocked
        ? 'Webové odemykání blokováno'
        : (state.active ? (state.expires_at ? `Zbývá: ${formatCountdown(state.expires_at)}` : 'Aktivní bez limitu') : 'Stiskněte pro otevření');
      inner.append(iconWrap, buttonText, subtext);
      button.appendChild(inner);
      button.addEventListener('click', () => unlockSelectedUnit(unit, button));
      wrapper.appendChild(button);

      const controls = document.createElement('div');
      controls.className = 'mt-2 flex flex-wrap justify-center gap-2';
      if (access.permanent_unlock_allowed || state.active) {
        const permanentButton = document.createElement('button');
        permanentButton.type = 'button';
        permanentButton.className = `unit-permanent-toggle${state.active ? ' is-active' : ''}`;
        permanentButton.textContent = state.active ? 'Trvale uzamknout' : 'Trvale odemknout';
        permanentButton.disabled = !state.active && (!networkAllowed || blocked);
        permanentButton.addEventListener('click', () => {
          if (state.active) stopUnitPermanentUnlock(unit);
          else {
            activePermanentUnitId = unit.id;
            permanentUserMaxDuration = access.permanent_unlock_max_duration || 60;
            openPermanentUnlockModal(unit.id, permanentUserMaxDuration);
          }
        });
        controls.appendChild(permanentButton);
      }
      const permanentStatus = document.createElement('p');
      permanentStatus.className = 'w-full text-center text-[11px] text-gray-500 dark:text-gray-400';
      permanentStatus.textContent = state.active
        ? `Trvalé odemčení aktivní${state.activated_by_username ? ` · ${state.activated_by_username}` : ''}`
        : (blocked ? 'Webové ovládání blokováno' : '');
      card.append(heading, wrapper, controls, permanentStatus);
      unitControlsContainer.appendChild(card);
    });
  }

  async function unlockSelectedUnit(unit, button) {
    if (button.disabled) return;
    const text = button.querySelector('.door-btn-text');
    const subtext = button.querySelector('.door-btn-subtext');
    const wrapper = button.closest('.door-wrapper');
    const originalText = text ? text.textContent : button.textContent;
    const originalSubtext = subtext ? subtext.textContent : '';
    button.disabled = true;
    if (text) text.textContent = 'ODESÍLÁM...';
    else button.textContent = 'Odesílám…';
    if (subtext) subtext.textContent = 'Komunikuji s 2N';
    button.classList.add('sending');
    try {
      const response = await fetch(`/api/units/${unit.id}/unlock`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ client_probe_ok: unitProbeVerified.has(unit.id) })
      });
      const data = await response.json().catch(() => null);
      if (!response.ok || !data || !data.success) {
        throw new Error((data && data.message) || 'Jednotku se nepodařilo odemknout.');
      }
      if (text) text.textContent = 'ODEMČENO';
      else button.textContent = 'Odemčeno';
      if (subtext) subtext.textContent = 'Dveře jsou otevřeny';
      button.classList.remove('sending');
      button.classList.add('unlocked');
      if (wrapper) wrapper.classList.add('unlocked');
      showToast(data.message, 'success');
      setTimeout(() => {
        if (text) text.textContent = originalText;
        else button.textContent = originalText;
        if (subtext) subtext.textContent = originalSubtext;
        button.classList.remove('unlocked');
        if (wrapper) wrapper.classList.remove('unlocked');
        const access = unit.access || {};
        button.disabled = !access.can_unlock || (!access.network_bypass && !serverNetworkAllowed && !unitProbeVerified.has(unit.id)) || Boolean(unit.web_unlock_blocked);
      }, 2500);
    } catch (error) {
      showToast(error.message || 'Chyba při odemykání jednotky.', 'error');
      if (text) text.textContent = originalText;
      else button.textContent = originalText;
      if (subtext) subtext.textContent = originalSubtext;
      button.classList.remove('sending');
      const access = unit.access || {};
      button.disabled = !access.can_unlock || (!access.network_bypass && !serverNetworkAllowed && !unitProbeVerified.has(unit.id)) || Boolean(unit.web_unlock_blocked);
    } finally {
      button.classList.remove('is-loading');
    }
  }

  async function stopUnitPermanentUnlock(unit) {
    if (!window.confirm(`Opravdu uzamknout jednotku „${unit.name}“?`)) return;
    try {
      const response = await fetch('/api/permanent-unlock/stop', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ unit_id: unit.id })
      });
      const data = await response.json().catch(() => null);
      if (!response.ok || !data || !data.success) {
        throw new Error((data && data.message) || 'Jednotku se nepodařilo uzamknout.');
      }
      showToast(data.message || `Jednotka „${unit.name}“ byla uzamčena.`, 'success');
      await Promise.all([loadUserUnits(), fetchPermanentUnlockStatus()]);
    } catch (error) {
      showToast(error.message || 'Jednotku se nepodařilo uzamknout.', 'error');
    }
  }

  async function probeSingleUrl(url, timeoutMs = 1800) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      await fetch(url, { method: 'GET', mode: 'no-cors', cache: 'no-store', signal: controller.signal });
      clearTimeout(timer);
      return true;
    } catch (_) {
      clearTimeout(timer);
      return false;
    }
  }

  async function runNetworkProbe() {
    if (serverNetworkAllowed) {
      isProbeVerified = true;
      isNetworkAllowed = true;
      unitProbeVerified = new Set(userUnits.filter(unit => unit.selected).map(unit => unit.id));
      updateNetworkUi(true);
      return;
    }

    if (isProbing) {
      networkProbeQueued = true;
      return;
    }
    isProbing = true;

    const timestamp = Date.now();
    const probeUnits = userUnits.filter(unit => unit.selected && !unit.access?.network_bypass);
    const taskUnits = probeUnits.length ? probeUnits : (!userUnits.length && deviceIp ? [{
      id: null, ip: deviceIp, protocol: deviceProtocol, port: devicePort
    }] : []);
    const tasks = taskUnits.map(async unit => {
      const host = unit.ip.includes(':') && !unit.ip.startsWith('[') ? `[${unit.ip}]` : unit.ip;
      const options = [
        `${unit.protocol}://${host}:${unit.port}`,
        `https://${host}`,
        `http://${host}`
      ];
      const results = await Promise.all([...new Set(options)].map(origin =>
        probeSingleUrl(`${origin}/api/switch/caps?_t=${timestamp}`)
      ));
      return { id: unit.id, ok: results.some(Boolean) };
    });

    try {
      const results = await Promise.allSettled(tasks);
      unitProbeVerified = new Set(results
        .filter(result => result.status === 'fulfilled' && result.value.ok && result.value.id !== null)
        .map(result => result.value.id));
      isProbeVerified = results.some(result => result.status === 'fulfilled' && result.value.ok);
      isNetworkAllowed = serverNetworkAllowed || isProbeVerified;
      updateNetworkUi(isNetworkAllowed || userUnits.some(unit => unit.selected && unit.access?.network_bypass));
    } finally {
      isProbing = false;
      if (networkProbeQueued) {
        networkProbeQueued = false;
        runNetworkProbe();
      }
    }
  }

  if (retryProbeBtn) {
    retryProbeBtn.addEventListener('click', async () => {
      retryProbeBtn.disabled = true;
      retryProbeBtn.textContent = 'Ověřuji...';
      await runNetworkProbe();
      retryProbeBtn.disabled = false;
      retryProbeBtn.textContent = 'Ověřit síť znovu';
    });
  }

  // ==========================================================================
  // ODEMYKÁNÍ DVEŘÍ
  // ==========================================================================
  function resetDoorButton() {
    isSending = false;
    if (webUnlockBlocked) {
      updateNetworkUi(isNetworkAllowed);
      return;
    }
    if (permanentUnlockActive) {
      doorBtn.disabled = false;
      doorBtn.className = 'door-btn-orig permanent';
      doorWrapper.className = 'door-wrapper permanent';
      doorBtnText.textContent = 'TRVALE ODEMČENO';
      if (svgSpinner) svgSpinner.classList.add('hidden');
      if (svgBlockedCross) svgBlockedCross.classList.add('hidden');
      if (svgLocked) svgLocked.classList.add('hidden');
      if (svgUnlocked) svgUnlocked.classList.remove('hidden');
      return;
    }
    doorBtn.disabled = !isNetworkAllowed;
    svgSpinner.classList.add('hidden');
    svgUnlocked.classList.add('hidden');
    if (!isNetworkAllowed) {
      if (svgLocked) svgLocked.classList.add('hidden');
      if (svgBlockedCross) svgBlockedCross.classList.remove('hidden');
      doorBtn.className = 'door-btn-orig blocked';
      doorWrapper.className = 'door-wrapper blocked';
      doorBtnText.textContent = 'BLOKOVÁNO';
      doorBtnSubtext.textContent = 'Bypass nepovolen';
    } else {
      if (svgBlockedCross) svgBlockedCross.classList.add('hidden');
      if (svgLocked) svgLocked.classList.remove('hidden');
      doorBtn.className = 'door-btn-orig';
      doorWrapper.className = 'door-wrapper';
      doorBtnText.textContent = 'ODEMKNOUT';
      doorBtnSubtext.textContent = 'Stiskněte pro otevření';
    }
  }

  doorBtn.addEventListener('click', async () => {
    if (permanentUnlockActive) {
      showToast('Zámek je trvale odemčen. Pro uzamčení stiskněte tlačítko „Znovu uzamknout“.', 'info');
      return;
    }
    if (isSending || doorBtn.disabled) return;
    isSending = true;
    doorBtn.disabled = true;

    svgLocked.classList.add('hidden');
    svgUnlocked.classList.add('hidden');
    svgSpinner.classList.remove('hidden');
    doorBtnText.textContent = 'ODESÍLÁM...';
    doorBtnSubtext.textContent = 'Komunikuji s 2N';
    doorBtn.className = 'door-btn-orig sending';

    if ('vibrate' in navigator) {
      try { navigator.vibrate(50); } catch (_) {}
    }

    try {
      const res = await fetch('/api/unlock', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ client_probe_ok: isProbeVerified })
      });

      const data = await res.json().catch(() => null);

      if (res.ok && data && data.success) {
        svgSpinner.classList.add('hidden');
        svgUnlocked.classList.remove('hidden');
        doorBtnText.textContent = 'ODEMČENO';
        doorBtnSubtext.textContent = 'Dveře jsou otevřeny';
        doorBtn.className = 'door-btn-orig unlocked';
        doorWrapper.className = 'door-wrapper unlocked';

        showToast(data.message || 'Dveře byly úspěšně odemčeny na 5 sekund.', 'success');

        if ('vibrate' in navigator) {
          try { navigator.vibrate([70, 50, 70]); } catch (_) {}
        }

        setTimeout(() => resetDoorButton(), 5000);
      } else {
        if (res.status === 401) {
          window.location.href = '/login';
          return;
        }

        svgSpinner.classList.add('hidden');
        svgLocked.classList.remove('hidden');
        doorBtnText.textContent = 'CHYBA';
        doorBtnSubtext.textContent = 'Zkuste znovu';
        doorBtn.className = 'door-btn-orig error';
        doorWrapper.className = 'door-wrapper error';

        showToast((data && data.message) || 'Nepodařilo se sepnout zámek 2N.', 'error');

        setTimeout(() => resetDoorButton(), 4000);
      }
    } catch (err) {
      svgSpinner.classList.add('hidden');
      svgLocked.classList.remove('hidden');
      doorBtnText.textContent = 'CHYBA SÍTĚ';
      doorBtnSubtext.textContent = 'Nedostupný server';
      doorBtn.className = 'door-btn-orig error';
      doorWrapper.className = 'door-wrapper error';

      showToast('Chyba spojení se serverem.', 'error');

      setTimeout(() => resetDoorButton(), 4000);
    }
  });

  // ==========================================================================
  // SYSTÉMOVÝ LOG (SPRÁVNÉ MAPOVÁNÍ KLÍČŮ: time, level, title, message)
  // ==========================================================================
  async function fetchLogs() {
    if (refreshLogsBtn) {
      refreshLogsBtn.disabled = true;
      const svg = refreshLogsBtn.querySelector('svg');
      if (svg) svg.classList.add('animate-spin');
    }

    try {
      const source = logSourceFilter ? logSourceFilter.value : 'all';
      const res = await fetch(`/api/logs?source=${encodeURIComponent(source)}`, { cache: 'no-store' });
      if (res.ok) {
        const data = await res.json();
        renderLogs(data.logs || []);
      } else {
        const data = await res.json().catch(() => null);
        if (res.status === 403) {
          showToast((data && data.message) || 'Na tuto akci nemáte právo. Obraťte se na správce systému.', 'error');
        }
        logsTableBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-rose-500">Chyba při načítání záznamů.</td></tr>`;
      }
    } catch (_) {
      logsTableBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-rose-500">Chyba při načítání záznamů.</td></tr>`;
    } finally {
      if (refreshLogsBtn) {
        setTimeout(() => {
          refreshLogsBtn.disabled = false;
          const svg = refreshLogsBtn.querySelector('svg');
          if (svg) svg.classList.remove('animate-spin');
        }, 300);
      }
    }
  }

  function renderLogs(logs) {
    if (!logs || logs.length === 0) {
      logsTableBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-gray-400 font-sans">Žádné záznamy pro tento zdroj.</td></tr>`;
      return;
    }

    logsTableBody.innerHTML = '';
    // Zobrazit záznamy od nejnovějších
    const displayLogs = [...logs].reverse().slice(0, 100);

    displayLogs.forEach(log => {
      const tr = document.createElement('tr');
      tr.className = 'hover:bg-gray-50/50 dark:hover:bg-gray-800/30 transition-colors';

      const level = (log.level || 'info').toLowerCase();
      let badgeClass = 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300';
      if (level === 'success') badgeClass = 'bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400';
      if (level === 'warning') badgeClass = 'bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400';
      if (level === 'error') badgeClass = 'bg-rose-50 text-rose-700 dark:bg-rose-500/10 dark:text-rose-400';
      if (level === 'info') badgeClass = 'bg-brand-50 text-brand-700 dark:bg-brand-500/10 dark:text-brand-400';

      const logTime = log.time || log.timestamp || '—';
      const logAction = log.title || log.action || '—';
      const logMsg = log.message || '';

      const timeCell = document.createElement('td');
      timeCell.className = 'px-4 py-2.5 whitespace-nowrap text-gray-500 dark:text-gray-400 font-mono text-[11px]';
      timeCell.textContent = logTime;
      const levelCell = document.createElement('td');
      levelCell.className = 'px-4 py-2.5 whitespace-nowrap';
      const badge = document.createElement('span');
      badge.className = `inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase ${badgeClass}`;
      badge.textContent = level.toUpperCase();
      levelCell.appendChild(badge);
      const sourceCell = document.createElement('td');
      sourceCell.className = 'px-4 py-2.5 whitespace-nowrap text-gray-600 dark:text-gray-300';
      sourceCell.textContent = log.source_type === 'unit' && log.unit_name ? log.unit_name : 'Systém';
      const actionCell = document.createElement('td');
      actionCell.className = 'px-4 py-2.5 whitespace-nowrap font-semibold text-gray-900 dark:text-white';
      actionCell.textContent = logAction;
      const messageCell = document.createElement('td');
      messageCell.className = 'px-4 py-2.5 text-gray-600 dark:text-gray-300';
      messageCell.textContent = logMsg;
      tr.append(timeCell, levelCell, sourceCell, actionCell, messageCell);
      logsTableBody.appendChild(tr);
    });
  }

  if (refreshLogsBtn) refreshLogsBtn.addEventListener('click', fetchLogs);
  if (logSourceFilter) logSourceFilter.addEventListener('change', fetchLogs);

  if (clearLogsBtn) {
    clearLogsBtn.addEventListener('click', async () => {
      if (!confirm('Opravdu si přejete smazat historii záznamů?')) return;
      try {
        const res = await fetch('/api/logs/clear', { method: 'POST', headers: authHeaders() });
        if (!res.ok) {
          const data = await res.json().catch(() => null);
          showToast((data && data.message) || 'Na tuto akci nemáte právo. Obraťte se na správce systému.', 'error');
          return;
        }
        showToast('Záznamy byly úspěšně vymazány.', 'info');
        fetchLogs();
      } catch (_) {
        showToast('Chyba při mazání záznamů.', 'error');
      }
    });
  }

  // ==========================================================================
  // INFORMACE O JEDNOTCE 2N (ADMIN ONLY)
  // ==========================================================================
  function showUnitPreferencesAlert(message, isError = false) {
    if (!userUnitPreferencesAlert) return;
    userUnitPreferencesAlert.textContent = message;
    userUnitPreferencesAlert.className = isError
      ? 'mt-3 rounded-xl border border-rose-200 bg-rose-50 p-2 text-xs font-medium text-rose-700 dark:border-rose-900/50 dark:bg-rose-950/20 dark:text-rose-300'
      : 'mt-3 rounded-xl border border-emerald-200 bg-emerald-50 p-2 text-xs font-medium text-emerald-700 dark:border-emerald-900/50 dark:bg-emerald-950/20 dark:text-emerald-300';
  }

  function renderUserUnitPreferences() {
    if (!userUnitPreferences) return;
    userUnitPreferences.replaceChildren();
    if (userUnits.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'text-gray-500';
      empty.textContent = 'Zatím není přidána žádná jednotka.';
      userUnitPreferences.appendChild(empty);
      if (saveUserUnitsBtn) saveUserUnitsBtn.disabled = true;
      return;
    }

    userUnits.forEach(unit => {
      const label = document.createElement('label');
      label.className = 'flex cursor-pointer items-center gap-2 rounded-xl border border-gray-200 bg-white px-3 py-2 dark:border-gray-700 dark:bg-gray-900';
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.value = String(unit.id);
      checkbox.checked = Boolean(unit.selected);
      checkbox.className = 'h-4 w-4 rounded text-brand-600 focus:ring-brand-500';
      const copy = document.createElement('span');
      copy.className = 'min-w-0 flex-1';
      const name = document.createElement('span');
      name.className = 'block truncate font-semibold text-gray-800 dark:text-gray-200';
      name.textContent = unit.name;
      const model = document.createElement('span');
      model.className = 'block truncate text-[11px] text-gray-500 dark:text-gray-400';
      model.textContent = unit.model;
      copy.append(name, model);
      label.append(checkbox, copy);
      userUnitPreferences.appendChild(label);
    });
    if (saveUserUnitsBtn) saveUserUnitsBtn.disabled = false;
  }

  function renderLogSourceFilter() {
    if (!logSourceFilter) return;
    const selected = logSourceFilter.value;
    logSourceFilter.replaceChildren();
    [
      ['all', 'Všechny zdroje'],
      ['system', 'Systém']
    ].forEach(([value, label]) => {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = label;
      logSourceFilter.appendChild(option);
    });
    userUnits.filter(unit => unit.selected).forEach(unit => {
      const option = document.createElement('option');
      option.value = String(unit.id);
      option.textContent = unit.name;
      logSourceFilter.appendChild(option);
    });
    if (Array.from(logSourceFilter.options).some(option => option.value === selected)) {
      logSourceFilter.value = selected;
    }
  }

  async function loadUserUnits() {
    try {
      const response = await fetch('/api/user/units', { cache: 'no-store' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Jednotky se nepodařilo načíst.');
      userUnits = Array.isArray(data.units) ? data.units : [];
      updatePermanentControlsVisibility();
      renderLogSourceFilter();
      renderHomeUnitCards();
      renderUserUnitPreferences();
      if (!currentUserBypass) runNetworkProbe();
    } catch (error) {
      showToast(error.message || 'Chyba při načítání jednotek.', 'error');
    }
  }

  async function saveUserUnitPreferences() {
    const unitIds = Array.from(userUnitPreferences.querySelectorAll('input[type="checkbox"]:checked'))
      .map(input => Number(input.value));
    saveUserUnitsBtn.disabled = true;
    try {
      const response = await fetch('/api/user/units', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ unit_ids: unitIds })
      });
      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.message || 'Výběr jednotek se nepodařilo uložit.');
      }
      showUnitPreferencesAlert('Výběr jednotek byl uložen.');
      await loadUserUnits();
      showToast('Zobrazené jednotky a oznámení byly aktualizovány.', 'success');
    } catch (error) {
      showUnitPreferencesAlert(error.message || 'Výběr jednotek se nepodařilo uložit.', true);
    } finally {
      saveUserUnitsBtn.disabled = false;
    }
  }

  function renderManagedUnits(units) {
    if (!unitsList) return;
    unitsList.replaceChildren();
    if (units.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'py-4 text-center text-xs text-gray-500';
      empty.textContent = 'Aplikace zatím nemá zaregistrovanou žádnou jednotku.';
      unitsList.appendChild(empty);
      return;
    }

    units.forEach(unit => {
      const row = document.createElement('article');
      row.className = 'flex flex-col gap-3 rounded-xl border border-gray-200 p-3 sm:flex-row sm:items-center sm:justify-between dark:border-gray-700';
      const details = document.createElement('div');
      details.className = 'min-w-0';
      const name = document.createElement('h4');
      name.className = 'truncate text-sm font-semibold text-gray-900 dark:text-white';
      name.textContent = unit.name;
      const model = document.createElement('p');
      model.className = 'text-xs text-gray-500 dark:text-gray-400';
      model.textContent = `${unit.model} · ${unit.ip}`;
      const status = document.createElement('p');
      status.className = unit.connected
        ? 'mt-1 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400'
        : 'mt-1 text-[11px] font-semibold text-amber-600 dark:text-amber-400';
      status.textContent = unit.connected
        ? `Připojeno${unit.last_seen ? ` · naposledy ${new Date(`${unit.last_seen}Z`).toLocaleString()}` : ''}`
        : 'Nedostupné · čeká na spojení';
      details.append(name, model, status);
      row.appendChild(details);

      const actions = document.createElement('div');
      actions.className = 'flex shrink-0 gap-2';
      const rename = document.createElement('button');
      rename.type = 'button';
      rename.className = 'rounded-lg border border-gray-200 px-3 py-1.5 text-xs font-semibold text-gray-700 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-300 dark:hover:bg-gray-800';
      rename.textContent = 'Přejmenovat';
      rename.addEventListener('click', async () => {
        const newName = window.prompt('Nový název jednotky:', unit.name);
        if (newName === null || newName.trim() === unit.name) return;
        rename.disabled = true;
        try {
          const response = await fetch(`/api/units/${unit.id}`, {
            method: 'PATCH',
            headers: authHeaders(),
            body: JSON.stringify({ name: newName.trim() })
          });
          const data = await response.json();
          if (!response.ok || !data.success) throw new Error(data.message || 'Jednotku se nepodařilo přejmenovat.');
          showToast(data.message || 'Jednotka byla přejmenována.', 'success');
          await Promise.all([loadManagedUnits(), loadUserUnits()]);
        } catch (error) {
          showToast(error.message || 'Jednotku se nepodařilo přejmenovat.', 'error');
          rename.disabled = false;
        }
      });
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'rounded-lg border border-rose-200 px-3 py-1.5 text-xs font-semibold text-rose-700 hover:bg-rose-50 dark:border-rose-900/50 dark:text-rose-300 dark:hover:bg-rose-950/30';
      remove.textContent = 'Odebrat';
      remove.addEventListener('click', async () => {
        if (!window.confirm(`Opravdu odebrat jednotku „${unit.name}“? Tuto akci nelze vrátit.`)) return;
        remove.disabled = true;
        try {
          const response = await fetch(`/api/units/${unit.id}`, {
            method: 'DELETE',
            headers: authHeaders()
          });
          const data = await response.json();
          if (!response.ok || !data.success) throw new Error(data.message || 'Jednotku se nepodařilo odebrat.');
          showToast('Jednotka byla odebrána.', 'success');
          await Promise.all([loadManagedUnits(), loadUserUnits()]);
        } catch (error) {
          showToast(error.message || 'Jednotku se nepodařilo odebrat.', 'error');
          remove.disabled = false;
        }
      });
      actions.append(rename, remove);
      row.appendChild(actions);
      unitsList.appendChild(row);
    });
  }

  async function loadManagedUnits() {
    if (!unitsList) return;
    if (unitsList.children.length === 0) {
      unitsList.textContent = 'Načítám jednotky…';
    }
    try {
      const response = await fetch('/api/units', { cache: 'no-store' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Jednotky se nepodařilo načíst.');
      unitTypes = Array.isArray(data.unit_types) ? data.unit_types : [];
      if (unitModelInput && unitTypes.length) {
        const currentValue = unitModelInput.value;
        unitModelInput.replaceChildren();
        unitTypes.forEach(modelName => {
          const option = document.createElement('option');
          option.value = modelName;
          option.textContent = modelName;
          unitModelInput.appendChild(option);
        });
        if (unitTypes.includes(currentValue)) unitModelInput.value = currentValue;
      }
      renderManagedUnits(Array.isArray(data.units) ? data.units : []);
    } catch (error) {
      unitsList.textContent = error.message || 'Chyba při načítání jednotek.';
    }
  }

  function setNtpAlert(message, type = 'error') {
    if (!ntpSettingsAlert) return;
    const styles = {
      success: 'rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-xs font-medium text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-300',
      warning: 'rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs font-medium text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300',
      error: 'rounded-xl border border-rose-200 bg-rose-50 p-3 text-xs font-medium text-rose-700 dark:border-rose-900/60 dark:bg-rose-950/30 dark:text-rose-300'
    };
    ntpSettingsAlert.textContent = message;
    ntpSettingsAlert.className = styles[type] || styles.error;
  }

  function renderNtpStatus(data) {
    if (!ntpStatus || !ntpLastSync) return;
    if (!data.ntp_server) {
      ntpStatus.textContent = 'Synchronizace NTP je vypnutá; aplikace používá čas hostitele.';
      ntpLastSync.textContent = '';
      return;
    }

    const offset = Number(data.offset_seconds || 0);
    const offsetText = `${offset >= 0 ? '+' : ''}${offset.toFixed(3)} s`;
    ntpStatus.textContent = data.synchronized
      ? `Synchronizováno s ${data.ntp_server} · korekce ${offsetText}`
      : (data.error || `Čeká se na synchronizaci s ${data.ntp_server}.`);
    ntpLastSync.textContent = data.last_sync
      ? `Poslední úspěšná synchronizace: ${new Date(data.last_sync).toLocaleString('cs-CZ', { timeZone: 'Europe/Prague' })}`
      : 'Zatím neproběhla úspěšná synchronizace.';
  }

  async function loadGlobalSettings() {
    try {
      const response = await fetch('/api/global-settings', { cache: 'no-store' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Globální nastavení se nepodařilo načíst.');
      if (ntpServerInput) ntpServerInput.value = data.ntp_server || '';
      renderNtpStatus(data);
    } catch (error) {
      if (ntpStatus) ntpStatus.textContent = error.message || 'Stav NTP se nepodařilo načíst.';
    }
  }

  async function saveNtpSettings(server) {
    const buttons = [saveNtpBtn, disableNtpBtn].filter(Boolean);
    buttons.forEach(button => { button.disabled = true; });
    if (saveNtpBtn) saveNtpBtn.textContent = 'Ukládám…';
    if (ntpSettingsAlert) ntpSettingsAlert.classList.add('hidden');

    try {
      const response = await fetch('/api/global-settings', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ ntp_server: server })
      });
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.message || 'NTP nastavení se nepodařilo uložit.');
      renderNtpStatus(data);
      setNtpAlert(data.message, data.ntp_server && !data.synchronized ? 'warning' : 'success');
    } catch (error) {
      setNtpAlert(error.message || 'NTP nastavení se nepodařilo uložit.');
      await loadGlobalSettings();
    } finally {
      buttons.forEach(button => { button.disabled = false; });
      if (saveNtpBtn) saveNtpBtn.textContent = 'Ověřit server a uložit';
    }
  }

  if (ntpSettingsForm) {
    ntpSettingsForm.addEventListener('submit', event => {
      event.preventDefault();
      saveNtpSettings(ntpServerInput ? ntpServerInput.value : '');
    });
  }
  if (disableNtpBtn) {
    disableNtpBtn.addEventListener('click', () => {
      if (ntpServerInput) ntpServerInput.value = '';
      saveNtpSettings('');
    });
  }

  if (refreshUnitsBtn) refreshUnitsBtn.addEventListener('click', loadManagedUnits);
  if (saveUserUnitsBtn) saveUserUnitsBtn.addEventListener('click', saveUserUnitPreferences);

  if (addUnitForm) {
    addUnitForm.addEventListener('submit', async event => {
      event.preventDefault();
      addUnitAlert.classList.add('hidden');
      addUnitSubmitBtn.disabled = true;
      addUnitSubmitBtn.textContent = 'Ověřuji API…';
      try {
        const response = await fetch('/api/units', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({
            name: unitNameInput.value,
            model: unitModelInput.value,
            ip: unitIpInput.value,
            api_username: unitApiUserInput.value,
            api_password: unitApiPasswordInput.value
          })
        });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.message || 'Jednotku se nepodařilo přidat.');
        addUnitForm.reset();
        unitApiPasswordInput.value = '';
        showToast(data.message || 'Jednotka byla přidána.', 'success');
        await Promise.all([loadManagedUnits(), loadUserUnits()]);
      } catch (error) {
        addUnitAlert.textContent = error.message || 'Jednotku se nepodařilo přidat.';
        addUnitAlert.className = 'sm:col-span-2 rounded-xl border border-rose-200 bg-rose-50 p-3 text-xs font-medium text-rose-700 dark:border-rose-900/50 dark:bg-rose-950/20 dark:text-rose-300';
      } finally {
        addUnitSubmitBtn.disabled = false;
        addUnitSubmitBtn.textContent = 'Ověřit a přidat jednotku';
      }
    });
  }

  async function loadConfig(preferredUnitId) {
    try {
      const unitsResponse = await fetch('/api/user/units', { cache: 'no-store' });
      const unitsData = await unitsResponse.json();
      if (!unitsResponse.ok) throw new Error(unitsData.message || 'Jednotky se nepodařilo načíst.');
      const units = (unitsData.units || []).filter(unit => currentUserRole === 'admin' || unit.selected);
      if (infoUnitSelect) {
        const currentValue = preferredUnitId || infoUnitSelect.value;
        infoUnitSelect.replaceChildren();
        units.forEach(unit => {
          const option = document.createElement('option');
          option.value = String(unit.id);
          option.textContent = unit.name;
          infoUnitSelect.appendChild(option);
        });
        if (currentValue && units.some(unit => String(unit.id) === String(currentValue))) {
          infoUnitSelect.value = String(currentValue);
        } else if (units.length) {
          infoUnitSelect.value = String(units[0].id);
        }
      }
      const unitId = infoUnitSelect ? infoUnitSelect.value : String(units[0]?.id || '');
      if (!unitId) {
        if (infoApiStatus) {
          infoApiStatus.textContent = 'Žádná jednotka';
          infoApiStatus.className = 'font-medium text-amber-600 dark:text-amber-400';
        }
        return;
      }
      const response = await fetch(`/api/units/${encodeURIComponent(unitId)}/info`, { cache: 'no-store' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Informace jednotky se nepodařilo načíst.');
      const unit = data.unit || {};
      if (infoApiStatus) {
        const status = data.unit_details
          ? ['Připojeno', 'text-emerald-600 dark:text-emerald-400']
          : ['Nedostupné', 'text-rose-600 dark:text-rose-400'];
        infoApiStatus.textContent = status[0];
        infoApiStatus.className = `font-medium ${status[1]}`;
      }
      if (infoDeviceIp) infoDeviceIp.textContent = unit.ip || 'Nevyplněno';
      if (infoProtocolPort) infoProtocolPort.textContent = `${(unit.protocol || 'https').toUpperCase()} / Port ${unit.port || 443}`;
      if (infoSwitchId) infoSwitchId.textContent = `Spínač ${data.switch_id || 1}`;
      if (infoApiUser) infoApiUser.textContent = unit.api_username || 'Nevyplněno';
      if (infoAuthType) infoAuthType.textContent = unit.auth_type === 'digest' ? 'HTTP Digest Auth' : 'HTTP Basic Auth';
      const infoUnitName = document.getElementById('infoUnitName');
      if (infoUnitName) infoUnitName.textContent = unit.name || '—';
      const infoAllowedSubnets = document.getElementById('infoAllowedSubnets');
      if (infoAllowedSubnets) infoAllowedSubnets.textContent = data.allowed_subnets || 'Není nastaveno';

      const details = data.unit_details;
      const infoDeviceModel = document.getElementById('infoDeviceModel');
      const infoSerialNumber = document.getElementById('infoSerialNumber');
      const infoMacAddress = document.getElementById('infoMacAddress');
      const infoHwVersion = document.getElementById('infoHwVersion');
      const infoSwVersion = document.getElementById('infoSwVersion');
      const infoFirmwarePackage = document.getElementById('infoFirmwarePackage');
      if (infoDeviceModel) infoDeviceModel.textContent = details?.variant || details?.deviceName || details?.deviceModel || unit.model || '—';
      if (infoSerialNumber) infoSerialNumber.textContent = details?.serialNumber || details?.serial || '—';
      if (infoMacAddress) infoMacAddress.textContent = (details?.macAddr || details?.macAddress || details?.mac || '—').toUpperCase();
      if (infoHwVersion) infoHwVersion.textContent = details?.hwVersion || details?.hardwareVersion || '—';
      if (infoSwVersion) infoSwVersion.textContent = details?.swVersion || details?.softwareVersion || details?.version || '—';
      if (infoFirmwarePackage) {
        const pkg = details?.firmwarePackage || details?.package || '—';
        const bld = details?.buildType ? ` (${details.buildType})` : '';
        infoFirmwarePackage.textContent = `${pkg}${bld}`;
      }
    } catch (error) {
      console.error('Chyba při načítání informací o jednotce:', error);
      if (infoApiStatus) {
        infoApiStatus.textContent = error.message || 'Nedostupné';
        infoApiStatus.className = 'font-medium text-rose-600 dark:text-rose-400';
      }
    }
  }

  if (infoUnitSelect) infoUnitSelect.addEventListener('change', () => loadConfig(infoUnitSelect.value));

  if (testConnectionBtn) {
    testConnectionBtn.addEventListener('click', async () => {
      testConnectionBtn.disabled = true;
      testConnectionBtnText.textContent = 'Testuji...';
      testConnAlert.classList.add('hidden');

      try {
        await loadConfig(infoUnitSelect?.value);
        if (infoApiStatus?.textContent === 'Připojeno') showToast('Spojení s jednotkou je plně funkční.', 'success');
        else showToast(infoApiStatus?.textContent || 'Test spojení selhal.', 'error');
      } catch (e) {
        showToast('Chyba sítě při testu spojení.', 'error');
      } finally {
        testConnectionBtn.disabled = false;
        testConnectionBtnText.textContent = 'Otestovat spojení';
      }
    });
  }

  // ==========================================================================
  // SPRÁVA UŽIVATELŮ (ADMIN ONLY)
  // ==========================================================================
  if (openAddUserBtn) {
    openAddUserBtn.addEventListener('click', () => {
      addUserCard.classList.toggle('hidden');
      if (addUserAlert) addUserAlert.classList.add('hidden');
      const isAdmin = (currentUserRole === 'admin');
      if (newRoleAdminOption) {
        newRoleAdminOption.hidden = !isAdmin;
        newRoleAdminOption.disabled = !isAdmin;
      }
      const newRoleSupervisorOption = newRoleSelect.querySelector('option[value="správce"]');
      if (newRoleSupervisorOption) {
        newRoleSupervisorOption.hidden = !isAdmin;
        newRoleSupervisorOption.disabled = !isAdmin;
      }
      if (newUserBypassWrapper) {
        newUserBypassWrapper.style.display = isAdmin ? 'flex' : 'none';
      }
      if (!isAdmin && newRoleSelect && newRoleSelect.value !== 'user') {
        newRoleSelect.value = 'user';
      }
    });
  }

  if (cancelAddUserBtn) {
    cancelAddUserBtn.addEventListener('click', () => {
      addUserCard.classList.add('hidden');
      addUserForm.reset();
    });
  }

  let cachedUsersList = [];
  let shouldUnlockAccountOnSave = false;

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function loadUsers() {
    try {
      if (usersListContainer) {
        usersListContainer.innerHTML = `
          <div class="ou-users-loading">
            <div class="ou-spinner"></div>
            <span>Načítám uživatele...</span>
          </div>
        `;
      }
      const res = await fetch('/api/users');
      if (res.ok) {
        const data = await res.json();
        cachedUsersList = data.users || [];
        renderUsers(cachedUsersList);
      } else {
        const data = await res.json().catch(() => null);
        if (res.status === 403) {
          showToast((data && data.message) || 'Na tuto akci nemáte právo. Obraťte se na správce systému.', 'error');
        }
        if (usersListContainer) {
          usersListContainer.innerHTML = `<div class="ou-users-empty text-rose-500">Přístup odepřen nebo chyba načítání.</div>`;
        }
      }
    } catch (_) {
      if (usersListContainer) {
        usersListContainer.innerHTML = `<div class="ou-users-empty text-rose-500">Chyba sítě při načítání uživatelů.</div>`;
      }
    }
  }

  function renderUsers(users) {
    if (!usersListContainer) return;

    if (!users || users.length === 0) {
      usersListContainer.innerHTML = `
        <div class="ou-users-empty">
          <svg class="h-8 w-8 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
            <circle cx="9" cy="7" r="4"></circle>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
          </svg>
          <span>Žádní uživatelé nebyli nalezeni.</span>
        </div>
      `;
      return;
    }

    usersListContainer.innerHTML = '';
    const isAdmin = (currentUserRole === 'admin');

    users.forEach(u => {
      const initial = (u.username || '?').charAt(0).toUpperCase();
      const isSelf = (u.username.toLowerCase() === currentUsername.toLowerCase());
      const isProtectedUser = (u.username.toLowerCase() === 'admin');

      // Avatar class
      let avatarClass = 'ou-avatar-user';
      if (u.role === 'admin') avatarClass = 'ou-avatar-admin';
      else if (u.role === 'správce') avatarClass = 'ou-avatar-spravce';

      // Role badge
      let roleBadgeHtml = '';
      if (u.role === 'admin') {
        roleBadgeHtml = `<span class="ou-badge ou-badge-role-admin">Administrátor</span>`;
      } else if (u.role === 'správce') {
        roleBadgeHtml = `<span class="ou-badge ou-badge-role-spravce">Správce</span>`;
      } else {
        roleBadgeHtml = `<span class="ou-badge ou-badge-role-user">Uživatel</span>`;
      }

      // Status badge
      let statusBadgeHtml = '';
      if (u.is_disabled) {
        statusBadgeHtml = `<span class="ou-badge ou-badge-status-disabled">Deaktivován</span>`;
      } else if (u.is_locked) {
        statusBadgeHtml = `<span class="ou-badge ou-badge-status-locked">Uzamčen</span>`;
      } else {
        statusBadgeHtml = `<span class="ou-badge ou-badge-status-active">Aktivní</span>`;
      }

      // Permissions chips
      let metaChips = [];
      if (u.network_bypass) {
        metaChips.push(`<span class="ou-chip">🌐 Bypass sítě</span>`);
      }
      if (u.permanent_unlock_allowed) {
        const dur = (u.permanent_unlock_max_duration || 60);
        const durText = (dur >= 60 && dur % 60 === 0) ? `${dur / 60} h` : `${dur} min`;
        metaChips.push(`<span class="ou-chip ou-chip-permanent">⏱️ Trvalé (max. ${durText})</span>`);
      }
      if (!u.can_unlock) {
        metaChips.push(`<span class="ou-chip ou-chip-danger">🚫 Odemykání zakázáno</span>`);
      }
      if (u.time_restricted) {
        metaChips.push(`<span class="ou-chip ou-chip-time">📅 Rozvrh aktivní</span>`);
      }
      if (u.sidebar_menu && Array.isArray(u.sidebar_menu)) {
        metaChips.push(`<span class="ou-chip">🧭 Menu: ${u.sidebar_menu.length}</span>`);
      }
      if (u.can_manage_users) {
        metaChips.push(`<span class="ou-chip ou-chip-permanent">👥 Správa uživatelů</span>`);
      }

      const noteHtml = u.user_note ? `<span class="ou-user-note" title="${escapeHtml(u.user_note)}">${escapeHtml(u.user_note)}</span>` : '';
      const chipsHtml = metaChips.join(' ');

      // Delete button
      const canDelete = isAdmin
        ? (!isSelf && !isProtectedUser)
        : (!isSelf && !isProtectedUser && Boolean(currentUserManagePermissions.can_delete_users) && (isAdmin || u.role === 'user'));

      const deleteBtnHtml = canDelete ? `
        <button type="button" data-user-id="${u.id}" class="ou-btn-delete delete-user-btn" title="Smazat uživatele">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
        </button>
      ` : '';

      const row = document.createElement('div');
      row.className = 'ou-user-row';
      row.innerHTML = `
        <div class="ou-user-left">
          <div class="ou-user-avatar ${avatarClass}">${initial}</div>
          <div class="ou-user-info">
            <div class="ou-user-header-line">
              <span class="ou-user-name">${escapeHtml(u.username)}</span>
              ${isSelf ? '<span class="ou-badge ou-badge-self">Vy</span>' : ''}
              ${roleBadgeHtml}
              ${statusBadgeHtml}
            </div>
            <div class="ou-user-meta-line">
              ${noteHtml}
              ${chipsHtml || '<span class="text-[11px] text-gray-400">Základní oprávnění</span>'}
            </div>
          </div>
        </div>
        <div class="ou-user-right">
          <button type="button" data-user-id="${u.id}" class="ou-btn-perm open-perm-modal-btn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
            <span>Oprávnění</span>
          </button>
          ${deleteBtnHtml}
        </div>
      `;
      usersListContainer.appendChild(row);
    });

    // Listenery pro otevření modalu oprávnění
    document.querySelectorAll('.open-perm-modal-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const uId = parseInt(btn.getAttribute('data-user-id'), 10);
        openUserPermissionsModal(uId);
      });
    });

    // Listenery pro smazání
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const uId = btn.getAttribute('data-user-id');
        if (!confirm('Opravdu smazat tohoto uživatele?')) return;
        try {
          const res = await fetch(`/api/users/${uId}`, {
            method: 'DELETE',
            headers: authHeaders()
          });
          const resData = await res.json();
          if (res.ok) {
            showToast('Uživatel byl smazán.', 'success');
            loadUsers();
          } else {
            showToast(resData.message || 'Chyba při mazání.', 'error');
          }
        } catch (_) {
          showToast('Chyba sítě.', 'error');
        }
      });
    });
  }

  async function openUserPermissionsModal(userId) {
    const user = cachedUsersList.find(u => u.id === userId);
    if (!user) {
      showToast('Uživatel nebyl nalezen.', 'error');
      return;
    }

    shouldUnlockAccountOnSave = false;
    permUserId.value = user.id;
    permModalUsernameDisplay.textContent = user.username;

    // Role badge
    permModalRoleBadge.textContent = user.role.toUpperCase();
    if (user.role === 'admin') {
      permModalRoleBadge.className = 'ml-1 inline-flex items-center rounded-md px-1.5 py-0.2 text-[10px] font-semibold bg-purple-50 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400';
    } else if (user.role === 'správce') {
      permModalRoleBadge.className = 'ml-1 inline-flex items-center rounded-md px-1.5 py-0.2 text-[10px] font-semibold bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400';
    } else {
      permModalRoleBadge.className = 'ml-1 inline-flex items-center rounded-md px-1.5 py-0.2 text-[10px] font-semibold bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300';
    }

    const isAdmin = (currentUserRole === 'admin');
    const isProtected = (user.username.toLowerCase() === 'admin');
    const isSelf = (user.username.toLowerCase() === currentUsername.toLowerCase());
    const callerPerms = currentUserManagePermissions || {};

    const canEditRole = isAdmin || (Boolean(callerPerms.can_edit_role) && !isProtected && !isSelf && user.role === 'user');
    const canEditBypass = isAdmin || (Boolean(callerPerms.can_edit_network_bypass) && !isProtected && !isSelf);
    const canEditUnlock = isAdmin || (Boolean(callerPerms.can_edit_can_unlock) && !isProtected && !isSelf);
    const canEditPermanent = isAdmin || (Boolean(callerPerms.can_edit_permanent_unlock) && !isProtected && !isSelf);
    const canEditTime = isAdmin || (Boolean(callerPerms.can_edit_time_restrictions) && !isProtected && !isSelf);
    const canEditMenu = isAdmin || (Boolean(callerPerms.can_edit_sidebar_menu) && !isProtected && !isSelf);
    const canEditNote = isAdmin || Boolean(callerPerms.can_edit_user_note);
    const canEditDisabled = (isAdmin && !isProtected) || (Boolean(callerPerms.can_edit_is_disabled) && !isProtected && !isSelf);
    const canResetPwd = isAdmin || Boolean(callerPerms.can_reset_password);
    const canEditMgmt = (isAdmin && !isProtected) || (Boolean(callerPerms.can_edit_management_rights) && !isProtected && !isSelf);
    const canDeleteThis = (isAdmin || Boolean(callerPerms.can_delete_users)) && !isSelf && !isProtected && (isAdmin || user.role === 'user');

    // Role select
    permRoleSelect.value = user.role;
    permRoleSelect.disabled = !canEditRole;
    const adminOpt = permRoleSelect.querySelector('option[value="admin"]');
    if (adminOpt) {
      adminOpt.disabled = !isAdmin;
      adminOpt.hidden = !isAdmin;
    }

    // Deaktivace účtu
    if (permDisabledToggle) {
      permDisabledToggle.checked = Boolean(user.is_disabled);
      permDisabledToggle.disabled = !canEditDisabled;
    }
    if (permDeactivatedBadge) {
      permDeactivatedBadge.classList.toggle('hidden', !user.is_disabled);
    }

    // Banner uzamčení
    if (user.is_locked) {
      permLockedBanner.classList.remove('hidden');
      permLockedBannerText.textContent = `Účet je uzamčen do ${user.locked_until ? user.locked_until.slice(11, 16) : 'odvolání'}`;
    } else {
      permLockedBanner.classList.add('hidden');
    }
    if (permUnlockAccountBtn) {
      permUnlockAccountBtn.disabled = !canEditDisabled;
    }

    // Network bypass
    permBypassToggle.checked = Boolean(user.network_bypass);
    permBypassToggle.disabled = !canEditBypass;

    // Can unlock + warning
    const canUnlockVal = (user.can_unlock !== undefined) ? Boolean(user.can_unlock) : true;
    permCanUnlockToggle.checked = canUnlockVal;
    permCanUnlockToggle.disabled = !canEditUnlock;
    if (permCanUnlockWarning) permCanUnlockWarning.classList.toggle('hidden', canUnlockVal);

    // Trvalé odemčení – ruční zadání (pokud jsou prvky v DOM)
    if (permPermanentToggle) {
      permPermanentToggle.checked = Boolean(user.permanent_unlock_allowed);
      permPermanentToggle.disabled = !canEditPermanent;
    }
    if (permPermanentConfigWrapper) {
      permPermanentConfigWrapper.classList.toggle('hidden', !user.permanent_unlock_allowed);
    }
    // Reset unit to minutes, fill value
    permDurationUnitIsHours = false;
    if (permDurationUnitMinutes) {
      permDurationUnitMinutes.classList.add('active-unit');
      permDurationUnitMinutes.classList.remove('text-gray-500', 'dark:text-gray-400');
      permDurationUnitMinutes.classList.add('text-gray-900', 'dark:text-white');
      permDurationUnitMinutes.disabled = !canEditPermanent;
    }
    if (permDurationUnitHours) {
      permDurationUnitHours.classList.remove('active-unit');
      permDurationUnitHours.classList.add('text-gray-500', 'dark:text-gray-400');
      permDurationUnitHours.classList.remove('text-gray-900', 'dark:text-white');
      permDurationUnitHours.disabled = !canEditPermanent;
    }
    const savedMinutes = user.permanent_unlock_max_duration || 60;
    if (permPermanentDurationValue) {
      permPermanentDurationValue.value = savedMinutes;
      permPermanentDurationValue.max = 1440;
      permPermanentDurationValue.disabled = !canEditPermanent;
    }
    updatePermDurationHint(savedMinutes);



    // Nové heslo a poznámka
    permNewPassword.value = '';
    permNewPassword.disabled = !canResetPwd;
    permUserNote.value = user.user_note || '';
    permUserNote.disabled = !canEditNote;

    // Položky bočního menu pro daného uživatele
    const userMenu = (Array.isArray(user.sidebar_menu) && user.sidebar_menu.length > 0)
      ? user.sidebar_menu
      : (user.role === 'admin' ? ['home', 'logs', 'info', 'users', 'keys', 'permanent', 'schedule'] : (user.role === 'správce' ? ['home', 'logs', 'info', 'keys', 'permanent'] : ['home']));

    if (permMenu_home) { permMenu_home.checked = userMenu.includes('home'); permMenu_home.disabled = !canEditMenu; }
    if (permMenu_logs) { permMenu_logs.checked = userMenu.includes('logs'); permMenu_logs.disabled = !canEditMenu; }
    if (permMenu_info) { permMenu_info.checked = userMenu.includes('info'); permMenu_info.disabled = !canEditMenu; }
    if (permMenu_users) { permMenu_users.checked = userMenu.includes('users'); permMenu_users.disabled = !canEditMenu; }
    if (permMenu_permanent) { permMenu_permanent.checked = userMenu.includes('permanent'); permMenu_permanent.disabled = !canEditMenu; }
    if (permMenu_schedule) { permMenu_schedule.checked = userMenu.includes('schedule'); permMenu_schedule.disabled = !canEditMenu; }
    if (permMenu_keys) { permMenu_keys.checked = userMenu.includes('keys'); permMenu_keys.disabled = !canEditMenu; }
    if (permMenuDefaultBtn) permMenuDefaultBtn.disabled = !canEditMenu;
    if (permMenuSelectAllBtn) permMenuSelectAllBtn.disabled = !canEditMenu;
    if (permMenuHomeOnlyBtn) permMenuHomeOnlyBtn.disabled = !canEditMenu;

    // Správa ostatních uživatelů
    const canManageVal = Boolean(user.can_manage_users);
    if (permCanManageUsersToggle) {
      permCanManageUsersToggle.checked = canManageVal;
      permCanManageUsersToggle.disabled = !canEditMgmt;
    }
    if (permManagementSubConfigWrapper) {
      permManagementSubConfigWrapper.classList.toggle('hidden', !canManageVal);
    }

    const mgmtPerms = (typeof user.user_management_permissions === 'object' && user.user_management_permissions !== null)
      ? user.user_management_permissions
      : {};

    const mgmtInputs = [
      [permMgmt_role, mgmtPerms.can_edit_role],
      [permMgmt_bypass, mgmtPerms.can_edit_network_bypass],
      [permMgmt_unlock, mgmtPerms.can_edit_can_unlock],
      [permMgmt_permanent, mgmtPerms.can_edit_permanent_unlock],
      [permMgmt_time, mgmtPerms.can_edit_time_restrictions],
      [permMgmt_menu, mgmtPerms.can_edit_sidebar_menu],
      [permMgmt_note, mgmtPerms.can_edit_user_note],
      [permMgmt_disabled, mgmtPerms.can_edit_is_disabled],
      [permMgmt_password, mgmtPerms.can_reset_password],
      [permMgmt_delete, mgmtPerms.can_delete_users]
    ];
    mgmtInputs.forEach(([elem, val]) => {
      if (elem) {
        elem.checked = Boolean(val);
        elem.disabled = !canEditMgmt;
      }
    });

    // Smazat tlačítko – zobrazit jen pokud má caller právo smazat
    if (permModalDeleteRow) {
      permModalDeleteRow.classList.toggle('hidden', !canDeleteThis);
    }

    if (permUnitAccessSection && permUnitAccessList) {
      permUnitAccessSection.classList.toggle('hidden', isProtected);
      permUnitAccessList.replaceChildren();
      if (!isProtected) {
        try {
          const response = await fetch(`/api/users/${encodeURIComponent(userId)}`);
          const detail = await response.json();
          if (!response.ok) throw new Error(detail.message || 'Oprávnění jednotek se nepodařilo načíst.');
          (detail.user.unit_access || []).forEach(access => {
            const card = document.createElement('div');
            card.className = 'rounded-xl border border-gray-200 bg-white p-3 dark:border-gray-700 dark:bg-gray-900';
            const title = document.createElement('h5');
            title.className = 'mb-2 text-xs font-bold text-gray-900 dark:text-white';
            title.textContent = access.unit_name;
            card.appendChild(title);
            const controls = document.createElement('div');
            controls.className = 'grid grid-cols-1 gap-2 sm:grid-cols-2';
            [
              ['can_unlock', 'Povolit odemykání', canEditUnlock],
              ['network_bypass', 'Síťový bypass', canEditBypass],
              ['permanent_unlock_allowed', 'Trvalé odemčení', canEditPermanent]
            ].forEach(([field, label, canEdit]) => {
              const labelEl = document.createElement('label');
              labelEl.className = 'flex items-center gap-2 text-[11px] text-gray-700 dark:text-gray-300';
              const input = document.createElement('input');
              input.type = 'checkbox';
              input.dataset.unitId = String(access.unit_id);
              input.dataset.unitField = field;
              input.checked = Boolean(access[field]);
              input.disabled = !canEdit;
              input.className = 'h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500';
              labelEl.append(input, document.createTextNode(label));
              controls.appendChild(labelEl);
            });
            const durationLabel = document.createElement('label');
            durationLabel.className = 'flex items-center gap-2 text-[11px] text-gray-700 dark:text-gray-300';
            durationLabel.appendChild(document.createTextNode('Max. doba (min)'));
            const duration = document.createElement('input');
            duration.type = 'number';
            duration.min = '1';
            duration.max = '1440';
            duration.value = String(access.permanent_unlock_max_duration || 60);
            duration.dataset.unitId = String(access.unit_id);
            duration.dataset.unitField = 'permanent_unlock_max_duration';
            duration.disabled = !canEditPermanent;
            duration.className = 'w-24 rounded-lg border border-gray-200 px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800 dark:text-white';
            durationLabel.appendChild(duration);
            controls.appendChild(durationLabel);
            card.appendChild(controls);
            permUnitAccessList.appendChild(card);
          });
          if (!detail.user.unit_access?.length) {
            permUnitAccessList.textContent = 'Nejsou nakonfigurovány žádné jednotky.';
          }
        } catch (error) {
          permUnitAccessList.textContent = error.message || 'Oprávnění jednotek se nepodařilo načíst.';
          showToast(error.message || 'Oprávnění jednotek se nepodařilo načíst.', 'error');
        }
      }
    }

    // Skrýt alert
    permModalAlert.classList.add('hidden');
    permModalAlert.textContent = '';

    userPermissionsModal.classList.remove('hidden');
  }

  // Pomocná funkce pro výpočet a zobrazení textu s délkou v minutách
  function updatePermDurationHint(totalMinutes) {
    if (!permDurationCalculatedHint) return;
    const span = permDurationCalculatedHint.querySelector('span');
    if (!span) return;
    const h = Math.floor(totalMinutes / 60);
    const m = totalMinutes % 60;
    let readable = '';
    if (h > 0 && m > 0) readable = `${h} hod ${m} min`;
    else if (h > 0) readable = `${h === 1 ? '1 hodina' : h + ' hodin'}`;
    else readable = `${m} minut`;
    span.textContent = `Zámek lze trvale ponechat otevřený maximálně na ${totalMinutes} min (${readable}).`;
  }

  function closeUserPermissionsModal() {
    userPermissionsModal.classList.add('hidden');
    userPermissionsForm.reset();
  }

  if (closePermModalBtn) closePermModalBtn.addEventListener('click', closeUserPermissionsModal);
  if (cancelPermModalBtn) cancelPermModalBtn.addEventListener('click', closeUserPermissionsModal);
  if (userPermissionsModal) {
    userPermissionsModal.addEventListener('click', (e) => {
      if (e.target === userPermissionsModal) closeUserPermissionsModal();
    });
  }



  if (permDisabledToggle) {
    permDisabledToggle.addEventListener('change', () => {
      if (permDeactivatedBadge) permDeactivatedBadge.classList.toggle('hidden', !permDisabledToggle.checked);
    });
  }

  if (permCanUnlockToggle) {
    permCanUnlockToggle.addEventListener('change', () => {
      if (permCanUnlockWarning) permCanUnlockWarning.classList.toggle('hidden', permCanUnlockToggle.checked);
    });
  }

  if (permPermanentToggle) {
    permPermanentToggle.addEventListener('change', () => {
      if (permPermanentConfigWrapper) permPermanentConfigWrapper.classList.toggle('hidden', !permPermanentToggle.checked);
    });
  }

  if (permCanManageUsersToggle) {
    permCanManageUsersToggle.addEventListener('change', () => {
      if (permManagementSubConfigWrapper) {
        permManagementSubConfigWrapper.classList.toggle('hidden', !permCanManageUsersToggle.checked);
      }
    });
  }

  if (permMenuDefaultBtn) {
    permMenuDefaultBtn.addEventListener('click', () => {
      const targetRole = permRoleSelect ? permRoleSelect.value : 'user';
      let defMenu = ['home'];
      if (targetRole === 'admin') {
        defMenu = ['home', 'logs', 'info', 'users', 'keys', 'permanent', 'schedule'];
      } else if (targetRole === 'správce') {
        defMenu = ['home', 'logs', 'info', 'users', 'keys', 'permanent'];
      }
      if (permMenu_home) permMenu_home.checked = defMenu.includes('home');
      if (permMenu_logs) permMenu_logs.checked = defMenu.includes('logs');
      if (permMenu_info) permMenu_info.checked = defMenu.includes('info');
      if (permMenu_users) permMenu_users.checked = defMenu.includes('users');
      if (permMenu_permanent) permMenu_permanent.checked = defMenu.includes('permanent');
      if (permMenu_schedule) permMenu_schedule.checked = defMenu.includes('schedule');
      if (permMenu_keys) permMenu_keys.checked = defMenu.includes('keys');
    });
  }

  if (permMenuSelectAllBtn) {
    permMenuSelectAllBtn.addEventListener('click', () => {
      [permMenu_home, permMenu_logs, permMenu_info, permMenu_users, permMenu_keys, permMenu_permanent, permMenu_schedule].forEach(cb => {
        if (cb) cb.checked = true;
      });
    });
  }

  if (permMenuHomeOnlyBtn) {
    permMenuHomeOnlyBtn.addEventListener('click', () => {
      if (permMenu_home) permMenu_home.checked = true;
      [permMenu_logs, permMenu_info, permMenu_users, permMenu_keys, permMenu_permanent, permMenu_schedule].forEach(cb => {
        if (cb && cb !== permMenu_home) cb.checked = false;
      });
    });
  }

  // Tlačítka Minuty / Hodiny v sekci trvalého odemčení
  function setPermDurationUnit(isHours) {
    permDurationUnitIsHours = isHours;
    const currentRaw = parseFloat(permPermanentDurationValue.value) || 1;

    if (isHours) {
      // Přepínáme z minut na hodiny – přepočítáme hodnotu
      const asHours = Math.max(1, Math.round(currentRaw / 60 * 10) / 10);
      permPermanentDurationValue.value = asHours;
      permPermanentDurationValue.max = 24;
      permPermanentDurationValue.step = 0.5;
      updatePermDurationHint(Math.round(asHours * 60));
      permDurationUnitHours.classList.add('active-unit');
      permDurationUnitHours.classList.remove('text-gray-500', 'dark:text-gray-400');
      permDurationUnitHours.classList.add('text-gray-900', 'dark:text-white');
      permDurationUnitMinutes.classList.remove('active-unit');
      permDurationUnitMinutes.classList.add('text-gray-500', 'dark:text-gray-400');
      permDurationUnitMinutes.classList.remove('text-gray-900', 'dark:text-white');
    } else {
      // Přepínáme z hodin na minuty
      const asMinutes = Math.max(1, Math.round(currentRaw * 60));
      permPermanentDurationValue.value = asMinutes;
      permPermanentDurationValue.max = 1440;
      permPermanentDurationValue.step = 1;
      updatePermDurationHint(asMinutes);
      permDurationUnitMinutes.classList.add('active-unit');
      permDurationUnitMinutes.classList.remove('text-gray-500', 'dark:text-gray-400');
      permDurationUnitMinutes.classList.add('text-gray-900', 'dark:text-white');
      permDurationUnitHours.classList.remove('active-unit');
      permDurationUnitHours.classList.add('text-gray-500', 'dark:text-gray-400');
      permDurationUnitHours.classList.remove('text-gray-900', 'dark:text-white');
    }
  }

  if (permDurationUnitMinutes) permDurationUnitMinutes.addEventListener('click', () => setPermDurationUnit(false));
  if (permDurationUnitHours) permDurationUnitHours.addEventListener('click', () => setPermDurationUnit(true));

  if (permPermanentDurationValue) {
    permPermanentDurationValue.addEventListener('input', () => {
      const raw = parseFloat(permPermanentDurationValue.value) || 1;
      const totalMinutes = permDurationUnitIsHours ? Math.round(raw * 60) : Math.round(raw);
      updatePermDurationHint(totalMinutes);
    });
  }

  if (permUnlockAccountBtn) {
    permUnlockAccountBtn.addEventListener('click', () => {
      shouldUnlockAccountOnSave = true;
      permLockedBanner.classList.add('hidden');
      showToast('Účet bude po uložení odemčen.', 'info');
    });
  }

  // Tlačítko Smazat uživatele uvnitř modalu oprávnění
  if (permModalDeleteBtn) {
    permModalDeleteBtn.addEventListener('click', async () => {
      const uId = parseInt(permUserId.value, 10);
      const uName = permModalUsernameDisplay.textContent.trim();
      if (!uId || !confirm(`Opravdu trvale smazat účet "${uName}"? Tuto akci nelze vrátit.`)) return;
      try {
        const res = await fetch(`/api/users/${uId}`, { method: 'DELETE', headers: authHeaders() });
        const data = await res.json();
        if (res.ok) {
          showToast(`Uživatel '${uName}' byl smazán.`, 'success');
          closeUserPermissionsModal();
          loadUsers();
        } else {
          showToast(data.message || 'Chyba při mazání uživatele.', 'error');
        }
      } catch (_) {
        showToast('Chyba sítě při komunikaci se serverem.', 'error');
      }
    });
  }

  if (savePermModalBtn) {
    savePermModalBtn.addEventListener('click', async () => {
      const uId = parseInt(permUserId.value, 10);
      if (!uId) return;

      // Výpočet minut z pole + jednotky
      const rawDuration = parseFloat(permPermanentDurationValue ? permPermanentDurationValue.value : 60) || 60;
      const durationMinutes = permDurationUnitIsHours ? Math.round(rawDuration * 60) : Math.round(rawDuration);

      // Boční menu
      const selectedMenu = [];
      if (permMenu_home && permMenu_home.checked) selectedMenu.push('home');
      if (permMenu_logs && permMenu_logs.checked) selectedMenu.push('logs');
      if (permMenu_info && permMenu_info.checked) selectedMenu.push('info');
      if (permMenu_users && permMenu_users.checked) selectedMenu.push('users');
      if (permMenu_permanent && permMenu_permanent.checked) selectedMenu.push('permanent');
      if (permMenu_schedule && permMenu_schedule.checked) selectedMenu.push('schedule');
      if (permMenu_keys && permMenu_keys.checked) selectedMenu.push('keys');
      if (selectedMenu.length === 0) selectedMenu.push('home');

      // Správa ostatních uživatelů
      const canManageUsersVal = permCanManageUsersToggle ? permCanManageUsersToggle.checked : false;
      const userMgmtPerms = {
        can_edit_role: permMgmt_role ? permMgmt_role.checked : false,
        can_edit_network_bypass: permMgmt_bypass ? permMgmt_bypass.checked : false,
        can_edit_can_unlock: permMgmt_unlock ? permMgmt_unlock.checked : false,
        can_edit_permanent_unlock: permMgmt_permanent ? permMgmt_permanent.checked : false,
        can_edit_time_restrictions: permMgmt_time ? permMgmt_time.checked : false,
        can_edit_sidebar_menu: permMgmt_menu ? permMgmt_menu.checked : false,
        can_edit_user_note: permMgmt_note ? permMgmt_note.checked : false,
        can_edit_is_disabled: permMgmt_disabled ? permMgmt_disabled.checked : false,
        can_reset_password: permMgmt_password ? permMgmt_password.checked : false,
        can_delete_users: permMgmt_delete ? permMgmt_delete.checked : false
      };

      const existingUser = cachedUsersList.find(u => u.id === uId) || {};
      const payload = {
        role: permRoleSelect.value,
        is_disabled: permDisabledToggle ? permDisabledToggle.checked : false,
        network_bypass: permBypassToggle ? permBypassToggle.checked : false,
        can_unlock: permCanUnlockToggle ? permCanUnlockToggle.checked : true,
        permanent_unlock_allowed: permPermanentToggle ? permPermanentToggle.checked : Boolean(existingUser.permanent_unlock_allowed),
        permanent_unlock_max_duration: permPermanentDurationValue ? Math.max(1, Math.min(1440, durationMinutes)) : (existingUser.permanent_unlock_max_duration || 60),
        time_restricted: Boolean(existingUser.time_restricted),
        user_note: permUserNote ? permUserNote.value.trim() : '',
        unlock_account: shouldUnlockAccountOnSave,
        sidebar_menu: selectedMenu,
        can_manage_users: canManageUsersVal,
        user_management_permissions: userMgmtPerms
      };
      if (permUnitAccessList && !permUnitAccessSection?.classList.contains('hidden')) {
        const unitAccess = new Map();
        permUnitAccessList.querySelectorAll('[data-unit-id][data-unit-field]').forEach(input => {
          const unitId = Number(input.dataset.unitId);
          if (!unitAccess.has(unitId)) unitAccess.set(unitId, { unit_id: unitId });
          const entry = unitAccess.get(unitId);
          if (input.dataset.unitField === 'permanent_unlock_max_duration') {
            entry.permanent_unlock_max_duration = Number(input.value);
          } else {
            entry[input.dataset.unitField] = input.checked;
          }
        });
        payload.unit_access = Array.from(unitAccess.values());
      }

      if (permNewPassword.value.trim()) {
        if (permNewPassword.value.trim().length < 8) {
          permModalAlert.className = 'rounded-xl border p-2.5 text-xs font-medium border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300';
          permModalAlert.textContent = 'Nové heslo musí mít alespoň 8 znaků.';
          permModalAlert.classList.remove('hidden');
          return;
        }
        payload.new_password = permNewPassword.value.trim();
      }

      savePermModalBtn.disabled = true;
      savePermModalBtn.innerHTML = `
        <svg class="h-3.5 w-3.5 animate-spin text-white" viewBox="0 0 24 24" fill="none">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
        </svg>
        <span>Ukládám...</span>
      `;

      try {
        const res = await fetch(`/api/users/${uId}/permissions`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify(payload)
        });
        const resData = await res.json();
        if (res.ok) {
          showToast(resData.message || 'Oprávnění uživatele byla uložena.', 'success');
          closeUserPermissionsModal();
          loadUsers();

          // Pokud se úprava týká přihlášeného uživatele, aktualizovat lokální stav
          if (permModalUsernameDisplay.textContent.trim().toLowerCase() === currentUsername.toLowerCase()) {
            currentUserRole = payload.role;
            currentUserBypass = payload.network_bypass;
            currentUserSidebarMenu = payload.sidebar_menu;
            currentUserCanManageUsers = payload.can_manage_users;
            currentUserManagePermissions = payload.user_management_permissions;
            isNetworkAllowed = currentUserBypass || isNetworkAllowed;
            updateNetworkUi(isNetworkAllowed);
            updateSidebarNavVisibility();
          }
        } else {
          permModalAlert.className = 'rounded-xl border p-2.5 text-xs font-medium border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300';
          permModalAlert.textContent = resData.message || 'Chyba při ukládání oprávnění.';
          permModalAlert.classList.remove('hidden');
        }
      } catch (_) {
        permModalAlert.className = 'rounded-xl border p-2.5 text-xs font-medium border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300';
        permModalAlert.textContent = 'Chyba sítě při komunikaci se serverem.';
        permModalAlert.classList.remove('hidden');
      } finally {
        savePermModalBtn.disabled = false;
        savePermModalBtn.innerHTML = `<span>Uložit nastavení</span>`;
      }
    });
  }


  if (addUserForm) {
    addUserForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      addUserAlert.classList.add('hidden');

      const username = newUsernameInput.value.trim();
      const password = newPasswordInput.value;
      const role = newRoleSelect.value;
      const isAdmin = (currentUserRole === 'admin');
      const network_bypass = isAdmin ? newUserBypass.checked : false;

      if (!isAdmin && role !== 'user') {
        showToast('Na tuto akci nemáte právo. Obraťte se na správce systému.', 'error');
        return;
      }

      try {
        const res = await fetch('/api/users', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ username, password, role, network_bypass })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(data.message || `Uživatel '${username}' byl vytvořen.`, 'success');
          addUserForm.reset();
          loadUsers();
          addUserCard.classList.add('hidden');
        } else {
          showToast(data.message || 'Nepodařilo se vytvořit uživatele.', 'error');
        }
      } catch (_) {
        showToast('Chyba komunikace se serverem.', 'error');
      }
    });
  }

  // ==========================================================================
  // ZMĚNA HESLA
  // ==========================================================================
  if (changePasswordForm) {
    changePasswordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      changePasswordAlert.classList.add('hidden');

      const current_password = currentPasswordInput.value;
      const new_password = newPassInput.value;
      const confirm_password = confirmPassInput.value;

      if (new_password !== confirm_password) {
        showToast('Nové heslo a potvrzení se neshodují.', 'error');
        return;
      }

      changePasswordSubmitBtn.disabled = true;
      try {
        const res = await fetch('/api/auth/change-password', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ current_password, new_password })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(data.message || 'Heslo bylo úspěšně změněno.', 'success');
          changePasswordForm.reset();
          changePasswordForm.classList.add('hidden');
        } else {
          showToast(data.message || 'Chyba při změně hesla.', 'error');
        }
      } catch (_) {
        showToast('Chyba sítě při změně hesla.', 'error');
      } finally {
        changePasswordSubmitBtn.disabled = false;
      }
    });
  }

  // ==========================================================================
  // BIOMETRIE (OTISK PRSTU / WEBAUTHN)
  // ==========================================================================
  if (biometricAuthToggle) {
    biometricAuthToggle.addEventListener('change', async () => {
      const wantEnable = biometricAuthToggle.checked;
      if (wantEnable) {
        if (!window.PublicKeyCredential) {
          showToast('Tento prohlížeč nepodporuje WebAuthn / otisk prstu.', 'error');
          biometricAuthToggle.checked = false;
          return;
        }

        biometricStatusText.textContent = 'Přiložte prst ke snímači...';

        try {
          const res = await fetch('/api/webauthn/register/options', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({ csrf_token: csrfToken })
          });

          if (!res.ok) {
            const errData = await res.json().catch(() => null);
            throw new Error((errData && errData.message) || 'Nelze inicializovat registraci.');
          }

          const options = await res.json();
          options.challenge = base64urlToBuffer(options.challenge);
          options.user.id = base64urlToBuffer(options.user.id);
          if (options.excludeCredentials && options.excludeCredentials.length > 0) {
            options.excludeCredentials = options.excludeCredentials.map(c => ({
              ...c,
              id: base64urlToBuffer(c.id)
            }));
          }

          const credential = await navigator.credentials.create({ publicKey: options });
          if (!credential) {
            throw new Error('Registrace otisku byla zrušena.');
          }

          const regData = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
              attestationObject: bufferToBase64url(credential.response.attestationObject)
            },
            csrf_token: csrfToken
          };

          const verifyRes = await fetch('/api/webauthn/register/verify', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify(regData)
          });

          const verData = await verifyRes.json().catch(() => null);
          if (verifyRes.ok && verData && verData.success) {
            biometricAuthToggle.checked = true;
            localStorage.setItem('door_biometrics_enabled', 'true');
            localStorage.setItem('door_biometrics_username', currentUsername);
            biometricStatusText.textContent = 'Stav: aktivní (otisk uložen)';
            showToast('Přihlášení otiskem prstu aktivováno.', 'success');
          } else {
            throw new Error((verData && verData.message) || 'Ověření otisku selhalo.');
          }
        } catch (err) {
          biometricAuthToggle.checked = false;
          localStorage.removeItem('door_biometrics_enabled');
          biometricStatusText.textContent = 'Stav: neaktivní';
          if (err.name !== 'NotAllowedError') {
            showToast('Chyba registrace otisku: ' + (err.message || err), 'error');
          }
        }
      } else {
        try {
          const res = await fetch('/api/webauthn/credentials', {
            method: 'DELETE',
            headers: authHeaders()
          });
          const data = await res.json().catch(() => null);
          if (!res.ok || !data || !data.success) {
            throw new Error((data && data.message) || 'Biometrické přihlášení se nepodařilo deaktivovat.');
          }
          localStorage.removeItem('door_biometrics_enabled');
          biometricStatusText.textContent = 'Stav: neaktivní';
          showToast('Otisk prstu byl deaktivován.', 'info');
        } catch (err) {
          biometricAuthToggle.checked = true;
          showToast('Chyba při vypínání biometrie: ' + (err.message || err), 'error');
        }
      }
    });
  }

  // ==========================================================================
  // PUSH OZNÁMENÍ (OPRAVA STAVU A ZNOVUPOVOLENÍ)
  // ==========================================================================
  if (pushNotificationToggle) {
    pushNotificationToggle.addEventListener('change', async () => {
      const wantEnable = pushNotificationToggle.checked;
      if (wantEnable) {
        if (!('Notification' in window) || !('serviceWorker' in navigator)) {
          showToast('Prohlížeč nepodporuje Push notifikace.', 'error');
          pushNotificationToggle.checked = false;
          return;
        }

        // Dynamicky ověřit aktuální stav oprávnění
        let perm = Notification.permission;
        if (perm === 'default') {
          perm = await Notification.requestPermission();
        }

        if (perm === 'denied') {
          pushNotificationToggle.checked = false;
          showToast('Oznámení jsou blokována v nastavení prohlížeče. Povolte je v záhlaví vedle adresy URL.', 'error', 6000);
          return;
        }

        if (perm !== 'granted') {
          pushNotificationToggle.checked = false;
          showToast('Oprávnění pro oznámení nebylo uděleno.', 'error');
          return;
        }

        try {
          // Ujistit se, že service worker je zaregistrován
          let reg = await navigator.serviceWorker.getRegistration();
          if (!reg) {
            reg = await navigator.serviceWorker.register('/sw.js');
          }
          await navigator.serviceWorker.ready;

          let subscription = await reg.pushManager.getSubscription();
          if (subscription) {
            try { await subscription.unsubscribe(); } catch (_) {}
          }

          subscription = await reg.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: base64urlToBuffer(vapidPublicKey)
          });

          const subJson = subscription.toJSON();
          const res = await fetch('/api/push/subscribe', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({
              endpoint: subJson.endpoint,
              keys: subJson.keys,
              csrf_token: csrfToken
            })
          });

          if (res.ok) {
            pushNotificationStatusText.textContent = 'Stav: aktivní';
            if (testPushBtn) testPushBtn.classList.remove('hidden');
            showToast('Push oznámení byla úspěšně aktivována.', 'success');
          } else {
            pushNotificationToggle.checked = false;
            showToast('Nepodařilo se uložit registraci oznámení na serveru.', 'error');
          }
        } catch (err) {
          pushNotificationToggle.checked = false;
          showToast('Chyba při registraci oznámení: ' + (err.message || err), 'error');
        }
      } else {
        try {
          const reg = await navigator.serviceWorker.ready;
          const sub = await reg.pushManager.getSubscription();
          if (sub) {
            await fetch('/api/push/unsubscribe', {
              method: 'POST',
              headers: authHeaders(),
              body: JSON.stringify({
                endpoint: sub.endpoint,
                csrf_token: csrfToken
              })
            });
            await sub.unsubscribe();
          }
          pushNotificationStatusText.textContent = 'Stav: neaktivní';
          if (testPushBtn) testPushBtn.classList.add('hidden');
          showToast('Push oznámení byla deaktivována.', 'info');
        } catch (err) {
          showToast('Chyba při vypínání oznámení.', 'error');
        }
      }
    });
  }

  if (testPushBtn) {
    testPushBtn.addEventListener('click', async () => {
      testPushBtn.disabled = true;
      try {
        const res = await fetch('/api/push/test', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ csrf_token: csrfToken })
        });
        const data = await res.json().catch(() => null);
        if (res.ok && data && data.success) {
          showToast('Testovací oznámení bylo odesláno na zařízení.', 'success');
        } else {
          showToast((data && data.message) || 'Chyba při odeslání testovacího oznámení.', 'error');
        }
      } catch (_) {
        showToast('Chyba při komunikaci se serverem.', 'error');
      } finally {
        testPushBtn.disabled = false;
      }
    });
  }

  // ==========================================================================
  // ODHLÁŠENÍ
  // ==========================================================================
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      logoutBtn.disabled = true;
      try {
        const res = await fetch('/api/logout', { method: 'POST', headers: authHeaders() });
        if (res.ok || res.status === 401) {
          window.location.href = '/login';
          return;
        }
        const data = await res.json().catch(() => null);
        showToast((data && data.message) || 'Odhlášení se nepodařilo. Zkuste to znovu.', 'error');
      } catch (_) {
        showToast('Chyba sítě při odhlášení. Zkuste to znovu.', 'error');
      }
      logoutBtn.disabled = false;
    });
  }

  // ==========================================================================
  // TRVALÉ ODEMČENÍ – stav a UI
  // ==========================================================================
  let permanentUnlockActive = false;
  let permanentCountdownInterval = null;
  let permanentUserAllowed = false;
  let permanentUserMaxDuration = 60;
  let activePermanentUnitId = null;

  const btnStartPermanent = document.getElementById('btnStartPermanent');
  const btnStopPermanent = document.getElementById('btnStopPermanent');
  const permanentControlsWrapper = document.getElementById('permanentControlsWrapper');
  const permanentStatusDot = document.getElementById('permanentStatusDot');
  const permanentStatusHeader = document.getElementById('permanentStatusHeader');
  const permanentStatusDetail = document.getElementById('permanentStatusDetail');
  const permanentStatusBadgeIcon = document.getElementById('permanentStatusBadgeIcon');
  const permanentAdminActionWrap = document.getElementById('permanentAdminActionWrap');
  const permanentUsersTableBody = document.getElementById('permanentUsersTableBody');
  const permanentUnlockModal = document.getElementById('permanentUnlockModal');

  function updatePermanentControlsVisibility() {
    if (!permanentControlsWrapper) return;
    const showLegacyControls = userUnits.length === 0
      && (permanentUserAllowed || permanentUnlockActive);
    permanentControlsWrapper.classList.toggle('hidden', !showLegacyControls);
  }

  function formatCountdown(expiresAt) {
    if (!expiresAt) return '';
    // Vždy parsovat jako UTC (string by měl mít Z suffix)
    const expMs = Date.parse(expiresAt);
    if (isNaN(expMs)) return '';
    const diff = Math.max(0, Math.floor((expMs - Date.now()) / 1000));
    return formatSeconds(diff);
  }

  function formatSeconds(diff) {
    diff = Math.max(0, diff);
    const h = Math.floor(diff / 3600);
    const m = Math.floor((diff % 3600) / 60);
    const s = diff % 60;
    if (h > 0) return `${h}h ${String(m).padStart(2,'0')}m ${String(s).padStart(2,'0')}s`;
    if (m > 0) return `${m}m ${String(s).padStart(2,'0')}s`;
    return `${s}s`;
  }

  function applyPermanentUnlockUi(state) {
    const active = Boolean(state && (state.active || state.is_active));
    permanentUnlockActive = active;
    updatePermanentControlsVisibility();
    webUnlockBlocked = Boolean(state && typeof state.web_unlock_blocked === 'boolean'
      ? state.web_unlock_blocked
      : webUnlockBlocked);
    renderHomeUnitCards();

    // Hlavní tlačítko dveří
    if (webUnlockBlocked) {
      doorBtn.disabled = true;
      doorBtn.className = 'door-btn-orig blocked';
      doorWrapper.className = 'door-wrapper blocked';
      doorBtnText.textContent = 'WEB ZABLOKOVÁN';
      doorBtnSubtext.textContent = active
        ? 'Zámek zůstává trvale odemčen'
        : 'Přiložte bezpečnostní klíč k povolení';
      if (svgBlockedCross) svgBlockedCross.classList.toggle('hidden', active);
      if (svgSpinner) svgSpinner.classList.add('hidden');
      if (svgLocked) svgLocked.classList.toggle('hidden', active);
      if (svgUnlocked) svgUnlocked.classList.toggle('hidden', !active);
      if (doorStatusIndicator) doorStatusIndicator.className = 'h-2 w-2 rounded-full bg-rose-500';
      if (doorStatusText) doorStatusText.textContent = 'Webové odemykání zablokováno';
    } else if (active) {
      doorBtn.disabled = false;
      doorBtn.className = 'door-btn-orig permanent';
      doorWrapper.className = 'door-wrapper permanent';
      doorBtnText.textContent = 'TRVALE ODEMČENO';
      const remaining = state.expires_at ? formatCountdown(state.expires_at) : '';
      doorBtnSubtext.textContent = remaining ? `Zbývá: ${remaining}` : 'Aktivní';
      if (svgBlockedCross) svgBlockedCross.classList.add('hidden');
      if (svgSpinner) svgSpinner.classList.add('hidden');
      if (svgLocked) svgLocked.classList.add('hidden');
      if (svgUnlocked) svgUnlocked.classList.remove('hidden');
      if (doorStatusIndicator) doorStatusIndicator.className = 'h-2 w-2 rounded-full bg-amber-500 animate-pulse';
      if (doorStatusText) doorStatusText.textContent = 'Trvale odemčeno';
    } else {
      if (isNetworkAllowed) {
        doorBtn.className = 'door-btn-orig';
        doorWrapper.className = 'door-wrapper';
        doorBtnText.textContent = 'ODEMKNOUT';
        doorBtnSubtext.textContent = 'Stiskněte pro otevření';
        if (svgBlockedCross) svgBlockedCross.classList.add('hidden');
        if (svgSpinner) svgSpinner.classList.add('hidden');
        if (svgUnlocked) svgUnlocked.classList.add('hidden');
        if (svgLocked) svgLocked.classList.remove('hidden');
        if (doorStatusIndicator) doorStatusIndicator.className = 'h-2 w-2 rounded-full bg-emerald-500';
        if (doorStatusText) doorStatusText.textContent = 'Připraveno k odemčení';
      }
    }

    // Stop tlačítko
    if (btnStopPermanent) {
      btnStopPermanent.classList.toggle('hidden', !active);
    }
    if (btnStartPermanent) {
      btnStartPermanent.classList.toggle('hidden', active);
      btnStartPermanent.disabled = webUnlockBlocked;
      btnStartPermanent.title = webUnlockBlocked
        ? 'Webové odemykání je zablokováno bezpečnostním klíčem.'
        : '';
    }

    // Status karta v záložce Trvalé odemčení
    if (permanentStatusDot) {
      permanentStatusDot.className = active
        ? 'h-2.5 w-2.5 rounded-full bg-amber-500 animate-pulse'
        : 'h-2.5 w-2.5 rounded-full bg-gray-400';
    }
    if (permanentStatusHeader) {
      permanentStatusHeader.textContent = active
        ? 'Trvalé odemčení aktivní'
        : 'Zámek v běžném režimu (uzamčen)';
    }
    if (permanentStatusDetail) {
      if (active && state.expires_at) {
        const remaining = formatCountdown(state.expires_at);
        const who = (state.activated_by_username || state.started_by_username) ? ` · Spustil: ${state.activated_by_username || state.started_by_username}` : '';
        permanentStatusDetail.textContent = `Zbývající čas: ${remaining}${who}`;
      } else {
        permanentStatusDetail.textContent = 'Dveře se automaticky uzamknou po spuštění příkazu.';
      }
    }
    if (permanentStatusBadgeIcon) {
      permanentStatusBadgeIcon.className = active
        ? 'flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-amber-100 text-amber-600 dark:bg-amber-500/20 dark:text-amber-400'
        : 'flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400';
      permanentStatusBadgeIcon.innerHTML = active
        ? `<svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a5 5 0 0 1 5 5v2H7V7a5 5 0 0 1 5-5z"/><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M12 16v2"/></svg>`
        : `<svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
    }
  }

  function startPermanentCountdownRefresh(state) {
    if (permanentCountdownInterval) {
      clearInterval(permanentCountdownInterval);
      permanentCountdownInterval = null;
    }
    const active = Boolean(state && (state.active || state.is_active));
    if (!active) return;

    // Primárně použij remaining_seconds z backendu, fallback na expires_at
    let localRemaining;
    if (typeof state.remaining_seconds === 'number' && state.remaining_seconds > 0) {
      localRemaining = state.remaining_seconds;
    } else if (state.expires_at) {
      const expMs = Date.parse(state.expires_at);
      localRemaining = isNaN(expMs) ? 0 : Math.max(0, Math.floor((expMs - Date.now()) / 1000));
    } else {
      return; // Žádná informace o čase
    }

    const tick = () => {
      const text = formatSeconds(localRemaining);
      if (doorBtnSubtext && permanentUnlockActive) {
        doorBtnSubtext.textContent = `Zbývá: ${text}`;
      }
      if (permanentStatusDetail && permanentUnlockActive) {
        const who = (state.activated_by_username || state.started_by_username)
          ? ` · Spustil: ${state.activated_by_username || state.started_by_username}` : '';
        permanentStatusDetail.textContent = `Zbývající čas: ${text}${who}`;
      }
      if (localRemaining <= 0) {
        clearInterval(permanentCountdownInterval);
        permanentCountdownInterval = null;
        fetchPermanentUnlockStatus();
        return;
      }
      localRemaining--;
    };

    tick(); // ihned zobrazit
    permanentCountdownInterval = setInterval(tick, 1000);
  }

  async function fetchPermanentUnlockStatus() {
    try {
      const res = await fetch('/api/permanent-unlock/status');
      if (!res.ok) return;
      const data = await res.json();
      if (Array.isArray(data.units)) {
        const byId = new Map(data.units.map(item => [item.unit.id, item]));
        userUnits = userUnits.map(unit => {
          const current = byId.get(unit.id);
          return current ? {
            ...unit,
            permanent_state: current.state,
            web_unlock_blocked: current.web_unlock_blocked,
            access: { ...unit.access, ...current.permission },
          } : unit;
        });
        permanentUnlockActive = userUnits.some(unit => unit.permanent_state?.active);
        updatePermanentControlsVisibility();
        renderHomeUnitCards();
        if (userUnits.length) {
          const active = userUnits.filter(unit => unit.permanent_state?.active);
          if (permanentStatusHeader) permanentStatusHeader.textContent = active.length
            ? `Trvalé odemčení aktivní (${active.length} jednotek)`
            : 'Jednotky jsou v běžném režimu';
          if (permanentStatusDetail) permanentStatusDetail.textContent = active.length
            ? active.map(unit => `${unit.name}${unit.permanent_state.activated_by_username ? ` – ${unit.permanent_state.activated_by_username}` : ''}`).join(', ')
            : 'Žádná jednotka není trvale odemčena.';
          return;
        }
      }
      // Backend vrací { permission: { allowed, max_duration }, state: {...} }
      const perm = data.permission || {};
      webUnlockBlocked = Boolean(data.web_unlock_blocked);
      permanentUserAllowed = Boolean(perm.allowed);
      permanentUserMaxDuration = perm.max_duration || 60;

      // Zobrazit ovládací prvky na home pokud má uživatel oprávnění
      updatePermanentControlsVisibility();

      applyPermanentUnlockUi({ ...data.state, web_unlock_blocked: webUnlockBlocked });
      startPermanentCountdownRefresh(data.state);
    } catch (_) {}
  }

  // Přidat trvalé odemčení do pollStatus, aby se aktualizovalo i bez manuálního dotazu
  const _origPollStatus = window.__permanentUnlockPollHooked;
  if (!_origPollStatus) {
    window.__permanentUnlockPollHooked = true;
    const _permanentPollInterval = setInterval(fetchPermanentUnlockStatus, 3000);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') fetchPermanentUnlockStatus();
    });
  }

  // Modal pro trvalé odemčení
  function openPermanentUnlockModal(unitId = null, maxDuration = null) {
    if (!permanentUnlockModal) return;
    activePermanentUnitId = unitId;
    const maxDur = maxDuration || permanentUserMaxDuration || 60;

    // Zobrazit limit
    const infoEl = permanentUnlockModal.querySelector('#modalMaxDurationDisplay');
    if (infoEl) infoEl.textContent = `${maxDur} min`;

    // Dynamicky vygenerovat 3 doporučené chipy nepřesahující limit
    const chipsContainer = permanentUnlockModal.querySelector('#durationChipsContainer');
    if (chipsContainer) {
      const candidates = [5, 10, 15, 20, 30, 45, 60, 90, 120, 180, 240, 360, 480, 720, 1440];
      const valid = candidates.filter(v => v <= maxDur);
      let picks = [];
      if (valid.length >= 3) {
        // Vyber 3 rovnoměrně rozmístěné: malá, střední, max (nebo blízko max)
        const last = valid[valid.length - 1];
        const first = valid[0];
        const mid = valid[Math.floor(valid.length / 2)];
        // Střední hodnota nesmí být shodná s první nebo poslední
        const midFiltered = valid.find(v => v > first && v < last) || mid;
        picks = [...new Set([first, midFiltered, last])].slice(0, 3);
      } else {
        picks = valid;
      }

      chipsContainer.innerHTML = '';
      picks.forEach((val, i) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.setAttribute('data-min', val);
        btn.className = 'duration-chip py-2 px-1 text-center rounded-xl border text-xs font-semibold transition-all cursor-pointer ' +
          'border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:border-amber-500 hover:text-amber-600';
        btn.textContent = val >= 60
          ? (val % 60 === 0 ? `${val / 60} h` : `${val} min`)
          : `${val} min`;
        if (i === 0) btn.classList.add('active'); // výchozí výběr = min
        chipsContainer.appendChild(btn);
      });

      // Event listenery na nové chipy
      chipsContainer.querySelectorAll('.duration-chip').forEach(chip => {
        chip.addEventListener('click', () => {
          chipsContainer.querySelectorAll('.duration-chip').forEach(c => c.classList.remove('active'));
          chip.classList.add('active');
          const customInput = permanentUnlockModal.querySelector('#customDurationInput');
          if (customInput) {
            customInput.value = '';
            customInput.classList.remove('active');
          }
        });
      });
    }

    // Reset custom input
    const customInput = permanentUnlockModal.querySelector('#customDurationInput');
    if (customInput) {
      customInput.value = '';
      customInput.max = maxDur;
      customInput.classList.remove('active');
    }

    permanentUnlockModal.classList.remove('hidden');
  }

  function closePermanentUnlockModal() {
    if (permanentUnlockModal) permanentUnlockModal.classList.add('hidden');
  }

  if (permanentUnlockModal) {
    // Zavřít při kliknutí mimo modal
    permanentUnlockModal.addEventListener('click', (e) => {
      if (e.target === permanentUnlockModal) closePermanentUnlockModal();
    });

    // Zavřít tlačítka
    const closePermanentModalBtn = document.getElementById('closePermanentModalBtn');
    if (closePermanentModalBtn) closePermanentModalBtn.addEventListener('click', closePermanentUnlockModal);
    const cancelPermanentModalBtn = document.getElementById('cancelPermanentModalBtn');
    if (cancelPermanentModalBtn) cancelPermanentModalBtn.addEventListener('click', closePermanentUnlockModal);

    const customInput = permanentUnlockModal.querySelector('#customDurationInput');
    if (customInput) {
      customInput.addEventListener('input', () => {
        const hasCustomValue = customInput.value.trim() !== '';
        customInput.classList.toggle('active', hasCustomValue);
        if (hasCustomValue) {
          permanentUnlockModal.querySelectorAll('.duration-chip').forEach(chip => chip.classList.remove('active'));
        }
      });
    }

    // Potvrzení
    const confirmPermanentBtn = document.getElementById('confirmPermanentStartBtn');
    if (confirmPermanentBtn) {
      confirmPermanentBtn.addEventListener('click', async () => {
        let duration = null;
        const activeChip = permanentUnlockModal.querySelector('.duration-chip.active');
        const customValue = customInput && customInput.value.trim();
        if (customValue) {
          duration = Number(customValue);
          if (!Number.isInteger(duration) || duration <= 0) {
            showToast('Zadejte celé číslo minut větší než 0.', 'error');
            return;
          }
        } else if (activeChip) {
          duration = parseInt(activeChip.getAttribute('data-min'), 10);
        }
        if (!duration || duration <= 0) {
          showToast('Vyberte nebo zadejte dobu trvání.', 'error');
          return;
        }
        if (duration > permanentUserMaxDuration) {
          showToast(`Maximální povolená doba je ${permanentUserMaxDuration} minut.`, 'error');
          return;
        }
        closePermanentUnlockModal();
        try {
          const res = await fetch('/api/permanent-unlock/start', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({
              duration_minutes: duration,
              unit_id: activePermanentUnitId,
              client_probe_ok: activePermanentUnitId === null
                ? isProbeVerified
                : unitProbeVerified.has(activePermanentUnitId),
              csrf_token: csrfToken
            })
          });
          const data = await res.json().catch(() => null);
          if (res.ok && data && data.success) {
            showToast('Trvalé odemčení bylo aktivováno.', 'success');
            if (activePermanentUnitId !== null) {
              await loadUserUnits();
              await fetchPermanentUnlockStatus();
            } else {
              applyPermanentUnlockUi(data.state);
              startPermanentCountdownRefresh(data.state);
            }
          } else {
            showToast((data && data.message) || 'Nepodařilo se aktivovat trvalé odemčení.', 'error');
          }
        } catch (_) {
          showToast('Chyba sítě.', 'error');
        }
      });
    }
  }

  if (btnStartPermanent) {
    btnStartPermanent.addEventListener('click', () => {
      openPermanentUnlockModal();
    });
  }

  if (btnStopPermanent) {
    btnStopPermanent.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/permanent-unlock/stop', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ csrf_token: csrfToken })
        });
        const data = await res.json().catch(() => null);
        if (res.ok && data && data.success) {
          showToast('Trvalé odemčení bylo deaktivováno.', 'info');
          applyPermanentUnlockUi(data.state || { active: false });
          startPermanentCountdownRefresh(null);
          if (isNetworkAllowed) resetDoorButton();
        } else {
          showToast((data && data.message) || 'Nepodařilo se deaktivovat trvalé odemčení.', 'error');
        }
      } catch (_) {
        showToast('Chyba sítě.', 'error');
      }
    });
  }

  // ==========================================================================
  // SPRÁVA OPRÁVNĚNÍ TRVALÉHO ODEMČENÍ (záložka Permanent)
  // ==========================================================================
  async function loadPermanentUsersTable() {
    if (!permanentUsersTableBody) return;
    try {
      const res = await fetch('/api/users');
      if (!res.ok) {
        const error = await res.json().catch(() => null);
        if (res.status === 403) {
          showToast((error && error.message) || 'Na tuto akci nemáte právo. Obraťte se na správce systému.', 'error');
        }
        permanentUsersTableBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-rose-500">Přístup odepřen.</td></tr>`;
        return;
      }
      const data = await res.json();
      const users = data.users || [];
      if (users.length === 0) {
        permanentUsersTableBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-gray-400">Žádní uživatelé.</td></tr>`;
        return;
      }
      permanentUsersTableBody.innerHTML = '';
      const isAdmin = (currentUserRole === 'admin');

      users.forEach(u => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-gray-50/50 dark:hover:bg-gray-800/30 transition-colors';
        const allowedChecked = u.permanent_unlock_allowed ? 'checked' : '';
        const maxDur = u.permanent_unlock_max_duration || 60;
        const isProtectedUser = (u.username.toLowerCase() === 'admin');
        const isRowDisabled = isProtectedUser || (!isAdmin && u.role !== 'user');
        const maxLimit = isAdmin ? 1440 : 120;

        let toggleHtml = '';
        if (isRowDisabled) {
          toggleHtml = `
            <label class="clean-switch opacity-50 cursor-not-allowed">
              <input type="checkbox" class="perm-unlock-allowed-toggle" data-user-id="${u.id}" ${allowedChecked} disabled>
              <span class="clean-slider"></span>
            </label>
          `;
        } else {
          toggleHtml = `
            <label class="clean-switch">
              <input type="checkbox" class="perm-unlock-allowed-toggle" data-user-id="${u.id}" ${allowedChecked}>
              <span class="clean-slider"></span>
            </label>
          `;
        }

        let durationHtml = '';
        if (isRowDisabled) {
          durationHtml = `
            <div class="flex items-center gap-2">
              <input type="number" class="perm-unlock-duration-input w-20 rounded-lg border border-gray-200 bg-gray-100 px-2 py-1 text-xs font-semibold text-gray-400 focus:outline-none dark:border-gray-700 dark:bg-gray-800/50 dark:text-gray-500 opacity-50 cursor-not-allowed" value="${maxDur}" min="1" max="1440" data-user-id="${u.id}" disabled>
              <span class="text-xs text-gray-400">min</span>
            </div>
          `;
        } else {
          durationHtml = `
            <div class="flex items-center gap-2">
              <input type="number" class="perm-unlock-duration-input w-20 rounded-lg border border-gray-200 bg-white px-2 py-1 text-xs font-semibold text-gray-700 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200" value="${maxDur}" min="1" max="${maxLimit}" data-user-id="${u.id}">
              <span class="text-xs text-gray-400">min</span>
            </div>
          `;
        }

        tr.innerHTML = `
          <td class="px-4 py-3 whitespace-nowrap">
            <div class="flex items-center gap-2.5">
              <div class="flex h-6 w-6 items-center justify-center rounded-full bg-brand-100 text-xs font-bold text-brand-600 dark:bg-brand-500/20 dark:text-brand-400">${u.username.charAt(0).toUpperCase()}</div>
              <span class="font-semibold text-gray-900 dark:text-white">${u.username}</span>
            </div>
          </td>
          <td class="px-4 py-3 whitespace-nowrap">
            <span class="inline-flex items-center rounded-lg px-2 py-0.5 text-[11px] font-semibold ${u.role === 'admin' ? 'bg-purple-100 text-purple-700 dark:bg-purple-500/20 dark:text-purple-300' : (u.role === 'správce' ? 'bg-blue-100 text-blue-700 dark:bg-blue-500/20 dark:text-blue-300' : 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300')}">
              ${u.role === 'admin' ? 'Administrátor' : (u.role === 'správce' ? 'Správce' : 'Uživatel')}
            </span>
          </td>
          <td class="px-4 py-3 whitespace-nowrap">
            ${toggleHtml}
          </td>
          <td class="px-4 py-3 whitespace-nowrap">
            ${durationHtml}
          </td>
        `;
        permanentUsersTableBody.appendChild(tr);
      });

      // Společná ukládací funkce pro řádek
      async function saveRow(uid, row, isToggleTrigger) {
        const allowedChk = row.querySelector('.perm-unlock-allowed-toggle');
        const durationInp = row.querySelector('.perm-unlock-duration-input');
        if (allowedChk && allowedChk.disabled) return;
        const allowed = allowedChk ? allowedChk.checked : false;
        let max_duration = durationInp ? parseInt(durationInp.value, 10) : 60;
        if (isNaN(max_duration) || max_duration < 1) max_duration = 1;
        const isAdmin = (currentUserRole === 'admin');
        const maxLimit = isAdmin ? 1440 : 120;
        if (max_duration > maxLimit) {
          max_duration = maxLimit;
          if (durationInp) durationInp.value = maxLimit;
          if (!isAdmin) {
            showToast('Správce může nastavit maximální dobu nejvýše 2 hodiny (120 min).', 'warning');
          }
        }
        if (durationInp) durationInp.value = max_duration;

        try {
          const res = await fetch(`/api/permanent-unlock/users/${uid}`, {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({
              allowed: allowed,
              max_duration: max_duration,
              csrf_token: csrfToken
            })
          });
          const data = await res.json().catch(() => null);
          if (res.ok && data && data.success) {
            showToast(data.message || 'Oprávnění bylo uloženo.', 'success');
            // Pokud byl změněn profil aktuálně přihlášeného uživatele, aktualizovat ihned lokální stav
            const usernameEl = row.querySelector('.font-semibold');
            const rowUsername = usernameEl ? usernameEl.textContent.trim().toLowerCase() : '';
            if (rowUsername && rowUsername === currentUsername.toLowerCase()) {
              permanentUserAllowed = allowed;
              permanentUserMaxDuration = max_duration;
              updatePermanentControlsVisibility();
            }
          } else {
            showToast((data && data.message) || 'Chyba při ukládání.', 'error');
            if (isToggleTrigger && allowedChk) {
              allowedChk.checked = !allowed;
            }
          }
        } catch (_) {
          showToast('Chyba sítě při ukládání.', 'error');
          if (isToggleTrigger && allowedChk) {
            allowedChk.checked = !allowed;
          }
        }
      }

      // Listeners pro přepínače a dobu — vše auto-save
      permanentUsersTableBody.querySelectorAll('tr').forEach(row => {
        const allowedChk = row.querySelector('.perm-unlock-allowed-toggle');
        const durationInp = row.querySelector('.perm-unlock-duration-input');
        const uid = (allowedChk && allowedChk.getAttribute('data-user-id')) ||
                    (durationInp && durationInp.getAttribute('data-user-id'));
        if (!uid) return;

        if (allowedChk) {
          allowedChk.addEventListener('change', () => {
            saveRow(uid, row, true);
          });
        }
        if (durationInp) {
          durationInp.addEventListener('change', () => {
            saveRow(uid, row, false);
          });
        }
      });
    } catch (_) {
      permanentUsersTableBody.innerHTML = `<tr><td colspan="5" class="px-5 py-6 text-center text-rose-500">Chyba sítě.</td></tr>`;
    }
  }

  // Tlačítko Obnovit stav v záložce Permanent
  const refreshPermanentBtn = document.getElementById('refreshPermanentBtn');
  if (refreshPermanentBtn) {
    refreshPermanentBtn.addEventListener('click', async () => {
      refreshPermanentBtn.classList.add('opacity-50');
      try {
        await Promise.all([loadPermanentUsersTable(), fetchPermanentUnlockStatus()]);
        showToast('Stav trvalého odemčení byl aktualizován.', 'info');
      } finally {
        refreshPermanentBtn.classList.remove('opacity-50');
      }
    });
  }

  // Admin tlačítko Okamžitě uzamknout v záložce Permanent
  const adminStopPermanentBtn = document.getElementById('adminStopPermanentBtn');
  if (adminStopPermanentBtn) {
    adminStopPermanentBtn.addEventListener('click', async () => {
      if (!confirm('Opravdu chcete okamžitě ukončit trvalé odemčení a uzamknout dveře?')) return;
      try {
        const res = await fetch('/api/permanent-unlock/stop', {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ csrf_token: csrfToken })
        });
        const data = await res.json().catch(() => null);
        if (res.ok && data && data.success) {
          showToast('Trvalé odemčení bylo deaktivováno.', 'info');
          applyPermanentUnlockUi(data.state || { active: false });
          startPermanentCountdownRefresh(null);
          if (isNetworkAllowed) resetDoorButton();
        } else {
          showToast((data && data.message) || 'Nepodařilo se ukončit trvalé odemčení.', 'error');
        }
      } catch (_) {
        showToast('Chyba sítě.', 'error');
      }
    });
  }

  // ==========================================================================
  // PATCH initSession – inicializace trvalého odemčení
  // ==========================================================================
  const _origInitSession = initSession;
  async function initSessionWithPermanent() {
    await _origInitSession();
    // Načíst stav trvalého odemčení po inicializaci session
    await Promise.all([fetchPermanentUnlockStatus(), loadUserUnits()]);
    // Aktualizovat viditelnost navigace podle nastavení bočního menu uživatele
    updateSidebarNavVisibility();
    // Zobrazit admin akční prvky v záložce permanent (jen pro admin)
    if (permanentAdminActionWrap) {
      permanentAdminActionWrap.classList.toggle('hidden', currentUserRole !== 'admin');
    }
    // Zkontrolovat zda aktuální tab je povolen v bočním menu
    const menu = (currentUserSidebarMenu && Array.isArray(currentUserSidebarMenu) && currentUserSidebarMenu.length > 0)
      ? currentUserSidebarMenu
      : ['home'];
    const currentTab = tabFromCurrentPath();
    if (currentTab === 'units' && currentUserRole === 'admin') {
      switchTab('units', { pushHistory: false });
    } else if (!menu.includes(currentTab)) {
      switchTab(menu[0] || 'home', { pushHistory: false });
    }
  }

  // Spustit inicializaci
  initSessionWithPermanent();

  // ==========================================================================
  // ROZVRH ODEMYKÁNÍ – Schedule Editor
  // ==========================================================================

  // State
  let schedGridBuilt = false;
  let schedUsersLoaded = false;
  let schedSelectedUserId = null;
  let schedSelectedUnitId = null;
  // schedule: { dayIndex(str): Set of hours }
  let schedData = {};
  // drag state
  let schedDragging = false;
  let schedDragValue = true; // true = turn on, false = turn off

  const DAY_LABELS = ['Po', 'Út', 'St', 'Čt', 'Pá', 'So', 'Ne'];

  function schedGetEl(id) { return document.getElementById(id); }

  function buildScheduleGrid() {
    if (schedGridBuilt) return;
    schedGridBuilt = true;
    const grid = schedGetEl('schedGrid');
    if (!grid) return;

    // Clear
    while (grid.firstChild) grid.removeChild(grid.firstChild);

    // Header row: empty corner + 24 hour labels
    const corner = document.createElement('div');
    grid.appendChild(corner);
    for (let h = 0; h < 24; h++) {
      const lbl = document.createElement('div');
      lbl.className = 'sched-hour-lbl';
      lbl.textContent = String(h).padStart(2, '0');
      grid.appendChild(lbl);
    }

    // 7 day rows
    for (let d = 0; d < 7; d++) {
      const dayLbl = document.createElement('div');
      dayLbl.className = 'sched-day-lbl';
      dayLbl.textContent = DAY_LABELS[d];
      grid.appendChild(dayLbl);

      for (let h = 0; h < 24; h++) {
        const cell = document.createElement('div');
        cell.className = 'sched-cell';
        cell.dataset.day = d;
        cell.dataset.hour = h;

        cell.addEventListener('mousedown', (e) => {
          e.preventDefault();
          schedDragging = true;
          const isOn = cell.classList.contains('on');
          schedDragValue = !isOn;
          schedToggleCell(cell, schedDragValue);
        });

        cell.addEventListener('mouseenter', () => {
          if (schedDragging) schedToggleCell(cell, schedDragValue);
        });

        cell.addEventListener('touchstart', (e) => {
          schedDragging = true;
          const isOn = cell.classList.contains('on');
          schedDragValue = !isOn;
          schedToggleCell(cell, schedDragValue);
        }, { passive: true });

        cell.addEventListener('touchmove', (e) => {
          if (!schedDragging) return;
          const touch = e.touches[0];
          const el = document.elementFromPoint(touch.clientX, touch.clientY);
          if (el && el.classList.contains('sched-cell')) schedToggleCell(el, schedDragValue);
        }, { passive: true });

        grid.appendChild(cell);
      }
    }

    document.addEventListener('mouseup', () => { schedDragging = false; });
    document.addEventListener('touchend', () => { schedDragging = false; });
  }

  function schedToggleCell(cell, value) {
    const d = String(cell.dataset.day);
    const h = parseInt(cell.dataset.hour, 10);
    if (!schedData[d]) schedData[d] = new Set();
    if (value) {
      schedData[d].add(h);
      cell.classList.add('on');
    } else {
      schedData[d].delete(h);
      cell.classList.remove('on');
    }
  }

  function schedApplyDataToGrid() {
    const grid = schedGetEl('schedGrid');
    if (!grid) return;
    const cells = grid.querySelectorAll('.sched-cell');
    cells.forEach(cell => {
      const d = String(cell.dataset.day);
      const h = parseInt(cell.dataset.hour, 10);
      const isOn = schedData[d] && schedData[d].has(h);
      cell.classList.toggle('on', isOn);
    });
  }

  function schedSerialize() {
    const out = {};
    for (const d of Object.keys(schedData)) {
      const hours = Array.from(schedData[d]).sort((a, b) => a - b);
      if (hours.length > 0) out[d] = hours;
    }
    return out;
  }

  function schedDeserialize(raw) {
    schedData = {};
    if (!raw || typeof raw !== 'object') return;
    for (const d of Object.keys(raw)) {
      const hours = raw[d];
      if (Array.isArray(hours)) {
        schedData[String(d)] = new Set(hours.map(Number));
      }
    }
  }

  async function loadScheduleForUser(userId) {
    try {
      const res = await fetch(`/api/users/${encodeURIComponent(userId)}/schedule?unit_id=${encodeURIComponent(schedSelectedUnitId)}`, {
        headers: {
          'X-CSRF-Token': csrfToken,
          'X-CSRFToken': csrfToken
        }
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const json = await res.json();
      schedDeserialize(json.schedule || {});
      schedApplyDataToGrid();
    } catch (err) {
      console.error('Chyba při načítání rozvrhu:', err);
      schedData = {};
      schedApplyDataToGrid();
    }
  }

  async function saveSchedule() {
    if (!schedSelectedUserId || !schedSelectedUnitId) return;
    const saveBtn = schedGetEl('schedSaveBtn');
    const statusEl = schedGetEl('schedSaveStatus');
    if (saveBtn) saveBtn.disabled = true;
    if (statusEl) { statusEl.textContent = 'Ukládám…'; statusEl.className = 'sched-save-status'; }

    try {
      const payload = {
        schedule: schedSerialize(),
        unit_id: Number(schedSelectedUnitId),
        csrf_token: csrfToken
      };
      const res = await fetch(`/api/users/${encodeURIComponent(schedSelectedUserId)}/schedule`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
          'X-CSRFToken': csrfToken
        },
        body: JSON.stringify(payload)
      });
      const json = await res.json();
      if (json.success) {
        if (statusEl) { statusEl.textContent = '✓ Rozvrh uložen'; statusEl.className = 'sched-save-status ok'; }
      } else {
        if (statusEl) { statusEl.textContent = '✕ ' + (json.message || 'Chyba'); statusEl.className = 'sched-save-status err'; }
      }
    } catch (err) {
      if (statusEl) { statusEl.textContent = '✕ Chyba sítě'; statusEl.className = 'sched-save-status err'; }
    } finally {
      if (saveBtn) saveBtn.disabled = false;
      setTimeout(() => {
        if (statusEl) { statusEl.textContent = ''; statusEl.className = 'sched-save-status'; }
      }, 4000);
    }
  }

  function schedApplyPreset(preset) {
    if (preset === 'clear') {
      schedData = {};
      schedApplyDataToGrid();
      return;
    }

    if (preset === 'business_week') {
      // Všední dny (Po-Pá), 8:00 - 17:00 (hodiny 8 až 16)
      const hours = [8, 9, 10, 11, 12, 13, 14, 15, 16];
      schedData['0'] = new Set(hours);
      schedData['1'] = new Set(hours);
      schedData['2'] = new Set(hours);
      schedData['3'] = new Set(hours);
      schedData['4'] = new Set(hours);
      schedData['5'] = new Set();
      schedData['6'] = new Set();
    } else if (preset === 'all_week') {
      // Všední dny (Po-Pá), celý den (0-23)
      const hours = Array.from({length: 24}, (_, i) => i);
      schedData['0'] = new Set(hours);
      schedData['1'] = new Set(hours);
      schedData['2'] = new Set(hours);
      schedData['3'] = new Set(hours);
      schedData['4'] = new Set(hours);
      schedData['5'] = new Set();
      schedData['6'] = new Set();
    } else if (preset === 'weekend_all') {
      // Víkend (So-Ne), celý den (0-23)
      const hours = Array.from({length: 24}, (_, i) => i);
      schedData['0'] = new Set();
      schedData['1'] = new Set();
      schedData['2'] = new Set();
      schedData['3'] = new Set();
      schedData['4'] = new Set();
      schedData['5'] = new Set(hours);
      schedData['6'] = new Set(hours);
    } else if (preset === 'all_247') {
      // Všechny dny 24/7 (0-6, 0-23)
      const hours = Array.from({length: 24}, (_, i) => i);
      for (let d = 0; d < 7; d++) {
        schedData[String(d)] = new Set(hours);
      }
    }

    schedApplyDataToGrid();
  }

  function schedApplyTimeRange() {
    const fromVal = (schedGetEl('schedPresetFrom') || {}).value || '00:00';
    const toVal   = (schedGetEl('schedPresetTo')   || {}).value || '23:00';
    const fromH = parseInt(fromVal.split(':')[0], 10);
    const toH   = parseInt(toVal.split(':')[0], 10);
    const h0 = Math.min(fromH, toH);
    const h1 = Math.max(fromH, toH);
    const hours = Array.from({length: h1 - h0 + 1}, (_, i) => i + h0);

    const activeDays = Array.from(
      (schedGetEl('schedPresetDays') || document.createElement('div')).querySelectorAll('.sched-day-pill.active')
    ).map(el => String(el.dataset.day));
    const days = activeDays.length > 0 ? activeDays : ['0','1','2','3','4','5','6'];

    for (const d of days) {
      if (!schedData[d]) schedData[d] = new Set();
      hours.forEach(h => schedData[d].add(h));
    }
    schedApplyDataToGrid();
  }

  async function initScheduleTab() {
    buildScheduleGrid();

    const unitSelect = schedGetEl('schedUnitSelect');
    if (unitSelect) {
      const selectedUnit = schedSelectedUnitId || unitSelect.value;
      unitSelect.replaceChildren();
      const unitPlaceholder = document.createElement('option');
      unitPlaceholder.value = '';
      unitPlaceholder.textContent = '— Vyberte jednotku —';
      unitSelect.appendChild(unitPlaceholder);
      userUnits.filter(unit => currentUserRole === 'admin' || unit.selected).forEach(unit => {
        const option = document.createElement('option');
        option.value = String(unit.id);
        option.textContent = unit.name;
        unitSelect.appendChild(option);
      });
      if (selectedUnit && userUnits.some(unit => String(unit.id) === String(selectedUnit))) {
        unitSelect.value = String(selectedUnit);
        schedSelectedUnitId = unitSelect.value;
      } else {
        schedSelectedUnitId = null;
      }
    }

    // Populate user dropdown if not done yet
    if (!schedUsersLoaded) {
      const sel = schedGetEl('schedUserSelect');
      if (sel) {
        try {
          const res = await fetch('/api/users', {
            headers: {
              'X-CSRF-Token': csrfToken,
              'X-CSRFToken': csrfToken
            }
          });
          if (res.ok) {
            const json = await res.json();
            const users = json.users || [];
            // Clear and rebuild
            while (sel.firstChild) sel.removeChild(sel.firstChild);
            const placeholder = document.createElement('option');
            placeholder.value = '';
            placeholder.textContent = '— Vyberte uživatele —';
            sel.appendChild(placeholder);
            users.forEach(u => {
              const opt = document.createElement('option');
              opt.value = u.id;
              opt.textContent = `${u.username} (${u.role})`;
              sel.appendChild(opt);
            });
            schedUsersLoaded = true;
          }
        } catch (err) {
          console.error('Chyba při načítání uživatelů pro rozvrh:', err);
        }
      }
    }

    // Wire events (idempotent via flag)
    if (!window._schedEventsWired) {
      window._schedEventsWired = true;

      const sel = schedGetEl('schedUserSelect');
      if (sel) {
        sel.addEventListener('change', async () => {
          const uid = sel.value;
          schedSelectedUserId = uid || null;
          const wrap = schedGetEl('schedEditorWrap');
          if (wrap) wrap.classList.toggle('hidden', !uid || !schedSelectedUnitId);
          if (uid && schedSelectedUnitId) await loadScheduleForUser(uid);
        });
      }
      if (unitSelect) {
        unitSelect.addEventListener('change', async () => {
          schedSelectedUnitId = unitSelect.value || null;
          const wrap = schedGetEl('schedEditorWrap');
          if (wrap) wrap.classList.toggle('hidden', !schedSelectedUserId || !schedSelectedUnitId);
          if (schedSelectedUserId && schedSelectedUnitId) {
            await loadScheduleForUser(schedSelectedUserId);
          }
        });
      }

      // Preset buttons
      const presetsContainer = document.querySelector('.sched-presets');
      if (presetsContainer) {
        presetsContainer.addEventListener('click', (e) => {
          const btn = e.target.closest('[data-preset]');
          if (!btn) return;
          schedApplyPreset(btn.dataset.preset);
        });
      }

      // Apply time range button
      const applyBtn = schedGetEl('schedApplyRangeBtn');
      if (applyBtn) applyBtn.addEventListener('click', schedApplyTimeRange);

      // Day pills toggle in preset section
      const dayPillsContainer = schedGetEl('schedPresetDays');
      if (dayPillsContainer) {
        dayPillsContainer.addEventListener('click', (e) => {
          const pill = e.target.closest('.sched-day-pill');
          if (!pill) return;
          pill.classList.toggle('active');
        });
      }

      // Save button
      const saveBtn = schedGetEl('schedSaveBtn');
      if (saveBtn) saveBtn.addEventListener('click', saveSchedule);
    }
    const editorWrap = schedGetEl('schedEditorWrap');
    if (editorWrap) editorWrap.classList.toggle('hidden', !schedSelectedUserId || !schedSelectedUnitId);
    if (schedSelectedUserId && schedSelectedUnitId) {
      await loadScheduleForUser(schedSelectedUserId);
    }
  }

});
