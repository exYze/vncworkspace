const API_URL = window.location.hostname === 'localhost' && window.location.port === '8080'
    ? '/api'
    : 'http://localhost:8000/api';

const state = {
    token: localStorage.getItem('token'),
    user: null,
    workspaces: [],
    activeSession: null,
    theme: localStorage.getItem('theme') || 'dark',
    adminData: {
        users: [],
        workspaces: [],
        sessions: [],
        settings: {},
        stats: {}
    }
};

const app = {
    init: async () => {
        app.applyTheme();

        // Check for token in URL (from Authentik redirect)
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        if (token) {
            state.token = token;
            localStorage.setItem('token', token);
            // Clear query params
            window.history.replaceState({}, document.title, "/");
        }

        if (state.token) {
            try {
                await app.fetchUser();
                app.navigateTo('dashboard');
            } catch (e) {
                app.logout();
            }
        } else {
            app.navigateTo('login');
        }
    },

    // --- Auth ---
    handleLogin: async (e) => {
        e.preventDefault();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;

        try {
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);

            const res = await fetch(`${API_URL}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData
            });

            if (!res.ok) throw new Error('Login failed');

            const data = await res.json();
            state.token = data.access_token;
            localStorage.setItem('token', state.token);

            await app.fetchUser();
            app.navigateTo('dashboard');
            app.showToast('Welcome back!', 'success');
        } catch (err) {
            app.showToast('Invalid credentials', 'error');
        }
    },

    handleAuthentikLogin: () => {
        window.location.href = `${API_URL}/auth/login/authentik`;
    },

    handleRegister: async (e) => {
        e.preventDefault();
        const username = document.getElementById('reg-username').value;
        const email = document.getElementById('reg-email').value;
        const password = document.getElementById('reg-password').value;

        try {
            const res = await fetch(`${API_URL}/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password })
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Registration failed');
            }

            app.showToast('Account created! Please login.', 'success');
            app.toggleAuthMode();
        } catch (err) {
            app.showToast(err.message, 'error');
        }
    },

    logout: () => {
        state.token = null;
        state.user = null;
        localStorage.removeItem('token');
        document.getElementById('navbar').style.display = 'none';
        app.navigateTo('login');
    },

    fetchUser: async () => {
        const res = await fetch(`${API_URL}/auth/me`, {
            headers: { 'Authorization': `Bearer ${state.token}` }
        });
        if (!res.ok) throw new Error('Failed to fetch user');
        state.user = await res.json();
        app.updateUI();
    },

    // --- Navigation & UI ---
    navigateTo: (viewId) => {
        document.querySelectorAll('.view').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));

        if (viewId === 'login' || viewId === 'register') {
            document.getElementById(`${viewId}-view`).classList.add('active');
            document.getElementById('navbar').style.display = 'none';
        } else {
            document.getElementById(`${viewId}-view`).classList.add('active');
            document.getElementById('navbar').style.display = 'flex';

            const navLink = document.getElementById(`nav-${viewId}`);
            if (navLink) navLink.classList.add('active');

            if (viewId === 'dashboard') app.loadDashboard();
            if (viewId === 'admin') app.loadAdmin();
        }
    },

    toggleAuthMode: () => {
        const loginView = document.getElementById('login-view');
        const regView = document.getElementById('register-view');

        if (loginView.classList.contains('active')) {
            loginView.classList.remove('active');
            regView.classList.add('active');
        } else {
            regView.classList.remove('active');
            loginView.classList.add('active');
        }
    },

    updateUI: () => {
        if (state.user) {
            document.getElementById('user-name').textContent = state.user.username;
            if (state.user.is_admin) {
                document.getElementById('nav-admin').classList.remove('hidden');
            } else {
                document.getElementById('nav-admin').classList.add('hidden');
            }
        }
    },

    toggleTheme: () => {
        state.theme = state.theme === 'dark' ? 'light' : 'dark';
        localStorage.setItem('theme', state.theme);
        app.applyTheme();
    },

    applyTheme: () => {
        document.documentElement.setAttribute('data-theme', state.theme);
        const icon = document.getElementById('theme-icon');
        icon.className = state.theme === 'dark' ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
    },

    showToast: (msg, type = 'info') => {
        const toast = document.getElementById('toast');
        toast.textContent = msg;
        toast.style.borderLeft = `4px solid ${type === 'success' ? '#10b981' : '#ef4444'}`;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 3000);
    },

    // --- Dashboard Logic ---
    loadDashboard: async () => {
        await Promise.all([app.fetchWorkspaces(), app.fetchSessionStatus()]);
    },

    fetchWorkspaces: async () => {
        try {
            const res = await fetch(`${API_URL}/workspaces`, {
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            state.workspaces = await res.json();
            app.renderWorkspaces();
        } catch (err) {
            console.error(err);
        }
    },

    renderWorkspaces: () => {
        const container = document.getElementById('workspaces-container');
        container.innerHTML = state.workspaces.map(ws => `
            <div class="workspace-card">
                <div class="card-header">
                    <div class="card-icon"><i class="${ws.icon || 'fa-solid fa-desktop'}"></i></div>
                    <div>
                        <h3>${ws.friendly_name}</h3>
                        <small>${ws.category}</small>
                    </div>
                </div>
                <div class="card-body">
                    <p>${ws.description}</p>
                    <button onclick="app.startSession(${ws.id})" class="btn-primary btn-block" ${state.activeSession ? 'disabled' : ''}>
                        ${state.activeSession ? 'Session Active' : 'Launch Workspace'}
                    </button>
                </div>
            </div>
        `).join('');
    },

    fetchSessionStatus: async () => {
        try {
            const res = await fetch(`${API_URL}/sessions/status`, {
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            const session = await res.json();
            state.activeSession = session;

            const statusSection = document.getElementById('active-session-section');
            if (session) {
                statusSection.style.display = 'block';
                document.getElementById('session-ws-name').textContent = session.workspace_image.friendly_name;
                document.getElementById('session-port').textContent = session.vnc_port;
                app.renderWorkspaces(); // Re-render to disable buttons
            } else {
                statusSection.style.display = 'none';
                app.renderWorkspaces();
            }
        } catch (err) {
            console.error(err);
        }
    },

    startSession: async (workspaceId) => {
        try {
            app.showToast('Starting workspace...', 'info');
            const res = await fetch(`${API_URL}/sessions/start`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${state.token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ workspace_image_id: workspaceId })
            });

            if (!res.ok) throw new Error('Failed to start session');

            await app.fetchSessionStatus();
            app.showToast('Workspace ready!', 'success');
        } catch (err) {
            app.showToast(err.message, 'error');
        }
    },

    stopSession: async () => {
        if (!confirm('The machine will be deleted if you stop it. Are you sure you want to proceed?')) return;

        try {
            const res = await fetch(`${API_URL}/sessions/stop`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${state.token}` }
            });

            if (!res.ok) throw new Error('Failed to stop session');

            state.activeSession = null;
            await app.fetchSessionStatus();
            app.showToast('Session stopped', 'success');
        } catch (err) {
            app.showToast(err.message, 'error');
        }
    },

    connectSession: () => {
        if (!state.activeSession) return;
        // In a real scenario, we might use a proxy or direct connection
        // For this demo, we assume localhost mapping
        const port = state.activeSession.vnc_port;
        const password = state.activeSession.vnc_password || 'password';
        // Try multiple parameter formats for KasmVNC
        // Format 1: Direct parameters
        window.open(`https://localhost:${port}/?password=${password}&autoconnect=true&resize=scale`, '_blank');
    },

    // --- Admin Logic ---
    loadAdmin: async () => {
        if (!state.user.is_admin) return app.navigateTo('dashboard');
        await app.loadAdminStats();
        await app.loadAdminUsers();
        // Default tab
        app.switchAdminTab('users');
    },

    switchAdminTab: (tabId) => {
        document.querySelectorAll('.admin-tab').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.admin-sidebar li').forEach(el => el.classList.remove('active'));

        document.getElementById(`admin-${tabId}-view`).classList.add('active');
        document.getElementById(`tab-${tabId}`).classList.add('active');

        if (tabId === 'users') app.loadAdminUsers();
        if (tabId === 'workspaces') app.loadAdminWorkspaces();
        if (tabId === 'sessions') app.loadAdminSessions();
        if (tabId === 'settings') app.loadAdminSettings();
    },

    loadAdminStats: async () => {
        try {
            const res = await fetch(`${API_URL}/admin/stats`, {
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            const stats = await res.json();
            const container = document.getElementById('admin-stats');
            container.innerHTML = `
                <div class="stat-card">
                    <div class="stat-value">${stats.total_users}</div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.total_workspaces}</div>
                    <div class="stat-label">Workspaces</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.active_sessions}</div>
                    <div class="stat-label">Active Sessions</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${stats.total_sessions}</div>
                    <div class="stat-label">Total Sessions</div>
                </div>
            `;
        } catch (err) { console.error(err); }
    },

    loadAdminUsers: async () => {
        try {
            const res = await fetch(`${API_URL}/admin/users`, {
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            const users = await res.json();
            const tbody = document.getElementById('users-table-body');
            tbody.innerHTML = users.map(u => `
                <tr>
                    <td>${u.id}</td>
                    <td>${u.username}</td>
                    <td><span class="badge ${u.is_admin ? 'badge-primary' : 'badge-secondary'}">${u.is_admin ? 'Admin' : 'Student'}</span></td>
                    <td>${new Date(u.created_at).toLocaleDateString()}</td>
                    <td>
                        <button onclick="app.deleteUser(${u.id})" class="btn-sm btn-danger"><i class="fa-solid fa-trash"></i></button>
                    </td>
                </tr>
            `).join('');
        } catch (err) { console.error(err); }
    },

    deleteUser: async (id) => {
        if (!confirm('Delete this user?')) return;
        try {
            await fetch(`${API_URL}/admin/users/${id}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            app.loadAdminUsers();
        } catch (err) { app.showToast('Failed to delete user', 'error'); }
    },

    loadAdminWorkspaces: async () => {
        try {
            const res = await fetch(`${API_URL}/admin/workspaces`, {
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            const workspaces = await res.json();
            const tbody = document.getElementById('workspaces-table-body');

            // Add "Add New" button to header if not present (hacky but works for now)
            const header = document.querySelector('#admin-workspaces-view .tab-header');
            if (!header.querySelector('.btn-primary')) {
                const btn = document.createElement('button');
                btn.className = 'btn btn-primary btn-sm';
                btn.innerHTML = '<i class="fa-solid fa-plus"></i> Add New';
                btn.onclick = () => app.openModal('add-workspace-modal');
                header.appendChild(btn);
            }

            tbody.innerHTML = workspaces.map(w => `
                <tr>
                    <td>${w.name}</td>
                    <td>${w.friendly_name}</td>
                    <td>${w.category}</td>
                    <td><span class="badge badge-success">Enabled</span></td>
                </tr>
            `).join('');
        } catch (err) { console.error(err); }
    },

    // --- Modal Logic ---
    openModal: (modalId) => {
        document.getElementById(modalId).classList.add('active');
    },

    closeModal: (modalId) => {
        document.getElementById(modalId).classList.remove('active');
    },

    handleCreateWorkspace: async (e) => {
        e.preventDefault();
        const data = {
            name: document.getElementById('ws-image').value,
            friendly_name: document.getElementById('ws-name').value,
            description: document.getElementById('ws-desc').value,
            category: document.getElementById('ws-category').value,
            icon: document.getElementById('ws-icon').value,
            enabled: true
        };

        try {
            const res = await fetch(`${API_URL}/admin/workspaces`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${state.token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            if (!res.ok) throw new Error('Failed to create workspace');

            app.showToast('Workspace created!', 'success');
            app.closeModal('add-workspace-modal');
            app.loadAdminWorkspaces();
            e.target.reset();
        } catch (err) {
            app.showToast(err.message, 'error');
        }
    },

    loadAdminSessions: async () => {
        try {
            const res = await fetch(`${API_URL}/admin/sessions`, {
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            const sessions = await res.json();
            const tbody = document.getElementById('sessions-table-body');
            tbody.innerHTML = sessions.map(s => `
                <tr>
                    <td>${s.user.username}</td>
                    <td>${s.workspace_image.friendly_name}</td>
                    <td>${s.container_name}</td>
                    <td>${s.vnc_port}</td>
                    <td>${new Date(s.created_at).toLocaleTimeString()}</td>
                    <td>
                        <button onclick="app.killSession(${s.user_id})" class="btn-sm btn-danger">Kill</button>
                    </td>
                </tr>
            `).join('');
        } catch (err) { console.error(err); }
    },

    killSession: async (userId) => {
        if (!confirm('Force stop this session?')) return;
        try {
            await fetch(`${API_URL}/admin/sessions/${userId}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            app.loadAdminSessions();
            app.showToast('Session killed', 'success');
        } catch (err) { app.showToast('Failed to kill session', 'error'); }
    },

    loadAdminSettings: async () => {
        try {
            const res = await fetch(`${API_URL}/admin/settings`, {
                headers: { 'Authorization': `Bearer ${state.token}` }
            });
            const settings = await res.json();
            if (settings.session_timeout_minutes) {
                document.getElementById('setting-timeout').value = settings.session_timeout_minutes;
            }
        } catch (err) { console.error(err); }
    },

    saveSessionTimeout: async () => {
        const value = document.getElementById('setting-timeout').value;
        try {
            await fetch(`${API_URL}/admin/settings/session_timeout_minutes`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${state.token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ value })
            });
            app.showToast('Settings saved', 'success');
        } catch (err) { app.showToast('Failed to save settings', 'error'); }
    }
};

// Initialize
document.addEventListener('DOMContentLoaded', app.init);
