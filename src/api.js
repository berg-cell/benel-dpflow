// src/api.js — Camada de comunicação com o backend DP Flow
// Coloque este arquivo em: src/api.js

const BASE = import.meta.env.VITE_API_URL || "https://benel-dpflow-backend-production.up.railway.app";

let _accessToken = null;
let _refreshToken = null;
let _onSessionExpired = null;

export function setTokens(access, refresh) {
  _accessToken = access;
  _refreshToken = refresh;
  if (refresh) sessionStorage.setItem("dpflow_refresh", refresh);
  if (access) sessionStorage.setItem("dpflow_access", access);
}

export function getAccessToken() { return _accessToken; }

export function loadTokensFromStorage() {
  _accessToken = sessionStorage.getItem("dpflow_access");
  _refreshToken = sessionStorage.getItem("dpflow_refresh");
  return { accessToken: _accessToken, refreshToken: _refreshToken };
}

export function clearTokens() {
  _accessToken = null;
  _refreshToken = null;
  sessionStorage.removeItem("dpflow_refresh");
  sessionStorage.removeItem("dpflow_access");
}

export function onSessionExpired(callback) {
  _onSessionExpired = callback;
}

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (_accessToken) headers["Authorization"] = `Bearer ${_accessToken}`;

  let res = await fetch(`${BASE}/api${path}`, { ...options, headers });

  // Token expirado — tentar refresh automático
  if (res.status === 401 && _refreshToken) {
    try {
      const rr = await fetch(`${BASE}/api/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: _refreshToken }),
      });
      if (rr.ok) {
        const rd = await rr.json();
        setTokens(rd.data.accessToken, rd.data.refreshToken);
        headers["Authorization"] = `Bearer ${_accessToken}`;
        res = await fetch(`${BASE}/api${path}`, { ...options, headers });
      } else {
        clearTokens();
        if (_onSessionExpired) _onSessionExpired();
        throw Object.assign(new Error("Sessão expirada. Faça login novamente."), { code: "SESSION_EXPIRED" });
      }
    } catch (e) {
      if (e.code === "SESSION_EXPIRED") throw e;
      clearTokens();
      if (_onSessionExpired) _onSessionExpired();
      throw Object.assign(new Error("Sessão expirada. Faça login novamente."), { code: "SESSION_EXPIRED" });
    }
  }

  const data = await res.json();
  if (!res.ok) throw new Error(data.message || `Erro ${res.status}`);
  return data.data ?? data;
}

export const api = {
  // ── Auth ──────────────────────────────────────────────────────────────────
  login: (email, senha) =>
    request("/auth/login", { method: "POST", body: JSON.stringify({ email, senha }) }),

  logout: () =>
    request("/auth/logout", { method: "POST" }),

  me: () => request("/auth/me"),

  // ── Colaboradores ─────────────────────────────────────────────────────────
  listarColaboradores: () => request("/colaboradores"),

  criarColaborador: (data) =>
    request("/colaboradores", { method: "POST", body: JSON.stringify(data) }),

  atualizarColaborador: (id, data) =>
    request(`/colaboradores/${id}`, { method: "PUT", body: JSON.stringify(data) }),

  importarColaboradores: (lista) =>
    request("/colaboradores/importar", {
      method: "POST",
      body: JSON.stringify({ colaboradores: lista }),
    }),

  // ── Eventos ───────────────────────────────────────────────────────────────
  listarEventos: () => request("/eventos"),

  criarEvento: (data) =>
    request("/eventos", { method: "POST", body: JSON.stringify(data) }),

  atualizarEvento: (id, data) =>
    request(`/eventos/${id}`, { method: "PUT", body: JSON.stringify(data) }),

  // ── Blocos ────────────────────────────────────────────────────────────────
  listarBlocos: (filtros = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(filtros).filter(([, v]) => v))
    ).toString();
    return request(`/blocos${qs ? "?" + qs : ""}`);
  },

  buscarBloco: (id) => request(`/blocos/${id}`),

  criarBloco: (data) =>
    request("/blocos", { method: "POST", body: JSON.stringify(data) }),

  aprovarBloco: (id, acao, justificativa) =>
    request(`/blocos/${id}/aprovar`, {
      method: "PUT",
      body: JSON.stringify({ acao, justificativa: justificativa || "" }),
    }),

  exportarTxtUrl: () =>
    `${BASE}/api/blocos/exportar/txt`,

  // ── Usuários ──────────────────────────────────────────────────────────────
  listarUsuarios: () => request("/usuarios"),

  criarUsuario: (data) =>
    request("/usuarios", { method: "POST", body: JSON.stringify(data) }),

  atualizarUsuario: (id, data) =>
    request(`/usuarios/${id}`, { method: "PUT", body: JSON.stringify(data) }),

  // ── Auditoria ─────────────────────────────────────────────────────────────
  listarAuditoria: () => request("/auditoria"),

  // ── Health ────────────────────────────────────────────────────────────────
  health: () => request("/health"),

  // ── Ocorrências Disciplinares ─────────────────────────────────────────────────
  listarOcorrencias: (qs = "") => request(`/ocorrencias${qs ? "?" + qs : ""}`),

  criarOcorrencia: (data) =>
    request("/ocorrencias", { method: "POST", body: JSON.stringify(data) }),

  cancelarOcorrencia: (id) =>
    request(`/ocorrencias/${id}/cancelar`, { method: "PUT", body: JSON.stringify({}) }),

  exportarOcorrenciasUrl: () => `${BASE}/api/ocorrencias/exportar`,

  resetarSenhaAdmin: (id, novaSenha) =>
    request(`/usuarios/${id}/reset-senha`, {
      method: "PUT",
      body: JSON.stringify({ novaSenha }),
    }),

  getToken: () => _accessToken,

};
