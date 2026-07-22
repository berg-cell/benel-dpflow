import { useState, useContext, createContext, useEffect, useCallback, useRef } from "react";
import { api, setTokens, clearTokens, onSessionExpired } from "./api";
import {
  sanitize, sanitizeObject, validateField, validarSchemaTotvs,
  validarBlocoParaExportacao, verificarRateLimit, resetarRateLimit,
  criarSessao, obterSessao, encerrarSessao, verificarPermissaoBloco,
  filtrarBlocosPermitidos, registrarAuditoria, obterAuditLog, ACOES,
  aplicarCSP, detectarPromptInjection, sanitizarComProtecao, validarFormulario,
} from "./lib/security";
import { LOGO_BENEL, ASSINATURA_BENEL } from "./lib/assets";
import { fmtDateLocal, formatReal, generateTXTLine, valorPorExtenso, fmtDataPS } from "./lib/format";
import { Card, Button, Input, Select, Modal, verificarForcaSenha, IndicadorSenha } from "./components/ui";

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY MODULE — DP Flow | Benel 
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY MODULE — DP Flow | Benel Soluções em Transporte e Logística
// Implementação: Sanitização XSS, Rate Limiting, Validação de Schema TOTVS RM,
// Prevenção IDOR, Sessão com expiração, Audit Log, Content Security Policy
// ═══════════════════════════════════════════════════════════════════════════════

// ─── CONTEXTO DE AUTH ────────────────────────────────────────────────────────
const AuthContext = createContext(null);

// ─── UTILITÁRIOS ─────────────────────────────────────────────────────────────
// Converte data do banco para YYYY-MM-DD usando UTC (sem conversão de fuso)

const STATUS_CONFIG = {
  pendente_gestor:   { label: "Pendente Gestor",   color: "#F59E0B", bg: "#FEF3C7", dot: "#F59E0B" },
  pendente_superior: { label: "Pendente Superior", color: "#8B5CF6", bg: "#EDE9FE", dot: "#8B5CF6" },
  pendente_dp:       { label: "Pendente DP",       color: "#3B82F6", bg: "#DBEAFE", dot: "#3B82F6" },
  aprovado_final:    { label: "Aprovado",           color: "#10B981", bg: "#D1FAE5", dot: "#10B981" },
  rejeitado:         { label: "Rejeitado",          color: "#EF4444", bg: "#FEE2E2", dot: "#EF4444" },
  devolvido:         { label: "Devolvido",          color: "#F97316", bg: "#FFEDD5", dot: "#F97316" },
  rascunho:          { label: "Rascunho",           color: "#6B7280", bg: "#F3F4F6", dot: "#6B7280" },
};

const PERFIL_CONFIG = {
  gestor:     { label: "Gestor",     color: "#3B82F6" },
  superior:   { label: "Superior",   color: "#8B5CF6" },
  dp:         { label: "DP",         color: "#10B981" },
  presidente: { label: "Presidente", color: "#DC2626" },
  admin:      { label: "Admin",      color: "#F59E0B" },
};

// ─── LAYOUT OFICIAL RM LABORE ─────────────────────────────────────────────────
// Col 01 | Tam 16 | String       | Chapa do Funcionário
// Col 17 | Tam 08 | String       | Data pagamento (DDMMAAAA)
// Col 25 | Tam 04 | Alfanumérico | Código do evento
// Col 29 | Tam 06 | String       | Hora (HHH:MM)
// Col 35 | Tam 15 | Real         | Referência (999999999999.99)
// Col 50 | Tam 15 | Real         | Valor (999999999999.99)
// Col 65 | Tam 15 | Real         | Valor original (999999999999.99)
// Col 80 | Tam 01 | Caractere    | Dados alterados manualmente (S ou N)
// Col 81 | Tam 01 | Caractere    | Dados de férias (S ou N)
// Total  | 81 caracteres por linha

// ─── COMPONENTES BASE ─────────────────────────────────────────────────────────
function Badge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.rascunho;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 10px", borderRadius: 20, fontSize: 11, fontWeight: 600,
      color: cfg.color, background: cfg.bg, letterSpacing: 0.3
    }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: cfg.dot }} />
      {cfg.label}
    </span>
  );
}

// ─── LOGIN SEGURO ─────────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [email, setEmail] = useState("");
  const [senha, setSenha] = useState("");
  const [erro, setErro] = useState("");
  const [aviso, setAviso] = useState("");
  const [loading, setLoading] = useState(false);
  const [bloqueado, setBloqueado] = useState(false);

  // Aplicar CSP ao montar
  useEffect(() => { aplicarCSP(); }, []);

  const handleLogin = async () => {
    setErro(""); setAviso("");

    const emailLimpo = sanitize(email.trim());
    if (!emailLimpo || !/^[^@]+@[^@]+\.[^@]+$/.test(emailLimpo)) {
      setErro("Informe um e-mail válido.");
      return;
    }

    const rate = verificarRateLimit(emailLimpo);
    if (!rate.permitido) {
      setBloqueado(true);
      setErro(rate.erro);
      registrarAuditoria(null, ACOES.RATE_LIMIT, { email: emailLimpo });
      return;
    }
    if (rate.aviso) setAviso(rate.aviso);

    setLoading(true);
    try {
      const data = await api.login(emailLimpo, senha);
      // data = { accessToken, refreshToken, usuario: { id, nome, email, perfil } }
      setTokens(data.accessToken, data.refreshToken);
      resetarRateLimit(emailLimpo);
      const u = {
        ...data.usuario,
        avatar: data.usuario.nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase(),
        senha: "",
      };
      const sessao = criarSessao(u);
      registrarAuditoria(sessao, ACOES.LOGIN_OK, { email: emailLimpo });
      onLogin(u, sessao);
    } catch (err) {
      registrarAuditoria(null, ACOES.LOGIN_FALHA, { email: emailLimpo });
      setErro(err.message || "E-mail ou senha inválidos.");
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => { if (e.key === "Enter" && !bloqueado) handleLogin(); };

  return (
    <div style={{
      minHeight: "100vh", background: "linear-gradient(135deg, #0F2447 0%, #1B3A6B 50%, #2D5AA0 100%)",
      display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "'DM Sans', sans-serif"
    }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet" />

      {/* Decoração */}
      <div style={{ position: "fixed", inset: 0, overflow: "hidden", pointerEvents: "none" }}>
        {[...Array(6)].map((_, i) => (
          <div key={i} style={{
            position: "absolute",
            width: [300,200,150,400,250,180][i],
            height: [300,200,150,400,250,180][i],
            borderRadius: "50%",
            border: "1px solid rgba(255,255,255,0.05)",
            left: ["10%","60%","80%","5%","50%","30%"][i],
            top: ["20%","10%","60%","70%","80%","40%"][i],
          }} />
        ))}
      </div>

      <div style={{ position: "relative", zIndex: 1, width: "100%", maxWidth: 420, padding: "0 20px" }}>
        {/* Logo Benel */}
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{
            background: "rgba(255,255,255,0.95)", backdropFilter: "blur(10px)",
            borderRadius: 16, padding: "16px 28px", marginBottom: 16,
            boxShadow: "0 4px 24px rgba(0,0,0,0.2)",
            display: "inline-block"
          }}>
            <img src={LOGO_BENEL} alt="Benel" style={{ height: 64, display: "block" }} />
          </div>
          <p style={{ color: "rgba(255,255,255,0.55)", margin: "6px 0 0", fontSize: 13 }}>
            Sistema de Gestão de Variáveis para Folha de Pagamento
          </p>
        </div>

        {/* Card */}
        <div style={{
          background: "rgba(255,255,255,0.97)", borderRadius: 18,
          padding: "32px", boxShadow: "0 24px 80px rgba(0,0,0,0.35)"
        }}>
          <h2 style={{ margin: "0 0 6px", fontSize: 18, fontWeight: 700, color: "#0F2447" }}>Entrar</h2>
          <p style={{ margin: "0 0 24px", fontSize: 12, color: "#6B7280" }}>
            Acesse com suas credenciais corporativas
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <Input label="E-mail" value={email} onChange={setEmail} type="email" placeholder="seu@email.com" style={{ onKeyDown: handleKeyDown }} />
            <Input label="Senha" value={senha} onChange={setSenha} type="password" placeholder="••••••••" />

            {aviso && (
              <div style={{
                background: "#FFFBEB", border: "1px solid #FCD34D",
                borderRadius: 8, padding: "8px 12px", fontSize: 12, color: "#92400E"
              }}>
                ⚠️ {aviso}
              </div>
            )}
            {erro && (
              <div style={{
                background: "#FEF2F2", border: "1px solid #FCA5A5",
                borderRadius: 8, padding: "8px 12px", fontSize: 12, color: "#DC2626"
              }}>
                🔒 {erro}
              </div>
            )}

            <Button onClick={handleLogin} disabled={loading || bloqueado} size="lg" style={{ marginTop: 4, width: "100%" }}>
              {loading ? "Verificando..." : bloqueado ? "🔒 Acesso Bloqueado" : "Entrar"}
            </Button>
          </div>

          {/* Suporte */}
          <div style={{
            marginTop: 20, padding: "10px 14px", background: "#F8FAFC",
            borderRadius: 8, border: "1px solid #E2E8F0", textAlign: "center"
          }}>
            <p style={{ margin: 0, fontSize: 11, color: "#94A3B8" }}>
              Problemas de acesso? Contate o administrador do sistema.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── SIDEBAR ─────────────────────────────────────────────────────────────────

// ─── SIDEBAR COM SUBMENU ──────────────────────────────────────────────────────
const CADASTROS_SUBMENU = [
  { id: "cad_colaboradores", label: "Colaboradores",  icon: "👥", perfis: ["dp","admin"] },
  { id: "cad_eventos",       label: "Eventos",         icon: "⚡", perfis: ["dp","admin"] },
  { id: "cad_hierarquia",    label: "Hierarquia",      icon: "🏢", perfis: ["dp","admin"] },
  { id: "cad_alcadas",       label: "Alçadas",         icon: "🔀", perfis: ["dp","admin"] },
  { id: "cad_usuarios",      label: "Usuários",        icon: "🔑", perfis: ["admin"] },
];

const BENEFICIOS_SUBMENU = [
  { id: "plano_saude", label: "Solicitação de Plano de Saúde", icon: "💊", perfis: ["dp","admin","gestor"] },
];

const NAV_ITEMS = [
  { id: "cadastros",     label: "Cadastros",                            icon: "🗂",  perfis: ["dp","admin"], submenu: CADASTROS_SUBMENU },
  { id: "atualizacao_cadastral", label: "Atualização de Dados Cadastrais", icon: "📝", perfis: ["gestor","dp","admin","presidente"] },
  { id: "ocorrencias",      label: "Solicitações de Advertências/Suspensões", icon: "⚠️", perfis: ["gestor","dp","admin"] },
  { id: "autorizacoes",     label: "Autorização de Desconto",                icon: "📋", perfis: ["gestor","dp","admin","presidente"] },
  { id: "solicitacoes",     label: "Solicitações de Pagamento",               icon: "≡",  perfis: ["gestor","superior","dp","admin"] },
  { id: "desligamentos", label: "Solicitações de Desligamento",         icon: "🚪", perfis: ["gestor","superior","dp","admin","presidente"] },
  { id: "beneficios",    label: "Benefícios",                           icon: "🏥", perfis: ["dp","admin","gestor"], submenu: BENEFICIOS_SUBMENU },
  { id: "aprovacoes",    label: "Aprovações",                           icon: "✓",  perfis: ["superior","dp","admin"] },
  { id: "dashboard",     label: "Dashboard",                            icon: "◉",  perfis: ["gestor","superior","dp","admin"] },
  { id: "exportacao",    label: "Exportação TXT",                       icon: "↓",  perfis: ["dp","admin"] },
  { id: "auditoria",     label: "Auditoria",                            icon: "📜", perfis: ["dp","admin"] },
];


// ─── TOPBAR ───────────────────────────────────────────────────────────────────
function Topbar({ title, subtitle, user, onLogout }) {
  return (
    <div style={{
      height: 60, background: "#fff", borderBottom: "1px solid #E5E7EB",
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "0 28px", flexShrink: 0
    }}>
      <div>
        <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#111827" }}>{title}</h2>
        {subtitle && <p style={{ margin: 0, fontSize: 11, color: "#9CA3AF" }}>{subtitle}</p>}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <button onClick={onLogout} style={{
          background: "none", border: "1px solid #E5E7EB", borderRadius: 8,
          padding: "5px 12px", fontSize: 12, color: "#6B7280", cursor: "pointer", fontFamily: "inherit"
        }}>Sair</button>
      </div>
    </div>
  );
}

// ─── DASHBOARD ────────────────────────────────────────────────────────────────
function Dashboard({ solicitacoes, blocos, user }) {
  const total = blocos.length;
  const pendentes = blocos.filter(b => b.status.startsWith("pendente")).length;
  const aprovados = blocos.filter(b => b.status === "aprovado_final").length;
  const devolvidos = blocos.filter(b => b.status === "devolvido").length;

  const valorTotal = blocos
    .filter(b => b.status === "aprovado_final")
    .reduce((a, b) => a + b.linhas.reduce((s, l) => s + parseFloat(l.valor || 0), 0), 0);

  const stats = [
    { label: "Total de Blocos", value: total,     color: "#3B82F6", bg: "#EFF6FF", icon: "≡" },
    { label: "Pendentes",       value: pendentes,  color: "#F59E0B", bg: "#FFFBEB", icon: "⏳" },
    { label: "Aprovados",       value: aprovados,  color: "#10B981", bg: "#F0FDF4", icon: "✓" },
    { label: "Devolvidos",      value: devolvidos, color: "#F97316", bg: "#FFF7ED", icon: "↩" },
  ];

  return (
    <div style={{ padding: 28, display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
        {stats.map(s => (
          <div key={s.label} style={{ background: "#fff", borderRadius: 12, border: "1px solid #E5E7EB", padding: "18px 20px" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: "#6B7280", textTransform: "uppercase", letterSpacing: 0.5 }}>{s.label}</span>
              <div style={{ width: 30, height: 30, borderRadius: 8, background: s.bg, display: "flex", alignItems: "center", justifyContent: "center", color: s.color, fontSize: 14, fontWeight: 700 }}>{s.icon}</div>
            </div>
            <div style={{ fontSize: 28, fontWeight: 700, color: "#111827" }}>{s.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {/* Valor total aprovado */}
        <Card>
          <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700, color: "#111827" }}>💰 Valor Total Aprovado</h3>
          <div style={{ fontSize: 32, fontWeight: 700, color: "#10B981" }}>
            R$ {valorTotal.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
          </div>
          <p style={{ margin: "6px 0 0", fontSize: 12, color: "#6B7280" }}>{aprovados} bloco(s) aprovado(s) no período</p>
        </Card>

        {/* Últimos blocos */}
        <Card>
          <h3 style={{ margin: "0 0 14px", fontSize: 14, fontWeight: 700, color: "#111827" }}>🕐 Últimos Blocos</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {blocos.slice(-4).reverse().map(b => (
              <div key={b.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "7px 0", borderBottom: "1px solid #F3F4F6" }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: "#111827" }}>{b.descricao}</div>
                  <div style={{ fontSize: 11, color: "#6B7280" }}>{b.linhas.length} lançamento(s) · {b.competencia}</div>
                </div>
                <Badge status={b.status} />
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Distribuição por status */}
      <Card>
        <h3 style={{ margin: "0 0 16px", fontSize: 14, fontWeight: 700, color: "#111827" }}>📊 Distribuição por Status</h3>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          {Object.entries(STATUS_CONFIG).map(([key, cfg]) => {
            const count = blocos.filter(b => b.status === key).length;
            if (!count) return null;
            const pct = Math.round((count / Math.max(total, 1)) * 100);
            return (
              <div key={key} style={{ flex: "1 1 150px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                  <span style={{ fontSize: 11, color: "#6B7280" }}>{cfg.label}</span>
                  <span style={{ fontSize: 11, fontWeight: 700, color: cfg.color }}>{count}</span>
                </div>
                <div style={{ height: 6, background: "#F3F4F6", borderRadius: 3 }}>
                  <div style={{ height: "100%", width: pct + "%", background: cfg.color, borderRadius: 3 }} />
                </div>
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}

function Sidebar({ active, onNav, user }) {
  const [abertos, setAbertos] = useState(() => {
    const init = {};
    if (active && active.startsWith("cad_")) init["cadastros"] = true;
    if (active === "plano_saude") init["beneficios"] = true;
    return init;
  });

  const toggleMenu = (id) => setAbertos(o => ({ ...o, [id]: !o[id] }));

  const items = NAV_ITEMS.filter(i => i.perfis.includes(user.perfil));

  const btnStyle = (isActive) => ({
    display: "flex", alignItems: "center", gap: 10,
    padding: "9px 12px", borderRadius: 8, border: "none",
    background: isActive ? "rgba(59,130,246,0.2)" : "transparent",
    color: isActive ? "#93C5FD" : "rgba(255,255,255,0.55)",
    cursor: "pointer", textAlign: "left", fontFamily: "inherit",
    fontSize: 13, fontWeight: isActive ? 600 : 400,
    borderLeft: isActive ? "2px solid #3B82F6" : "2px solid transparent",
    transition: "all 0.15s", width: "100%"
  });

  return (
    <div style={{
      width: 224, minHeight: "100vh", background: "#0F2447",
      display: "flex", flexDirection: "column", flexShrink: 0,
      fontFamily: "'DM Sans', sans-serif"
    }}>
      {/* Logo Benel */}
      <div style={{ padding: "16px 16px 14px", borderBottom: "1px solid rgba(255,255,255,0.07)" }}>
        <div style={{
          background: "rgba(255,255,255,0.95)", borderRadius: 10,
          padding: "8px 12px", display: "flex", alignItems: "center", justifyContent: "center"
        }}>
          <img src={LOGO_BENEL} alt="Benel" style={{ height: 38, display: "block", maxWidth: "100%" }} />
        </div>
        <div style={{ textAlign: "center", marginTop: 6, fontSize: 9, color: "rgba(255,255,255,0.35)", letterSpacing: 1, textTransform: "uppercase" }}>
          Gestão de Folha de Pagamento
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "12px 10px", display: "flex", flexDirection: "column", gap: 2, overflowY: "auto" }}>
        {items.map(item => {
          if (item.submenu) {
            const subItems = item.submenu.filter(s => s.perfis.includes(user.perfil));
            const isOpen = !!abertos[item.id];
            const isParentActive = item.id === "cadastros"
              ? (active && active.startsWith("cad_"))
              : subItems.some(s => s.id === active);
            return (
              <div key={item.id}>
                {/* Botão pai */}
                <button
                  onClick={() => toggleMenu(item.id)}
                  style={{
                    ...btnStyle(isParentActive),
                    justifyContent: "space-between"
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ fontSize: 14 }}>{item.icon}</span>
                    {item.label}
                  </div>
                  <span style={{
                    fontSize: 10, transition: "transform 0.2s",
                    transform: isOpen ? "rotate(180deg)" : "rotate(0deg)",
                    color: "rgba(255,255,255,0.4)"
                  }}>▼</span>
                </button>

                {/* Submenu */}
                {isOpen && (
                  <div style={{
                    marginLeft: 10, marginTop: 2, marginBottom: 4,
                    borderLeft: "1px solid rgba(255,255,255,0.1)",
                    paddingLeft: 10, display: "flex", flexDirection: "column", gap: 1
                  }}>
                    {subItems.map(sub => (
                      <button
                        key={sub.id}
                        onClick={() => onNav(sub.id)}
                        style={{
                          display: "flex", alignItems: "center", gap: 8,
                          padding: "7px 10px", borderRadius: 6, border: "none",
                          background: active === sub.id ? "rgba(59,130,246,0.25)" : "transparent",
                          color: active === sub.id ? "#93C5FD" : "rgba(255,255,255,0.45)",
                          cursor: "pointer", textAlign: "left", fontFamily: "inherit",
                          fontSize: 12, fontWeight: active === sub.id ? 600 : 400,
                          borderLeft: active === sub.id ? "2px solid #3B82F6" : "2px solid transparent",
                          transition: "all 0.15s", width: "100%"
                        }}
                      >
                        <span style={{ fontSize: 12 }}>{sub.icon}</span>
                        {sub.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          }
          return (
            <button key={item.id} onClick={() => onNav(item.id)} style={btnStyle(active === item.id)}>
              <span style={{ fontSize: 14 }}>{item.icon}</span>
              {item.label}
            </button>
          );
        })}
      </nav>

      {/* User */}
      <div style={{ padding: "14px", borderTop: "1px solid rgba(255,255,255,0.07)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 34, height: 34, borderRadius: 10,
            background: PERFIL_CONFIG[user.perfil]?.color,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 12, fontWeight: 700, color: "#fff", flexShrink: 0
          }}>{user.avatar}</div>
          <div style={{ overflow: "hidden" }}>
            <div style={{ color: "#fff", fontSize: 12, fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{user.nome}</div>
            <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: 0.5, color: PERFIL_CONFIG[user.perfil]?.color, textTransform: "uppercase" }}>
              {PERFIL_CONFIG[user.perfil]?.label}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── HELPERS DE IMPORTAÇÃO ────────────────────────────────────────────────────
function parseCSV(text) {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];

  // Detectar separador: ; ou ,
  const sep = lines[0].includes(";") ? ";" : ",";

  // Dividir linha respeitando aspas
  const splitLine = (line) => {
    const result = []; let cur = ""; let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') { inQ = !inQ; continue; }
      if (c === sep && !inQ) { result.push(cur.trim()); cur = ""; continue; }
      cur += c;
    }
    result.push(cur.trim());
    return result;
  };

  // Mapa de colunas PT -> EN (com e sem acento)
  const MAPA = {
    "matrícula": "chapa", "matricula": "chapa", "chapa": "chapa",
    "nome": "nome",
    "função": "funcao", "funcao": "funcao", "cargo": "funcao", "desc_funcao": "funcao",
    "seção": "desc_cc", "secao": "desc_cc", "setor": "desc_cc", "desc_cc": "desc_cc",
    "cpf": "cpf",
    "admissão": "data_admissao", "admissao": "data_admissao",
    "data_admissao": "data_admissao", "data admissao": "data_admissao",
    "c. custo": "centro_custo", "centro_custo": "centro_custo", "centro custo": "centro_custo",
    "situação": "situacao", "situacao": "situacao", "status": "situacao",
    "desc_situacao": "situacao",
    "cod_situacao": "cod_situacao", "cód. situação": "cod_situacao", "cod situacao": "cod_situacao",
    "tipo_contrato": "tipo_contrato", "tipo contrato": "tipo_contrato",
    "data_fim_contrato": "data_fim_contrato", "data fim contrato": "data_fim_contrato",
    "prazo45": "prazo45", "prazo90": "prazo90",
    "data_fim_estabilidade": "data_fim_estabilidade", "data fim estabilidade": "data_fim_estabilidade",
    "descricao_estabilidade": "descricao_estabilidade", "descrição estabilidade": "descricao_estabilidade",
    // Novos campos pessoais/endereço
    "rg": "rg",
    "rg_orgemissor": "rg_orgao", "rg_orgao": "rg_orgao",
    "rg_uf": "rg_uf",
    "ctps": "ctps",
    "ctps_serie": "ctps_serie",
    "rua_func": "logradouro", "logradouro": "logradouro",
    "numero_func": "numero", "numero": "numero",
    "compl_func": "complemento", "complemento": "complemento",
    "bairro": "bairro",
    "cidade": "cidade",
    "uf": "uf",
    "cep": "cep",
    "telefone1": "telefone1",
    "sexo": "sexo",
    "estado_civil": "estado_civil", "estadocivil": "estado_civil",
    "nome_mae": "nome_mae",
    "pis": "pis",
    "posicao_escala": "posicao_escala",
    "motorista_lider": "motorista_lider",
    "munkeiro": "munkeiro",
    "prancheiro": "prancheiro",
    "tamanho_macacao": "tamanho_macacao",
    "tamanho_bota": "tamanho_bota",
  };

  const rawHeaders = splitLine(lines[0]);
  const headers = rawHeaders.map(h => MAPA[h.toLowerCase().trim()] || h.toLowerCase().trim());

  // Converter data DD/MM/AAAA -> AAAA-MM-DD
  const fmtData = (v) => {
    if (!v) return "";
    if (/^\d{2}\/\d{2}\/\d{4}$/.test(v)) {
      const [d, m, a] = v.split("/");
      return `${a}-${m}-${d}`;
    }
    return v;
  };

  // Extrair código do centro de custo "01.08 - DIRETORIA" -> "01.08"
  const fmtCC = (v) => {
    if (!v) return "";
    return v.includes(" - ") ? v.split(" - ")[0].trim() : v.trim();
  };

  return lines.slice(1).filter(l => l.trim()).map(line => {
    const vals = splitLine(line);
    const row = Object.fromEntries(headers.map((h, i) => [h, vals[i] || ""]));
    // Aplicar conversões
    if (row.data_admissao)         row.data_admissao         = fmtData(row.data_admissao);
    if (row.data_fim_contrato)     row.data_fim_contrato     = fmtData(row.data_fim_contrato);
    if (row.data_fim_estabilidade) row.data_fim_estabilidade = fmtData(row.data_fim_estabilidade);
    if (row.prazo45)               row.prazo45               = fmtData(row.prazo45);
    if (row.prazo90)               row.prazo90               = fmtData(row.prazo90);
    if (row.centro_custo)          row.centro_custo          = fmtCC(row.centro_custo);
    // Normalizar situacao a partir de desc_situacao se não vier mapeado
    if (!row.situacao && row.desc_situacao) {
      row.situacao = row.desc_situacao.toLowerCase().includes("ativo") ? "Ativo" : "Inativo";
    }
    return row;
  });
}

function ImportacaoModal({ open, onClose, titulo, colunas, exemplo, onImportar }) {
  const [texto, setTexto] = useState("");
  const [resultado, setResultado] = useState(null);
  const [arquivo, setArquivo] = useState(null);

  const onArquivo = (e) => {
    const f = e.target.files[0];
    if (!f) return;
    setArquivo(f.name);
    const reader = new FileReader();
    reader.onload = ev => {
      let text = ev.target.result;
      // Detectar se tem caracteres corrompidos (Latin-1 lido como UTF-8)
      if (text.includes("\uFFFD") || /[\x80-\x9F]/.test(text)) {
        // Reler como Latin-1
        const reader2 = new FileReader();
        reader2.onload = ev2 => setTexto(ev2.target.result);
        reader2.readAsText(f, "ISO-8859-1");
      } else {
        setTexto(text);
      }
    };
    reader.readAsText(f, "UTF-8");
  };

  const processar = () => {
    try {
      const rows = parseCSV(texto);
      const erros = [];
      const validos = [];
      rows.forEach((row, i) => {
        // Usar campo real (antes do "/") para validar
        const faltando = colunas.filter(c => {
          if (!c.obrigatorio) return false;
          const campoReal = c.campo.split("/")[0].trim();
          return !row[campoReal];
        });
        if (faltando.length > 0) {
          erros.push({ linha: i + 2, msg: "Campos obrigatórios faltando: " + faltando.map(c => c.campo).join(", ") });
        } else {
          validos.push(row);
        }
      });
      setResultado({ validos, erros, total: rows.length });
    } catch (e) {
      setResultado({ validos: [], erros: [{ linha: 0, msg: "Erro ao processar arquivo: " + e.message }], total: 0 });
    }
  };

  const [importando, setImportando] = useState(false);

  const confirmar = async () => {
    setImportando(true);
    try {
      await onImportar(resultado.validos);
      setTexto(""); setResultado(null); setArquivo(null);
      onClose();
    } catch(e) {
      alert("Erro ao importar: " + e.message);
    } finally {
      setImportando(false);
    }
  };

  const baixarModelo = () => {
    const header = colunas.map(c => c.campo).join(",");
    const exemplo_row = colunas.map(c => c.exemplo || "").join(",");
    const blob = new Blob([header + "\n" + exemplo_row], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url;
    a.download = "modelo_" + titulo.toLowerCase().replace(/ /g, "_") + ".csv"; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Modal open={open} onClose={() => { setTexto(""); setResultado(null); setArquivo(null); onClose(); }}
      title={"Importar " + titulo} width={640}>
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

        {/* Colunas esperadas */}
        <div style={{ background: "#F0F9FF", border: "1px solid #BAE6FD", borderRadius: 8, padding: "12px 14px" }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#0369A1", marginBottom: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>
            Colunas esperadas no CSV
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {colunas.map(c => (
              <span key={c.campo} style={{
                padding: "2px 8px", borderRadius: 6, fontSize: 11, fontFamily: "monospace",
                background: c.obrigatorio ? "#1D4ED8" : "#93C5FD",
                color: c.obrigatorio ? "#fff" : "#1E3A5F", fontWeight: 600
              }}>{c.campo}{c.obrigatorio ? " *" : ""}</span>
            ))}
          </div>
          <div style={{ marginTop: 8, display: "flex", gap: 10, alignItems: "center" }}>
            <Button variant="secondary" size="sm" onClick={baixarModelo}>⬇ Baixar modelo CSV</Button>
            <span style={{ fontSize: 11, color: "#0369A1" }}>* = obrigatório</span>
          </div>
        </div>

        {/* Upload */}
        <div style={{
          border: "2px dashed #D1D5DB", borderRadius: 10, padding: "20px",
          textAlign: "center", background: arquivo ? "#F0FDF4" : "#FAFAFA"
        }}>
          <div style={{ fontSize: 28, marginBottom: 8 }}>{arquivo ? "✅" : "📂"}</div>
          <div style={{ fontSize: 13, fontWeight: 600, color: arquivo ? "#065F46" : "#374151", marginBottom: 8 }}>
            {arquivo ? arquivo : "Selecione o arquivo CSV"}
          </div>
          <label style={{
            padding: "7px 16px", background: "#1B3A6B", color: "#fff",
            borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: "pointer"
          }}>
            {arquivo ? "Trocar arquivo" : "Selecionar CSV"}
            <input type="file" accept=".csv,.txt" onChange={onArquivo} style={{ display: "none" }} />
          </label>
        </div>

        {/* Ou colar texto */}
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: "#374151", marginBottom: 6 }}>
            Ou cole o conteúdo CSV diretamente:
          </div>
          <textarea
            value={texto} onChange={e => setTexto(e.target.value)}
            placeholder={"chapa,nome,funcao...\n0001,João Silva,Analista..."}
            rows={5}
            style={{
              width: "100%", border: "1px solid #D1D5DB", borderRadius: 8,
              padding: "10px 12px", fontSize: 12, fontFamily: "monospace",
              resize: "vertical", boxSizing: "border-box", background: "#FAFAFA"
            }}
          />
        </div>

        {/* Resultado */}
        {resultado && (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <div style={{ display: "flex", gap: 10 }}>
              <div style={{ flex: 1, background: "#D1FAE5", border: "1px solid #6EE7B7", borderRadius: 8, padding: "10px 14px", textAlign: "center" }}>
                <div style={{ fontSize: 22, fontWeight: 800, color: "#065F46" }}>{resultado.validos.length}</div>
                <div style={{ fontSize: 11, color: "#065F46", fontWeight: 600 }}>Registros válidos</div>
              </div>
              <div style={{ flex: 1, background: resultado.erros.length > 0 ? "#FEE2E2" : "#F3F4F6", border: "1px solid " + (resultado.erros.length > 0 ? "#FCA5A5" : "#E5E7EB"), borderRadius: 8, padding: "10px 14px", textAlign: "center" }}>
                <div style={{ fontSize: 22, fontWeight: 800, color: resultado.erros.length > 0 ? "#991B1B" : "#6B7280" }}>{resultado.erros.length}</div>
                <div style={{ fontSize: 11, color: resultado.erros.length > 0 ? "#991B1B" : "#6B7280", fontWeight: 600 }}>Erros</div>
              </div>
            </div>
            {resultado.erros.length > 0 && (
              <div style={{ background: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: 8, padding: "10px 14px", maxHeight: 120, overflowY: "auto" }}>
                {resultado.erros.map((e, i) => (
                  <div key={i} style={{ fontSize: 11, color: "#DC2626", marginBottom: 3 }}>
                    Linha {e.linha}: {e.msg}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 4, borderTop: "1px solid #F3F4F6" }}>
          <Button variant="secondary" onClick={() => { setTexto(""); setResultado(null); setArquivo(null); onClose(); }}>Cancelar</Button>
          {!resultado
            ? <Button onClick={processar} disabled={!texto.trim()}>Processar arquivo</Button>
            : <Button variant="success" onClick={confirmar} disabled={resultado.validos.length === 0 || importando}>
                {importando ? "⏳ Importando..." : `Importar ${resultado.validos.length} registros`}
              </Button>
          }
        </div>
      </div>
    </Modal>
  );
}

// ─── CADASTRO: COLABORADORES ──────────────────────────────────────────────────
function CadColaboradores({ colaboradores, setColaboradores }) {
  const [busca, setBusca] = useState("");
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [form, setForm] = useState({ chapa: "", nome: "", funcao: "", situacao: "Ativo", centro_custo: "", desc_cc: "", cpf: "", data_admissao: "" });
  const [fMatricula, setFMatricula] = useState("");
  const [fNome,      setFNome]      = useState("");
  const [fFuncao,    setFuncao]     = useState("");
  const [fSecao,     setFSecao]     = useState("");
  const [fCpf,       setFCpf]       = useState("");
  const [fAdmissao,  setFAdmissao]  = useState("");
  const [fCC,        setFCC]        = useState("");
  const [fSituacao,  setFSituacao]  = useState("");

  const norm = s => (s||"").toLowerCase();

  useEffect(() => {
    api.listarColaboradores(true).then(data => {
      if (data && data.length > 0) setColaboradores(data);
    }).catch(() => {});
  }, []);

  const lista = colaboradores
    .filter(c => c.cod_situacao !== "D")
    .filter(c => !fMatricula || (c.chapa||"").includes(fMatricula))
    .filter(c => !fNome      || norm(c.nome).includes(norm(fNome)))
    .filter(c => !fFuncao    || norm(c.desc_funcao||c.funcao).includes(norm(fFuncao)))
    .filter(c => !fSecao     || norm(c.desc_cc).includes(norm(fSecao)))
    .filter(c => !fCpf       || (c.cpf||"").includes(fCpf))
    .filter(c => !fAdmissao  || fmtDateLocal(c.data_admissao) === fAdmissao)
    .filter(c => !fCC        || norm((c.centro_custo||"")+" "+(c.desc_cc||"")).includes(norm(fCC)))
    .filter(c => !fSituacao  || norm(c.situacao) === norm(fSituacao));

  const abrirNovo = () => { setForm({ chapa: "", nome: "", funcao: "", situacao: "Ativo", centro_custo: "", desc_cc: "", cpf: "", data_admissao: "" }); setModalForm("novo"); };
  const abrirEditar = (c) => {
    const admissao = c.data_admissao
      ? c.data_admissao.split("T")[0]
      : "";
    setForm({ ...c, data_admissao: admissao });
    setModalForm("editar");
  };

  const salvar = async () => {
    if (!form.chapa || !form.nome) { alert("Chapa e Nome são obrigatórios."); return; }
    try {
      if (modalForm === "novo") {
        const novo = await api.criarColaborador(form);
        setColaboradores(p => [...p, novo]);
      } else {
        await api.atualizarColaborador(form.id, form);
        setColaboradores(p => p.map(c => c.id === form.id ? { ...c, ...form } : c));
      }
      setModalForm(null);
    } catch (err) {
      alert("Erro: " + err.message);
    }
  };

  const inativar = async (id) => {
    const c = colaboradores.find(c => c.id === id);
    if (!c) return;
    const novaSituacao = c.situacao === "Ativo" ? "Inativo" : "Ativo";
    try {
      await api.atualizarColaborador(id, { situacao: novaSituacao });
      setColaboradores(p => p.map(c => c.id === id ? { ...c, situacao: novaSituacao } : c));
    } catch (err) { alert("Erro: " + err.message); }
  };

  const fmtAdmissao = (v) => {
    if (!v) return null;
    if (/^\d{2}\/\d{2}\/\d{4}$/.test(v)) {
      const [d, m, a] = v.split("/");
      return `${a}-${m}-${d}`;
    }
    return v || null;
  };

  const onImportar = async (rows) => {
    const novos = rows.map(r => ({
      chapa:                  r.chapa || "",
      nome:                   r.nome || "",
      funcao:                 r.funcao || "",
      desc_funcao:            r.desc_funcao || "",
      situacao:               r.situacao || "Ativo",
      cod_situacao:           r.cod_situacao || null,
      centro_custo:           r.centro_custo || "",
      desc_cc:                r.desc_cc || "",
      descricao_filial:       r.descricao_filial || "",
      cpf:                    r.cpf || "",
      data_admissao:          fmtAdmissao(r.data_admissao),
      tipo_contrato:          r.tipo_contrato || null,
      data_fim_contrato:      r.data_fim_contrato || null,
      data_fim_estabilidade:  r.data_fim_estabilidade || null,
      descricao_estabilidade: r.descricao_estabilidade || null,
      prazo45:                r.prazo45 || null,
      prazo90:                r.prazo90 || null,
      // Novos campos pessoais/endereço
      rg:                     r.rg || null,
      rg_orgao:               r.rg_orgao || r.rg_orgemissor || null,
      rg_uf:                  r.rg_uf || null,
      ctps:                   r.ctps || null,
      ctps_serie:             r.ctps_serie || null,
      logradouro:             r.logradouro || r.rua_func || null,
      numero:                 r.numero || r.numero_func || null,
      complemento:            r.complemento || r.compl_func || null,
      bairro:                 r.bairro || null,
      cidade:                 r.cidade || null,
      uf:                     r.uf || null,
      cep:                    r.cep || null,
      telefone1:              r.telefone1 || null,
      sexo:                   r.sexo || null,
      estado_civil:           r.estado_civil || null,
      nome_mae:               r.nome_mae || null,
      pis:                    r.pis || null,
      // Campos de atualização cadastral
      posicao_escala:         r.posicao_escala || null,
      motorista_lider:        r.motorista_lider || null,
      munkeiro:               r.munkeiro || null,
      prancheiro:             r.prancheiro || null,
      tamanho_macacao:        r.tamanho_macacao || null,
      tamanho_bota:           r.tamanho_bota || null,
    })).filter(r => r.chapa && r.nome);

    await api.importarColaboradores(novos);
    const atualizados = await api.listarColaboradores(true);
    if (atualizados && atualizados.length > 0) setColaboradores(atualizados);
    alert(`✅ ${novos.length} colaborador(es) importado(s) com sucesso!`);
  };

  const colunas = [
    { campo: "chapa / Matrícula", obrigatorio: true, exemplo: "0001" },
    { campo: "nome / Nome", obrigatorio: true, exemplo: "João da Silva" },
    { campo: "funcao / Função", obrigatorio: false, exemplo: "Analista" },
    { campo: "desc_cc / Seção", obrigatorio: false, exemplo: "BNL - CE FOR - ADM" },
    { campo: "cpf / CPF", obrigatorio: false, exemplo: "64830730382" },
    { campo: "data_admissao / Admissão", obrigatorio: false, exemplo: "01/02/2022" },
    { campo: "centro_custo / C. Custo", obrigatorio: false, exemplo: "01.08 - DIRETORIA" },
    { campo: "situacao / Situação", obrigatorio: false, exemplo: "Ativo" },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
<p style={{ margin: 0, fontSize: 12, color: "#6B7280" }}>{colaboradores.length} colaborador(es) cadastrado(s)</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Novo Colaborador</Button>
        </div>
      </div>


      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Matrícula", "Nome", "Função", "Seção", "CPF", "Admissão", "C. Custo", "Situação", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              {(() => {
                const inp = { style: { width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" } };
                const sel = { style: { width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" } };
                return (<>
                  <th style={{ padding:"5px 8px" }}><input value={fMatricula} onChange={e=>setFMatricula(e.target.value)} placeholder="🔍 Matrícula" {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}><input value={fNome}      onChange={e=>setFNome(e.target.value)}      placeholder="🔍 Nome"      {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}><input value={fFuncao}    onChange={e=>setFuncao(e.target.value)}     placeholder="🔍 Função"    {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}><input value={fSecao}     onChange={e=>setFSecao(e.target.value)}     placeholder="🔍 Seção"     {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}><input value={fCpf}       onChange={e=>setFCpf(e.target.value)}       placeholder="🔍 CPF"       {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}><input type="date" value={fAdmissao} onChange={e=>setFAdmissao(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
                  <th style={{ padding:"5px 8px" }}><input value={fCC}        onChange={e=>setFCC(e.target.value)}        placeholder="🔍 C. Custo"  {...inp} /></th>
                  <th style={{ padding:"5px 8px" }}>
                    <select value={fSituacao} onChange={e=>setFSituacao(e.target.value)} {...sel}>
                      <option value="">Todos</option><option value="Ativo">Ativo</option><option value="Inativo">Inativo</option>
                    </select>
                  </th>
                  <th style={{ padding:"5px 8px" }}>
                    <button onClick={()=>{setFMatricula("");setFNome("");setFuncao("");setFSecao("");setFCpf("");setFAdmissao("");setFCC("");setFSituacao("");}}
                      style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button>
                  </th>
                </>);
              })()}
            </tr>
          </thead>
          <tbody>
            {lista.length === 0 ? (
              <tr><td colSpan={6} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhum colaborador encontrado</td></tr>
            ) : lista.map((c, i) => (
              <tr key={c.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ fontFamily: "monospace", fontSize: 12, fontWeight: 700, background: "#F3F4F6", padding: "2px 8px", borderRadius: 4 }}>{c.chapa}</span>
                </td>
                <td style={{ padding: "11px 16px", fontSize: 13, fontWeight: 600, color: "#111827" }}>{c.nome}</td>
                <td style={{ padding: "11px 16px", fontSize: 12, color: "#374151" }}>{c.desc_funcao || c.funcao || "—"}</td>
                <td style={{ padding: "11px 16px", fontSize: 12, color: "#374151" }}>{c.desc_cc || "—"}</td>
                <td style={{ padding: "11px 16px", fontSize: 12, color: "#374151", fontFamily: "monospace" }}>{c.cpf || "—"}</td>
                <td style={{ padding: "11px 16px", fontSize: 12, color: "#374151" }}>{c.data_admissao ? new Date(c.data_admissao.split("T")[0]).toLocaleDateString("pt-BR", { timeZone: "UTC" }) : "—"}</td>
                <td style={{ padding: "11px 16px", fontSize: 12, color: "#374151" }}>{c.centro_custo ? (c.centro_custo + " — " + c.desc_cc) : "—"}</td>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ padding: "2px 10px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: c.situacao === "Ativo" ? "#D1FAE5" : "#FEE2E2", color: c.situacao === "Ativo" ? "#065F46" : "#991B1B" }}>
                    {c.situacao}
                  </span>
                </td>
                <td style={{ padding: "11px 16px", display: "flex", gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => abrirEditar(c)}>✏ Editar</Button>
                  <Button variant={c.situacao === "Ativo" ? "secondary" : "success"} size="sm" onClick={() => inativar(c.id)}>
                    {c.situacao === "Ativo" ? "Inativar" : "Ativar"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <ImportacaoModal open={modalImport} onClose={() => setModalImport(false)}
        titulo="Colaboradores" colunas={colunas} onImportar={onImportar} />

      <Modal open={!!modalForm} onClose={() => setModalForm(null)}
        title={modalForm === "novo" ? "Novo Colaborador" : "Editar Colaborador"} width={520}>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Input label="Matrícula (Chapa) *" value={form.chapa} onChange={v => setForm(p => ({ ...p, chapa: v }))} placeholder="0001" required />
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>Situação</label>
              <select value={form.situacao} onChange={e => setForm(p => ({ ...p, situacao: e.target.value }))}
                style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
                <option value="Ativo">Ativo</option>
                <option value="Inativo">Inativo</option>
              </select>
            </div>
          </div>
          <Input label="Nome completo *" value={form.nome} onChange={v => setForm(p => ({ ...p, nome: v }))} placeholder="Nome do colaborador" required />
          <Input label="Função" value={form.funcao} onChange={v => setForm(p => ({ ...p, funcao: v }))} placeholder="Ex: Analista, Motorista..." />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 12 }}>
            <Input label="Cód. Centro de Custo" value={form.centro_custo} onChange={v => setForm(p => ({ ...p, centro_custo: v }))} placeholder="001" />
            <Input label="Descrição CC" value={form.desc_cc} onChange={v => setForm(p => ({ ...p, desc_cc: v }))} placeholder="Ex: TI, RH, Logística..." />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Input label="CPF" value={form.cpf || ""} onChange={v => setForm(p => ({ ...p, cpf: v }))} placeholder="000.000.000-00" />
            <Input label="Data de Admissão" value={form.data_admissao ? form.data_admissao.split("T")[0] : ""} onChange={v => setForm(p => ({ ...p, data_admissao: v }))} type="date" />
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(null)}>Cancelar</Button>
            <Button onClick={salvar}>{modalForm === "novo" ? "Criar" : "Salvar"}</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ─── CADASTRO: EVENTOS ────────────────────────────────────────────────────────
function CadEventos({ eventos, setEventos }) {
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [form, setForm] = useState({ codigo: "", descricao: "", tipo: "provento", forma: "valor" });
  const [fCodigo,  setFCodigo]  = useState("");
  const [fDesc,    setFDesc]    = useState("");
  const [fTipo,    setFTipo]    = useState("");
  const [fForma,   setFForma]   = useState("");
  const norm = s => (s||"").toLowerCase();
  const eventosFiltrados = eventos
    .filter(e => !fCodigo || (e.codigo||"").includes(fCodigo))
    .filter(e => !fDesc   || norm(e.descricao).includes(norm(fDesc)))
    .filter(e => !fTipo   || e.tipo === fTipo)
    .filter(e => !fForma  || e.forma === fForma);

  useEffect(() => {
    api.listarEventos().then(data => {
      if (data && data.length > 0) setEventos(data);
    }).catch(() => {});
  }, []);

  const abrirNovo = () => { setForm({ codigo: "", descricao: "", tipo: "provento", forma: "valor" }); setModalForm("novo"); };
  const abrirEditar = (e) => { setForm({ ...e }); setModalForm("editar"); };

  const salvar = async () => {
    if (!form.codigo || !form.descricao) { alert("Código e Descrição são obrigatórios."); return; }
    try {
      if (modalForm === "novo") {
        const novo = await api.criarEvento(form);
        setEventos(p => [...p, novo]);
      } else {
        await api.atualizarEvento(form.id, form);
        setEventos(p => p.map(e => e.id === form.id ? { ...form } : e));
      }
      setModalForm(null);
    } catch (err) { alert("Erro: " + err.message); }
  };

  const excluir = async (id) => {
    if (!window.confirm("Deseja excluir este evento?")) return;
    try {
      await api.atualizarEvento(id, { ativo: false });
      setEventos(p => p.filter(e => e.id !== id));
    } catch (err) { alert("Erro: " + err.message); }
  };

  const onImportar = async (rows) => {
    const novos = rows.map(r => ({
      codigo:    r.codigo || r.Codigo || "",
      descricao: r.descricao || r.Descricao || "",
      tipo:      r.tipo || r.Tipo || "provento",
      forma:     r.forma || r.Forma || "valor",
    })).filter(r => r.codigo && r.descricao);
    try {
      for (const ev of novos) {
        try { await api.criarEvento(ev); } catch (_) {}
      }
      const data = await api.listarEventos();
      if (data) setEventos(data);
      alert(`✅ ${novos.length} evento(s) importado(s)!`);
    } catch (err) { alert("Erro: " + err.message); }
  };

  const colunas = [
    { campo: "codigo", obrigatorio: true, exemplo: "1148" },
    { campo: "descricao", obrigatorio: true, exemplo: "Auxílio Quilometragem" },
    { campo: "tipo", obrigatorio: false, exemplo: "provento" },
    { campo: "forma", obrigatorio: false, exemplo: "valor" },
  ];

  const sel = (label, val, onChange, opts) => (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>{label}</label>
      <select value={val} onChange={e => onChange(e.target.value)}
        style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
        {opts.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  );

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <p style={{ margin: 0, fontSize: 12, color: "#6B7280" }}>{eventos.length} evento(s) cadastrado(s)</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Novo Evento</Button>
        </div>
      </div>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Código", "Descrição", "Tipo", "Forma de Lançamento", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding: "5px 8px" }}><input value={fCodigo} onChange={e=>setFCodigo(e.target.value)} placeholder="🔍 Código" style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding: "5px 8px" }}><input value={fDesc}   onChange={e=>setFDesc(e.target.value)}   placeholder="🔍 Descrição" style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding: "5px 8px" }}><select value={fTipo}  onChange={e=>setFTipo(e.target.value)}   style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="provento">Provento</option><option value="desconto">Desconto</option></select></th>
              <th style={{ padding: "5px 8px" }}><select value={fForma} onChange={e=>setFForma(e.target.value)}  style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="valor">Valor</option><option value="hora">Hora</option><option value="referencia">Referência</option></select></th>
              <th style={{ padding: "5px 8px" }}><button onClick={()=>{setFCodigo("");setFDesc("");setFTipo("");setFForma("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {eventosFiltrados.map((e, i) => (
              <tr key={e.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ fontFamily: "monospace", fontSize: 13, fontWeight: 700, color: "#1B3A6B" }}>{e.codigo}</span>
                </td>
                <td style={{ padding: "11px 16px", fontSize: 13, fontWeight: 600, color: "#111827" }}>{e.descricao}</td>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ padding: "2px 10px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: e.tipo === "provento" ? "#D1FAE5" : "#FEE2E2", color: e.tipo === "provento" ? "#065F46" : "#991B1B" }}>{e.tipo}</span>
                </td>
                <td style={{ padding: "11px 16px", fontSize: 12, color: "#374151", textTransform: "capitalize" }}>{e.forma}</td>
                <td style={{ padding: "11px 16px", display: "flex", gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => abrirEditar(e)}>✏ Editar</Button>
                  <Button variant="danger" size="sm" onClick={() => excluir(e.id)}>🗑</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <ImportacaoModal open={modalImport} onClose={() => setModalImport(false)}
        titulo="Eventos" colunas={colunas} onImportar={onImportar} />

      <Modal open={!!modalForm} onClose={() => setModalForm(null)}
        title={modalForm === "novo" ? "Novo Evento" : "Editar Evento"} width={480}>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          <Input label="Código *" value={form.codigo} onChange={v => setForm(p => ({ ...p, codigo: v }))} placeholder="1148" required />
          <Input label="Descrição *" value={form.descricao} onChange={v => setForm(p => ({ ...p, descricao: v }))} placeholder="Nome do evento" required />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            {sel("Tipo", form.tipo, v => setForm(p => ({ ...p, tipo: v })), [
              { value: "provento", label: "Provento" }, { value: "desconto", label: "Desconto" }
            ])}
            {sel("Forma de Lançamento", form.forma, v => setForm(p => ({ ...p, forma: v })), [
              { value: "valor", label: "Valor (R$)" }, { value: "hora", label: "Hora" }, { value: "referencia", label: "Referência" }
            ])}
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(null)}>Cancelar</Button>
            <Button onClick={salvar}>{modalForm === "novo" ? "Criar" : "Salvar"}</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ─── CADASTRO: HIERARQUIA ─────────────────────────────────────────────────────
function CadHierarquia({ hierarquia, setHierarquia, usuarios }) {
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [form, setForm] = useState({ gestor_id: "", superior_id: "", centro_custo: "", desc_cc: "" });
  const [filtroGestor,   setFiltroGestor]   = useState("");
  const [filtroSuperior, setFiltroSuperior] = useState("");
  const [filtroCC,       setFiltroCC]       = useState("");
  const [filtroAtivo,    setFiltroAtivo]    = useState("");

  const norm = (s) => (s||"").toLowerCase().trim();

  const hierarquiaFiltrada = hierarquia.filter(h => {
    if (filtroGestor   && !norm(h.gestor_nome).includes(norm(filtroGestor)))     return false;
    if (filtroSuperior && !norm(h.superior_nome).includes(norm(filtroSuperior))) return false;
    if (filtroCC       && !norm(h.centro_custo + " " + h.desc_cc).includes(norm(filtroCC))) return false;
    if (filtroAtivo === "ativo"   && !h.ativo)  return false;
    if (filtroAtivo === "inativo" &&  h.ativo)  return false;
    return true;
  });

  useEffect(() => {
    api.listarHierarquia().then(data => {
      if (data && data.length > 0) setHierarquia(data);
    }).catch(() => {});
  }, []);

  const gestores   = usuarios.filter(u => u.ativo !== false);
  const superiores = usuarios.filter(u => u.ativo !== false);

  const [centrosCusto, setCentrosCusto] = useState([]);
  useEffect(() => {
    api.listarCentrosCusto().then(data => {
      if (Array.isArray(data)) setCentrosCusto(data);
    }).catch(() => {});
  }, []);

  const abrirNovo = () => { setForm({ gestor_id: "", superior_id: "", centro_custo: "", desc_cc: "" }); setModalForm("novo"); };
  const abrirEditar = (h) => { setForm({ ...h }); setModalForm("editar"); };

  const salvar = async () => {
    if (!form.gestor_id || !form.superior_id) { alert("Gestor e Superior são obrigatórios."); return; }
    const payload = { gestor_id: parseInt(form.gestor_id), superior_id: parseInt(form.superior_id), centro_custo: form.centro_custo, desc_cc: form.desc_cc };
    try {
      if (modalForm === "novo") {
        const novo = await api.criarHierarquia(payload);
        setHierarquia(p => [...p, novo]);
      } else {
        const upd = await api.atualizarHierarquia(form.id, { ...payload, ativo: form.ativo ?? true });
        setHierarquia(p => p.map(h => h.id === form.id ? upd : h));
      }
      setModalForm(null);
    } catch (err) { alert("Erro: " + err.message); }
  };

  const toggleAtivo = async (id) => {
    const h = hierarquia.find(h => h.id === id);
    if (!h) return;
    try {
      await api.atualizarHierarquia(id, { gestor_id: h.gestor_id, superior_id: h.superior_id, ativo: !h.ativo });
      setHierarquia(p => p.map(h => h.id === id ? { ...h, ativo: !h.ativo } : h));
    } catch (err) { alert("Erro: " + err.message); }
  };

  const onImportar = (rows) => {
    const novos = rows.map((r, i) => ({
      id: Date.now() + i,
      gestor_nome: r.gestor_nome || r.GestorNome || "",
      superior_nome: r.superior_nome || r.SuperiorNome || "",
      centro_custo: r.centro_custo || r.CentroCusto || "",
      desc_cc: r.desc_cc || r.DescCC || "",
      gestor_id: 0, superior_id: 0, ativo: true,
    }));
    setHierarquia(p => [...p, ...novos]);
  };

  const colunas = [
    { campo: "gestor_nome", obrigatorio: true, exemplo: "Carlos Mendes" },
    { campo: "superior_nome", obrigatorio: true, exemplo: "Ana Souza" },
    { campo: "centro_custo", obrigatorio: false, exemplo: "001" },
    { campo: "desc_cc", obrigatorio: false, exemplo: "TI" },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <p style={{ margin: 0, fontSize: 12, color: "#6B7280" }}>Define quem aprova as solicitações de cada gestor</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Nova Regra</Button>
        </div>
      </div>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["1ª Alçada", "2ª Alçada", "Centro de Custo", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding: "6px 10px" }}>
                <input value={filtroGestor} onChange={e => setFiltroGestor(e.target.value)}
                  placeholder="🔍 Buscar 1ª alçada..."
                  style={{ width: "100%", padding: "5px 8px", borderRadius: 6, border: "1px solid #D1D5DB", fontSize: 11, fontFamily: "inherit", boxSizing: "border-box" }} />
              </th>
              <th style={{ padding: "6px 10px" }}>
                <input value={filtroSuperior} onChange={e => setFiltroSuperior(e.target.value)}
                  placeholder="🔍 Buscar 2ª alçada..."
                  style={{ width: "100%", padding: "5px 8px", borderRadius: 6, border: "1px solid #D1D5DB", fontSize: 11, fontFamily: "inherit", boxSizing: "border-box" }} />
              </th>
              <th style={{ padding: "6px 10px" }}>
                <input value={filtroCC} onChange={e => setFiltroCC(e.target.value)}
                  placeholder="🔍 Buscar CC..."
                  style={{ width: "100%", padding: "5px 8px", borderRadius: 6, border: "1px solid #D1D5DB", fontSize: 11, fontFamily: "inherit", boxSizing: "border-box" }} />
              </th>
              <th style={{ padding: "6px 10px" }}>
                <select value={filtroAtivo} onChange={e => setFiltroAtivo(e.target.value)}
                  style={{ width: "100%", padding: "5px 8px", borderRadius: 6, border: "1px solid #D1D5DB", fontSize: 11, fontFamily: "inherit" }}>
                  <option value="">Todos</option>
                  <option value="ativo">Ativo</option>
                  <option value="inativo">Inativo</option>
                </select>
              </th>
              <th style={{ padding: "6px 10px" }}>
                <button onClick={() => { setFiltroGestor(""); setFiltroSuperior(""); setFiltroCC(""); setFiltroAtivo(""); }}
                  style={{ fontSize: 10, padding: "4px 8px", borderRadius: 6, border: "1px solid #D1D5DB", background: "#fff", cursor: "pointer", color: "#6B7280" }}>
                  ✕ Limpar
                </button>
              </th>
            </tr>
          </thead>
          <tbody>
            {hierarquiaFiltrada.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhuma regra encontrada</td></tr>
            ) : hierarquiaFiltrada.map((h, i) => (
              <tr key={h.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "11px 16px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ width: 28, height: 28, borderRadius: 8, background: "#3B82F6", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: "#fff" }}>
                      {h.gestor_nome?.charAt(0)}
                    </div>
                    <span style={{ fontSize: 13, fontWeight: 600, color: "#111827" }}>{h.gestor_nome}</span>
                  </div>
                </td>
                <td style={{ padding: "11px 16px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ width: 28, height: 28, borderRadius: 8, background: "#8B5CF6", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: "#fff" }}>
                      {h.superior_nome?.charAt(0)}
                    </div>
                    <span style={{ fontSize: 13, fontWeight: 600, color: "#111827" }}>{h.superior_nome}</span>
                  </div>
                </td>
                <td style={{ padding: "11px 16px", fontSize: 12, color: "#374151" }}>{h.centro_custo ? (h.centro_custo + " — " + h.desc_cc) : "Todos"}</td>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ padding: "2px 10px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: h.ativo ? "#D1FAE5" : "#FEE2E2", color: h.ativo ? "#065F46" : "#991B1B" }}>
                    {h.ativo ? "Ativo" : "Inativo"}
                  </span>
                </td>
                <td style={{ padding: "11px 16px", display: "flex", gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => abrirEditar(h)}>✏ Editar</Button>
                  <Button variant={h.ativo ? "secondary" : "success"} size="sm" onClick={() => toggleAtivo(h.id)}>
                    {h.ativo ? "Inativar" : "Ativar"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <ImportacaoModal open={modalImport} onClose={() => setModalImport(false)}
        titulo="Hierarquia" colunas={colunas} onImportar={onImportar} />

      <Modal open={!!modalForm} onClose={() => setModalForm(null)}
        title={modalForm === "novo" ? "Nova Regra de Hierarquia" : "Editar Hierarquia"} width={480}>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>1ª Alçada *</label>
            <select value={form.gestor_id} onChange={e => setForm(p => ({ ...p, gestor_id: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
              <option value="">Selecione...</option>
              {gestores.map(u => <option key={u.id} value={u.id}>{u.nome}</option>)}
            </select>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>2ª Alçada *</label>
            <select value={form.superior_id} onChange={e => setForm(p => ({ ...p, superior_id: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
              <option value="">Selecione...</option>
              {superiores.map(u => <option key={u.id} value={u.id}>{u.nome}</option>)}
            </select>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 12 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Cód. Centro de Custo</label>
              <select value={form.centro_custo || ""} onChange={e => {
                const cod = e.target.value;
                const cc = centrosCusto.find(c => c.codccusto === cod);
                setForm(p => ({ ...p, centro_custo: cod, desc_cc: cc ? cc.nome : p.desc_cc }));
              }} style={{ width: "100%", padding: "8px 10px", borderRadius: 8, border: "1px solid #D1D5DB", fontSize: 13 }}>
                <option value="">Todos</option>
                {centrosCusto.filter(c => c.tipo !== "BLOQUEADO").map(c => (
                  <option key={c.codccusto} value={c.codccusto}>{c.codccusto}</option>
                ))}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Descrição CC</label>
              <input value={form.desc_cc || ""} readOnly
                style={{ width: "100%", padding: "8px 10px", borderRadius: 8, border: "1px solid #D1D5DB", fontSize: 13, background: "#F9FAFB", color: "#6B7280", boxSizing: "border-box" }}
                placeholder="Preenchido automaticamente" />
            </div>
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(null)}>Cancelar</Button>
            <Button onClick={salvar}>{modalForm === "novo" ? "Criar" : "Salvar"}</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ─── CADASTRO: ALÇADAS ────────────────────────────────────────────────────────
function CadAlcadas({ alcadas, setAlcadas, eventos }) {
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [form, setForm] = useState({ evento_id: "", num_alcadas: 1, exige_anexo: false });
  const [fEvento,  setFEvento]  = useState("");
  const [fAnexo,   setFAnexo]   = useState("");
  const [fStatus,  setFStatus]  = useState("");
  const norm = s => (s||"").toLowerCase();
  const alcadasFiltradas = alcadas
    .filter(a => !fEvento || norm(a.evento_nome).includes(norm(fEvento)))
    .filter(a => fAnexo === "" ? true : fAnexo === "sim" ? a.exige_anexo : !a.exige_anexo)
    .filter(a => fStatus === "" ? true : fStatus === "ativo" ? a.ativo : !a.ativo);

  useEffect(() => {
    api.listarAlcadas().then(data => {
      if (data && data.length > 0) setAlcadas(data);
    }).catch(() => {});
  }, []);

  const abrirNovo = () => { setForm({ evento_id: "", num_alcadas: 1, exige_anexo: false }); setModalForm("novo"); };
  const abrirEditar = (a) => { setForm({ ...a }); setModalForm("editar"); };

  const salvar = async () => {
    if (!form.evento_id) { alert("Selecione o evento."); return; }
    const payload = { evento_id: parseInt(form.evento_id), num_alcadas: parseInt(form.num_alcadas) || 1, exige_anexo: !!form.exige_anexo };
    try {
      if (modalForm === "novo") {
        const nova = await api.criarAlcada(payload);
        setAlcadas(p => [...p, nova]);
      } else {
        const upd = await api.atualizarAlcada(form.id, { ...payload, ativo: form.ativo ?? true });
        setAlcadas(p => p.map(a => a.id === form.id ? upd : a));
      }
      setModalForm(null);
    } catch (err) { alert("Erro: " + err.message); }
  };

  const toggleAtivo = async (id) => {
    const a = alcadas.find(a => a.id === id);
    if (!a) return;
    try {
      await api.atualizarAlcada(id, { evento_id: a.evento_id, num_alcadas: a.num_alcadas, exige_anexo: a.exige_anexo, ativo: !a.ativo });
      setAlcadas(p => p.map(a => a.id === id ? { ...a, ativo: !a.ativo } : a));
    } catch (err) { alert("Erro: " + err.message); }
  };

  const onImportar = (rows) => {
    const novos = rows.map((r, i) => ({
      id: Date.now() + i,
      evento_nome: r.evento_nome || r.EventoNome || "",
      num_alcadas: parseInt(r.num_alcadas || r.NumAlcadas || "1"),
      exige_anexo: (r.exige_anexo || r.ExigeAnexo || "").toLowerCase() === "sim",
      evento_id: 0, ativo: true,
    }));
    setAlcadas(p => [...p, ...novos]);
  };

  const colunas = [
    { campo: "evento_nome", obrigatorio: true, exemplo: "Auxílio Quilometragem" },
    { campo: "num_alcadas", obrigatorio: true, exemplo: "2" },
    { campo: "exige_anexo", obrigatorio: false, exemplo: "sim" },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <p style={{ margin: 0, fontSize: 12, color: "#6B7280" }}>Define quantas aprovações cada tipo de evento exige</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Nova Regra</Button>
        </div>
      </div>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Evento", "Nº de Alçadas", "Exige Anexo", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding: "5px 8px" }}><input value={fEvento} onChange={e=>setFEvento(e.target.value)} placeholder="🔍 Evento" style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding: "5px 8px" }} />
              <th style={{ padding: "5px 8px" }}><select value={fAnexo} onChange={e=>setFAnexo(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="sim">Obrigatório</option><option value="nao">Não exige</option></select></th>
              <th style={{ padding: "5px 8px" }}><select value={fStatus} onChange={e=>setFStatus(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="ativo">Ativo</option><option value="inativo">Inativo</option></select></th>
              <th style={{ padding: "5px 8px" }}><button onClick={()=>{setFEvento("");setFAnexo("");setFStatus("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {alcadasFiltradas.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhuma regra encontrada</td></tr>
            ) : alcadasFiltradas.map((a, i) => (
              <tr key={a.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "11px 16px", fontSize: 13, fontWeight: 600, color: "#111827" }}>{a.evento_nome}</td>
                <td style={{ padding: "11px 16px" }}>
                  <div style={{ display: "flex", gap: 4 }}>
                    {[...Array(a.num_alcadas)].map((_, idx) => (
                      <span key={idx} style={{ width: 24, height: 24, borderRadius: 6, background: idx === 0 ? "#3B82F6" : "#8B5CF6", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: "#fff" }}>
                        {idx + 1}
                      </span>
                    ))}
                    <span style={{ fontSize: 12, color: "#6B7280", marginLeft: 4, alignSelf: "center" }}>
                      {a.num_alcadas === 1 ? "Apenas gestor" : "Gestor + Superior"}
                    </span>
                  </div>
                </td>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ padding: "2px 10px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: a.exige_anexo ? "#FEF3C7" : "#F3F4F6", color: a.exige_anexo ? "#92400E" : "#6B7280" }}>
                    {a.exige_anexo ? "📎 Obrigatório" : "Não exige"}
                  </span>
                </td>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ padding: "2px 10px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: a.ativo ? "#D1FAE5" : "#FEE2E2", color: a.ativo ? "#065F46" : "#991B1B" }}>
                    {a.ativo ? "Ativo" : "Inativo"}
                  </span>
                </td>
                <td style={{ padding: "11px 16px", display: "flex", gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => abrirEditar(a)}>✏ Editar</Button>
                  <Button variant={a.ativo ? "secondary" : "success"} size="sm" onClick={() => toggleAtivo(a.id)}>
                    {a.ativo ? "Inativar" : "Ativar"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <ImportacaoModal open={modalImport} onClose={() => setModalImport(false)}
        titulo="Alçadas" colunas={colunas} onImportar={onImportar} />

      <Modal open={!!modalForm} onClose={() => setModalForm(null)}
        title={modalForm === "novo" ? "Nova Regra de Alçada" : "Editar Alçada"} width={460}>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>Evento *</label>
            <select value={form.evento_id} onChange={e => setForm(p => ({ ...p, evento_id: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
              <option value="">Selecione...</option>
              {eventos.map(e => <option key={e.id} value={e.id}>{e.codigo} — {e.descricao}</option>)}
            </select>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>Número de Alçadas *</label>
            <select value={form.num_alcadas} onChange={e => setForm(p => ({ ...p, num_alcadas: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
              <option value={1}>1 alçada — Apenas Gestor</option>
              <option value={2}>2 alçadas — Gestor + Superior</option>
            </select>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", background: "#FFFBEB", borderRadius: 8, border: "1px solid #FCD34D" }}>
            <input type="checkbox" id="exige_anexo" checked={!!form.exige_anexo}
              onChange={e => setForm(p => ({ ...p, exige_anexo: e.target.checked }))}
              style={{ width: 16, height: 16, cursor: "pointer" }} />
            <label htmlFor="exige_anexo" style={{ fontSize: 13, fontWeight: 600, color: "#92400E", cursor: "pointer" }}>
              📎 Exige anexo obrigatório
            </label>
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(null)}>Cancelar</Button>
            <Button onClick={salvar}>{modalForm === "novo" ? "Criar" : "Salvar"}</Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

// ─── CADASTRO: USUÁRIOS ───────────────────────────────────────────────────────
function CadUsuarios({ usuarios, setUsuarios }) {
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [modalReset, setModalReset] = useState(null);
  const [novaSenha, setNovaSenha] = useState("");
  const [confirmaSenha, setConfirmaSenha] = useState("");
  const [msgReset, setMsgReset] = useState(null);
  const [salvandoReset, setSalvandoReset] = useState(false);
  const [salvando, setSalvando] = useState(false);
  const [form, setForm] = useState({ nome: "", email: "", perfil: "gestor", senha: "Benel@2025", secao: "", ativo: true });
  const [fNomeU,   setFNomeU]   = useState("");
  const [fEmailU,  setFEmailU]  = useState("");
  const [fPerfilU, setFPerfilU] = useState("");
  const [fStatusU, setFStatusU] = useState("");
  const norm = s => (s||"").toLowerCase();
  const usuariosFiltrados = usuarios
    .filter(u => !fNomeU   || norm(u.nome).includes(norm(fNomeU)))
    .filter(u => !fEmailU  || norm(u.email).includes(norm(fEmailU)))
    .filter(u => !fPerfilU || u.perfil === fPerfilU)
    .filter(u => fStatusU === "" ? true : fStatusU === "ativo" ? u.ativo !== false : u.ativo === false);

  const carregarUsuarios = async () => {
    try {
      const data = await api.listarUsuarios();
      if (data && data.length > 0) {
        const comAvatar = data.map(u => ({
          ...u,
          avatar: u.nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase()
        }));
        setUsuarios(comAvatar);
      }
    } catch (e) { console.warn("Erro ao carregar usuários:", e.message); }
  };

  useEffect(() => { carregarUsuarios(); }, []);

  const abrirNovo = () => { setForm({ nome: "", email: "", perfil: "gestor", senha: "Benel@2025", secao: "", ativo: true }); setModalForm("novo"); };
  const abrirEditar = (u) => { setForm({ ...u, senha: "" }); setModalForm("editar"); };

  const abrirReset = (u) => {
    setModalReset(u);
    setNovaSenha("");
    setConfirmaSenha("");
    setMsgReset(null);
  };

  const salvar = async () => {
    if (!form.nome || !form.email) { alert("Nome e E-mail são obrigatórios."); return; }
    if (modalForm === "novo" && !form.senha) { alert("Informe uma senha inicial."); return; }
    setSalvando(true);
    try {
      if (modalForm === "novo") {
        const novo = await api.criarUsuario({ nome: form.nome, email: form.email, perfil: form.perfil, senha: form.senha });
        const av = form.nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase();
        setUsuarios(p => [...p, { ...novo, avatar: av }]);
      } else {
        await api.atualizarUsuario(form.id, { nome: form.nome, email: form.email, perfil: form.perfil, ativo: form.ativo });
        setUsuarios(p => p.map(u => u.id === form.id ? { ...u, nome: form.nome, email: form.email, perfil: form.perfil, ativo: form.ativo } : u));
      }
      setModalForm(null);
    } catch (err) {
      alert("Erro: " + err.message);
    } finally { setSalvando(false); }
  };

  const executarReset = async () => {
    if (!novaSenha || !verificarForcaSenha(novaSenha).valida) {
      setMsgReset({ tipo: "erro", texto: "A senha deve ter 8+ caracteres, letra maiúscula, minúscula, número e caractere especial (@$!%*?&_-#)." });
      return;
    }
    if (novaSenha !== confirmaSenha) {
      setMsgReset({ tipo: "erro", texto: "As senhas não coincidem." });
      return;
    }
    setSalvandoReset(true);
    try {
      await api.resetarSenhaAdmin(modalReset.id, novaSenha);
      setMsgReset({ tipo: "ok", texto: `Senha de ${modalReset.nome} redefinida com sucesso!` });
      setTimeout(() => { setModalReset(null); setMsgReset(null); }, 1500);
    } catch (err) {
      setMsgReset({ tipo: "erro", texto: err.message || "Erro ao redefinir senha." });
    } finally {
      setSalvandoReset(false);
    }
  };

  const toggleAtivo = async (id) => {
    const u = usuarios.find(u => u.id === id);
    if (!u) return;
    const novoAtivo = u.ativo === false ? true : false;
    try {
      await api.atualizarUsuario(id, { ativo: novoAtivo });
      setUsuarios(p => p.map(u => u.id === id ? { ...u, ativo: novoAtivo } : u));
    } catch (err) { alert("Erro: " + err.message); }
  };

  const onImportar = (rows) => {
    const novos = rows.map((r, i) => {
      const nome = r.nome || r.Nome || "";
      const av = nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase();
      return { id: Date.now() + i, nome, email: r.email || r.Email || "", perfil: r.perfil || r.Perfil || "gestor", senha: r.senha || "123", avatar: av, ativo: true };
    }).filter(r => r.nome && r.email);
    setUsuarios(p => {
      const emailsExistentes = new Set(p.map(u => u.email));
      return [...p, ...novos.filter(n => !emailsExistentes.has(n.email))];
    });
  };

  const colunas = [
    { campo: "nome", obrigatorio: true, exemplo: "João da Silva" },
    { campo: "email", obrigatorio: true, exemplo: "joao@empresa.com" },
    { campo: "perfil", obrigatorio: false, exemplo: "gestor" },
    { campo: "senha", obrigatorio: false, exemplo: "123456" },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <p style={{ margin: 0, fontSize: 12, color: "#6B7280" }}>{usuarios.length} usuário(s) cadastrado(s)</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Novo Usuário</Button>
        </div>
      </div>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Avatar", "Nome", "E-mail", "Perfil", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding: "5px 8px" }} />
              <th style={{ padding: "5px 8px" }}><input value={fNomeU}  onChange={e=>setFNomeU(e.target.value)}  placeholder="🔍 Nome"   style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding: "5px 8px" }}><input value={fEmailU} onChange={e=>setFEmailU(e.target.value)} placeholder="🔍 E-mail" style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding: "5px 8px" }}><select value={fPerfilU} onChange={e=>setFPerfilU(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="gestor">Gestor</option><option value="superior">Superior</option><option value="dp">DP</option><option value="presidente">Presidente</option><option value="admin">Admin</option></select></th>
              <th style={{ padding: "5px 8px" }}><select value={fStatusU} onChange={e=>setFStatusU(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="ativo">Ativo</option><option value="inativo">Inativo</option></select></th>
              <th style={{ padding: "5px 8px" }}><button onClick={()=>{setFNomeU("");setFEmailU("");setFPerfilU("");setFStatusU("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {usuariosFiltrados.map((u, i) => (
              <tr key={u.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "11px 16px" }}>
                  <div style={{ width: 32, height: 32, borderRadius: 8, background: PERFIL_CONFIG[u.perfil]?.color, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, color: "#fff" }}>{u.avatar}</div>
                </td>
                <td style={{ padding: "11px 16px", fontSize: 13, fontWeight: 600, color: "#111827" }}>{u.nome}</td>
                <td style={{ padding: "11px 16px", fontSize: 12, color: "#374151" }}>{u.email}</td>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ padding: "2px 10px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: PERFIL_CONFIG[u.perfil]?.color + "22", color: PERFIL_CONFIG[u.perfil]?.color }}>
                    {PERFIL_CONFIG[u.perfil]?.label}
                  </span>
                </td>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ padding: "2px 10px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: u.ativo !== false ? "#D1FAE5" : "#FEE2E2", color: u.ativo !== false ? "#065F46" : "#991B1B" }}>
                    {u.ativo !== false ? "Ativo" : "Inativo"}
                  </span>
                </td>
                <td style={{ padding: "11px 16px", display: "flex", gap: 6 }}>
                  <Button variant="ghost" size="sm" onClick={() => abrirEditar(u)}>✏ Editar</Button>
                  <Button variant="warning" size="sm" onClick={() => abrirReset(u)}>🔑 Senha</Button>
                  <Button variant={u.ativo !== false ? "secondary" : "success"} size="sm" onClick={() => toggleAtivo(u.id)}>
                    {u.ativo !== false ? "Inativar" : "Ativar"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <ImportacaoModal open={modalImport} onClose={() => setModalImport(false)}
        titulo="Usuários" colunas={colunas} onImportar={onImportar} />

      <Modal open={!!modalForm} onClose={() => setModalForm(null)}
        title={modalForm === "novo" ? "Novo Usuário" : "Editar Usuário"} width={460}>
        <div style={{ display: "flex", flexDirection: "column", gap: 13 }}>
          <Input label="Nome completo *" value={form.nome} onChange={v => setForm(p => ({ ...p, nome: v }))} placeholder="Nome do usuário" required />
          <Input label="E-mail *" value={form.email} onChange={v => setForm(p => ({ ...p, email: v }))} type="email" placeholder="email@empresa.com" required />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>Perfil</label>
              <select value={form.perfil} onChange={e => setForm(p => ({ ...p, perfil: e.target.value }))}
                style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
                <option value="gestor">Gestor</option>
                <option value="superior">Superior</option>
                <option value="dp">DP</option>
                <option value="presidente">Presidente</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <Input label="Seção / Departamento" value={form.secao || ""} onChange={v => setForm(p => ({ ...p, secao: v }))} placeholder="Ex: Logística, RH..." />
          </div>
          {modalForm === "novo" && (
            <div>
              <Input label="Senha inicial *" value={form.senha} onChange={v => setForm(p => ({ ...p, senha: v }))} type="password" placeholder="Ex: Benel@2026" required />
              <IndicadorSenha senha={form.senha} />
            </div>
          )}
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(null)}>Cancelar</Button>
            <Button onClick={salvar} disabled={salvando}>{salvando ? "Salvando..." : modalForm === "novo" ? "Criar" : "Salvar"}</Button>
          </div>
        </div>
      </Modal>

      {/* Modal Reset de Senha — somente Admin */}
      <Modal open={!!modalReset} onClose={() => setModalReset(null)}
        title="🔑 Redefinir Senha" width={420}>
        {modalReset && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ background: "#FFF7ED", border: "1px solid #FCD34D", borderRadius: 8, padding: "10px 14px" }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#92400E" }}>Usuário</div>
              <div style={{ fontSize: 14, fontWeight: 600, color: "#111827" }}>{modalReset.nome}</div>
              <div style={{ fontSize: 12, color: "#6B7280" }}>{modalReset.email}</div>
            </div>
            {msgReset && (
              <div style={{
                padding: "8px 12px", borderRadius: 8, fontSize: 12,
                background: msgReset.tipo === "ok" ? "#D1FAE5" : "#FEE2E2",
                color: msgReset.tipo === "ok" ? "#065F46" : "#991B1B",
                border: `1px solid ${msgReset.tipo === "ok" ? "#6EE7B7" : "#FCA5A5"}`
              }}>
                {msgReset.tipo === "ok" ? "✅" : "❌"} {msgReset.texto}
              </div>
            )}
            <div>
              <Input
                label="Nova Senha *"
                value={novaSenha}
                onChange={setNovaSenha}
                type="password"
                placeholder="Mín. 8 chars, maiúscula, número e especial"
                required
              />
              <IndicadorSenha senha={novaSenha} />
            </div>
            <Input
              label="Confirmar Nova Senha *"
              value={confirmaSenha}
              onChange={setConfirmaSenha}
              type="password"
              placeholder="Repita a nova senha"
              required
            />
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
              <Button variant="secondary" onClick={() => setModalReset(null)}>Cancelar</Button>
              <Button variant="warning" onClick={executarReset} disabled={salvandoReset}>
                {salvandoReset ? "Salvando..." : "🔑 Redefinir Senha"}
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
// ─── SOLICITAÇÕES EM BLOCO ────────────────────────────────────────────────────

const LINHA_VAZIA = () => ({
  _id: Date.now() + Math.random(),
  colaborador_id: "", colaborador: null,
  hora: "", valor: "", referencia: "", observacao: ""
});

function Solicitacoes({ solicitacoes, setSolicitacoes, blocos, setBlocos, user, colaboradores = [], eventos = [], recarregarDados }) {
  const [filtroStatus, setFiltroStatus] = useState("");
  const [modalNovoBloco, setModalNovoBloco] = useState(false);
  const [modalBloco, setModalBloco] = useState(null);
  const [modalRelatorio, setModalRelatorio] = useState(null);
  const [editandoBloco, setEditandoBloco] = useState(null);

  const blocosFiltrados = blocos.filter(b => !filtroStatus || b.status === filtroStatus);

  const abrirNovoBloco = () => {
    setEditandoBloco({ id: null, competencia: "", descricao: "", evento_id: "", anexo_nome: null, anexo_tamanho: null, linhas: [LINHA_VAZIA(), LINHA_VAZIA()] });
    setModalNovoBloco(true);
  };

  const abrirEdicaoBloco = (bloco) => {
    setEditandoBloco({ ...bloco, linhas: bloco.linhas.map(l => ({ ...l })) });
    setModalNovoBloco(true);
  };

  const salvarBloco = async () => {
    if (!editandoBloco.evento_id)   { alert("Selecione o Evento do Bloco."); return; }
    if (!editandoBloco.competencia) { alert("Selecione a Competência."); return; }

    // Buscar evento primeiro (necessário para determinar forma)
    const eventoObj = eventos.find(e => e.id === parseInt(editandoBloco.evento_id));

    const forma = eventoObj?.forma || "valor";
    const linhasValidas = editandoBloco.linhas.filter(l => {
      if (!l.colaborador_id || String(l.colaborador_id) === "") return false;
      if (forma === "hora")       return !!(l.hora);
      if (forma === "referencia") return parseFloat(l.referencia) > 0;
      return parseFloat(l.valor) > 0;
    });

    // Descrição automática: Evento + Competência
    const mesLabel = MESES.find(m => m.value === editandoBloco.competencia)?.label || editandoBloco.competencia;
    const descricaoAuto = editandoBloco.descricao || `${eventoObj?.descricao || "Bloco"} — ${mesLabel}`;

    // Data automática: último dia da competência (MMAAAA → AAAA-MM-DD)
    const comp = editandoBloco.competencia; // ex: "042026"
    const dataComp = comp.length === 6
      ? `${comp.slice(2)}-${comp.slice(0,2)}-01`
      : new Date().toISOString().split("T")[0];

    const payload = {
      descricao: descricaoAuto,
      competencia: editandoBloco.competencia,
      evento_id: parseInt(editandoBloco.evento_id),
      linhas: linhasValidas.map(l => ({
        colaborador_id: parseInt(l.colaborador_id) || 0,
        data: dataComp,
        hora: eventoObj?.forma === "hora" ? (l.hora || null) : null,
        referencia: eventoObj?.forma === "referencia" ? (parseFloat(l.referencia) || null) : null,
        valor: parseFloat(l.valor) || 0,
        observacao: l.observacao || "",
      })),
    };

    try {
      if (editandoBloco.id) {
        await api.aprovarBloco(editandoBloco.id, "editar", "");
      } else {
        await api.criarBloco(payload);
      }
      // Recarregar blocos do banco com colaboradores e eventos resolvidos
      if (recarregarDados) await recarregarDados();
    } catch (err) {
      alert("Erro ao salvar: " + err.message);
    }
    setModalNovoBloco(false);
    setEditandoBloco(null);
  };

  const podeEditar = (bloco) => bloco.status === "pendente_gestor" || bloco.status === "devolvido";

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
        </div>
        <Button onClick={abrirNovoBloco}>+ Nova Solicitação de Pagamento</Button>
      </div>

      {/* Filtro */}
      <Card style={{ marginBottom: 18, padding: "12px 18px" }}>
        <div style={{ display: "flex", gap: 14, alignItems: "flex-end" }}>
          <Select label="Status" value={filtroStatus} onChange={setFiltroStatus}
            options={Object.entries(STATUS_CONFIG).map(([k, v]) => ({ value: k, label: v.label }))} />
          <Button variant="secondary" size="sm" onClick={() => setFiltroStatus("")}>Limpar</Button>
        </div>
      </Card>

      {/* Lista de blocos */}
      {blocosFiltrados.length === 0 ? (
        <Card style={{ textAlign: "center", padding: "40px 0" }}>
          <div style={{ fontSize: 36, marginBottom: 10 }}>📋</div>
          <p style={{ margin: 0, fontSize: 14, color: "#6B7280" }}>Nenhum bloco encontrado. Crie o primeiro!</p>
        </Card>
      ) : blocosFiltrados.map(bloco => {
        const totalBloco = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
        return (
          <Card key={bloco.id} style={{ marginBottom: 14, padding: 0, overflow: "hidden" }}>
            {/* Cabeçalho do bloco */}
            <div style={{ padding: "14px 20px", background: "#F8FAFC", borderBottom: "1px solid #E5E7EB", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 14, fontWeight: 700, color: "#111827" }}>{bloco.descricao}</span>
                  <Badge status={bloco.status} />
                  {bloco.evento && (
                    <span style={{ fontSize: 11, fontWeight: 600, padding: "2px 8px", borderRadius: 6, background: "#EFF6FF", color: "#1D4ED8" }}>
                      ⚡ {bloco.evento.codigo} — {bloco.evento.descricao}
                    </span>
                  )}
                  {bloco.anexo_nome && (
                    <span style={{ fontSize: 11, padding: "2px 8px", borderRadius: 6, background: "#FFFBEB", color: "#92400E", border: "1px solid #FCD34D" }}>
                      📎 {bloco.anexo_nome}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 11, color: "#6B7280" }}>
                  Competência: <b>{bloco.competencia}</b> · Solicitante: <b>{bloco.solicitante}</b> · Criado em: <b>{bloco.criado_em}</b>
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{ textAlign: "right", marginRight: 8 }}>
                  <div style={{ fontSize: 11, color: "#6B7280" }}>{bloco.linhas.length} lançamento(s)</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: "#10B981" }}>R$ {totalBloco.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}</div>
                </div>
                {podeEditar(bloco) && (
                  <Button variant="secondary" size="sm" onClick={() => abrirEdicaoBloco(bloco)}>✏ Editar</Button>
                )}
                <Button variant="ghost" size="sm" onClick={() => setModalBloco(bloco)}>Ver</Button>
                <Button variant="secondary" size="sm" onClick={() => setModalRelatorio(bloco)}>📄 Relatório</Button>
              </div>
            </div>
            {/* Linhas do bloco */}
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "#FAFAFA" }}>
                  {["Matrícula", "Colaborador", "Data", "Hora", "Valor", "Observação"].map(h => (
                    <th key={h} style={{ padding: "7px 16px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#9CA3AF", textTransform: "uppercase", letterSpacing: 0.4 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {bloco.linhas.map((l, i) => (
                  <tr key={i} style={{ borderTop: "1px solid #F3F4F6" }}>
                    <td style={{ padding: "9px 16px" }}>
                      <span style={{ fontFamily: "monospace", fontSize: 12, fontWeight: 700, background: "#F3F4F6", padding: "2px 8px", borderRadius: 4 }}>{l.colaborador?.chapa}</span>
                    </td>
                    <td style={{ padding: "9px 16px", fontSize: 12, fontWeight: 600, color: "#111827" }}>{l.colaborador?.nome}</td>
                    <td style={{ padding: "9px 16px", fontSize: 12, color: "#374151" }}>{l.data}</td>
                    <td style={{ padding: "9px 16px", fontSize: 12, color: "#374151" }}>{l.hora || "—"}</td>
                    <td style={{ padding: "9px 16px", fontSize: 12, fontWeight: 700, color: "#059669" }}>R$ {parseFloat(l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}</td>
                    <td style={{ padding: "9px 16px", fontSize: 11, color: "#6B7280", fontStyle: "italic" }}>{l.observacao || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        );
      })}

      {editandoBloco && (
        <ModalNovoBloco
          open={modalNovoBloco}
          onClose={() => { setModalNovoBloco(false); setEditandoBloco(null); }}
          bloco={editandoBloco}
          setBloco={setEditandoBloco}
          onSalvar={salvarBloco}
          colaboradores={colaboradores}
          eventos={eventos}
        />
      )}

      {modalBloco && (
        <Modal open={!!modalBloco} onClose={() => setModalBloco(null)} title={"Bloco: " + modalBloco.descricao} width={700}>
          <DetalhesBloco bloco={modalBloco} />
        </Modal>
      )}

      {modalRelatorio && (
        <Modal open={!!modalRelatorio} onClose={() => setModalRelatorio(null)} title={"Relatório — " + modalRelatorio.descricao} width={750}>
          <RelatorioBloco bloco={modalRelatorio} />
        </Modal>
      )}
    </div>
  );
}



// ─── MODAL NOVO/EDITAR BLOCO ──────────────────────────────────────────────────
const MESES = [
  { value: "012026", label: "Janeiro/2026" },
  { value: "022026", label: "Fevereiro/2026" },
  { value: "032026", label: "Março/2026" },
  { value: "042026", label: "Abril/2026" },
  { value: "052026", label: "Maio/2026" },
  { value: "062026", label: "Junho/2026" },
  { value: "072026", label: "Julho/2026" },
  { value: "082026", label: "Agosto/2026" },
  { value: "092025", label: "Setembro/2025" },
  { value: "102025", label: "Outubro/2025" },
  { value: "112025", label: "Novembro/2025" },
  { value: "122025", label: "Dezembro/2025" },
  { value: "012025", label: "Janeiro/2025" },
  { value: "022025", label: "Fevereiro/2025" },
  { value: "032025", label: "Março/2025" },
];

function CelulaColaborador({ linha, idx, updateLinha, colaboradores = [] }) {
  const [buscaNome, setBuscaNome] = useState(linha.colaborador?.nome || "");
  const [buscaChapa, setBuscaChapa] = useState(linha.colaborador?.chapa || "");
  const [sugestoesNome, setSugestoesNome] = useState([]);
  const [sugestoesChapa, setSugestoesChapa] = useState([]);

  const selecionarColaborador = (colab) => {
    setBuscaNome(colab.nome);
    setBuscaChapa(colab.chapa);
    setSugestoesNome([]);
    setSugestoesChapa([]);
    updateLinha(idx, "colaborador_id", parseInt(colab.id));
    updateLinha(idx, "colaborador", colab);
  };

  const normalizar = (s) =>
    (s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();

  const onChangeNome = (v) => {
    setBuscaNome(v);
    updateLinha(idx, "colaborador_id", "");
    updateLinha(idx, "colaborador", null);
    setBuscaChapa("");
    if (v.length >= 2) {
      const termo = normalizar(v);
      setSugestoesNome(
        colaboradores
          .filter(c => c.cod_situacao !== "D")
          .filter(c => normalizar(c.nome).includes(termo))
          .slice(0, 10)
      );
    } else {
      setSugestoesNome([]);
    }
  };

  const onChangeChapa = (v) => {
    setBuscaChapa(v);
    updateLinha(idx, "colaborador_id", "");
    updateLinha(idx, "colaborador", null);
    setBuscaNome("");
    if (v.length >= 2) {
      setSugestoesChapa(
        colaboradores
          .filter(c => c.cod_situacao !== "D")
          .filter(c => (c.chapa || "").includes(v.trim()))
          .slice(0, 10)
      );
    } else {
      setSugestoesChapa([]);
    }
  };

  const inputStyle = {
    width: "100%", border: "1px solid #D1D5DB", borderRadius: 6,
    padding: "5px 7px", fontSize: 11, fontFamily: "inherit", background: "#fff",
    boxSizing: "border-box"
  };
  const selectedStyle = { ...inputStyle, borderColor: "#10B981", background: "#F0FDF4" };
  const dropStyle = {
    position: "absolute", top: "100%", left: 0, right: 0, zIndex: 100,
    background: "#fff", border: "1px solid #D1D5DB", borderRadius: 6,
    boxShadow: "0 4px 16px rgba(0,0,0,0.12)", maxHeight: 160, overflowY: "auto"
  };
  const dropItemStyle = {
    padding: "7px 10px", fontSize: 11, cursor: "pointer",
    borderBottom: "1px solid #F3F4F6", color: "#111827"
  };

  return (
    <div style={{ display: "flex", gap: 4 }}>
      {/* Matrícula */}
      <div style={{ position: "relative", width: 72 }}>
        <input
          value={buscaChapa}
          onChange={e => onChangeChapa(e.target.value)}
          placeholder="Matrícula"
          style={linha.colaborador_id ? selectedStyle : inputStyle}
        />
        {sugestoesChapa.length > 0 && (
          <div style={dropStyle}>
            {sugestoesChapa.map(c => (
              <div key={c.id} style={dropItemStyle}
                onMouseDown={() => selecionarColaborador(c)}>
                <b>{c.chapa}</b>
              </div>
            ))}
          </div>
        )}
      </div>
      {/* Nome */}
      <div style={{ position: "relative", flex: 1 }}>
        <input
          value={buscaNome}
          onChange={e => onChangeNome(e.target.value)}
          placeholder="Nome do colaborador"
          style={linha.colaborador_id ? selectedStyle : inputStyle}
        />
        {sugestoesNome.length > 0 && (
          <div style={dropStyle}>
            {sugestoesNome.map(c => (
              <div key={c.id} style={dropItemStyle}
                onMouseDown={() => selecionarColaborador(c)}>
                <span style={{ color: "#6B7280", marginRight: 6 }}>{c.chapa}</span>{c.nome}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ModalNovoBloco({ open, onClose, bloco, setBloco, onSalvar, colaboradores = [], eventos = [] }) {
  const addLinha = () => setBloco(b => ({ ...b, linhas: [...b.linhas, LINHA_VAZIA()] }));
  const removeLinha = (idx) => setBloco(b => ({ ...b, linhas: b.linhas.filter((_, i) => i !== idx) }));
  const updateLinha = (idx, campo, val) => setBloco(b => ({
    ...b, linhas: b.linhas.map((l, i) => i === idx ? { ...l, [campo]: val } : l)
  }));

  if (!bloco) return null;

  const totalBloco = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
  const eventoSelecionado = eventos.find(e => e.id === parseInt(bloco.evento_id));

  const onAnexo = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setBloco(b => ({ ...b, anexo_nome: file.name, anexo_tamanho: (file.size / 1024).toFixed(1) + " KB" }));
  };

  return (
    <Modal open={open} onClose={onClose} title={bloco.id ? "Editar Solicitação de Pagamento" : "Nova Solicitação de Pagamento"} width={980}>
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

        {/* ── Cabeçalho do Bloco ── */}
        <div style={{ background: "#F8FAFC", borderRadius: 10, border: "1px solid #E5E7EB", padding: "16px 18px" }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 12 }}>
            Cabeçalho do Bloco
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 14 }}>
            <Input
              label="Descrição do Bloco (automática)"
              value={bloco.descricao}
              onChange={v => setBloco(b => ({ ...b, descricao: v }))}
              placeholder="Preenchido automaticamente..."
            />

            {/* Competência — select de meses */}
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", letterSpacing: 0.3 }}>
                Competência <span style={{ color: "#EF4444" }}>*</span>
              </label>
              <select
                value={bloco.competencia}
                onChange={e => {
                  const comp = e.target.value;
                  // Calcular data predefinida: dia 05 do mês seguinte
                  let dataPredef = "";
                  if (comp && comp.length === 6) {
                    const mes = parseInt(comp.slice(0, 2));
                    const ano = parseInt(comp.slice(2));
                    const proxMes = mes === 12 ? 1 : mes + 1;
                    const proxAno = mes === 12 ? ano + 1 : ano;
                    dataPredef = `${proxAno}-${String(proxMes).padStart(2,"0")}-05`;
                  }
                  setBloco(b => ({
                    ...b,
                    competencia: comp,
                    linhas: b.linhas.map(l => ({ ...l, data: dataPredef || l.data }))
                  }));
                }}
                style={{
                  border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px",
                  fontSize: 13, fontFamily: "inherit", background: "#fff", cursor: "pointer",
                  color: bloco.competencia ? "#111827" : "#9CA3AF"
                }}
              >
                <option value="">Selecione o mês...</option>
                {MESES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </div>

            {/* Evento único do bloco */}
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", letterSpacing: 0.3 }}>
                Evento do Bloco <span style={{ color: "#EF4444" }}>*</span>
              </label>
              <select
                value={bloco.evento_id || ""}
                onChange={e => setBloco(b => ({ ...b, evento_id: e.target.value }))}
                style={{
                  border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px",
                  fontSize: 13, fontFamily: "inherit", background: "#fff", cursor: "pointer",
                  color: bloco.evento_id ? "#111827" : "#9CA3AF"
                }}
              >
                <option value="">Selecione o evento...</option>
                {eventos.filter(e => e.ativo !== false).map(e => (
                  <option key={e.id} value={e.id}>{e.codigo} — {e.descricao}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Info do evento selecionado */}
          {eventoSelecionado && (
            <div style={{
              marginTop: 10, display: "flex", alignItems: "center", gap: 10,
              padding: "8px 12px", background: "#EFF6FF", borderRadius: 8, border: "1px solid #BFDBFE"
            }}>
              <span style={{ fontSize: 11, color: "#1D4ED8" }}>
                ⚡ Todos os lançamentos deste bloco serão do evento
                <b style={{ marginLeft: 4 }}>{eventoSelecionado.codigo} — {eventoSelecionado.descricao}</b>
              </span>
              <span style={{
                padding: "1px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700,
                background: eventoSelecionado.tipo === "provento" ? "#D1FAE5" : "#FEE2E2",
                color: eventoSelecionado.tipo === "provento" ? "#065F46" : "#991B1B"
              }}>{eventoSelecionado.tipo}</span>
              <span style={{
                padding: "1px 8px", borderRadius: 6, fontSize: 10, fontWeight: 600,
                background: "#F3F4F6", color: "#374151"
              }}>{eventoSelecionado.forma}</span>
            </div>
          )}
        </div>

        {/* ── Anexo do Bloco ── */}
        <div style={{
          display: "flex", alignItems: "center", gap: 14,
          padding: "12px 16px", background: "#FFFBEB", border: "1px dashed #FCD34D", borderRadius: 10
        }}>
          <span style={{ fontSize: 20 }}>📎</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#92400E" }}>Anexo do Bloco</div>
            {bloco.anexo_nome ? (
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}>
                <span style={{ fontSize: 12, color: "#065F46", fontWeight: 600 }}>✓ {bloco.anexo_nome}</span>
                <span style={{ fontSize: 11, color: "#6B7280" }}>({bloco.anexo_tamanho})</span>
                <button
                  onClick={() => setBloco(b => ({ ...b, anexo_nome: null, anexo_tamanho: null }))}
                  style={{ background: "none", border: "none", color: "#EF4444", cursor: "pointer", fontSize: 12 }}
                >✕ Remover</button>
              </div>
            ) : (
              <div style={{ fontSize: 11, color: "#92400E", marginTop: 2 }}>
                Nenhum arquivo selecionado. Formatos aceitos: PDF, JPG, PNG, XLSX.
              </div>
            )}
          </div>
          <label style={{
            padding: "7px 14px", background: "#F59E0B", color: "#fff", borderRadius: 8,
            fontSize: 12, fontWeight: 600, cursor: "pointer", whiteSpace: "nowrap"
          }}>
            {bloco.anexo_nome ? "Trocar arquivo" : "Selecionar arquivo"}
            <input type="file" accept=".pdf,.jpg,.jpeg,.png,.xlsx,.xls" onChange={onAnexo}
              style={{ display: "none" }} />
          </label>
        </div>

        {/* ── Tabela de Lançamentos ── */}
        {!bloco.evento_id ? (
          <div style={{
            padding: "28px", textAlign: "center", background: "#F8FAFC",
            border: "2px dashed #D1D5DB", borderRadius: 10
          }}>
            <div style={{ fontSize: 28, marginBottom: 8 }}>⚡</div>
            <p style={{ margin: 0, fontSize: 13, color: "#6B7280" }}>
              Selecione o <b>Evento do Bloco</b> acima para liberar os lançamentos
            </p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: "#374151" }}>
                Lançamentos — <span style={{ color: "#1D4ED8" }}>{eventoSelecionado?.descricao}</span>
                <span style={{ marginLeft: 6, fontSize: 11, color: "#6B7280" }}>({bloco.linhas.length} linha{bloco.linhas.length !== 1 ? "s" : ""})</span>
              </span>
              <Button variant="secondary" size="sm" onClick={addLinha}>+ Adicionar linha</Button>
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 600 }}>
              <thead>
                <tr style={{ background: "#0F2447" }}>
                  {["Matrícula / Colaborador *",
                    ...(eventoSelecionado?.forma === "hora"       ? ["Hora *"]        : []),
                    ...(eventoSelecionado?.forma === "referencia" ? ["Referência *"]   : []),
                    ...(eventoSelecionado?.forma === "valor"      ? ["Valor (R$) *"]   : ["Valor (R$)"]),
                    "Observação", ""].map(h => (
                    <th key={h} style={{
                      padding: "9px 10px", textAlign: "left", fontSize: 10, fontWeight: 700,
                      color: "rgba(255,255,255,0.7)", textTransform: "uppercase", letterSpacing: 0.4
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {bloco.linhas.map((linha, idx) => (
                  <tr key={linha._id} style={{ borderBottom: "1px solid #F3F4F6", background: idx % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                    {/* Matrícula + Nome — sem alteração */}
                    <td style={{ padding: "6px 8px", minWidth: 260 }}>
                      <CelulaColaborador linha={linha} idx={idx} updateLinha={updateLinha} colaboradores={colaboradores} />
                    </td>
                    {/* Hora — somente para forma=hora */}
                    {eventoSelecionado?.forma === "hora" && (
                      <td style={{ padding: "6px 8px", minWidth: 100 }}>
                        <input type="time" value={linha.hora || ""} onChange={e => updateLinha(idx, "hora", e.target.value)}
                          style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                      </td>
                    )}
                    {/* Referência — somente para forma=referencia */}
                    {eventoSelecionado?.forma === "referencia" && (
                      <td style={{ padding: "6px 8px", minWidth: 110 }}>
                        <input type="number" step="0.01" min="0" value={linha.referencia || ""}
                          onChange={e => updateLinha(idx, "referencia", e.target.value)}
                          placeholder="0.00"
                          style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                      </td>
                    )}
                    {/* Valor — somente para forma=valor obrigatório; para hora/referencia é opcional */}
                    {eventoSelecionado?.forma === "valor" && (
                      <td style={{ padding: "6px 8px", minWidth: 110 }}>
                        <input type="number" step="0.01" min="0" value={linha.valor || ""}
                          onChange={e => updateLinha(idx, "valor", e.target.value)}
                          placeholder="0.00"
                          style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                      </td>
                    )}
                    {/* Observação */}
                    <td style={{ padding: "6px 8px", minWidth: 160 }}>
                      <input value={linha.observacao || ""} onChange={e => updateLinha(idx, "observacao", e.target.value)}
                        placeholder="Opcional"
                        style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                    </td>
                    <td style={{ padding: "6px 8px" }}>
                      {bloco.linhas.length > 1 && (
                        <button onClick={() => removeLinha(idx)} style={{
                          background: "#FEE2E2", border: "none", borderRadius: 6,
                          padding: "5px 8px", color: "#EF4444", cursor: "pointer", fontSize: 12, fontWeight: 700
                        }}>✕</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
              <tfoot>
                <tr style={{ background: "#F0FDF4", borderTop: "2px solid #10B981" }}>
                  <td colSpan={3} style={{ padding: "10px 10px", fontSize: 12, fontWeight: 700, color: "#065F46" }}>
                    TOTAL — {bloco.linhas.filter(l => l.valor && l.colaborador_id).length} lançamento(s) preenchidos
                  </td>
                  <td colSpan={3} style={{ padding: "10px 10px", fontSize: 15, fontWeight: 800, color: "#065F46" }}>
                    R$ {totalBloco.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
                  </td>
                </tr>
              </tfoot>
            </table>
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, paddingTop: 8, borderTop: "1px solid #F3F4F6" }}>
          <Button variant="secondary" onClick={onClose}>Cancelar</Button>
          <Button onClick={onSalvar}>
            {bloco.id ? "Salvar Alterações" : "Enviar para Aprovação"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}


// ─── DETALHES DO BLOCO ────────────────────────────────────────────────────────
function DetalhesBloco({ bloco }) {
  if (!bloco) return null;
  const total = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
  const ACAO_COLOR = {
    criado: "#3B82F6", editado: "#F59E0B",
    aprovado_gestor: "#10B981", aprovado_superior: "#8B5CF6",
    aprovado_dp: "#059669", devolvido: "#F97316", rejeitado: "#EF4444",
  };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
        <Badge status={bloco.status} />
        <span style={{ fontSize: 12, color: "#6B7280" }}>Competência: <b>{bloco.competencia}</b> · {bloco.linhas.length} lançamento(s)</span>
        <span style={{ marginLeft: "auto", fontSize: 15, fontWeight: 700, color: "#10B981" }}>
          R$ {total.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
        </span>
      </div>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ background: "#F9FAFB" }}>
            {["Colaborador", "Evento", "Data", "Hora", "Valor", "Observação"].map(h => (
              <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {bloco.linhas.map((l, i) => (
            <tr key={i} style={{ borderTop: "1px solid #F3F4F6" }}>
              <td style={{ padding: "9px 12px", fontSize: 12, fontWeight: 600, color: "#111827" }}>{l.colaborador?.nome}</td>
              <td style={{ padding: "9px 12px", fontSize: 12, color: "#374151" }}>{l.evento?.descricao}</td>
              <td style={{ padding: "9px 12px", fontSize: 12, color: "#374151" }}>{l.data}</td>
              <td style={{ padding: "9px 12px", fontSize: 12, color: "#374151" }}>{l.hora || "—"}</td>
              <td style={{ padding: "9px 12px", fontSize: 12, fontWeight: 700, color: "#10B981" }}>R$ {parseFloat(l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}</td>
              <td style={{ padding: "9px 12px", fontSize: 11, color: "#6B7280", fontStyle: "italic" }}>{l.observacao || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div>
        <h4 style={{ margin: "0 0 10px", fontSize: 13, fontWeight: 700, color: "#374151" }}>Histórico do Bloco</h4>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {bloco.historico.map((h, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "center", gap: 12,
              padding: "8px 14px", background: "#F9FAFB", borderRadius: 8,
              borderLeft: `3px solid ${ACAO_COLOR[h.acao] || "#6B7280"}`
            }}>
              <div style={{ flex: 1 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: "#111827" }}>{h.usuario}</span>
                <span style={{ fontSize: 11, color: "#6B7280" }}> · {h.acao.replace(/_/g, " ")} · {h.data}</span>
                {h.obs && <div style={{ fontSize: 11, color: "#F97316", marginTop: 2 }}>"{h.obs}"</div>}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── RELATÓRIO DO BLOCO ───────────────────────────────────────────────────────
function RelatorioBloco({ bloco }) {
  if (!bloco) return null;
  const total = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
  const ACAO_LABEL = {
    criado: "Criação", editado: "Edição", aprovado_gestor: "Aprovação Gestor",
    aprovado_superior: "Aprovação Superior", aprovado_dp: "Aprovação DP",
    devolvido: "Devolução", rejeitado: "Rejeição"
  };
  const ACAO_COLOR = {
    criado: "#3B82F6", editado: "#F59E0B", aprovado_gestor: "#10B981",
    aprovado_superior: "#8B5CF6", aprovado_dp: "#059669", devolvido: "#F97316", rejeitado: "#EF4444"
  };

  const imprimir = () => window.print();

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Cabeçalho do relatório */}
      <div style={{ background: "#0F2447", borderRadius: 10, padding: "18px 22px", color: "#fff" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ background: "rgba(255,255,255,0.95)", borderRadius: 8, padding: "6px 14px", display: "inline-block" }}>
                <img src={LOGO_BENEL} alt="Benel" style={{ height: 32, display: "block" }} />
              </div>
            </div>
            <div style={{ fontSize: 11, letterSpacing: 1, color: "rgba(255,255,255,0.5)", textTransform: "uppercase", marginBottom: 4 }}>Relatório de Bloco</div>
            <div style={{ fontSize: 20, fontWeight: 800 }}>{bloco.descricao}</div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.6)", marginTop: 4 }}>
              Competência: <b style={{ color: "#93C5FD" }}>{bloco.competencia}</b> · Solicitante: <b style={{ color: "#93C5FD" }}>{bloco.solicitante}</b>
            </div>
          </div>
          <div style={{ textAlign: "right" }}>
            <Badge status={bloco.status} />
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.5)", marginTop: 6 }}>Gerado em: {new Date().toLocaleString("pt-BR")}</div>
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginTop: 16 }}>
          {[
            { label: "Total de lançamentos", value: bloco.linhas.length },
            { label: "Valor total", value: `R$ ${total.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}` },
            { label: "Etapas no histórico", value: bloco.historico.length },
          ].map(c => (
            <div key={c.label} style={{ background: "rgba(255,255,255,0.07)", borderRadius: 8, padding: "10px 14px" }}>
              <div style={{ fontSize: 10, color: "rgba(255,255,255,0.45)", textTransform: "uppercase", letterSpacing: 0.5 }}>{c.label}</div>
              <div style={{ fontSize: 18, fontWeight: 800, marginTop: 2 }}>{c.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Lançamentos */}
      <div>
        <h4 style={{ margin: "0 0 10px", fontSize: 13, fontWeight: 700, color: "#111827", textTransform: "uppercase", letterSpacing: 0.5 }}>
          Lançamentos
        </h4>
        <table style={{ width: "100%", borderCollapse: "collapse", border: "1px solid #E5E7EB", borderRadius: 8, overflow: "hidden" }}>
          <thead>
            <tr style={{ background: "#1B3A6B" }}>
              {["#", "Colaborador", "Chapa", "C.Custo", "Evento", "Cód.", "Data", "Hora", "Valor"].map(h => (
                <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "rgba(255,255,255,0.75)", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {bloco.linhas.map((l, i) => (
              <tr key={i} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#F8FAFC" }}>
                <td style={{ padding: "9px 12px", fontSize: 11, color: "#9CA3AF" }}>{i + 1}</td>
                <td style={{ padding: "9px 12px", fontSize: 12, fontWeight: 600, color: "#111827" }}>{l.colaborador?.nome}</td>
                <td style={{ padding: "9px 12px", fontSize: 11, fontFamily: "monospace", color: "#374151" }}>{l.colaborador?.chapa}</td>
                <td style={{ padding: "9px 12px", fontSize: 11, color: "#374151" }}>{l.colaborador?.centro_custo} — {l.colaborador?.desc_cc}</td>
                <td style={{ padding: "9px 12px", fontSize: 12, color: "#374151" }}>{l.evento?.descricao}</td>
                <td style={{ padding: "9px 12px", fontSize: 11, fontFamily: "monospace", color: "#374151" }}>{l.evento?.codigo}</td>
                <td style={{ padding: "9px 12px", fontSize: 12, color: "#374151" }}>{l.data}</td>
                <td style={{ padding: "9px 12px", fontSize: 12, color: "#374151" }}>{l.hora || "—"}</td>
                <td style={{ padding: "9px 12px", fontSize: 12, fontWeight: 800, color: "#059669" }}>
                  R$ {parseFloat(l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
                </td>
              </tr>
            ))}
          </tbody>
          <tfoot>
            <tr style={{ background: "#F0FDF4", borderTop: "2px solid #10B981" }}>
              <td colSpan={8} style={{ padding: "10px 12px", fontSize: 12, fontWeight: 700, color: "#065F46" }}>TOTAL</td>
              <td style={{ padding: "10px 12px", fontSize: 14, fontWeight: 800, color: "#065F46" }}>
                R$ {total.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
              </td>
            </tr>
          </tfoot>
        </table>
      </div>

      {/* Trilha de aprovação */}
      <div>
        <h4 style={{ margin: "0 0 12px", fontSize: 13, fontWeight: 700, color: "#111827", textTransform: "uppercase", letterSpacing: 0.5 }}>
          Trilha Completa de Aprovação
        </h4>
        <div style={{ position: "relative", paddingLeft: 28 }}>
          <div style={{ position: "absolute", left: 9, top: 0, bottom: 0, width: 2, background: "#E5E7EB" }} />
          {bloco.historico.map((h, i) => (
            <div key={i} style={{ position: "relative", marginBottom: 14 }}>
              <div style={{
                position: "absolute", left: -28, top: 2,
                width: 18, height: 18, borderRadius: "50%",
                background: ACAO_COLOR[h.acao] || "#6B7280",
                border: "3px solid #fff",
                boxShadow: `0 0 0 2px ${ACAO_COLOR[h.acao] || "#6B7280"}33`
              }} />
              <div style={{ background: "#F9FAFB", borderRadius: 10, padding: "10px 14px", border: "1px solid #E5E7EB" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <span style={{
                      fontSize: 11, fontWeight: 700, padding: "2px 8px", borderRadius: 6,
                      background: (ACAO_COLOR[h.acao] || "#6B7280") + "18",
                      color: ACAO_COLOR[h.acao] || "#6B7280"
                    }}>{ACAO_LABEL[h.acao] || h.acao}</span>
                    <span style={{ marginLeft: 8, fontSize: 12, fontWeight: 600, color: "#111827" }}>{h.usuario}</span>
                  </div>
                  <span style={{ fontSize: 11, color: "#9CA3AF" }}>{h.data}</span>
                </div>
                {h.obs && (
                  <div style={{ marginTop: 6, fontSize: 11, color: "#374151", fontStyle: "italic", borderLeft: "2px solid #F97316", paddingLeft: 8 }}>
                    {h.obs}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, borderTop: "1px solid #F3F4F6", paddingTop: 12 }}>
        <Button variant="secondary" onClick={imprimir}>🖨 Imprimir</Button>
      </div>
    </div>
  );
}

// ─── EXPORTAÇÃO TXT ───────────────────────────────────────────────────────────
const LAYOUT_RM = [
  { col: "01", tam: 16, tipo: "String",       desc: "Chapa do Funcionário" },
  { col: "17", tam: 8,  tipo: "String",       desc: "Data pagamento (DDMMAAAA)" },
  { col: "25", tam: 4,  tipo: "Alfanumérico", desc: "Código do evento" },
  { col: "29", tam: 6,  tipo: "String",       desc: "Hora (HHH:MM)" },
  { col: "35", tam: 15, tipo: "Real",         desc: "Referência (999999999999.99)" },
  { col: "50", tam: 15, tipo: "Real",         desc: "Valor (999999999999.99)" },
  { col: "65", tam: 15, tipo: "Real",         desc: "Valor original (999999999999.99)" },
  { col: "80", tam: 1,  tipo: "Caractere",    desc: "Dados alterados manualmente (S ou N)" },
  { col: "81", tam: 1,  tipo: "Caractere",    desc: "Dados de férias (S ou N)" },
];

function Exportacao({ solicitacoes, blocos }) {
  const blocosAprov = (blocos || []).filter(b => b.status === "aprovado_final");
  const [preview, setPreview] = useState(false);
  const [showLayout, setShowLayout] = useState(false);

  // Gera todas as linhas a partir dos blocos aprovados
  const linhas = blocosAprov.flatMap(bloco =>
    bloco.linhas.map(l => {
      const solFormatada = {
        ...l,
        valor_original: l.valor,
        competencia: bloco.competencia,
        status: bloco.status,
      };
      const colabs = [l.colaborador].filter(Boolean);
      const evts = [l.evento].filter(Boolean);
      if (!l.colaborador || !l.evento) return "";
      // Montar linha direto com objeto colaborador/evento já resolvidos
      const chapa = (l.colaborador.chapa || "").padEnd(16, " ").slice(0, 16);
      let dataTXT = "00000000";
      if (l.data) { const p = l.data.split("-"); if (p.length === 3) dataTXT = p[2] + p[1] + p[0]; }
      const codEvento = (l.evento.codigo || "").padEnd(4, " ").slice(0, 4);
      let horaTXT = "000:00";
      if (l.hora) { const hp = l.hora.split(":"); horaTXT = String(parseInt(hp[0]||0)).padStart(3,"0") + ":" + String(parseInt(hp[1]||0)).padStart(2,"0"); }
      const hora = horaTXT.slice(0, 6);
      const fmtReal = (v, t) => parseFloat(v||0).toFixed(2).padStart(t, " ");
      const ref     = fmtReal(l.referencia || 0, 15);
      const val     = fmtReal(l.valor || 0, 15);
      const valOrig = fmtReal(l.valor_original || l.valor || 0, 15);
      return chapa + dataTXT.slice(0,8) + codEvento + hora + ref + val + valOrig + "N" + "N";
    })
  ).filter(Boolean);

  const totalValor = blocosAprov.reduce((a, b) =>
    a + b.linhas.reduce((s, l) => s + parseFloat(l.valor || 0), 0), 0
  );

  const baixarTXT = () => {
    const conteudo = linhas.join("\n");
    const blob = new Blob([conteudo], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "movimento_rm_" + new Date().toISOString().split("T")[0] + ".txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
        <div>

        </div>
        <Button variant="secondary" size="sm" onClick={() => setShowLayout(l => !l)}>
          {showLayout ? "Ocultar layout" : "📋 Ver layout RM"}
        </Button>
      </div>

      {/* Layout RM Labore */}
      {showLayout && (
        <Card style={{ marginBottom: 20, padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", background: "#0F2447", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: "#fff" }}>Layout de Importação do Movimento (RM Labore)</span>
            <span style={{ fontSize: 11, color: "#93C5FD", background: "rgba(255,255,255,0.1)", padding: "2px 8px", borderRadius: 4 }}>81 caracteres por linha</span>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#F1F5F9" }}>
                {["Coluna", "Tamanho", "Tipo", "Descrição"].map(h => (
                  <th key={h} style={{ padding: "8px 14px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#475569", textTransform: "uppercase", letterSpacing: 0.4 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {LAYOUT_RM.map((row, i) => (
                <tr key={i} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#F8FAFC" }}>
                  <td style={{ padding: "9px 14px", fontFamily: "monospace", fontSize: 12, fontWeight: 700, color: "#1B3A6B" }}>{row.col}</td>
                  <td style={{ padding: "9px 14px", fontSize: 12, color: "#374151" }}>{row.tam}</td>
                  <td style={{ padding: "9px 14px" }}>
                    <span style={{ padding: "2px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600,
                      background: row.tipo === "Real" ? "#EFF6FF" : row.tipo === "String" ? "#F0FDF4" : "#FEF3C7",
                      color: row.tipo === "Real" ? "#1D4ED8" : row.tipo === "String" ? "#065F46" : "#92400E"
                    }}>{row.tipo}</span>
                  </td>
                  <td style={{ padding: "9px 14px", fontSize: 12, color: "#374151" }}>{row.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* Cards de resumo */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 20 }}>
        {[
          { label: "Blocos aprovados", value: blocosAprov.length, color: "#10B981" },
          { label: "Linhas no arquivo", value: linhas.length, color: "#3B82F6" },
          { label: "Valor total", value: "R$ " + totalValor.toLocaleString("pt-BR", { minimumFractionDigits: 2 }), color: "#8B5CF6" },
        ].map(c => (
          <Card key={c.label}>
            <div style={{ fontSize: 11, color: "#6B7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>{c.label}</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: c.color }}>{c.value}</div>
          </Card>
        ))}
      </div>

      {/* Tabela de registros */}
      <Card style={{ marginBottom: 16, padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "12px 16px", borderBottom: "1px solid #F3F4F6" }}>
          <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: "#111827" }}>Registros para exportar</h3>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Bloco", "Chapa", "Colaborador", "Evento (Cód.)", "Data", "Hora", "Referência", "Valor", "Valor Original"].map(h => (
                <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {blocosAprov.length === 0 ? (
              <tr><td colSpan={9} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>
                Nenhum bloco aprovado para exportar
              </td></tr>
            ) : blocosAprov.flatMap(bloco =>
              bloco.linhas.map((l, i) => (
                <tr key={bloco.id + "-" + i} style={{ borderTop: "1px solid #F3F4F6" }}>
                  <td style={{ padding: "8px 12px", fontSize: 11, color: "#6B7280" }}>{bloco.descricao}</td>
                  <td style={{ padding: "8px 12px" }}>
                    <span style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700, background: "#F3F4F6", padding: "1px 6px", borderRadius: 4 }}>{l.colaborador?.chapa}</span>
                  </td>
                  <td style={{ padding: "8px 12px", fontSize: 12, fontWeight: 600, color: "#111827" }}>{l.colaborador?.nome}</td>
                  <td style={{ padding: "8px 12px", fontSize: 11, color: "#374151" }}>
                    {l.evento?.descricao} <span style={{ color: "#9CA3AF" }}>({l.evento?.codigo})</span>
                  </td>
                  <td style={{ padding: "8px 12px", fontSize: 11, color: "#374151" }}>{l.data}</td>
                  <td style={{ padding: "8px 12px", fontSize: 11, color: "#374151" }}>{l.hora || "—"}</td>
                  <td style={{ padding: "8px 12px", fontSize: 11, color: "#374151" }}>{l.referencia || "0.00"}</td>
                  <td style={{ padding: "8px 12px", fontSize: 12, fontWeight: 700, color: "#059669" }}>
                    R$ {parseFloat(l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
                  </td>
                  <td style={{ padding: "8px 12px", fontSize: 11, color: "#374151" }}>
                    R$ {parseFloat(l.valor_original || l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </Card>

      {/* Prévia TXT */}
      <Card style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: "#111827" }}>Prévia do arquivo TXT</h3>
            <p style={{ margin: "2px 0 0", fontSize: 11, color: "#6B7280" }}>Layout posicional — 81 caracteres por linha</p>
          </div>
          <Button variant="secondary" size="sm" onClick={() => setPreview(!preview)}>
            {preview ? "Ocultar" : "Mostrar prévia"}
          </Button>
        </div>
        {preview && (
          <div>
            {/* Régua de posições */}
            <div style={{ fontFamily: "monospace", fontSize: 10, color: "#475569", marginBottom: 4, paddingLeft: 48, letterSpacing: 0 }}>
              {"1               17      25  29    35             50             65             80"}
            </div>
            <div style={{ fontFamily: "monospace", fontSize: 10, color: "#334155", marginBottom: 8, paddingLeft: 48 }}>
              {"|←── chapa ────→||← data→||ev||hora||←─── ref ───→||←── valor ──→||←─valorOrig─→|AN"}
            </div>
            <div style={{
              background: "#0F172A", borderRadius: 8, padding: "14px 16px",
              fontFamily: "'DM Mono', monospace", fontSize: 12, color: "#94A3B8",
              overflowX: "auto", whiteSpace: "nowrap"
            }}>
              {linhas.length === 0
                ? <span style={{ color: "#475569" }}>Nenhum registro aprovado para exportar.</span>
                : linhas.map((l, i) => (
                  <div key={i} style={{ marginBottom: 4, display: "flex", gap: 12 }}>
                    <span style={{ color: "#475569", userSelect: "none", minWidth: 32 }}>{String(i + 1).padStart(3, "0")}</span>
                    <span>
                      <span style={{ color: "#34D399" }}>{l.slice(0, 16)}</span>
                      <span style={{ color: "#60A5FA" }}>{l.slice(16, 24)}</span>
                      <span style={{ color: "#FBBF24" }}>{l.slice(24, 28)}</span>
                      <span style={{ color: "#F472B6" }}>{l.slice(28, 34)}</span>
                      <span style={{ color: "#A78BFA" }}>{l.slice(34, 49)}</span>
                      <span style={{ color: "#38BDF8" }}>{l.slice(49, 64)}</span>
                      <span style={{ color: "#FB923C" }}>{l.slice(64, 79)}</span>
                      <span style={{ color: "#E2E8F0" }}>{l.slice(79)}</span>
                    </span>
                  </div>
                ))}
            </div>
            {/* Legenda de cores */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 10 }}>
              {[
                { cor: "#34D399", label: "Chapa (1-16)" },
                { cor: "#60A5FA", label: "Data (17-24)" },
                { cor: "#FBBF24", label: "Evento (25-28)" },
                { cor: "#F472B6", label: "Hora (29-34)" },
                { cor: "#A78BFA", label: "Referência (35-49)" },
                { cor: "#38BDF8", label: "Valor (50-64)" },
                { cor: "#FB923C", label: "Valor Original (65-79)" },
                { cor: "#E2E8F0", label: "Flags (80-81)" },
              ].map(c => (
                <div key={c.label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 2, background: c.cor }} />
                  <span style={{ fontSize: 10, color: "#6B7280" }}>{c.label}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>

      <Button onClick={baixarTXT} disabled={linhas.length === 0} size="lg">
        ↓ Baixar arquivo TXT — TOTVS RM Labore
      </Button>
    </div>
  );
}

// ─── AUDITORIA SEGURA ────────────────────────────────────────────────────────
function Auditoria({ solicitacoes, blocos, sessao }) {
  const [aba, setAba] = useState("seguranca");

  const logsSeguranca = obterAuditLog();

  const logsBlocos = blocos.flatMap(b =>
    (b.historico || []).map(h => ({ ...h, bloco_id: b.id, bloco: b.descricao }))
  ).sort((a, b) => new Date(b.data) - new Date(a.data));

  const ACAO_COLOR = {
    criado: "#3B82F6", editado: "#F59E0B",
    aprovado_gestor: "#10B981", aprovado_superior: "#8B5CF6",
    aprovado_dp: "#059669", devolvido: "#F97316", rejeitado: "#EF4444",
    LOGIN_SUCESSO: "#10B981", LOGIN_FALHA: "#EF4444", LOGOUT: "#6B7280",
    RATE_LIMIT_ATINGIDO: "#EF4444", TENTATIVA_INJECAO: "#EF4444",
    TXT_EXPORTADO: "#3B82F6", SESSAO_EXPIRADA: "#F97316",
    BLOCO_APROVADO: "#10B981", BLOCO_REJEITADO: "#EF4444",
    SCHEMA_TOTVS_INVALIDO: "#F97316", ACESSO_NEGADO: "#EF4444",
  };

  const abas = [
    { id: "seguranca", label: "🔒 Log de Segurança", count: logsSeguranca.length },
    { id: "blocos", label: "📋 Log de Blocos", count: logsBlocos.length },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ marginBottom: 20 }}>
      </div>

      {/* Abas */}
      <div style={{ display: "flex", gap: 4, marginBottom: 16, borderBottom: "2px solid #E5E7EB", paddingBottom: 0 }}>
        {abas.map(a => (
          <button key={a.id} onClick={() => setAba(a.id)} style={{
            padding: "8px 16px", border: "none", background: "none", cursor: "pointer",
            fontSize: 13, fontWeight: aba === a.id ? 700 : 400,
            color: aba === a.id ? "#1B3A6B" : "#6B7280",
            borderBottom: aba === a.id ? "2px solid #1B3A6B" : "2px solid transparent",
            marginBottom: -2, fontFamily: "inherit"
          }}>
            {a.label}
            <span style={{
              marginLeft: 6, padding: "1px 7px", borderRadius: 10, fontSize: 10,
              background: aba === a.id ? "#1B3A6B" : "#F3F4F6",
              color: aba === a.id ? "#fff" : "#6B7280", fontWeight: 700
            }}>{a.count}</span>
          </button>
        ))}
      </div>

      {/* Log de Segurança */}
      {aba === "seguranca" && (
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", background: "#0F2447", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: "#fff" }}>🔒 Log de Segurança — Eventos do Sistema</span>
            <span style={{ fontSize: 11, color: "#93C5FD" }}>{logsSeguranca.length} registro(s)</span>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#F9FAFB" }}>
                {["Data/Hora", "Ação", "Usuário", "Perfil", "Detalhes"].map(h => (
                  <th key={h} style={{ padding: "9px 14px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {logsSeguranca.length === 0 ? (
                <tr><td colSpan={5} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhum evento registrado nesta sessão</td></tr>
              ) : logsSeguranca.map((l, i) => (
                <tr key={i} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                  <td style={{ padding: "9px 14px", fontSize: 11, color: "#6B7280", fontFamily: "monospace" }}>{l.dataHora}</td>
                  <td style={{ padding: "9px 14px" }}>
                    <span style={{
                      padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700,
                      background: (ACAO_COLOR[l.acao] || "#6B7280") + "18",
                      color: ACAO_COLOR[l.acao] || "#6B7280"
                    }}>{l.acao}</span>
                  </td>
                  <td style={{ padding: "9px 14px", fontSize: 12, fontWeight: 600, color: "#111827" }}>{l.usuario}</td>
                  <td style={{ padding: "9px 14px", fontSize: 11, color: "#374151", textTransform: "capitalize" }}>{l.perfil || "—"}</td>
                  <td style={{ padding: "9px 14px", fontSize: 11, color: "#6B7280" }}>
                    {Object.keys(l.detalhes || {}).length > 0
                      ? Object.entries(l.detalhes).map(([k, v]) => (
                        <span key={k} style={{ marginRight: 8 }}>
                          <b>{k}:</b> {String(v).slice(0, 40)}
                        </span>
                      ))
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* Log de Blocos */}
      {aba === "blocos" && (
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "#F9FAFB" }}>
                {["Bloco", "Ação", "Usuário", "Data/Hora", "Observação"].map(h => (
                  <th key={h} style={{ padding: "9px 14px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {logsBlocos.length === 0 ? (
                <tr><td colSpan={5} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhum evento de bloco registrado</td></tr>
              ) : logsBlocos.map((l, i) => (
                <tr key={i} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                  <td style={{ padding: "9px 14px", fontSize: 12, color: "#374151" }}>{l.bloco}</td>
                  <td style={{ padding: "9px 14px" }}>
                    <span style={{
                      padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700,
                      background: (ACAO_COLOR[l.acao] || "#6B7280") + "18",
                      color: ACAO_COLOR[l.acao] || "#6B7280"
                    }}>{l.acao.replace(/_/g, " ")}</span>
                  </td>
                  <td style={{ padding: "9px 14px", fontSize: 12, fontWeight: 600, color: "#111827" }}>{l.usuario}</td>
                  <td style={{ padding: "9px 14px", fontSize: 11, color: "#6B7280" }}>{l.data}</td>
                  <td style={{ padding: "9px 14px", fontSize: 11, color: l.obs ? "#F97316" : "#9CA3AF", fontStyle: l.obs ? "italic" : "normal" }}>{l.obs || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

// ─── USUARIOS (placeholder) ───────────────────────────────────────────────────


function Aprovacoes({ blocos, setBlocos, user, recarregarDados }) {
  const [justificativa, setJustificativa] = useState("");
  const [modalAcao, setModalAcao] = useState(null);

  const getFilaParaUsuario = () => {
    if (user.perfil === "superior") return blocos.filter(b => b.status === "pendente_superior");
    if (user.perfil === "dp") return blocos.filter(b => b.status === "pendente_dp");
    if (user.perfil === "admin") return blocos.filter(b => b.status.startsWith("pendente"));
    return [];
    return [];
  };

  const fila = getFilaParaUsuario();

  const avancarStatus = (bloco) => {
    const mapa = {
      pendente_gestor: "pendente_superior",
      pendente_superior: "pendente_dp",
      pendente_dp: "aprovado_final",
    };
    return mapa[bloco.status] || bloco.status;
  };

  const executarAcao = async (acao) => {
    const { bloco } = modalAcao;
    const ts = new Date().toLocaleString("pt-BR");

    // Optimistic update imediato
    setBlocos(prev => prev.map(b => {
      if (b.id !== bloco.id) return b;
      let novoStatus = b.status;
      if (acao === "aprovar") novoStatus = avancarStatus(b);
      if (acao === "rejeitar") novoStatus = "rejeitado";
      if (acao === "devolver") novoStatus = "devolvido";
      const acaoNome = acao === "aprovar" ? ("aprovado_" + user.perfil) : acao;
      return {
        ...b, status: novoStatus,
        historico: [...b.historico, { acao: acaoNome, usuario: user.nome, data: ts, obs: justificativa }]
      };
    }));

    try {
      await api.aprovarBloco(bloco.id, acao, justificativa);
      if (recarregarDados) await recarregarDados();
    } catch (err) {
      console.warn("API indisponível, ação aplicada localmente:", err.message);
    }

    setModalAcao(null);
    setJustificativa("");
  };

  return (
    <div style={{ padding: 28 }}>

      {fila.length === 0 ? (
        <Card style={{ textAlign: "center", padding: "40px 0" }}>
          <div style={{ fontSize: 36, marginBottom: 10 }}>✅</div>
          <p style={{ margin: 0, fontSize: 14, fontWeight: 600, color: "#6B7280" }}>Nenhum bloco pendente para aprovação</p>
        </Card>
      ) : fila.map(bloco => {
        const total = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
        return (
          <Card key={bloco.id} style={{ marginBottom: 14, padding: 0, overflow: "hidden" }}>
            <div style={{ padding: "14px 20px", background: "#F8FAFC", borderBottom: "1px solid #E5E7EB", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 14, fontWeight: 700, color: "#111827" }}>{bloco.descricao}</span>
                  <Badge status={bloco.status} />
                </div>
                <div style={{ fontSize: 11, color: "#6B7280" }}>
                  Competência: <b>{bloco.competencia}</b> · Solicitante: <b>{bloco.solicitante}</b> · Criado: <b>{bloco.criado_em}</b>
                </div>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{ textAlign: "right", marginRight: 8 }}>
                  <div style={{ fontSize: 11, color: "#6B7280" }}>{bloco.linhas.length} lançamento(s)</div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: "#10B981" }}>R$ {total.toLocaleString("pt-BR", { minimumFractionDigits: 2 })}</div>
                </div>
                <Button variant="success" size="sm" onClick={() => setModalAcao({ bloco, acao: "aprovar" })}>✓ Aprovar Bloco</Button>
                <Button variant="warning" size="sm" onClick={() => setModalAcao({ bloco, acao: "devolver" })}>↩ Devolver</Button>
                <Button variant="danger" size="sm" onClick={() => setModalAcao({ bloco, acao: "rejeitar" })}>✕ Rejeitar</Button>
              </div>
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ background: "#FAFAFA" }}>
                  {["Colaborador", "Evento", "Data", "Hora", "Valor", "Observação"].map(h => (
                    <th key={h} style={{ padding: "7px 16px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#9CA3AF", textTransform: "uppercase" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {bloco.linhas.map((l, i) => (
                  <tr key={i} style={{ borderTop: "1px solid #F3F4F6" }}>
                    <td style={{ padding: "9px 16px" }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: "#111827" }}>{l.colaborador?.nome}</div>
                      <div style={{ fontSize: 10, color: "#6B7280" }}>Chapa: {l.colaborador?.chapa}</div>
                    </td>
                    <td style={{ padding: "9px 16px", fontSize: 12, color: "#374151" }}>{l.evento?.descricao}</td>
                    <td style={{ padding: "9px 16px", fontSize: 12, color: "#374151" }}>{l.data}</td>
                    <td style={{ padding: "9px 16px", fontSize: 12, color: "#374151" }}>{l.hora || "—"}</td>
                    <td style={{ padding: "9px 16px", fontSize: 12, fontWeight: 700, color: "#059669" }}>R$ {parseFloat(l.valor || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2 })}</td>
                    <td style={{ padding: "9px 16px", fontSize: 11, color: "#6B7280", fontStyle: "italic" }}>{l.observacao || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        );
      })}

      <Modal open={!!modalAcao} onClose={() => setModalAcao(null)} title={
        modalAcao?.acao === "aprovar" ? "Aprovar Bloco" :
        modalAcao?.acao === "devolver" ? "Devolver Bloco" : "Rejeitar Bloco"
      }>
        {modalAcao && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <p style={{ margin: 0, fontSize: 13, color: "#374151" }}>
              {modalAcao.acao === "aprovar"
                ? ("Confirma a aprovação do bloco " + modalAcao.bloco.descricao + " com " + modalAcao.bloco.linhas.length + " lançamento(s)?")
                : "Informe o motivo:"}
            </p>
            {modalAcao.acao !== "aprovar" && (
              <Input label="Justificativa *" value={justificativa} onChange={setJustificativa} placeholder="Descreva o motivo..." required />
            )}
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
              <Button variant="secondary" onClick={() => setModalAcao(null)}>Cancelar</Button>
              <Button
                variant={modalAcao.acao === "aprovar" ? "success" : modalAcao.acao === "devolver" ? "warning" : "danger"}
                onClick={() => executarAcao(modalAcao.acao)}
                disabled={modalAcao.acao !== "aprovar" && !justificativa}
              >
                {modalAcao.acao === "aprovar" ? "Confirmar Aprovação" : modalAcao.acao === "devolver" ? "Devolver" : "Rejeitar"}
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}




// ─── ADVERTÊNCIAS / SUSPENSÕES ────────────────────────────────────────────────
// ─── AUTORIZAÇÃO DE DESCONTO ──────────────────────────────────────────────────
const MESES_AUTORIZACAO = [
  { value: "01", label: "Janeiro" }, { value: "02", label: "Fevereiro" },
  { value: "03", label: "Março" },   { value: "04", label: "Abril" },
  { value: "05", label: "Maio" },    { value: "06", label: "Junho" },
  { value: "07", label: "Julho" },   { value: "08", label: "Agosto" },
  { value: "09", label: "Setembro" },{ value: "10", label: "Outubro" },
  { value: "11", label: "Novembro" },{ value: "12", label: "Dezembro" },
];

function gerarHTMLAutorizacao(dados, colaborador, logoBase64) {
  const {
    valor_total, num_parcelas, mes_inicio, ano_inicio,
    data_ocorrido, descricao_prejuizo, gestor_nome
  } = dados;

  const valorNum  = parseFloat(valor_total) || 0;
  const parcelas  = parseInt(num_parcelas) || 1;
  const valorParc = (valorNum / parcelas).toFixed(2).replace(".", ",");
  const mesLabel  = MESES_AUTORIZACAO.find(m => m.value === mes_inicio)?.label || mes_inicio;
  const valorExt  = valorPorExtenso(valorNum);
  const cpfFmt    = colaborador?.cpf || "_______________";
  const nome      = colaborador?.nome || "_______________";
  const valorFmt  = valorNum.toFixed(2).replace(".", ",");

  const hoje = new Date();
  const mesesNome = ["janeiro","fevereiro","março","abril","maio","junho","julho","agosto","setembro","outubro","novembro","dezembro"];
  const dataDoc   = `${hoje.getDate()} de ${mesesNome[hoje.getMonth()]} de ${hoje.getFullYear()}`;
  const dataOcorr = (() => {
    if (!data_ocorrido) return "___/___/______";
    try {
      const d = new Date(String(data_ocorrido).includes("T") ? data_ocorrido : data_ocorrido + "T12:00:00");
      return isNaN(d.getTime()) ? "___/___/______" : d.toLocaleDateString("pt-BR");
    } catch { return "___/___/______"; }
  })();

  return `
    <div style="font-family:Arial,sans-serif;font-size:10.5pt;line-height:1.45;max-width:680px;margin:0 auto;padding:24px 32px;color:#000;text-align:justify;">
      ${logoBase64 ? `<div style="text-align:center;margin-bottom:10px;"><img src="${logoBase64}" alt="Benel" style="height:52px;" /></div>` : ""}
      <h3 style="text-align:center;font-size:12pt;font-weight:bold;text-transform:uppercase;text-decoration:underline;margin:0 0 14px 0;letter-spacing:.5px;">
        Autorização para Desconto na Folha de Pagamento
      </h3>
      <p style="margin:0 0 12px 0;">
        Pelo presente, eu <u>${nome}</u>, CPF nº <u>${cpfFmt}</u>,
        AUTORIZO a <strong>BENEL–TRANPORTE E LOGÍSTICA LTDA</strong>, a proceder desconto no meu salário,
        a título de reparação da importância de <strong>R$&nbsp;${valorFmt}</strong>
        (<em>${valorExt}</em>), decorrentes de prejuízos causados à Empregadora,
        conforme exposto abaixo, sendo parcelados em <strong>${parcelas}</strong>
        parcela${parcelas > 1 ? "s" : ""} de <strong>R$&nbsp;${valorParc}</strong>,
        a começar na próxima folha de pagamento em <strong>${mesLabel}&nbsp;/&nbsp;${ano_inicio}</strong>.
      </p>
      <p style="font-weight:bold;margin:0 0 2px 0;">DESCRIÇÃO DO PREJUÍZO:</p>
      <p style="margin:0 0 10px 0;min-height:28px;">${descricao_prejuizo || "&nbsp;"}</p>
      <p style="margin:0 0 12px 0;">DATA DO OCORRIDO:&nbsp;<u>${dataOcorr}</u></p>
      <p style="margin:0 0 8px 0;">Declaro estar ciente do referido desconto, conforme parágrafo primeiro do artigo 462, da CLT e cláusula quinta do meu contrato de trabalho, transcritos abaixo:</p>
      <div style="border:1px solid #aaa;margin:0 0 8px 0;padding:7px 12px;font-size:9.5pt;">
        <p style="margin:0 0 4px 0;">Art. 462 – Ao empregador é vedado efetuar qualquer desconto nos salários do empregado, salvo quando este resultar de adiantamentos, de dispositivos de lei ou de contrato coletivo.</p>
        <p style="margin:0;"><strong>§ 1º</strong> – Em caso de dano causado pelo empregado, o desconto será lícito, <u>desde de que esta possibilidade tenha sido acordada ou na ocorrência de dolo do empregado.</u></p>
      </div>
      <div style="border:1px solid #aaa;margin:0 0 10px 0;padding:7px 12px;font-size:9.5pt;">
        <p style="margin:0;"><strong>5.</strong> Além dos descontos permitidos na legislação, a EMPREGADORA poderá descontar da remuneração do EMPREGADO(A) <strong>toda e qualquer importância</strong> que este seja devedor por prejuízo que vier a dar causa, contra a EMPREGADORA ou terceiros, por culpa ou dolo, e, ainda, por outras obrigações que porventura incidam em sua remuneração.</p>
      </div>
      <p style="margin:0 0 6px 0;">Declaro estar ciente de que o presente instrumento serve para fins de advertência disciplinar em virtude dos fatos acima discriminados, os quais decorrem do descumprimento às normas internas da empresa.</p>
      <p style="margin:0 0 6px 0;">Declaro, também, estar ciente que em caso de rescisão do contrato de trabalho, será descontado o valor remanescente do prejuízo, até o limite legal.</p>
      <p style="margin:0 0 18px 0;">Posto isso, assino de livre e espontânea vontade a presente autorização, para que produza os efeitos jurídicos necessários.</p>
      <p style="margin:0 0 36px 0;">___________________, ${dataDoc}.</p>
      <div style="display:flex;justify-content:space-around;margin-top:24px;">
        <div style="text-align:center;width:44%;">
          <div style="border-top:1px solid #000;padding-top:6px;font-size:10pt;">${nome}</div>
          <div style="font-size:9pt;color:#444;margin-top:2px;">Colaborador(a)</div>
        </div>
        <div style="text-align:center;width:44%;">
          <div style="border-top:1px solid #000;padding-top:6px;font-size:10pt;">${gestor_nome || "Gestor"}</div>
          <div style="font-size:9pt;color:#444;margin-top:2px;">Gestor(a)</div>
        </div>
      </div>
    </div>
  `;
}


// ─── PDF VIEWER — renderiza PDF via PDF.js sem depender de iframe/CSP ────────
function PdfViewer({ src, height = "72vh" }) {
  const canvasRef = useRef(null);
  const [numPages, setNumPages] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [pdfDoc, setPdfDoc] = useState(null);

  useEffect(() => {
    if (!src) return;
    // Carregar PDF.js via CDN
    const loadPdfJs = async () => {
      if (!window.pdfjsLib) {
        await new Promise((resolve, reject) => {
          const s = document.createElement("script");
          s.src = "/pdf.min.js";
          s.onload = resolve; s.onerror = reject;
          document.head.appendChild(s);
        });
        window.pdfjsLib.GlobalWorkerOptions.workerSrc = "/pdf.worker.min.js";
      }
      try {
        const b64 = src.includes(",") ? src.split(",")[1] : src;
        const bin = atob(b64);
        const arr = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
        const doc = await window.pdfjsLib.getDocument({ data: arr }).promise;
        setPdfDoc(doc);
        setNumPages(doc.numPages);
        setLoading(false);
      } catch(e) { setLoading(false); console.error("PDF load error", e); }
    };
    loadPdfJs();
  }, [src]);

  useEffect(() => {
    if (!pdfDoc || !canvasRef.current) return;
    const renderPage = async () => {
      const page = await pdfDoc.getPage(currentPage);
      const canvas = canvasRef.current;
      const ctx = canvas.getContext("2d");
      const viewport = page.getViewport({ scale: 1.5 });
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      await page.render({ canvasContext: ctx, viewport }).promise;
    };
    renderPage();
  }, [pdfDoc, currentPage]);

  if (loading) return (
    <div style={{ textAlign:"center", padding:"40px 0", color:"#6B7280" }}>
      <div style={{ fontSize:32, marginBottom:8 }}>⏳</div>
      <div>Carregando PDF...</div>
    </div>
  );

  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:12 }}>
      <canvas ref={canvasRef} style={{ maxWidth:"100%", borderRadius:6, border:"1px solid #E5E7EB", boxShadow:"0 2px 8px rgba(0,0,0,0.08)" }} />
      {numPages > 1 && (
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <button onClick={() => setCurrentPage(p => Math.max(1, p-1))} disabled={currentPage===1}
            style={{ padding:"5px 14px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", fontWeight:600, fontSize:13 }}>‹ Anterior</button>
          <span style={{ fontSize:13, color:"#374151" }}>Página {currentPage} de {numPages}</span>
          <button onClick={() => setCurrentPage(p => Math.min(numPages, p+1))} disabled={currentPage===numPages}
            style={{ padding:"5px 14px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", fontWeight:600, fontSize:13 }}>Próxima ›</button>
        </div>
      )}
    </div>
  );
}

function Autorizacoes({ user, colaboradores }) {
  const anoAtual = new Date().getFullYear();
  const FORM_VAZIO = {
    colaborador_id: "", valor_total: "", num_parcelas: "1",
    mes_inicio: String(new Date().getMonth() + 1).padStart(2, "0"),
    ano_inicio: String(anoAtual),
    data_ocorrido: "", descricao_prejuizo: "", observacoes: "",
  };

  const [lista, setLista]             = useState([]);
  const [carregando, setCarregando]   = useState(true);
  const [modalNovo, setModalNovo]     = useState(false);
  const [form, setForm]               = useState(FORM_VAZIO);
  const [colaboradorSel, setColabSel] = useState(null);
  const [buscaColab, setBuscaColab]   = useState("");
  const [sugestoes, setSugestoes]     = useState([]);
  const [erro, setErro]               = useState("");
  const [modalDoc, setModalDoc]       = useState(null);

  useEffect(() => {
    api.listarAutorizacoes()
      .then(data => { if (Array.isArray(data)) setLista(data); })
      .catch(() => {})
      .finally(() => setCarregando(false));
  }, []);

  const normalizar = (s) => (s||"").normalize("NFD").replace(/[\u0300-\u036f]/g,"").toLowerCase().trim();
  const buscaTimer = useRef(null);

  const onBusca = (v) => {
    setBuscaColab(v);
    setForm(f => ({ ...f, colaborador_id: "" }));
    setColabSel(null);
    if (v.length < 2) { setSugestoes([]); return; }
    const termo = normalizar(v);
    const local = colaboradores
      .filter(c => c.cod_situacao !== "D")
      .filter(c => normalizar(c.nome).includes(termo) || (c.chapa||"").includes(v.trim()))
      .slice(0, 15);
    setSugestoes(local);
  };

  const selecionarColab = (c) => {
    setColabSel(c);
    setBuscaColab(c.nome);
    setForm(f => ({ ...f, colaborador_id: c.id }));
    setSugestoes([]);
  };

  const valorParc = () => {
    const v = parseFloat(form.valor_total) || 0;
    const p = parseInt(form.num_parcelas) || 1;
    return p > 0 ? (v / p).toFixed(2) : "0.00";
  };

  const salvar = async () => {
    if (!form.colaborador_id)   return setErro("Selecione um colaborador.");
    if (!form.valor_total || parseFloat(form.valor_total) <= 0) return setErro("Informe o valor total.");
    if (!form.num_parcelas || parseInt(form.num_parcelas) < 1)  return setErro("Informe o número de parcelas.");
    if (!form.data_ocorrido)    return setErro("Informe a data do ocorrido.");
    if (!form.descricao_prejuizo.trim()) return setErro("Informe a descrição do prejuízo.");
    setErro("");
    try {
      const payload = {
        ...form,
        colaborador_nome: colaboradorSel?.nome,
        colaborador_cpf:  colaboradorSel?.cpf,
      };
      const nova = await api.criarAutorizacao(payload);
      setLista(l => [{ ...nova, colaborador: colaboradorSel, gestor_nome: user.nome }, ...l]);
      setModalNovo(false);
      setForm(FORM_VAZIO);
      setColabSel(null);
      setBuscaColab("");
    } catch(e) { setErro(e.message || "Erro ao salvar"); }
  };

  const anexar = async (id, file) => {
    if (file.size > 5*1024*1024) { alert("Arquivo muito grande (máx 5MB)"); return; }
    const reader = new FileReader();
    reader.onload = async (ev) => {
      try {
        await api.addAnexoAutorizacao(id, { nome_arquivo: file.name, dados_base64: ev.target.result });
        setLista(l => l.map(s => s.id === id ? { ...s, anexo_nome: file.name, status: "anexado" } : s));
      } catch(e) { alert("Erro ao anexar: " + e.message); }
    };
    reader.readAsDataURL(file);
  };

  const cancelar = async (id) => {
    if (!window.confirm("Cancelar esta autorização?")) return;
    try {
      await api.cancelarAutorizacao(id);
      setLista(l => l.map(s => s.id === id ? { ...s, status: "cancelado" } : s));
    } catch(e) { alert("Erro: " + e.message); }
  };

  const STATUS_CORES = {
    pendente:  { bg: "#FEF3C7", color: "#92400E", label: "Pendente" },
    anexado:   { bg: "#D1FAE5", color: "#065F46", label: "Anexado"  },
    cancelado: { bg: "#F3F4F6", color: "#6B7280", label: "Cancelado"},
  };

  const [fAColab,  setFAColab]  = useState("");
  const [fAStatus, setFAStatus] = useState("");
  const [fAGestor, setFAGestor] = useState("");
  const normA = s => (s||"").toLowerCase();
  const listaFiltradaA = lista
    .filter(s => s.status !== "cancelado")
    .filter(s => !fAColab  || normA(s.colaborador?.nome || s.colaborador_nome).includes(normA(fAColab)) || (s.colaborador?.chapa||"").includes(fAColab))
    .filter(s => !fAStatus || s.status === fAStatus)
    .filter(s => !fAGestor || normA(s.gestor_nome).includes(normA(fAGestor)));

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={{ fontSize: 13, color: "#6B7280" }}>{lista.filter(s=>s.status!=="cancelado").length} autorização(ões)</div>
        {["gestor","dp","admin"].includes(user.perfil) && (
          <button onClick={() => { setModalNovo(true); setErro(""); setForm(FORM_VAZIO); setColabSel(null); setBuscaColab(""); }}
            style={{ padding: "10px 20px", background: "#0F2447", color: "#fff", border: "none", borderRadius: 8, fontWeight: 600, fontSize: 14, cursor: "pointer" }}>
            + Nova Autorização
          </button>
        )}
      </div>

      <div style={{ background: "#fff", borderRadius: 12, border: "1px solid #E5E7EB", overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Colaborador", "Valor / Parcelas", "Data", "Início", "Solicitante", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 14px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding:"5px 8px" }}><input value={fAColab} onChange={e=>setFAColab(e.target.value)} placeholder="🔍 Colaborador/Chapa" style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }} />
              <th style={{ padding:"5px 8px" }} />
              <th style={{ padding:"5px 8px" }} />
              <th style={{ padding:"5px 8px" }}><input value={fAGestor} onChange={e=>setFAGestor(e.target.value)} placeholder="🔍 Solicitante" style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }}>
                <select value={fAStatus} onChange={e=>setFAStatus(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}>
                  <option value="">Todos</option>
                  <option value="pendente">Pendente</option>
                  <option value="anexado">Anexado</option>
                </select>
              </th>
              <th style={{ padding:"5px 8px" }}><button onClick={()=>{setFAColab("");setFAStatus("");setFAGestor("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {carregando ? (
              <tr><td colSpan={7} style={{ padding:32, textAlign:"center", color:"#9CA3AF" }}>Carregando...</td></tr>
            ) : listaFiltradaA.length === 0 ? (
              <tr><td colSpan={7} style={{ padding:40, textAlign:"center", color:"#9CA3AF" }}>
                <div style={{ fontSize:32, marginBottom:8 }}>📋</div>Nenhuma autorização encontrada
              </td></tr>
            ) : listaFiltradaA.map((s, i) => {
              const st = STATUS_CORES[s.status] || STATUS_CORES.pendente;
              const nomeColab = s.colaborador?.nome || s.colaborador_nome || "—";
              const chapaColab = s.colaborador?.chapa || s.colaborador_chapa || "";
              const docData = { ...s, gestor_nome: s.gestor_nome };
              const colabData = s.colaborador || { nome: s.colaborador_nome, cpf: s.colaborador_cpf };
              const trunc3 = (nome) => (nome || "").split(" ").slice(0, 3).join(" ").toUpperCase();
              return (
                <tr key={s.id} style={{ borderTop:"1px solid #F3F4F6", background: i%2===0?"#fff":"#FAFAFA" }}>
                  <td style={{ padding:"10px 14px" }}>
                    <div style={{ fontWeight:600, fontSize:12, color:"#111827" }}>{nomeColab}</div>
                    {chapaColab && <div style={{ fontSize:11, color:"#6B7280" }}>Chapa: {chapaColab}</div>}
                  </td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>
                    R$ {parseFloat(s.valor_total).toFixed(2).replace(".",",")} · {s.num_parcelas}x de R$ {(parseFloat(s.valor_total)/parseInt(s.num_parcelas)).toFixed(2).replace(".",",")}
                  </td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>
                    {new Date(s.criado_em).toLocaleDateString("pt-BR")}
                  </td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>
                    {MESES_AUTORIZACAO.find(m=>m.value===s.mes_inicio)?.label}/{s.ano_inicio}
                  </td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>{trunc3(s.gestor_nome)}</td>
                  <td style={{ padding:"10px 14px" }}>
                    <span style={{ padding:"3px 10px", borderRadius:20, fontSize:11, fontWeight:600, background:st.bg, color:st.color }}>{st.label}</span>
                  </td>
                  <td style={{ padding:"10px 14px" }}>
                    <div style={{ display:"flex", gap:6 }}>
                      <button onClick={() => setModalDoc({ ...docData, colaborador: colabData })} style={{ padding:"5px 10px", borderRadius:8, border:"1px solid #D1D5DB", background:"#fff", fontSize:12, cursor:"pointer", fontWeight:600 }}>📄 PDF</button>
                      <label style={{ padding:"5px 10px", borderRadius:8, border:"1px solid #10B981", background:"#F0FDF4", color:"#065F46", fontSize:12, cursor:"pointer", fontWeight:600, display:"inline-flex", alignItems:"center", gap:4, overflow:"hidden", maxWidth:120 }}>
                        📎 {s.anexo_nome ? "Substituir" : "Anexar"}
                        <input type="file" accept=".pdf,.jpg,.jpeg,.png" style={{ display:"none" }}
                          onChange={e => { const f = e.target.files[0]; if (f) anexar(s.id, f); }} />
                      </label>
                      {["dp","admin"].includes(user.perfil) && (
                        <button onClick={() => cancelar(s.id)} style={{ padding:"5px 10px", borderRadius:8, border:"1px solid #EF4444", background:"#FEF2F2", color:"#DC2626", fontSize:12, cursor:"pointer", fontWeight:600 }}>🚫</button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Modal Nova Autorização */}
      <Modal open={modalNovo} onClose={() => setModalNovo(false)} title="Nova Autorização de Desconto" width={620}>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {/* Colaborador */}
          <div style={{ position: "relative" }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Colaborador *</label>
            <input value={buscaColab} onChange={e => onBusca(e.target.value)} placeholder="Buscar por nome ou matrícula..."
              style={{ width: "100%", padding: "9px 12px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, boxSizing: "border-box" }} />
            {sugestoes.length > 0 && (
              <div style={{ position: "absolute", top: "100%", left: 0, right: 0, background: "#fff", border: "1px solid #E5E7EB", borderRadius: 8, boxShadow: "0 4px 12px rgba(0,0,0,0.1)", zIndex: 100, maxHeight: 200, overflowY: "auto" }}>
                {sugestoes.map(c => (
                  <div key={c.id} onMouseDown={() => selecionarColab(c)}
                    style={{ padding: "8px 14px", cursor: "pointer", fontSize: 13, borderBottom: "1px solid #F3F4F6" }}
                    onMouseEnter={e => e.currentTarget.style.background="#F9FAFB"}
                    onMouseLeave={e => e.currentTarget.style.background="#fff"}>
                    <b>{c.chapa}</b> — {c.nome} · {c.desc_funcao || c.funcao}
                  </div>
                ))}
              </div>
            )}
            {colaboradorSel && (
              <div style={{ marginTop: 6, padding: "8px 12px", background: "#F0FDF4", borderRadius: 8, fontSize: 12, color: "#166534", border: "1px solid #BBF7D0" }}>
                ✅ <b>{colaboradorSel.nome}</b> · {colaboradorSel.descricao_filial || colaboradorSel.desc_cc || "—"} · Matrícula: {colaboradorSel.chapa} · Função: {colaboradorSel.desc_funcao || colaboradorSel.funcao || "—"} · CC: {colaboradorSel.centro_custo} — {colaboradorSel.desc_cc} · CPF: {colaboradorSel.cpf || "—"}
              </div>
            )}
          </div>

          {/* Valor e Parcelas */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Valor Total (R$) *</label>
              <input type="number" step="0.01" min="0" value={form.valor_total}
                onChange={e => setForm(f => ({ ...f, valor_total: e.target.value }))}
                placeholder="0.00"
                style={{ width: "100%", padding: "9px 12px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, boxSizing: "border-box" }} />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Nº de Parcelas *</label>
              <input type="number" min="1" max="24" value={form.num_parcelas}
                onChange={e => setForm(f => ({ ...f, num_parcelas: e.target.value }))}
                style={{ width: "100%", padding: "9px 12px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, boxSizing: "border-box" }} />
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Valor da Parcela</label>
              <input readOnly value={"R$ " + valorParc().replace(".",",")}
                style={{ width: "100%", padding: "9px 12px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, background: "#F9FAFB", color: "#6B7280", boxSizing: "border-box" }} />
            </div>
          </div>

          {/* Início do desconto */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Mês de Início do Desconto *</label>
              <select value={form.mes_inicio} onChange={e => setForm(f => ({ ...f, mes_inicio: e.target.value }))}
                style={{ width: "100%", padding: "9px 12px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, boxSizing: "border-box" }}>
                {MESES_AUTORIZACAO.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Ano de Início do Desconto *</label>
              <select value={form.ano_inicio} onChange={e => setForm(f => ({ ...f, ano_inicio: e.target.value }))}
                style={{ width: "100%", padding: "9px 12px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, boxSizing: "border-box" }}>
                {[0,1,2].map(i => <option key={i} value={anoAtual+i}>{anoAtual+i}</option>)}
              </select>
            </div>
          </div>

          {/* Data do ocorrido */}
          <div>
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Data do Ocorrido *</label>
            <input type="date" value={form.data_ocorrido} onChange={e => setForm(f => ({ ...f, data_ocorrido: e.target.value }))}
              style={{ padding: "9px 12px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13 }} />
          </div>

          {/* Descrição do prejuízo */}
          <div>
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", display: "block", marginBottom: 4 }}>Descrição do Prejuízo *</label>
            <textarea value={form.descricao_prejuizo} onChange={e => setForm(f => ({ ...f, descricao_prejuizo: e.target.value }))}
              rows={3} placeholder="Descreva o motivo do desconto..."
              style={{ width: "100%", padding: "9px 12px", border: "1px solid #D1D5DB", borderRadius: 8, fontSize: 13, resize: "vertical", boxSizing: "border-box", fontFamily: "inherit" }} />
          </div>

          {erro && <div style={{ padding: "10px 14px", background: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: 8, fontSize: 13, color: "#DC2626" }}>⚠️ {erro}</div>}

          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, paddingTop: 8, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalNovo(false)}>Cancelar</Button>
            <Button onClick={salvar}>Gerar Autorização</Button>
          </div>
        </div>
      </Modal>

      {/* Modal Visualizar Documento — tela cheia */}
      {modalDoc && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.7)", zIndex:2000, display:"flex", flexDirection:"column" }}>
          <div style={{ background:"#fff", display:"flex", alignItems:"center", justifyContent:"space-between", padding:"12px 20px", borderBottom:"1px solid #E5E7EB", flexShrink:0 }}>
            <span style={{ fontWeight:700, fontSize:15 }}>📄 Autorização de Desconto</span>
            <div style={{ display:"flex", gap:10 }}>
              <button onClick={() => {
                const html = gerarHTMLAutorizacao(modalDoc, modalDoc.colaborador, LOGO_BENEL);
                const janela = window.open("", "_blank");
                janela.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8">
                  <title>Autorização de Desconto</title>
                  <style>body{margin:0;padding:0;}@media print{@page{margin:1.5cm;size:A4;}}</style>
                </head><body>${html}</body></html>`);
                janela.document.close();
                janela.focus();
                setTimeout(() => { janela.print(); }, 500);
              }} style={{ padding:"8px 18px", background:"#0F2447", color:"#fff", border:"none", borderRadius:8, fontWeight:700, fontSize:13, cursor:"pointer" }}>
                🖨️ Imprimir / Salvar PDF
              </button>
              <button onClick={() => setModalDoc(null)} style={{ padding:"8px 16px", background:"#F3F4F6", color:"#374151", border:"1px solid #D1D5DB", borderRadius:8, fontWeight:600, fontSize:13, cursor:"pointer" }}>
                ✕ Fechar
              </button>
            </div>
          </div>
          <div style={{ flex:1, overflowY:"auto", padding:"24px", background:"#F8FAFC" }}>
            <div style={{ maxWidth:820, margin:"0 auto", background:"#fff", borderRadius:8, boxShadow:"0 2px 12px rgba(0,0,0,0.08)", padding:"0" }}
              dangerouslySetInnerHTML={{ __html: gerarHTMLAutorizacao(modalDoc, modalDoc.colaborador, LOGO_BENEL) }}
            />
          </div>
        </div>
      )}
    </div>
  );
}

function Ocorrencias({ user, colaboradores }) {
  const [lista, setLista] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalForm, setModalForm] = useState(false);
  const [modalPDF, setModalPDF] = useState(null);
  const [filtros, setFiltros] = useState({ tipo: "", colaborador_id: "", data_inicio: "", data_fim: "" });
  const [form, setForm] = useState({
    tipo: "ADVERTENCIA", colaborador_id: "", chapa: "", nome_colaborador: "",
    cpf: "", secao: "", admissao: "",
    motivo: "", data_ocorrencia: "", data_inicio: "", dias_suspensao: "",
    anexo_nome: "", anexo_base64: ""
  });
  const [salvando, setSalvando] = useState(false);
  const [exportando, setExportando] = useState(false);
  const [msg, setMsg] = useState(null);

  // Filtros inline da tabela
  const [fColab,  setFColab]  = useState("");
  const [fTipo,   setFTipo]   = useState("");
  const [fGestor, setFGestor] = useState("");
  const [fStatus, setFStatus] = useState("");
  const [fData,   setFData]   = useState("");
  const norm = s => (s||"").toLowerCase();

  const listaFiltrada = lista
    .filter(o => !fColab  || norm(o.nome_colaborador).includes(norm(fColab)) || (o.chapa||"").includes(fColab))
    .filter(o => !fTipo   || o.tipo === fTipo)
    .filter(o => !fGestor || norm(o.gestor_nome).includes(norm(fGestor)))
    .filter(o => !fStatus || o.status === fStatus)
    .filter(o => !fData || fmtDateLocal(o.data_ocorrencia) === fData);

  const carregarOcorrencias = async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams(Object.fromEntries(Object.entries(filtros).filter(([,v]) => v))).toString();
      const data = await api.listarOcorrencias(qs);
      setLista(Array.isArray(data) ? data : []);
    } catch (e) {
      setMsg({ tipo: "erro", texto: "Erro ao carregar: " + e.message });
    } finally { setLoading(false); }
  };

  useEffect(() => { carregarOcorrencias(); }, []);

  const [colabSel, setColabSel] = useState(null);

  const selecionarColaborador = (colab) => {
    const admissao = colab.data_admissao || colab.admissao || "";
    setColabSel(colab);
    setForm(f => ({
      ...f,
      colaborador_id: colab.id,
      chapa: colab.chapa,
      nome_colaborador: colab.nome,
      cpf: colab.cpf || "",
      secao: colab.desc_cc || colab.secao || "",
      admissao: admissao ? admissao.split("T")[0] : "",
    }));
  };

  const calcularDataFim = () => {
    if (!form.data_inicio || !form.dias_suspensao) return "";
    const d = new Date(form.data_inicio);
    d.setDate(d.getDate() + parseInt(form.dias_suspensao) - 1);
    return d.toISOString().split("T")[0];
  };

  const salvar = async () => {
    if (!form.colaborador_id) { setMsg({ tipo: "erro", texto: "Selecione o colaborador." }); return; }
    if (!form.motivo.trim())  { setMsg({ tipo: "erro", texto: "Informe o motivo." }); return; }
    if (!form.data_ocorrencia) { setMsg({ tipo: "erro", texto: "Informe a data." }); return; }
    if (form.tipo === "SUSPENSAO" && (!form.data_inicio || !form.dias_suspensao)) {
      setMsg({ tipo: "erro", texto: "Informe data de início e quantidade de dias da suspensão." }); return;
    }
    setSalvando(true);
    try {
      await api.criarOcorrencia(form);
      setMsg({ tipo: "ok", texto: "Ocorrência registrada com sucesso!" });
      setModalForm(false);
      setForm({ tipo: "ADVERTENCIA", colaborador_id: "", chapa: "", nome_colaborador: "", motivo: "", data_ocorrencia: "", data_inicio: "", dias_suspensao: "" });
      carregarOcorrencias();
    } catch (e) {
      setMsg({ tipo: "erro", texto: e.message });
    } finally { setSalvando(false); }
  };

  const cancelarOcorrencia = async (id) => {
    if (!window.confirm("Deseja cancelar esta ocorrência?")) return;
    try {
      await api.cancelarOcorrencia(id);
      setMsg({ tipo: "ok", texto: "Ocorrência cancelada." });
      carregarOcorrencias();
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
  };

  const exportarCSV = async () => {
    setExportando(true);
    try {
      const url = api.exportarOcorrenciasUrl();
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${api.getToken()}` } });
      if (!resp.ok) { const d = await resp.json(); throw new Error(d.message); }
      const blob = await resp.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `anotacoes_rm_${new Date().toISOString().split("T")[0]}.txt`;
      a.click();
      URL.revokeObjectURL(a.href);
      setMsg({ tipo: "ok", texto: "Exportação concluída! Registros marcados como exportados." });
      carregarOcorrencias();
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
    finally { setExportando(false); }
  };

  const pendentesExportacao = lista.filter(o => o.status !== "CANCELADO").length;

  const gerarPDF = (oc) => setModalPDF(oc);

  const formatarData = (d) => {
    if (!d) return "—";
    return new Date(d).toLocaleDateString("pt-BR", { timeZone: "UTC" });
  };

  return (
    <div style={{ padding: 28 }}>
      {/* Cabeçalho */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <p style={{ margin: "4px 0 0", fontSize: 12, color: "#6B7280" }}>Registro de ocorrências disciplinares</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          {(user.perfil === "dp" || user.perfil === "admin") && (
            <Button variant="secondary" onClick={exportarCSV} disabled={exportando || pendentesExportacao === 0}>
              {exportando ? "Exportando..." : `↓ Exportar RM (${pendentesExportacao})`}
            </Button>
          )}
          <Button onClick={() => { setModalForm(true); setMsg(null); }}>+ Nova Ocorrência</Button>
        </div>
      </div>

      {/* Mensagem */}
      {msg && (
        <div style={{
          marginBottom: 16, padding: "10px 16px", borderRadius: 8, fontSize: 13,
          background: msg.tipo === "ok" ? "#D1FAE5" : "#FEE2E2",
          color: msg.tipo === "ok" ? "#065F46" : "#991B1B",
          border: `1px solid ${msg.tipo === "ok" ? "#6EE7B7" : "#FCA5A5"}`
        }}>
          {msg.tipo === "ok" ? "✅" : "❌"} {msg.texto}
        </div>
      )}

      {/* Filtros */}
      <Card style={{ marginBottom: 16, padding: "14px 18px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr auto", gap: 12, alignItems: "flex-end" }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 11, fontWeight: 600, color: "#374151" }}>Tipo</label>
            <select value={filtros.tipo} onChange={e => setFiltros(f => ({ ...f, tipo: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "7px 10px", fontSize: 12, fontFamily: "inherit" }}>
              <option value="">Todos</option>
              <option value="ADVERTENCIA">Advertência</option>
              <option value="SUSPENSAO">Suspensão</option>
            </select>
          </div>
          <Input label="Data início" value={filtros.data_inicio} onChange={v => setFiltros(f => ({ ...f, data_inicio: v }))} type="date" />
          <Input label="Data fim" value={filtros.data_fim} onChange={v => setFiltros(f => ({ ...f, data_fim: v }))} type="date" />
          <div /> 
          <Button variant="secondary" onClick={carregarOcorrencias}>🔍 Filtrar</Button>
        </div>
      </Card>

      {/* Tabela */}
      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Colaborador", "Tipo", "Data", "Período/Dias", "Gestor", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 14px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding:"5px 8px" }}><input value={fColab} onChange={e=>setFColab(e.target.value)} placeholder="🔍 Colaborador/Chapa" style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }}><select value={fTipo} onChange={e=>setFTipo(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="ADVERTENCIA">Advertência</option><option value="SUSPENSAO">Suspensão</option></select></th>
              <th style={{ padding:"5px 8px" }}>
                <input type="date" value={fData} onChange={e=>setFData(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} />
              </th>
              <th style={{ padding:"5px 8px" }} />
              <th style={{ padding:"5px 8px" }}><input value={fGestor} onChange={e=>setFGestor(e.target.value)} placeholder="🔍 Gestor" style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }}><select value={fStatus} onChange={e=>setFStatus(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}><option value="">Todos</option><option value="ATIVO">Ativo</option><option value="EXPORTADO">Exportado</option><option value="CANCELADO">Cancelado</option></select></th>
              <th style={{ padding:"5px 8px" }}><button onClick={()=>{setFColab("");setFTipo("");setFGestor("");setFStatus("");setFData("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Carregando...</td></tr>
            ) : listaFiltrada.length === 0 ? (
              <tr><td colSpan={7} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhuma ocorrência encontrada</td></tr>
            ) : listaFiltrada.map((oc, i) => {
              const btnBase = { padding:"5px 10px", borderRadius:6, fontSize:11, fontWeight:600, cursor:"pointer", whiteSpace:"nowrap", fontFamily:"inherit" };
              const trunc3 = (nome) => (nome || "").split(" ").slice(0, 3).join(" ").toUpperCase();
              return (
              <tr key={oc.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "10px 14px" }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: "#111827" }}>{oc.nome_colaborador}</div>
                  <div style={{ fontSize: 10, color: "#6B7280" }}>Chapa: {oc.chapa}</div>
                </td>
                <td style={{ padding: "10px 14px" }}>
                  <span style={{
                    padding: "3px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600,
                    background: oc.tipo === "ADVERTENCIA" ? "#FEF3C7" : "#FEE2E2",
                    color: oc.tipo === "ADVERTENCIA" ? "#92400E" : "#991B1B",
                    whiteSpace: "nowrap", display: "inline-block"
                  }}>
                    {oc.tipo === "ADVERTENCIA" ? "⚠️ Advertência" : "🚫 Suspensão"}
                  </span>
                </td>
                <td style={{ padding: "10px 14px", fontSize: 12, color: "#374151" }}>{formatarData(oc.data_ocorrencia)}</td>
                <td style={{ padding: "10px 14px", fontSize: 12, color: "#374151" }}>
                  {oc.tipo === "SUSPENSAO"
                    ? <span>{formatarData(oc.data_inicio)} → {formatarData(oc.data_fim)}<br/><b>{oc.dias_suspensao} dia(s)</b></span>
                    : "—"}
                </td>
                <td style={{ padding: "10px 14px", fontSize: 12, color: "#374151" }}>{trunc3(oc.gestor_nome)}</td>
                <td style={{ padding: "10px 14px" }}>
                  <span style={{
                    padding: "3px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600,
                    background: oc.status === "ATIVO" ? "#D1FAE5" : oc.status === "EXPORTADO" ? "#DBEAFE" : "#FEE2E2",
                    color: oc.status === "ATIVO" ? "#065F46" : oc.status === "EXPORTADO" ? "#1D4ED8" : "#991B1B"
                  }}>{oc.status}</span>
                </td>
                <td style={{ padding: "10px 14px" }}>
                  <div style={{ display:"flex", gap:4, alignItems:"center", flexWrap:"nowrap" }}>
                    <button onClick={() => gerarPDF(oc)} style={{ ...btnBase, border:"1px solid #D1D5DB", background:"#fff", color:"#374151" }}>📄 PDF</button>
                    <label style={{ ...btnBase, border:"1px solid #10B981", background:"#F0FDF4", color:"#065F46", display:"inline-block" }}>
                      📎 {oc.anexo_nome ? "Substituir" : "Anexar"}
                      <input type="file" accept=".pdf,.jpg,.jpeg,.png" style={{ display:"none" }}
                        onChange={async (e) => {
                          const file = e.target.files[0]; if (!file) return;
                          if (file.size > 5*1024*1024) { alert("Arquivo muito grande (max 5MB)"); return; }
                          const reader = new FileReader();
                          reader.onload = async (ev) => {
                            try {
                              await api.addAnexoOcorrencia(oc.id, { nome_arquivo: file.name, tipo_arquivo: file.type, dados_base64: ev.target.result });
                              alert("Anexo adicionado com sucesso!");
                            } catch(err) { alert(err.message); }
                          };
                          reader.readAsDataURL(file);
                        }} />
                    </label>
                    {oc.status === "ATIVO" && (
                      <button onClick={() => cancelarOcorrencia(oc.id)} style={{ ...btnBase, border:"1px solid #EF4444", background:"#FEF2F2", color:"#DC2626" }}>🚫</button>
                    )}
                  </div>
                </td>
              </tr>
              );
            })}
          </tbody>
        </table>
      </Card>

      {/* Modal Nova Ocorrência */}
      <Modal open={modalForm} onClose={() => setModalForm(false)} title="Registrar Ocorrência Disciplinar" width={600}>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {msg && modalForm && (
            <div style={{ padding: "8px 12px", borderRadius: 8, fontSize: 12, background: "#FEE2E2", color: "#991B1B" }}>❌ {msg.texto}</div>
          )}

          {/* Tipo */}
          <div style={{ display: "flex", gap: 10 }}>
            {["ADVERTENCIA", "SUSPENSAO"].map(t => (
              <button key={t} onClick={() => setForm(f => ({ ...f, tipo: t }))} style={{
                flex: 1, padding: "12px", borderRadius: 10, cursor: "pointer", fontFamily: "inherit",
                border: form.tipo === t ? "2px solid #1B3A6B" : "2px solid #E5E7EB",
                background: form.tipo === t ? "#EFF6FF" : "#FAFAFA",
                color: form.tipo === t ? "#1B3A6B" : "#6B7280",
                fontWeight: form.tipo === t ? 700 : 400, fontSize: 13
              }}>
                {t === "ADVERTENCIA" ? "⚠️ Advertência" : "🚫 Suspensão"}
              </button>
            ))}
          </div>

          {/* Colaborador */}
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>Colaborador *</label>
            <ColabSelect colaboradores={colaboradores} onSelect={selecionarColaborador} selecionado={form.nome_colaborador} />
            {colabSel && (
              <div style={{ marginTop: 4, padding: "8px 12px", background: "#F0FDF4", borderRadius: 8, fontSize: 12, color: "#166534", border: "1px solid #BBF7D0" }}>
                ✅ <b>{colabSel.nome}</b> · {colabSel.descricao_filial || colabSel.desc_cc || "—"} · Matrícula: {colabSel.chapa} · Função: {colabSel.desc_funcao || colabSel.funcao || "—"} · CC: {colabSel.centro_custo} — {colabSel.desc_cc}
              </div>
            )}
          </div>

          {/* Campos adicionais */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <Input label="CPF" value={form.cpf} onChange={v => setForm(f => ({ ...f, cpf: v }))} placeholder="000.000.000-00" />
            <Input label="Seção / Departamento" value={form.secao} onChange={v => setForm(f => ({ ...f, secao: v }))} placeholder="Ex: Logística" />
            <Input label="Data de Admissão" value={form.admissao ? form.admissao.split("T")[0] : ""} onChange={v => setForm(f => ({ ...f, admissao: v }))} type="date" />
          </div>

          {/* Motivo */}
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>Motivo *</label>
            <textarea value={form.motivo} onChange={e => setForm(f => ({ ...f, motivo: e.target.value }))}
              placeholder="Descreva detalhadamente o motivo da ocorrência..." rows={4}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", resize: "vertical" }} />
          </div>

          {/* Campos por tipo */}
          {form.tipo === "ADVERTENCIA" ? (
            <Input label="Data da Advertência *" value={form.data_ocorrencia}
              onChange={v => setForm(f => ({ ...f, data_ocorrencia: v }))} type="date" required />
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
              <Input label="Data de Início *" value={form.data_inicio}
                onChange={v => setForm(f => ({ ...f, data_inicio: v, data_ocorrencia: v }))} type="date" required />
              <Input label="Quantidade de Dias *" value={form.dias_suspensao}
                onChange={v => setForm(f => ({ ...f, dias_suspensao: v }))} type="number" placeholder="Ex: 3" required />
              <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>Data de Fim</label>
                <div style={{ padding: "8px 12px", border: "1px solid #E5E7EB", borderRadius: 8, fontSize: 13, background: "#F9FAFB", color: "#374151" }}>
                  {calcularDataFim() ? new Date(calcularDataFim()).toLocaleDateString("pt-BR", { timeZone: "UTC" }) : "—"}
                </div>
              </div>
            </div>
          )}

          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end", paddingTop: 6, borderTop: "1px solid #F3F4F6" }}>
            <Button variant="secondary" onClick={() => setModalForm(false)}>Cancelar</Button>
            <Button onClick={salvar} disabled={salvando}>{salvando ? "Salvando..." : "Registrar Ocorrência"}</Button>
          </div>
        </div>
      </Modal>

      {/* Modal PDF */}
      {modalPDF && (
        <Modal open={!!modalPDF} onClose={() => setModalPDF(null)}
          title={`Documento — ${modalPDF.tipo === "ADVERTENCIA" ? "Advertência" : "Suspensão"}`} width={700}>
          <PDFOcorrencia oc={modalPDF} />
        </Modal>
      )}
    </div>
  );
}

// ─── SELECT DE COLABORADOR COM AUTOCOMPLETE ───────────────────────────────────
function ColabSelect({ colaboradores, onSelect, selecionado }) {
  const [busca, setBusca] = useState(selecionado || "");
  const [sugestoes, setSugestoes] = useState([]);

  const normalizar = (s) =>
    (s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();

  const onBusca = (v) => {
    setBusca(v);
    if (v.length >= 2) {
      const termo = normalizar(v);
      setSugestoes(
        colaboradores
          .filter(c => c.cod_situacao !== "D")
          .filter(c =>
            normalizar(c.nome).includes(termo) ||
            (c.chapa || "").includes(v.trim())
          )
          .slice(0, 10)
      );
    } else { setSugestoes([]); }
  };

  return (
    <div style={{ position: "relative" }}>
      <input value={busca} onChange={e => onBusca(e.target.value)}
        placeholder="Digite nome ou matrícula..."
        style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", boxSizing: "border-box" }} />
      {sugestoes.length > 0 && (
        <div style={{ position: "absolute", top: "100%", left: 0, right: 0, zIndex: 100, background: "#fff", border: "1px solid #D1D5DB", borderRadius: 8, boxShadow: "0 4px 16px rgba(0,0,0,0.12)", maxHeight: 200, overflowY: "auto" }}>
          {sugestoes.map(c => (
            <div key={c.id} onMouseDown={() => { onSelect(c); setBusca(c.nome); setSugestoes([]); }}
              style={{ padding: "9px 14px", fontSize: 13, cursor: "pointer", borderBottom: "1px solid #F3F4F6", display: "flex", gap: 10 }}>
              <span style={{ fontFamily: "monospace", fontSize: 11, color: "#6B7280", minWidth: 50 }}>{c.chapa}</span>
              <span style={{ fontWeight: 600, color: "#111827" }}>{c.nome}</span>
              <span style={{ fontSize: 11, color: "#9CA3AF", marginLeft: "auto" }}>{c.funcao}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── TEMPLATE PDF DE OCORRÊNCIA — fiel ao modelo Benel ───────────────────────
function PDFOcorrencia({ oc }) {
  const isAdv = oc.tipo === "ADVERTENCIA";
  const MESES_EXT = ["Janeiro","Fevereiro","Março","Abril","Maio","Junho","Julho","Agosto","Setembro","Outubro","Novembro","Dezembro"];
  const fmt = (d) => {
    if (!d) return "___ de ________ de ____";
    const dt = new Date(d);
    const dia = dt.getUTCDate();
    const mes = MESES_EXT[dt.getUTCMonth()];
    const ano = dt.getUTCFullYear();
    return `${dia} de ${mes} de ${ano}`;
  };
  const hoje = new Date().toLocaleDateString("pt-BR");

  const imprimir = () => {
    const conteudo = document.getElementById("pdf-ocorrencia-benel").innerHTML;
    const win = window.open("", "_blank");
    win.document.write(`<!DOCTYPE html>
<html><head><title>${isAdv ? "Advertência" : "Suspensão"} — ${oc.nome_colaborador}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: Arial, sans-serif; font-size: 13px; color: #000; padding: 40px 50px; line-height: 1.5; }
  .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
  .logo-area img { height: 52px; }
  .titulo { font-size: 20px; font-weight: 900; text-transform: uppercase; letter-spacing: 2px; }
  .ficha { border: 1.5px solid #000; padding: 10px 14px; margin-bottom: 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 4px 20px; }
  .ficha span { font-size: 12px; }
  .suspensao-dias { font-size: 14px; font-weight: 700; margin-bottom: 16px; }
  .motivo-titulo { font-size: 18px; font-weight: 900; margin: 20px 0 10px; }
  .motivo-texto { text-align: justify; line-height: 1.7; margin-bottom: 20px; }
  .data-centro { text-align: center; margin: 30px 0 20px; font-size: 14px; }
  .assinaturas { margin-top: 40px; }
  .ass-empresa { text-align: center; margin-bottom: 30px; }
  .ass-linha { border-top: 1px solid #000; width: 320px; margin: 0 auto 6px; padding-top: 6px; font-weight: 700; font-size: 13px; }
  .ass-sublabel { font-size: 12px; color: #333; text-align: center; }
  .testemunhas { display: flex; justify-content: space-between; margin-top: 30px; }
  .testemunha { display: flex; align-items: flex-end; gap: 8px; font-size: 13px; }
  .testemunha-linha { border-bottom: 1px solid #000; width: 200px; height: 20px; }
  @media print { body { padding: 20px 30px; } }
</style></head>
<body>${conteudo}</body></html>`);
    win.document.close();
    setTimeout(() => win.print(), 400);
  };

  return (
    <div>
      <div id="pdf-ocorrencia-benel" style={{ fontFamily: "Arial, sans-serif", fontSize: 13, color: "#000", lineHeight: 1.5, background: "#fff" }}>

        {/* Cabeçalho: Logo + Título */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <img src={LOGO_BENEL} alt="Benel" style={{ height: 52 }} />
          <div style={{ fontSize: 20, fontWeight: 900, textTransform: "uppercase", letterSpacing: 2, textAlign: "right" }}>
            {isAdv ? "ADVERTÊNCIA DISCIPLINAR" : "SUSPENSÃO DISCIPLINAR"}
          </div>
        </div>

        {/* Ficha do colaborador */}
        <div style={{ border: "1.5px solid #000", padding: "10px 14px", marginBottom: 20, display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 20px" }}>
          <div style={{ fontWeight: 700 }}>Sr. (a) {oc.nome_colaborador}</div>
          <div style={{ fontWeight: 700 }}>{oc.chapa}{oc.secao ? `    SEÇÃO : ${oc.secao}` : ""}</div>
          <div>C.P.F : {oc.cpf || "___.___.___-__"}</div>
          <div>Admissão: {oc.admissao || oc.data_admissao ? fmt(oc.admissao || oc.data_admissao) : "__/__/____"}</div>
        </div>

        {/* Linha de tipo */}
        {isAdv ? (
          <div style={{ marginBottom: 16, fontWeight: 600 }}>Advertido Escrito:</div>
        ) : (
          <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 16 }}>
            Suspensão de: {oc.dias_suspensao} DIA(S)
          </div>
        )}

        {/* Motivo */}
        <div style={{ fontSize: 18, fontWeight: 900, margin: "20px 0 10px" }}>MOTIVO:</div>
        <div style={{ textAlign: "justify", lineHeight: 1.7, marginBottom: 24 }}>{oc.motivo}</div>

        {/* Texto legal */}
        {isAdv ? (
          <div style={{ textAlign: "justify", fontSize: 12, color: "#333", marginBottom: 20 }}>
            Esta advertência é aplicada em conformidade com as normas internas da empresa e a Consolidação das Leis do Trabalho (CLT).
            Informamos que a reincidência poderá acarretar em penalidades mais severas, incluindo suspensão ou rescisão por justa causa.
          </div>
        ) : (
          <div style={{ textAlign: "justify", fontSize: 12, color: "#333", marginBottom: 20 }}>
            A presente suspensão disciplinar refere-se ao período de {fmt(oc.data_inicio)} a {fmt(oc.data_fim)}, totalizando {oc.dias_suspensao} dia(s),
            aplicada em conformidade com o Art. 474 da CLT e as normas internas da empresa.
            Durante o período de suspensão o colaborador não deverá comparecer ao trabalho, não fazendo jus à remuneração dos dias suspensos.
          </div>
        )}

        {/* Data */}
        <div style={{ textAlign: "center", margin: "28px 0 20px", fontSize: 14 }}>
          {fmt(oc.data_ocorrencia)}
        </div>

        {/* Assinatura empresa */}
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <img src={ASSINATURA_BENEL} alt="Assinatura Benel" style={{ height: 80, display: "block", margin: "0 auto 4px", objectFit: "contain" }} />
          <div style={{ borderTop: "1px solid #000", width: 320, margin: "0 auto 6px", paddingTop: 6, fontWeight: 700 }}>
            BENEL TRANSPORTES E LOGISTICA LTDA-ES
          </div>
        </div>

        {/* Assinatura colaborador */}
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div style={{ height: 60 }} />
          <div style={{ borderTop: "1px solid #000", width: 320, margin: "0 auto 6px", paddingTop: 6, fontWeight: 700 }}>
            {oc.nome_colaborador}
          </div>
          <div style={{ fontSize: 12 }}>Assinatura do Empregado</div>
        </div>

        {/* Anexo no PDF */}
        {oc.anexo_base64 && (
          <div style={{ marginTop: 20, textAlign: "center" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#374151", marginBottom: 8 }}>📎 ANEXO: {oc.anexo_nome}</div>
            <img src={oc.anexo_base64} alt="Anexo" style={{ maxWidth: "100%", maxHeight: 300, border: "1px solid #E5E7EB", borderRadius: 4 }} />
          </div>
        )}

        {/* Testemunhas */}
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 20 }}>
          <div style={{ fontSize: 13 }}>
            Testemunha 1 <span style={{ display: "inline-block", borderBottom: "1px solid #000", width: 180, marginLeft: 4 }}>&nbsp;</span>
          </div>
          <div style={{ fontSize: 13 }}>
            Testemunha 2 <span style={{ display: "inline-block", borderBottom: "1px solid #000", width: 180, marginLeft: 4 }}>&nbsp;</span>
          </div>
        </div>

        {/* Anexo no PDF */}
        {oc.anexo_base64 && (
          <div style={{ marginTop: 24, borderTop: "1px solid #E5E7EB", paddingTop: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#374151", marginBottom: 8 }}>📎 ANEXO: {oc.anexo_nome}</div>
            <img src={oc.anexo_base64} alt="Anexo" style={{ maxWidth: "100%", maxHeight: 400, border: "1px solid #E5E7EB", borderRadius: 4 }} />
          </div>
        )}

      </div>

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, paddingTop: 16, borderTop: "1px solid #F3F4F6", marginTop: 20 }}>
        <Button variant="primary" onClick={imprimir}>🖨 Imprimir / Salvar PDF</Button>
      </div>
    </div>
  );
}

// ─── DESLIGAMENTOS ────────────────────────────────────────────────────────────
const TIPOS_DESL = [
  { value: "aviso_trabalhado",    label: "Aviso Prévio Trabalhado" },
  { value: "aviso_indenizado",    label: "Aviso Prévio Indenizado" },
  { value: "pedido_demissao",     label: "Pedido de Demissão" },
  { value: "termino_contrato",    label: "Término de Contrato" },
  { value: "antecipacao_contrato",label: "Antecipação de Término de Contrato" },
];

const STATUS_DESL = {
  rascunho:           { label: "Rascunho",           color: "#6B7280" },
  pendente_superior:  { label: "Pend. Superior",     color: "#F59E0B" },
  pendente_dp:        { label: "Pend. DP",           color: "#3B82F6" },
  aprovado:           { label: "Aprovado",           color: "#10B981" },
  reprovado:          { label: "Reprovado",          color: "#EF4444" },
  ajuste_solicitado:  { label: "Ajuste Solicitado",  color: "#8B5CF6" },
  finalizado:         { label: "Finalizado",         color: "#0F2447" },
  cancelado:          { label: "Cancelado",          color: "#9CA3AF" },
};

const ALCADA_DESL = {
  pendente_superior:  ["superior", "dp", "admin", "presidente"],
  // 2ª alçada — descomente quando quiser ativar:
  // pendente_dp:     ["dp", "admin"],
  ajuste_solicitado:  ["gestor", "dp", "admin", "presidente"],
};

function Desligamentos({ user, colaboradores, api, recarregarDados }) {
  const [lista,          setLista]          = useState([]);
  const [modalNovo,      setModalNovo]      = useState(false);
  const [modalDetalhe,   setModalDetalhe]   = useState(null);
  const [modalAcao,      setModalAcao]      = useState(null);
  const [carregando,     setCarregando]     = useState(true);
  const [salvando,       setSalvando]       = useState(false);
  const [erro,           setErro]           = useState("");
  const [modalPDF,       setModalPDF]       = useState(null);
  const [modalAnexoPedido, setModalAnexoPedido] = useState(null);

  const FORM_VAZIO = {
    colaborador_id: "", tipo: "", data_desligamento: "",
    data_aviso: "", reducao_jornada: false,
    justificativa: "", observacoes: "",
    pedido_anexo_nome: "", pedido_anexo_base64: "",
  };
  const [form, setForm] = useState(FORM_VAZIO);
  const [colaboradorSel, setColaboradorSel] = useState(null);
  const [buscaColab, setBuscaColab] = useState("");
  const [sugestoesColab, setSugestoesColab] = useState([]);

  const carregar = async () => {
    setCarregando(true);
    try {
      const r = await api.listarDesligamentos("");
      setLista(Array.isArray(r) ? r : (r.data || []));
    } catch (e) { setErro(e.message); }
    finally { setCarregando(false); }
  };

  useEffect(() => { carregar(); }, []);

  const normalizar = (s) =>
    (s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();

  const buscaTimer = useRef(null);

  const onBuscaColab = (v) => {
    setBuscaColab(v);
    setForm(f => ({ ...f, colaborador_id: "" }));
    setColaboradorSel(null);
    setBloqueioColab(null);

    if (v.length < 2) { setSugestoesColab([]); return; }

    const termo = normalizar(v);

    // Resultado local imediato como preview
    const local = colaboradores
      .filter(c => c.cod_situacao !== "D")
      .filter(c =>
        normalizar(c.nome).includes(termo) ||
        (c.chapa || "").includes(v.trim())
      )
      .slice(0, 15);
    setSugestoesColab(local);

    // Busca na API com debounce (sempre — não depende do resultado local)
    clearTimeout(buscaTimer.current);
    buscaTimer.current = setTimeout(async () => {
      try {
        const resultado = await api.buscarColaboradores(v.trim());
        const filtrado = (Array.isArray(resultado) ? resultado : [])
          .filter(c => c.cod_situacao !== "D")
          .slice(0, 15);
        if (filtrado.length > 0) setSugestoesColab(filtrado);
      } catch (_) { /* mantém o resultado local */ }
    }, 300);
  };

  const [validandoColab, setValidandoColab] = useState(false);
  const [bloqueioColab,  setBloqueioColab]  = useState(null); // { motivo, mensagem }

  const selecionarColab = async (c) => {
    setColaboradorSel(c);
    setBuscaColab(c.nome);
    setForm(f => ({ ...f, colaborador_id: c.id }));
    setSugestoesColab([]);
    setBloqueioColab(null);

    // Validação extra no frontend antes de chamar API (rápida, sem rede)
    if (c.cod_situacao === "D") {
      setBloqueioColab({
        motivo: "situacao",
        mensagem: "Colaborador não pode ser selecionado para desligamento, pois já consta com situação Demitido.",
      });
      return;
    }

    // Validação via backend (estabilidade e outros bloqueios persistidos)
    setValidandoColab(true);
    try {
      const v = await api.validarColaboradorDesligamento(c.id);
      if (!v.apto) {
        setBloqueioColab({ motivo: v.motivo, mensagem: v.mensagem });
      }
    } catch (_) {
      // Se API falhar, aplica validação local de estabilidade como fallback
      if (c.data_fim_estabilidade) {
        const fimEstab = new Date(c.data_fim_estabilidade.split("T")[0]);
        const hoje = new Date(); hoje.setHours(0,0,0,0);
        if (fimEstab >= hoje) {
          const fmtBR = (d) => d.toLocaleDateString("pt-BR", { timeZone: "UTC" });
          setBloqueioColab({
            motivo: "estabilidade",
            mensagem: `Este colaborador não pode ser desligado, pois possui estabilidade ativa: ${c.descricao_estabilidade || "Estabilidade"}. A estabilidade encerra em ${fmtBR(fimEstab)}.`,
          });
        }
      }
    } finally {
      setValidandoColab(false);
    }
  };

  const validarForm = () => {
    if (!form.colaborador_id)    return "Selecione um colaborador.";

    // Bloquear se houver bloqueio identificado ao selecionar o colaborador
    if (bloqueioColab) return bloqueioColab.mensagem;

    // Bloquear desligamento de colaborador com estabilidade ativa (fallback local)
    if (colaboradorSel?.data_fim_estabilidade) {
      const fimEstab = new Date(colaboradorSel.data_fim_estabilidade.split("T")[0]);
      const hoje = new Date(); hoje.setHours(0,0,0,0);
      if (fimEstab >= hoje) {
        const fmtBR = (d) => d.toLocaleDateString("pt-BR", { timeZone: "UTC" });
        return (
          "Solicitação não permitida.\n" +
          "Este colaborador possui estabilidade ativa e não pode ser desligado.\n\n" +
          "Detalhes da estabilidade:\n" +
          "• Motivo: " + (colaboradorSel.descricao_estabilidade || "—") + "\n" +
          "• Válida até: " + fmtBR(fimEstab)
        );
      }
    }
    if (!form.tipo)              return "Selecione o tipo de desligamento.";
    if (!form.data_desligamento) return "Informe a data de desligamento.";
    if (form.tipo === "antecipacao_contrato" && !form.justificativa)
      return "Justificativa obrigatória para antecipação de contrato.";

    if (["aviso_trabalhado","aviso_indenizado"].includes(form.tipo)) {
      if (colaboradorSel?.data_admissao) {
        const admissao = new Date(colaboradorSel.data_admissao.split("T")[0]);
        const d90  = new Date(admissao); d90.setDate(d90.getDate() + 89);
        const d45  = new Date(admissao); d45.setDate(d45.getDate() + 44);
        const hoje = new Date(); hoje.setHours(0,0,0,0);
        const fmtBR = (d) => d.toLocaleDateString("pt-BR", { timeZone: "UTC" });
        if (hoje <= d90) {
          return (
            "Solicitação não permitida para este colaborador.\n" +
            "Colaboradores em contrato de experiência (até 90 dias) não podem receber Aviso Prévio.\n\n" +
            "Detalhes do contrato:\n" +
            "• Início: " + fmtBR(admissao) + "\n" +
            "• Fim 1º período (admissão + 44 dias): " + fmtBR(d45) + "\n" +
            "• Fim 2º período (admissão + 89 dias): " + fmtBR(d90) + "\n\n" +
            "Use \"Término de Contrato\" ou \"Antecipação de Término\"."
          );
        }
      }
    }

    if (form.tipo === "termino_contrato" && colaboradorSel?.data_admissao) {
      const admissao = new Date(colaboradorSel.data_admissao.split("T")[0]);
      const d90  = new Date(admissao); d90.setDate(d90.getDate() + 89);
      const d45  = new Date(admissao); d45.setDate(d45.getDate() + 44);
      const hoje = new Date(); hoje.setHours(0,0,0,0);
      const fmtBR = (d) => d.toLocaleDateString("pt-BR", { timeZone: "UTC" });
      if (hoje > d90) {
        return (
          "Solicitação não permitida.\n" +
          "O colaborador já ultrapassou a data limite do contrato de experiência.\n\n" +
          "Detalhes do contrato:\n" +
          "• Início: " + fmtBR(admissao) + "\n" +
          "• Fim 1º período (admissão + 44 dias): " + fmtBR(d45) + "\n" +
          "• Fim 2º período (admissão + 89 dias): " + fmtBR(d90)
        );
      }
    }
    return null;
  };

  // Calcular data aviso (30 dias antes)
  const calcularDataAviso = (dataDesl) => {
    if (!dataDesl) return "";
    const d = new Date(dataDesl);
    d.setDate(d.getDate() - 30);
    return d.toISOString().split("T")[0];
  };

  const calcularDataTermino = (dataAdmissao) => {
    if (!dataAdmissao) return "";
    const admissao = new Date(dataAdmissao.split("T")[0]);
    const d45 = new Date(admissao); d45.setDate(d45.getDate() + 44);
    const d90 = new Date(admissao); d90.setDate(d90.getDate() + 89);
    const hoje = new Date(); hoje.setHours(0,0,0,0);
    return (hoje > d45 ? d90 : d45).toISOString().split("T")[0];
  };

  const salvar = async (enviar = false) => {
    const errVal = validarForm();
    if (errVal) { setErro(errVal); return; }
    setSalvando(true); setErro("");
    try {
      const payload = { ...form };
      if (form.tipo === "aviso_trabalhado" && !form.data_aviso)
        payload.data_aviso = calcularDataAviso(form.data_desligamento);

      const r = await api.criarDesligamento(payload);
      const id = r.id || r.data?.id;

      // Pedido de demissão: envia e aprova automaticamente (não precisa de aprovação)
      if (form.tipo === "pedido_demissao") {
        await api.enviarDesligamento(id);
        await api.aprovarDesligamento(id, "aprovar", "Aprovado automaticamente — pedido de demissão do colaborador");
      } else if (enviar) {
        await api.enviarDesligamento(id);
      }

      await carregar();
      setModalNovo(false);
      setForm(FORM_VAZIO);
      setColaboradorSel(null);
      setBuscaColab("");
    } catch (e) { setErro(e.message); }
    finally { setSalvando(false); }
  };

  const executarAcao = async () => {
    if (!modalAcao) return;
    setSalvando(true);
    try {
      await api.aprovarDesligamento(modalAcao.id, modalAcao.acao, modalAcao.observacao);
      await carregar();
      setModalAcao(null);
    } catch (e) { setErro(e.message); }
    finally { setSalvando(false); }
  };

  const abrirDetalhe = async (id) => {
    try {
      const r = await api.buscarDesligamento(id);
      setModalDetalhe(r);
    } catch (e) { setErro(e.message); }
  };

  const [fColab,   setFColab]   = useState("");
  const [fTipo,    setFTipo]    = useState("");
  const [fStatus2, setFStatus2] = useState("");
  const [fGestor2, setFGestor2] = useState("");
  const [fDataD,   setFDataD]   = useState("");
  const norm2 = s => (s||"").toLowerCase();

  const listaFiltrada = lista
    .filter(s => !fColab   || norm2(s.colaborador_nome).includes(norm2(fColab)) || (s.chapa||"").includes(fColab))
    .filter(s => !fTipo    || s.tipo === fTipo)
    .filter(s => !fStatus2 || s.status === fStatus2)
    .filter(s => !fGestor2 || norm2(s.gestor_nome).includes(norm2(fGestor2)))
    .filter(s => !fDataD || fmtDateLocal(s.data_desligamento) === fDataD);

  const podeAgir = (sol) => {
    if (!ALCADA_DESL[sol.status]?.includes(user.perfil)) return false;
    if (["dp", "admin", "presidente"].includes(user.perfil)) return true;
    if (user.perfil === "superior") {
      return !sol.superior_id || sol.superior_id === user.id;
    }
    return true;
  };

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
        {["gestor","dp","admin"].includes(user.perfil) && (
          <button onClick={() => { setModalNovo(true); setErro(""); setForm(FORM_VAZIO); setColaboradorSel(null); setBuscaColab(""); setBloqueioColab(null); }}
            style={{ padding: "10px 20px", background: "#0F2447", color: "#fff", border: "none", borderRadius: 8, fontWeight: 600, fontSize: 14, cursor: "pointer" }}>
            + Nova Solicitação
          </button>
        )}
      </div>

      {erro && <div style={{ background: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: 8, padding: "10px 16px", marginBottom: 16, color: "#DC2626", fontSize: 13 }}>⚠️ {erro}</div>}

      <div style={{ background: "#fff", borderRadius: 12, border: "1px solid #E5E7EB", overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Colaborador", "Tipo", "Desligamento", "Solicitante", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 14px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
            <tr style={{ background: "#F0F4F8", borderBottom: "2px solid #E5E7EB" }}>
              <th style={{ padding:"5px 8px" }}><input value={fColab} onChange={e=>setFColab(e.target.value)} placeholder="🔍 Colaborador/Chapa" style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }}>
                <select value={fTipo} onChange={e=>setFTipo(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}>
                  <option value="">Todos</option>
                  {TIPOS_DESL.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
              </th>
              <th style={{ padding:"5px 8px" }}>
                <input type="date" value={fDataD} onChange={e=>setFDataD(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} />
              </th>
              <th style={{ padding:"5px 8px" }}><input value={fGestor2} onChange={e=>setFGestor2(e.target.value)} placeholder="🔍 Solicitante" style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit", boxSizing:"border-box" }} /></th>
              <th style={{ padding:"5px 8px" }}>
                <select value={fStatus2} onChange={e=>setFStatus2(e.target.value)} style={{ width:"100%", padding:"5px 8px", borderRadius:6, border:"1px solid #D1D5DB", fontSize:11, fontFamily:"inherit" }}>
                  <option value="">Todos</option>
                  {Object.entries(STATUS_DESL).map(([v,d]) => <option key={v} value={v}>{d.label}</option>)}
                </select>
              </th>
              <th style={{ padding:"5px 8px" }}><button onClick={()=>{setFColab("");setFTipo("");setFStatus2("");setFGestor2("");setFDataD("");}} style={{ fontSize:10, padding:"4px 8px", borderRadius:6, border:"1px solid #D1D5DB", background:"#fff", cursor:"pointer", color:"#6B7280" }}>✕ Limpar</button></th>
            </tr>
          </thead>
          <tbody>
            {carregando ? (
              <tr><td colSpan={6} style={{ padding:32, textAlign:"center", color:"#9CA3AF" }}>Carregando...</td></tr>
            ) : listaFiltrada.length === 0 ? (
              <tr><td colSpan={6} style={{ padding:40, textAlign:"center", color:"#9CA3AF" }}>
                <div style={{ fontSize:32, marginBottom:8 }}>🚪</div>Nenhuma solicitação encontrada
              </td></tr>
            ) : listaFiltrada.map((sol, i) => {
              const st = STATUS_DESL[sol.status] || STATUS_DESL.rascunho;
              const tipo = TIPOS_DESL.find(t => t.value === sol.tipo);
              const btnBase = { padding:"5px 10px", borderRadius:6, fontSize:11, fontWeight:600, cursor:"pointer", whiteSpace:"nowrap", fontFamily:"inherit" };
              const trunc3 = (nome) => (nome || "").split(" ").slice(0, 3).join(" ").toUpperCase();
              return (
                <tr key={sol.id} style={{ borderTop:"1px solid #F3F4F6", background: i%2===0?"#fff":"#FAFAFA" }}>
                  <td style={{ padding:"10px 14px" }}>
                    <div style={{ fontWeight:600, fontSize:12, color:"#111827" }}>{sol.colaborador_nome}</div>
                    <div style={{ fontSize:11, color:"#6B7280" }}>Chapa: {sol.chapa}</div>
                  </td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>{tipo?.label || sol.tipo}</td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>{sol.data_desligamento ? new Date(sol.data_desligamento).toLocaleDateString("pt-BR", { timeZone:"UTC" }) : "—"}</td>
                  <td style={{ padding:"10px 14px", fontSize:12, color:"#374151" }}>{trunc3(sol.gestor_nome)}</td>
                  <td style={{ padding:"10px 14px" }}>
                    <span style={{ background: st.color+"22", color: st.color, borderRadius:6, padding:"3px 8px", fontSize:11, fontWeight:600 }}>{st.label}</span>
                  </td>
                  <td style={{ padding:"10px 14px" }}>
                    <div style={{ display:"flex", gap:4, flexWrap:"nowrap", alignItems:"center" }}>

                      {/* 1. Ver detalhe — sempre, primeiro */}
                      <button onClick={() => abrirDetalhe(sol.id)} style={{ ...btnBase, border:"1px solid #E5E7EB", background:"#fff", color:"#374151" }}>Ver</button>

                      {/* 2. PDF — só após aprovação, não pedido_demissão */}
                      {["aprovado","finalizado"].includes(sol.status) && sol.tipo !== "pedido_demissao" && (
                        <button onClick={async () => { try { const r = await api.buscarDesligamento(sol.id); setModalPDF(r); } catch(e){ setErro(e.message); } }}
                          style={{ ...btnBase, border:"1px solid #D1D5DB", background:"#fff", color:"#374151" }}>📄 PDF</button>
                      )}

                      {/* 3. Anexar/Substituir — só após aprovação, não pedido_demissão */}
                      {["aprovado","finalizado"].includes(sol.status) && sol.tipo !== "pedido_demissao" && (
                        <label style={{ ...btnBase, border:"1px solid #10B981", background:"#F0FDF4", color:"#065F46", display:"inline-block" }}>
                          📎 {parseInt(sol.qtd_anexos) > 0 ? "Substituir" : "Anexar"}
                          <input type="file" accept=".pdf,.jpg,.jpeg,.png" style={{ display:"none" }}
                            onChange={async (e) => {
                              const file = e.target.files[0]; if (!file) return;
                              if (file.size > 5*1024*1024) { setErro("Arquivo muito grande (max 5MB)"); return; }
                              const reader = new FileReader();
                              reader.onload = async (ev) => {
                                try {
                                  await api.addAnexoDesligamento(sol.id, { nome_arquivo: file.name, tipo_arquivo: file.type, dados_base64: ev.target.result });
                                  setErro(""); await carregar();
                                } catch(err) { setErro(err.message); }
                              };
                              reader.readAsDataURL(file);
                            }} />
                        </label>
                      )}

                      {/* 4. Ver anexo — quando há anexo */}
                      {parseInt(sol.qtd_anexos) > 0 && (
                        <button onClick={async () => { try { const r = await api.buscarDesligamento(sol.id); setModalAnexoPedido(r); } catch(e){ setErro(e.message); } }}
                          style={{ ...btnBase, border:"1px solid #6B7280", background:"#F9FAFB", color:"#374151" }}>👁️ Ver</button>
                      )}

                      {/* 5. Pedido de demissão — anexo específico */}
                      {sol.tipo === "pedido_demissao" && (
                        <button onClick={async () => { try { const r = await api.buscarDesligamento(sol.id); setModalAnexoPedido(r); } catch(e){ setErro(e.message); } }}
                          style={{ ...btnBase, border:"1px solid #10B981", background:"#F0FDF4", color:"#065F46" }}>📎 Anexo</button>
                      )}

                      {/* 6. Aprovar — só quando pendente */}
                      {podeAgir(sol) && sol.tipo !== "pedido_demissao" && (
                        <button onClick={() => setModalAcao({ id: sol.id, status: sol.status, acao: "aprovar", observacao: "" })}
                          style={{ ...btnBase, border:"none", background:"#10B981", color:"#fff" }}>✅ Aprovar</button>
                      )}

                      {/* 7. Enviar — rascunho do próprio gestor */}
                      {sol.status === "rascunho" && sol.gestor_id === user.id && (
                        <button onClick={async () => { try { await api.enviarDesligamento(sol.id); await carregar(); } catch(e){setErro(e.message);} }}
                          style={{ ...btnBase, border:"none", background:"#0F2447", color:"#fff" }}>Enviar</button>
                      )}

                      {/* 8. Cancelar */}
                      {["admin","dp"].includes(user.perfil) && !["cancelado","finalizado"].includes(sol.status) && (
                        <button onClick={async () => {
                          if (!window.confirm(`Cancelar a solicitação de desligamento de ${sol.colaborador_nome}?\n\nEsta ação não pode ser desfeita.`)) return;
                          try { await api.cancelarDesligamento(sol.id); await carregar(); } catch(e) { setErro(e.message); }
                        }} style={{ ...btnBase, border:"1px solid #EF4444", background:"#FEF2F2", color:"#DC2626" }}>🚫</button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Modal Novo */}
      {modalNovo && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ background: "#fff", borderRadius: 16, width: "100%", maxWidth: 600, maxHeight: "90vh", overflowY: "auto", padding: 28 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
              <h3 style={{ margin: 0, fontSize: 18, fontWeight: 700 }}>Nova Solicitação de Desligamento</h3>
              <button onClick={() => setModalNovo(false)} style={{ background: "none", border: "none", fontSize: 20, cursor: "pointer" }}>×</button>
            </div>

            {erro && (
              <div style={{ background: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: 8, padding: "10px 14px", marginBottom: 16, color: "#DC2626", fontSize: 12 }}>
                {erro.split("\n").map((linha, i) => (
                  <div key={i} style={{ marginBottom: linha === "" ? 6 : 2 }}>{linha ? `${i === 0 ? "⚠️ " : ""}${linha}` : ""}</div>
                ))}
              </div>
            )}

            {/* Colaborador */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 600, marginBottom: 6 }}>Colaborador *</label>
              <div style={{ position: "relative" }}>
                <input value={buscaColab} onChange={e => onBuscaColab(e.target.value)}
                  placeholder="Buscar por nome ou matrícula..."
                  style={{ width: "100%", padding: "9px 12px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, boxSizing: "border-box" }} />
                {sugestoesColab.length > 0 && (
                  <div style={{ position: "absolute", top: "100%", left: 0, right: 0, background: "#fff", border: "1px solid #E5E7EB", borderRadius: 8, zIndex: 10, maxHeight: 200, overflowY: "auto", boxShadow: "0 4px 12px rgba(0,0,0,0.1)" }}>
                    {sugestoesColab.map(c => (
                      <div key={c.id} onClick={() => selecionarColab(c)}
                        style={{ padding: "10px 14px", cursor: "pointer", fontSize: 13, borderBottom: "1px solid #F3F4F6" }}
                        onMouseEnter={e => e.target.style.background="#F8FAFC"}
                        onMouseLeave={e => e.target.style.background="#fff"}>
                        <b>{c.chapa}</b> — {c.nome} <span style={{ color: "#94A3B8" }}>{c.funcao}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              {validandoColab && (
                <div style={{ marginTop: 8, padding: "8px 14px", background: "#EFF6FF", borderRadius: 8, fontSize: 12, color: "#1D4ED8" }}>
                  🔄 Verificando aptidão do colaborador...
                </div>
              )}
              {!validandoColab && colaboradorSel && !bloqueioColab && (
                <div style={{ marginTop: 8, padding: "10px 14px", background: "#F0FDF4", borderRadius: 8, fontSize: 12, color: "#166534" }}>
                  ✅ <b>{colaboradorSel.nome}</b> · {colaboradorSel.descricao_filial || colaboradorSel.desc_cc || "—"} · Matrícula: {colaboradorSel.chapa} · Função: {colaboradorSel.desc_funcao || colaboradorSel.funcao || "—"} · CC: {colaboradorSel.centro_custo} — {colaboradorSel.desc_cc}
                  {colaboradorSel.tipo_contrato === "determinado" && <span style={{ marginLeft: 8, background: "#FEF3C7", color: "#92400E", padding: "1px 6px", borderRadius: 4 }}>Contrato até {colaboradorSel.data_fim_contrato ? new Date(colaboradorSel.data_fim_contrato).toLocaleDateString("pt-BR") : "—"}</span>}
                </div>
              )}
              {!validandoColab && bloqueioColab && (
                <div style={{ marginTop: 8, padding: "12px 14px", background: "#FEF2F2", border: "1px solid #FCA5A5", borderRadius: 8, fontSize: 12, color: "#DC2626" }}>
                  🚫 <b>Colaborador bloqueado para desligamento</b>
                  <div style={{ marginTop: 6, lineHeight: 1.6 }}>{bloqueioColab.mensagem}</div>
                </div>
              )}
            </div>

            {/* Tipo */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 600, marginBottom: 6 }}>Tipo de Desligamento *</label>
              <select value={form.tipo} onChange={e => {
                const novoTipo = e.target.value;
                if (novoTipo === "termino_contrato" && colaboradorSel?.data_admissao) {
                  setForm(f => ({ ...f, tipo: novoTipo, data_desligamento: calcularDataTermino(colaboradorSel.data_admissao) }));
                } else {
                  setForm(f => ({ ...f, tipo: novoTipo }));
                }
              }}
                style={{ width: "100%", padding: "9px 12px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13 }}>
                <option value="">Selecione...</option>
                {TIPOS_DESL.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>

            {/* Datas */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
              <div>
                <label style={{ display: "block", fontSize: 13, fontWeight: 600, marginBottom: 6 }}>Data de Desligamento *</label>
                <input type="date" value={form.data_desligamento}
                  onChange={e => setForm(f => ({ ...f, data_desligamento: e.target.value }))}
                  readOnly={form.tipo === "termino_contrato"}
                  style={{ width: "100%", padding: "9px 12px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, boxSizing: "border-box",
                    background: form.tipo === "termino_contrato" ? "#F3F4F6" : "#fff",
                    cursor: form.tipo === "termino_contrato" ? "not-allowed" : "auto" }} />
              </div>
              {form.tipo === "aviso_trabalhado" && (
                <div>
                  <label style={{ display: "block", fontSize: 13, fontWeight: 600, marginBottom: 6 }}>Data de Aviso</label>
                  <input type="date" value={form.data_aviso || calcularDataAviso(form.data_desligamento)}
                    onChange={e => setForm(f => ({ ...f, data_aviso: e.target.value }))}
                    style={{ width: "100%", padding: "9px 12px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, boxSizing: "border-box" }} />
                </div>
              )}
            </div>

            {/* Redução jornada */}
            {form.tipo === "aviso_trabalhado" && (
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, cursor: "pointer" }}>
                  <input type="checkbox" checked={form.reducao_jornada}
                    onChange={e => setForm(f => ({ ...f, reducao_jornada: e.target.checked }))} />
                  Colaborador terá redução de jornada durante o aviso
                </label>
              </div>
            )}

            {/* Justificativa */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                Justificativa {form.tipo === "antecipacao_contrato" ? "*" : "(opcional)"}
              </label>
              <textarea value={form.justificativa} onChange={e => setForm(f => ({ ...f, justificativa: e.target.value }))}
                rows={3} placeholder="Descreva o motivo do desligamento..."
                style={{ width: "100%", padding: "9px 12px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, resize: "vertical", boxSizing: "border-box" }} />
            </div>

            {/* Observações */}
            <div style={{ marginBottom: form.tipo === "pedido_demissao" ? 12 : 20 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 600, marginBottom: 6 }}>Observações</label>
              <textarea value={form.observacoes} onChange={e => setForm(f => ({ ...f, observacoes: e.target.value }))}
                rows={2} placeholder="Observações adicionais..."
                style={{ width: "100%", padding: "9px 12px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, resize: "vertical", boxSizing: "border-box" }} />
            </div>

            {/* Anexo do Pedido de Demissão — só para pedido_demissao */}
            {form.tipo === "pedido_demissao" && (
              <div style={{ marginBottom: 20 }}>
                <label style={{ display: "block", fontSize: 13, fontWeight: 600, marginBottom: 6 }}>
                  📎 Pedido de Demissão Assinado *
                </label>
                <div style={{
                  border: form.pedido_anexo_nome ? "2px solid #10B981" : "2px dashed #D1D5DB",
                  borderRadius: 10, padding: "14px 16px", background: form.pedido_anexo_nome ? "#F0FDF4" : "#FAFAFA",
                  display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12
                }}>
                  <div>
                    {form.pedido_anexo_nome ? (
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: "#065F46" }}>✅ {form.pedido_anexo_nome}</div>
                        <div style={{ fontSize: 11, color: "#6B7280", marginTop: 2 }}>Documento anexado com sucesso</div>
                      </div>
                    ) : (
                      <div>
                        <div style={{ fontSize: 13, color: "#374151", fontWeight: 600 }}>Nenhum arquivo selecionado</div>
                        <div style={{ fontSize: 11, color: "#9CA3AF", marginTop: 2 }}>PDF, JPG ou PNG — máx. 5MB</div>
                      </div>
                    )}
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <label style={{
                      padding: "7px 14px", borderRadius: 8, fontSize: 12, fontWeight: 600,
                      background: "#0F2447", color: "#fff", cursor: "pointer", whiteSpace: "nowrap"
                    }}>
                      {form.pedido_anexo_nome ? "Trocar arquivo" : "Selecionar arquivo"}
                      <input type="file" accept=".pdf,.jpg,.jpeg,.png" style={{ display: "none" }}
                        onChange={e => {
                          const file = e.target.files[0];
                          if (!file) return;
                          if (file.size > 5 * 1024 * 1024) { alert("Arquivo muito grande (máx 5MB)"); return; }
                          const reader = new FileReader();
                          reader.onload = ev => setForm(f => ({ ...f, pedido_anexo_nome: file.name, pedido_anexo_base64: ev.target.result }));
                          reader.readAsDataURL(file);
                        }} />
                    </label>
                    {form.pedido_anexo_nome && (
                      <button onClick={() => setForm(f => ({ ...f, pedido_anexo_nome: "", pedido_anexo_base64: "" }))}
                        style={{ padding: "7px 10px", borderRadius: 8, border: "1px solid #EF4444", background: "#FEF2F2", color: "#DC2626", fontSize: 12, cursor: "pointer" }}>
                        ✕
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, borderTop: "1px solid #F3F4F6", paddingTop: 16 }}>
              <button onClick={() => setModalNovo(false)} disabled={salvando}
                style={{ padding: "9px 20px", borderRadius: 8, border: "1px solid #E5E7EB", background: "#fff", fontSize: 14, cursor: "pointer" }}>
                Cancelar
              </button>
              {form.tipo !== "pedido_demissao" && (
                <button onClick={() => salvar(false)} disabled={salvando}
                  style={{ padding: "9px 20px", borderRadius: 8, border: "1px solid #0F2447", background: "#fff", color: "#0F2447", fontSize: 14, cursor: "pointer", fontWeight: 600 }}>
                  {salvando ? "Salvando..." : "Salvar Rascunho"}
                </button>
              )}
              <button onClick={() => salvar(form.tipo !== "pedido_demissao")} disabled={salvando}
                style={{ padding: "9px 20px", borderRadius: 8, border: "none", background: "#0F2447", color: "#fff", fontSize: 14, cursor: "pointer", fontWeight: 600 }}>
                {salvando
                  ? "Processando..."
                  : form.tipo === "pedido_demissao"
                  ? "Registrar Pedido de Demissão"
                  : "Enviar para Aprovação"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Detalhe */}
      {modalDetalhe && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ background: "#fff", borderRadius: 16, width: "100%", maxWidth: 650, maxHeight: "90vh", overflowY: "auto", padding: 28 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
              <h3 style={{ margin: 0, fontSize: 18, fontWeight: 700 }}>Detalhes da Solicitação #{modalDetalhe.id}</h3>
              <button onClick={() => setModalDetalhe(null)} style={{ background: "none", border: "none", fontSize: 20, cursor: "pointer" }}>×</button>
            </div>

            {/* Dados */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
              {[
                ["Colaborador",  modalDetalhe.colaborador_nome],
                ["Matrícula",    modalDetalhe.chapa],
                ["CPF",          modalDetalhe.cpf || "—"],
                ["Cargo",        modalDetalhe.funcao || "—"],
                ["Tipo",         TIPOS_DESL.find(t => t.value === modalDetalhe.tipo)?.label],
                ["Status",       STATUS_DESL[modalDetalhe.status]?.label],
                ["Desligamento", modalDetalhe.data_desligamento ? new Date(modalDetalhe.data_desligamento).toLocaleDateString("pt-BR") : "—"],
                ["Data Aviso",   modalDetalhe.data_aviso ? new Date(modalDetalhe.data_aviso).toLocaleDateString("pt-BR") : "—"],
                ["Solicitante",  modalDetalhe.gestor_nome],
                ["Centro Custo", `${modalDetalhe.centro_custo || "—"} — ${modalDetalhe.desc_cc || "—"}`],
              ].map(([l, v]) => (
                <div key={l} style={{ background: "#F8FAFC", borderRadius: 8, padding: "10px 14px" }}>
                  <div style={{ fontSize: 11, color: "#94A3B8", fontWeight: 600, marginBottom: 2 }}>{l}</div>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{v || "—"}</div>
                </div>
              ))}
            </div>

            {modalDetalhe.justificativa && (
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: "#94A3B8", marginBottom: 4 }}>JUSTIFICATIVA</div>
                <div style={{ background: "#F8FAFC", borderRadius: 8, padding: "10px 14px", fontSize: 13 }}>{modalDetalhe.justificativa}</div>
              </div>
            )}

            {/* Histórico */}
            {modalDetalhe.logs?.length > 0 && (
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: "#94A3B8", marginBottom: 8 }}>HISTÓRICO</div>
                {modalDetalhe.logs.map((l, i) => (
                  <div key={i} style={{ display: "flex", gap: 10, marginBottom: 8, fontSize: 12 }}>
                    <div style={{ width: 32, height: 32, borderRadius: "50%", background: "#0F2447", color: "#fff", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, flexShrink: 0 }}>
                      {l.usuario_nome?.slice(0,2).toUpperCase()}
                    </div>
                    <div>
                      <div style={{ fontWeight: 600 }}>{l.usuario_nome} <span style={{ color: "#94A3B8", fontWeight: 400 }}>· {l.acao}</span></div>
                      <div style={{ color: "#6B7280" }}>{l.observacao || ""} · {new Date(l.criado_em).toLocaleString("pt-BR")}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div style={{ display: "flex", justifyContent: "flex-end", paddingTop: 16, borderTop: "1px solid #F3F4F6" }}>
              <button onClick={() => setModalDetalhe(null)}
                style={{ padding: "9px 20px", borderRadius: 8, border: "1px solid #E5E7EB", background: "#fff", fontSize: 14, cursor: "pointer" }}>
                Fechar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Ação */}
      {modalAcao && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
          <div style={{ background: "#fff", borderRadius: 16, width: "100%", maxWidth: 460, padding: 28 }}>
            <h3 style={{ margin: "0 0 16px", fontSize: 17, fontWeight: 700 }}>Analisar Solicitação</h3>
            <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
              {["aprovar","reprovar","solicitar_ajuste"].map(a => (
                <button key={a} onClick={() => setModalAcao(m => ({ ...m, acao: a }))}
                  style={{ flex: 1, padding: "8px 0", borderRadius: 8, border: "2px solid",
                    borderColor: modalAcao.acao === a ? "#0F2447" : "#E5E7EB",
                    background: modalAcao.acao === a ? "#0F2447" : "#fff",
                    color: modalAcao.acao === a ? "#fff" : "#374151",
                    fontSize: 12, fontWeight: 600, cursor: "pointer" }}>
                  {a === "aprovar" ? "✅ Aprovar" : a === "reprovar" ? "❌ Reprovar" : "🔄 Ajuste"}
                </button>
              ))}
            </div>
            <textarea value={modalAcao.observacao}
              onChange={e => setModalAcao(m => ({ ...m, observacao: e.target.value }))}
              rows={3} placeholder="Observação (opcional para aprovação)..."
              style={{ width: "100%", padding: "9px 12px", borderRadius: 8, border: "1px solid #E5E7EB", fontSize: 13, resize: "none", boxSizing: "border-box", marginBottom: 16 }} />
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
              <button onClick={() => setModalAcao(null)} disabled={salvando}
                style={{ padding: "9px 20px", borderRadius: 8, border: "1px solid #E5E7EB", background: "#fff", fontSize: 14, cursor: "pointer" }}>
                Cancelar
              </button>
              <button onClick={executarAcao} disabled={salvando}
                style={{ padding: "9px 20px", borderRadius: 8, border: "none", background: "#0F2447", color: "#fff", fontSize: 14, cursor: "pointer", fontWeight: 600 }}>
                {salvando ? "Processando..." : "Confirmar"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal PDF Desligamento */}
      {/* Modal Ver Anexo — Pedido de Demissão */}
      {modalAnexoPedido && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.7)", zIndex:2000, display:"flex", flexDirection:"column" }}>
          {/* Barra superior */}
          <div style={{ background:"#fff", display:"flex", alignItems:"center", justifyContent:"space-between", padding:"12px 20px", borderBottom:"1px solid #E5E7EB", flexShrink:0 }}>
            <span style={{ fontWeight:700, fontSize:15 }}>📎 Anexos — {modalAnexoPedido.colaborador_nome}</span>
            <button onClick={() => setModalAnexoPedido(null)} style={{ background:"none", border:"none", fontSize:22, cursor:"pointer", color:"#374151" }}>×</button>
          </div>

          {/* Conteúdo */}
          <div style={{ flex:1, overflowY:"auto", padding:24, background:"#F8FAFC" }}>
            <div style={{ maxWidth:860, margin:"0 auto", display:"flex", flexDirection:"column", gap:16 }}>

              {/* Pedido de Demissão assinado */}
              {(modalAnexoPedido.pedido_anexo_dados || modalAnexoPedido.pedido_anexo_base64) && (() => {
                const src = modalAnexoPedido.pedido_anexo_dados || modalAnexoPedido.pedido_anexo_base64;
                const nome = modalAnexoPedido.pedido_anexo_nome;
                const isImg = src.startsWith("data:image");
                const isPdf = src.startsWith("data:application/pdf") || (nome||"").toLowerCase().endsWith(".pdf");
                return (
                  <div style={{ background:"#fff", borderRadius:12, boxShadow:"0 2px 12px rgba(0,0,0,0.08)", overflow:"hidden" }}>
                    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"12px 18px", borderBottom:"1px solid #F3F4F6", background:"#F0FDF4" }}>
                      <span style={{ fontSize:13, fontWeight:700, color:"#065F46" }}>📄 Pedido de Demissão Assinado — {nome}</span>
                      <div style={{ display:"flex", gap:8 }}>
                        <button onClick={() => {
                          if (isPdf) {
                            const b64 = src.split(",")[1];
                            const bin = atob(b64); const arr = new Uint8Array(bin.length);
                            for (let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
                            const blobUrl = URL.createObjectURL(new Blob([arr],{type:"application/pdf"}));
                            const w = window.open(blobUrl, "_blank");
                            setTimeout(()=>{ w.focus(); w.print(); }, 1000);
                          } else {
                            const w = window.open("","_blank");
                            w.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>${nome}</title><style>body{margin:0;display:flex;justify-content:center;padding:20px;}img{max-width:100%;}@media print{body{padding:0;}}</style></head><body><img src="${src}" /></body></html>`);
                            w.document.close(); w.focus(); setTimeout(()=>w.print(),600);
                          }
                        }} style={{ padding:"6px 14px", background:"#0F2447", color:"#fff", border:"none", borderRadius:8, fontSize:12, fontWeight:600, cursor:"pointer" }}>🖨️ Imprimir / Salvar</button>
                        <a href={src} download={nome} style={{ padding:"6px 14px", background:"#F3F4F6", color:"#374151", border:"1px solid #D1D5DB", borderRadius:8, fontSize:12, fontWeight:600, textDecoration:"none" }}>⬇ Baixar</a>
                        {/* Substituir */}
                        <label style={{ padding:"6px 14px", background:"#FEF3C7", color:"#92400E", border:"1px solid #FCD34D", borderRadius:8, fontSize:12, fontWeight:600, cursor:"pointer" }}>
                          🔄 Substituir
                          <input type="file" accept=".pdf,.jpg,.jpeg,.png" style={{ display:"none" }}
                            onChange={async (e) => {
                              const file = e.target.files[0]; if (!file) return;
                              if (file.size > 5*1024*1024) { alert("Arquivo muito grande (max 5MB)"); return; }
                              const reader = new FileReader();
                              reader.onload = async (ev) => {
                                try {
                                  await api.addAnexoDesligamento(modalAnexoPedido.id, { nome_arquivo: file.name, tipo_arquivo: file.type, dados_base64: ev.target.result });
                                  const r = await api.buscarDesligamento(modalAnexoPedido.id);
                                  setModalAnexoPedido(r);
                                } catch(err) { alert("Erro: " + err.message); }
                              };
                              reader.readAsDataURL(file);
                            }} />
                        </label>
                      </div>
                    </div>
                    <div style={{ padding:16, textAlign:"center", background:"#fff" }}>
                      {isImg ? (
                        <img src={src} alt={nome} style={{ maxWidth:"100%", borderRadius:8, border:"1px solid #E5E7EB" }} />
                      ) : isPdf ? (
                        <PdfViewer src={src} />
                      ) : (
                        <div style={{ padding:"30px 0", color:"#6B7280", fontSize:13 }}>
                          <div style={{ fontSize:48, marginBottom:8 }}>📄</div>
                          <div>{nome}</div>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* Anexos gerais */}
              {modalAnexoPedido.anexos && modalAnexoPedido.anexos.length > 0 && (
                <div style={{ background:"#fff", borderRadius:12, boxShadow:"0 2px 12px rgba(0,0,0,0.08)", overflow:"hidden" }}>
                  <div style={{ padding:"12px 18px", borderBottom:"1px solid #F3F4F6", background:"#EFF6FF" }}>
                    <span style={{ fontSize:13, fontWeight:700, color:"#1D4ED8" }}>📁 Documentos Anexados ({modalAnexoPedido.anexos.length})</span>
                  </div>
                  <div style={{ padding:16, display:"flex", flexDirection:"column", gap:10 }}>
                    {modalAnexoPedido.anexos.map((anx) => {
                      const src = anx.dados_base64;
                      const isImg = src?.startsWith("data:image");
                      const isPdf = src?.startsWith("data:application/pdf") || (anx.nome_arquivo||"").toLowerCase().endsWith(".pdf");
                      return (
                        <div key={anx.id} style={{ border:"1px solid #E5E7EB", borderRadius:8, overflow:"hidden" }}>
                          <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"10px 14px", background:"#FAFAFA" }}>
                            <div>
                              <div style={{ fontSize:13, fontWeight:600, color:"#111827" }}>📄 {anx.nome_arquivo}</div>
                              <div style={{ fontSize:11, color:"#6B7280" }}>{new Date(anx.criado_em).toLocaleDateString("pt-BR")}</div>
                            </div>
                            <div style={{ display:"flex", gap:8 }}>
                              {src && (
                                <button onClick={() => {
                                  if (isPdf) {
                                    const b64 = src.split(",")[1];
                                    const bin = atob(b64); const arr = new Uint8Array(bin.length);
                                    for (let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
                                    const blobUrl = URL.createObjectURL(new Blob([arr],{type:"application/pdf"}));
                                    const w = window.open(blobUrl, "_blank");
                                    setTimeout(()=>{ w.focus(); w.print(); }, 1000);
                                  } else {
                                    const w = window.open("","_blank");
                                    w.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>${anx.nome_arquivo}</title><style>body{margin:0;display:flex;justify-content:center;padding:20px;}img{max-width:100%;}@media print{body{padding:0;}}</style></head><body><img src="${src}" /></body></html>`);
                                    w.document.close(); w.focus(); setTimeout(()=>w.print(),600);
                                  }
                                }} style={{ padding:"5px 12px", background:"#0F2447", color:"#fff", border:"none", borderRadius:7, fontSize:11, fontWeight:600, cursor:"pointer" }}>🖨️ Imprimir</button>
                              )}
                              {src && (
                                <a href={src} download={anx.nome_arquivo} style={{ padding:"5px 12px", background:"#F3F4F6", color:"#374151", border:"1px solid #D1D5DB", borderRadius:7, fontSize:11, fontWeight:600, textDecoration:"none" }}>⬇ Baixar</a>
                              )}
                            </div>
                          </div>
                          {src && (
                            <div style={{ padding:"0 14px 14px", background:"#fff" }}>
                              {isImg ? (
                                <img src={src} alt={anx.nome_arquivo} style={{ maxWidth:"100%", borderRadius:6, border:"1px solid #E5E7EB" }} />
                              ) : isPdf ? (
                                <PdfViewer src={src} height="60vh" />
                              ) : null}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Nenhum anexo */}
              {!modalAnexoPedido.pedido_anexo_dados && !modalAnexoPedido.pedido_anexo_base64 &&
               (!modalAnexoPedido.anexos || modalAnexoPedido.anexos.length === 0) && (
                <div style={{ textAlign:"center", padding:"60px 0", color:"#9CA3AF", background:"#fff", borderRadius:12 }}>
                  <div style={{ fontSize:48, marginBottom:10 }}>📎</div>
                  <div>Nenhum documento anexado nesta solicitação</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {modalPDF && <ModalPDFDesligamento sol={modalPDF} onClose={() => setModalPDF(null)} />}
    </div>
  );
}

function ModalPDFDesligamento({ sol, onClose }) {
  const fmt = (d) => d ? new Date(d).toLocaleDateString("pt-BR", { timeZone: "UTC" }) : "__/__/____";
  const TIPOS = {
    aviso_trabalhado:     "AVISO PRÉVIO TRABALHADO",
    aviso_indenizado:     "AVISO PRÉVIO INDENIZADO",
    pedido_demissao:      "PEDIDO DE DEMISSÃO",
    termino_contrato:     "TÉRMINO DE CONTRATO DE TRABALHO",
    antecipacao_contrato: "RESCISÃO ANTECIPADA DO CONTRATO DE EXPERIÊNCIA PELO EMPREGADOR",
  };
  const titulo = TIPOS[sol.tipo] || "SOLICITAÇÃO DE DESLIGAMENTO";
  const temDeclaracao = ["aviso_indenizado","termino_contrato"].includes(sol.tipo);

  const imprimir = () => {
    const conteudo = document.getElementById("pdf-desligamento-benel").innerHTML;
    const win = window.open("", "_blank");
    win.document.write(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${titulo}</title>
    <style>body{font-family:Arial,sans-serif;font-size:13px;color:#000;line-height:1.6;padding:30px 40px;margin:0;}@media print{body{padding:20px 30px;}}</style>
    </head><body>${conteudo}</body></html>`);
    win.document.close();
    setTimeout(() => win.print(), 400);
  };

  const Ficha = () => (
    <div style={{ border: "1.5px solid #000", padding: "10px 14px", marginBottom: 20,
      display: "grid", gridTemplateColumns: "1fr 1fr", gap: "4px 20px" }}>
      <div style={{ fontWeight: 700 }}>Sr. (a) &nbsp;{sol.colaborador_nome}</div>
      <div style={{ fontWeight: 700 }}>{sol.chapa}{sol.desc_cc ? `    SEÇÃO : ${sol.desc_cc}` : ""}</div>
      <div>C.P.F : &nbsp;{sol.cpf || "___.___.___-__"}</div>
      <div>Admissão: &nbsp;{(sol.data_admissao||sol.admissao) ? fmt((sol.data_admissao||sol.admissao).split("T")[0]) : "__/__/____"}</div>
    </div>
  );

  const Assinaturas = () => (
    <>
      <div style={{ marginBottom: 8 }}>Fortaleza</div>
      <div style={{ marginBottom: 28, textAlign: "left" }}>
        <img src={ASSINATURA_BENEL} alt="Assinatura" style={{ height: 70, display: "block", margin: "0 auto 4px", objectFit: "contain" }} />
        <div style={{ borderTop: "1px solid #000", width: 320, margin: "0 auto 6px", paddingTop: 4, fontWeight: 700, textAlign: "center" }}>
          BENEL TRANSPORTES E LOGISTICA LTDA
        </div>
      </div>
      <div style={{ marginBottom: 28 }}><strong>Ciente:</strong> &nbsp;{fmt(sol.data_desligamento)}</div>
      <div style={{ textAlign: "center", marginTop: 20 }}>
        <div style={{ height: 56 }} />
        <div style={{ borderTop: "1px solid #000", width: 320, margin: "0 auto 4px", paddingTop: 6, fontWeight: 700 }}>{sol.colaborador_nome}</div>
        <div style={{ fontSize: 12 }}>Assinatura do Empregado</div>
      </div>
    </>
  );

  const Declaracao = () => (
    <>
      <hr style={{ border: "none", borderTop: "1px dotted #000", margin: "24px 0" }} />
      <div style={{ textAlign: "center", fontWeight: 900, fontSize: 14, marginBottom: 16 }}>DECLARAÇÃO DE CIÊNCIA DE PAGAMENTO</div>
      <p style={{ textAlign: "justify", marginBottom: 16 }}>Estou ciente que devo comparecer a sede da empresa e/ou agente homologador, até o dia __/___/_____, para confirmar o recebimento das minhas verbas rescisórias, feito dentro dos prazos legais. O não comparecimento na data acima citada automaticamente dará a minha ciência.</p>
      <p style={{ fontSize: 12, marginBottom: 24 }}>Obs.: Para homologação das verbas rescisórias a data, local e horário a combinar, dentro do prazo legal previsto na CLT.</p>
      <div style={{ textAlign: "center", marginTop: 20 }}>
        <div style={{ height: 56 }} />
        <div style={{ borderTop: "1px solid #000", width: 320, margin: "0 auto 4px", paddingTop: 6, fontWeight: 700 }}>{sol.colaborador_nome}</div>
        <div style={{ fontSize: 12 }}>Assinatura do Empregado</div>
      </div>
    </>
  );

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "flex-start", justifyContent: "center", zIndex: 1100, overflowY: "auto", padding: "20px 0" }}>
      <div style={{ background: "#fff", borderRadius: 16, width: "100%", maxWidth: 760, margin: "auto", padding: 28 }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700 }}>Documento de Desligamento</h3>
          <button onClick={onClose} style={{ background: "none", border: "none", fontSize: 22, cursor: "pointer" }}>×</button>
        </div>
        <div id="pdf-desligamento-benel" style={{ fontFamily: "Arial,sans-serif", fontSize: 13, color: "#000", lineHeight: 1.6 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
            <img src={LOGO_BENEL} alt="Benel" style={{ height: 52 }} />
            <div style={{ fontSize: 16, fontWeight: 900, textTransform: "uppercase", letterSpacing: 2, textAlign: "right", maxWidth: "55%" }}>{titulo}</div>
          </div>
          <Ficha />
          {sol.tipo === "aviso_trabalhado" && (<>
            <p style={{ textAlign: "justify", marginBottom: 16 }}>Pelo presente, notificamos que a partir desta data nossa parceria (Contrato de Trabalho), que foi construída ao longo da trajetória na <strong>BENEL TRANSPORTES E LOGISTICA LTDA</strong>, chegou ao fim, e por isso, vimos avisá-lo(la) que os efeitos do disposto art. 487, inc. II da CLT, deverá assinar umas das possibilidades abaixo:</p>
            <p style={{ marginBottom: 8 }}>( &nbsp;) &nbsp;Escolho reduzir minha jornada em duas horas, conforme determina o art. 488 da CLT.</p>
            <p style={{ marginBottom: 8 }}>( &nbsp;) &nbsp;Escolho faltar 07 (sete) dias corridos, sem prejuízo do salário, caso em que sua jornada diária de trabalho nos 30 dias restantes não será reduzida.</p>
            <p style={{ marginTop: 12, marginBottom: 8 }}>Favor marcar abaixo se concorda com o pedido da Empresa em reconsiderar o presente aviso prévio, conforme previsão do parágrafo único do art. 489 da CLT.</p>
            <p style={{ marginBottom: 16 }}>( &nbsp;) Sim &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ( &nbsp;) Não</p>
            <p style={{ fontStyle: "italic", fontSize: 12, marginBottom: 20 }}>Agradecemos a cooperação prestada por V.Sa., pedimos a devolução do presente aviso com o seu ciente.</p>
            <div style={{ marginBottom: 20 }}><strong>Início do Aviso:</strong> &nbsp;{sol.data_aviso ? fmt(sol.data_aviso) : "__/__/____"}&nbsp;&nbsp;&nbsp;&nbsp;<strong>Fim do Aviso:</strong> &nbsp;{fmt(sol.data_desligamento)}</div>
            <Assinaturas />
          </>)}
          {sol.tipo === "aviso_indenizado" && (<>
            <p style={{ textAlign: "justify", marginBottom: 24 }}>Comunicamos a V.Sa., nossa iniciativa de rescindir seu contrato de trabalho, para o que lhe damos o presente AVISO PRÉVIO que será indenizado pelo valor correspondente, conforme Artigo 487, parágrafo 1o. da Consolidação das Leis do Trabalho.</p>
            <Assinaturas />
            <p style={{ fontSize: 12, marginTop: 12 }}>Obs.: Para homologação das verbas rescisórias a data, local e horário a combinar, dentro do prazo legal previsto na CLT.</p>
            <Declaracao />
          </>)}
          {sol.tipo === "termino_contrato" && (<>
            <p style={{ textAlign: "justify", marginBottom: 24 }}>Comunicamos por meio desta, que seu contrato de trabalho por prazo determinado será rescindido no seu termo, em <strong>{fmt(sol.data_desligamento)}</strong>.</p>
            <Assinaturas />
            <p style={{ fontSize: 12, marginTop: 12 }}>Obs.: Para homologação das verbas rescisórias a data, local e horário a combinar, dentro do prazo legal previsto na CLT.</p>
            <Declaracao />
          </>)}
          {sol.tipo === "antecipacao_contrato" && (<>
            <p style={{ textAlign: "justify", marginBottom: 24 }}>Vimos pela presente comunicar-lhe que por não mais convir a esta empresa manter seu contrato de experiência{sol.data_fim_contrato ? `, cujo término estava previsto para o dia ${fmt(sol.data_fim_contrato)},` : ","} achamos por bem rescindi-lo antes do prazo acordado. Sendo assim, a partir de <strong>{fmt(sol.data_desligamento)}</strong>, não serão mais necessários seus serviços.</p>
            <Assinaturas />
          </>)}
          {sol.tipo === "pedido_demissao" && (<>
            <div style={{ background: "#F0FDF4", border: "1px solid #6EE7B7", borderRadius: 10, padding: "16px 20px", marginBottom: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: "#065F46", marginBottom: 8 }}>
                📎 Pedido de Demissão — Documento Original do Colaborador
              </div>
              <p style={{ fontSize: 12, color: "#374151", margin: 0 }}>
                Este tipo de desligamento é formalizado pelo próprio colaborador a próprio punho.
                O documento original deve ser anexado abaixo.
              </p>
            </div>
            {sol.pedido_anexo_dados || sol.pedido_anexo_base64 ? (
              <div style={{ textAlign: "center", marginBottom: 20 }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: "#374151", marginBottom: 8 }}>
                  📄 {sol.pedido_anexo_nome}
                </div>
                {sol.pedido_anexo_dados || sol.pedido_anexo_base64.startsWith("data:image") ? (
                  <img src={sol.pedido_anexo_dados || sol.pedido_anexo_base64} alt="Pedido de Demissão"
                    style={{ maxWidth: "100%", maxHeight: 500, border: "1px solid #E5E7EB", borderRadius: 8 }} />
                ) : (
                  <a href={sol.pedido_anexo_dados || sol.pedido_anexo_base64} download={sol.pedido_anexo_nome}
                    style={{ padding: "10px 20px", background: "#0F2447", color: "#fff", borderRadius: 8, fontSize: 13, fontWeight: 600, textDecoration: "none" }}>
                    ⬇ Baixar PDF anexado
                  </a>
                )}
              </div>
            ) : (
              <div style={{ textAlign: "center", padding: "30px 0", color: "#9CA3AF" }}>
                <div style={{ fontSize: 32, marginBottom: 8 }}>📎</div>
                <div>Nenhum documento anexado ainda</div>
              </div>
            )}
            <Assinaturas />
          </>)}
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, paddingTop: 16, borderTop: "1px solid #F3F4F6", marginTop: 20 }}>
          <button onClick={onClose} style={{ padding: "9px 20px", borderRadius: 8, border: "1px solid #E5E7EB", background: "#fff", fontSize: 14, cursor: "pointer" }}>Fechar</button>
          <button onClick={imprimir} style={{ padding: "9px 20px", borderRadius: 8, border: "none", background: "#0F2447", color: "#fff", fontSize: 14, cursor: "pointer", fontWeight: 600 }}>🖨 Imprimir / Salvar PDF</button>
        </div>
      </div>
    </div>
  );
}


// ── Helpers PlanoSaude ────────────────────────────────────────────────────────

function gerarHTMLTitular(colab, movimentacao) {
  const f = (v) => v || "_______________";
  const movMap = {
    INCLUSAO:    "(X) INCLUSÃO &nbsp; ( ) NÃO OPTANTE &nbsp; ( ) ALTERAÇÃO &nbsp; ( ) EXCLUSÃO",
    NAO_OPTANTE: "( ) INCLUSÃO &nbsp; (X) NÃO OPTANTE &nbsp; ( ) ALTERAÇÃO &nbsp; ( ) EXCLUSÃO",
    ALTERACAO:   "( ) INCLUSÃO &nbsp; ( ) NÃO OPTANTE &nbsp; (X) ALTERAÇÃO &nbsp; ( ) EXCLUSÃO",
    EXCLUSAO:    "( ) INCLUSÃO &nbsp; ( ) NÃO OPTANTE &nbsp; ( ) ALTERAÇÃO &nbsp; (X) EXCLUSÃO",
  };
  return `
    <div style="font-family:Arial,sans-serif;font-size:10pt;line-height:1.5;max-width:700px;margin:0 auto;padding:20px 28px;color:#000;">
      <div style="text-align:center;margin-bottom:6px;"><img src="${LOGO_BENEL}" alt="Benel" style="height:55px;" /></div>
      <h2 style="text-align:center;font-size:12pt;font-weight:bold;text-transform:uppercase;margin:0 0 2px 0;">PROPOSTA PLANO DE ASSISTÊNCIA MÉDICA</h2>
      <h3 style="text-align:center;font-size:11pt;font-weight:bold;text-transform:uppercase;margin:0 0 12px 0;">TITULAR</h3>
      <p style="font-weight:bold;text-align:center;margin:0 0 6px 0;font-size:9pt;">DADOS DA MOVIMENTAÇÃO</p>
      <div style="border:1px solid #000;padding:6px 14px;margin-bottom:12px;font-size:9.5pt;">${movMap[movimentacao] || movMap.INCLUSAO}</div>
      <p style="font-weight:bold;text-align:center;margin:0 0 6px 0;font-size:9pt;">DADOS PESSOAIS</p>
      <div style="border:1px solid #000;padding:10px 14px;margin-bottom:12px;font-size:9.5pt;">
        <p style="margin:0 0 6px 0;">C.P.F.: <u>${f(colab?.cpf)}</u> &nbsp;&nbsp; DATA DE ADMISSÃO: <u>${fmtDataPS(colab?.data_admissao) || "___/___/______"}</u></p>
        <p style="margin:0 0 6px 0;">NOME: <u>${f(colab?.nome)}</u> &nbsp;&nbsp; DATA DE NASC.: <u>${fmtDataPS(colab?.data_nascimento) || "___/___/______"}</u></p>
        <p style="margin:0 0 6px 0;">SEXO: <u>${colab?.sexo || "___________"}</u> &nbsp;&nbsp; RG: <u>${f(colab?.rg)}</u> &nbsp; ÓRGÃO: <u>${f(colab?.rg_orgao)}</u> &nbsp; UF: <u>${f(colab?.rg_uf)}</u></p>
        <p style="margin:0 0 6px 0;">ESTADO CIVIL: <u>${f(colab?.estado_civil)}</u> &nbsp;&nbsp; NOME DA MÃE: <u>${f(colab?.nome_mae)}</u></p>
        <p style="margin:0;">MATRÍCULA: <u>${f(colab?.chapa)}</u> &nbsp; PIS: <u>${f(colab?.pis)}</u> &nbsp; CTPS: <u>${f(colab?.ctps)}</u> &nbsp; SÉRIE: <u>${f(colab?.ctps_serie)}</u></p>
      </div>
      <p style="font-weight:bold;text-align:center;margin:0 0 6px 0;font-size:9pt;">DADOS DO ENDEREÇO</p>
      <div style="border:1px solid #000;padding:10px 14px;margin-bottom:12px;font-size:9.5pt;">
        <p style="margin:0 0 6px 0;">LOGRADOURO: <u>${f(colab?.logradouro)}</u> &nbsp; Nº: <u>${f(colab?.numero)}</u></p>
        <p style="margin:0 0 6px 0;">COMPLEMENTO: <u>${f(colab?.complemento)}</u> &nbsp; BAIRRO: <u>${f(colab?.bairro)}</u></p>
        <p style="margin:0 0 6px 0;">CIDADE: <u>${f(colab?.cidade)}</u> &nbsp; UF: <u>${f(colab?.uf)}</u> &nbsp; CEP: <u>${f(colab?.cep)}</u></p>
        <p style="margin:0;">TELEFONES: ( ) <u>${f(colab?.telefone1)}</u></p>
      </div>
      <p style="margin:0 0 40px 0;font-size:9.5pt;">_________________, _____ de ________________ de _________.</p>
      <div style="border-top:1px solid #000;width:260px;padding-top:5px;font-size:9.5pt;text-align:center;">ASSINATURA DO TITULAR</div>
    </div>`;
}

function gerarHTMLDependente(colab, dep, movimentacao) {
  const movMap = {
    INCLUSAO: "(X) INCLUSÃO &nbsp; ( ) ALTERAÇÃO &nbsp; ( ) EXCLUSÃO",
    ALTERACAO: "( ) INCLUSÃO &nbsp; (X) ALTERAÇÃO &nbsp; ( ) EXCLUSÃO",
    EXCLUSAO:  "( ) INCLUSÃO &nbsp; ( ) ALTERAÇÃO &nbsp; (X) EXCLUSÃO",
  };
  const parentescoMap = {
    CONJUGE:     "(X) CÔNJUGE &nbsp; ( ) FILHO(A) &nbsp; ( ) COMPANHEIRO(A) &nbsp; ( ) OUTROS",
    FILHO:       "( ) CÔNJUGE &nbsp; (X) FILHO(A) &nbsp; ( ) COMPANHEIRO(A) &nbsp; ( ) OUTROS",
    COMPANHEIRO: "( ) CÔNJUGE &nbsp; ( ) FILHO(A) &nbsp; (X) COMPANHEIRO(A) &nbsp; ( ) OUTROS",
    OUTROS:      "( ) CÔNJUGE &nbsp; ( ) FILHO(A) &nbsp; ( ) COMPANHEIRO(A) &nbsp; (X) OUTROS",
  };
  return `
    <div style="font-family:Arial,sans-serif;font-size:10pt;line-height:1.5;max-width:700px;margin:0 auto;padding:20px 28px;color:#000;">
      <div style="text-align:center;margin-bottom:6px;"><img src="${LOGO_BENEL}" alt="Benel" style="height:55px;" /></div>
      <h2 style="text-align:center;font-size:12pt;font-weight:bold;text-transform:uppercase;margin:0 0 2px 0;">PROPOSTA PLANO DE ASSISTÊNCIA MÉDICA</h2>
      <h3 style="text-align:center;font-size:11pt;font-weight:bold;text-transform:uppercase;margin:0 0 12px 0;">DEPENDENTES</h3>
      <p style="font-weight:bold;text-align:center;margin:0 0 6px 0;font-size:9pt;">DADOS DA MOVIMENTAÇÃO</p>
      <div style="border:1px solid #000;padding:6px 14px;margin-bottom:12px;font-size:9.5pt;">${movMap[movimentacao] || movMap.INCLUSAO}</div>
      <p style="font-weight:bold;text-align:center;margin:0 0 6px 0;font-size:9pt;">DADOS PESSOAIS DO DEPENDENTE</p>
      <div style="border:1px solid #000;padding:10px 14px;margin-bottom:12px;font-size:9.5pt;">
        <p style="margin:0 0 6px 0;">C.P.F.: <u>${dep?.dep_cpf || "_______________"}</u> &nbsp;&nbsp; NOME: <u>${dep?.dep_nome || "___________________________"}</u></p>
        <p style="margin:0 0 6px 0;">SEXO: ${dep?.dep_sexo === "M" ? "(X) MASCULINO &nbsp; ( ) FEMININO" : "(  ) MASCULINO &nbsp; (X) FEMININO"} &nbsp;&nbsp; DATA NASC.: <u>${fmtDataPS(dep?.dep_data_nasc) || "___/___/______"}</u> &nbsp; ESTADO CIVIL: <u>${dep?.dep_estado_civil || "_______________"}</u></p>
        <p style="margin:0 0 6px 0;">DATA DE CASAMENTO: <u>${fmtDataPS(dep?.dep_data_casamento) || "___/___/______"}</u></p>
        <p style="margin:0 0 4px 0;">GRAU DE PARENTESCO:</p>
        <p style="margin:0 0 6px 16px;">${parentescoMap[dep?.dep_grau_parentesco] || parentescoMap.CONJUGE}</p>
        <p style="margin:0;">NOME DA MÃE: <u>${dep?.dep_nome_mae || "___________________________"}</u></p>
      </div>
      <p style="font-size:8.5pt;color:#555;margin:0 0 6px 0;">Titular: ${colab?.nome || ""} — Matrícula: ${colab?.chapa || ""}</p>
      <p style="margin:0 0 40px 0;font-size:9.5pt;">_________________, _____ de ________________ de _________.</p>
      <div style="border-top:1px solid #000;width:260px;padding-top:5px;font-size:9.5pt;text-align:center;">ASSINATURA DO TITULAR</div>
    </div>`;
}

// ── Componente PlanoSaude ─────────────────────────────────────────────────────
function PlanoSaude({ user, colaboradores }) {
  const [lista, setLista]         = useState([]);
  const [loading, setLoading]     = useState(false);
  const [tipo, setTipo]           = useState(null); // null | "TITULAR" | "DEPENDENTE"
  const [modalPreview, setModalPreview] = useState(null);
  const [salvando, setSalvando]   = useState(false);
  const [msg, setMsg]             = useState(null);
  const [anexosModal, setAnexosModal] = useState(null);

  const [colabSel, setColabSel]   = useState(null);
  const [buscaColab, setBuscaColab] = useState("");
  const [movimentacao, setMovimentacao] = useState("INCLUSAO");

  const [depTitularSel, setDepTitularSel] = useState(null);
  const [buscaDep, setBuscaDep]   = useState("");
  const [depMov, setDepMov]       = useState("INCLUSAO");
  const [dep, setDep]             = useState({ dep_cpf:"", dep_nome:"", dep_sexo:"M", dep_data_nasc:"", dep_estado_civil:"", dep_data_casamento:"", dep_grau_parentesco:"CONJUGE", dep_nome_mae:"" });
  const [anexos, setAnexos]       = useState([]);

  const norm = s => (s||"").toLowerCase();
  const colsFilt = colaboradores
    .filter(c => c.cod_situacao !== "D")
    .filter(c => !buscaColab || norm(c.nome).includes(norm(buscaColab)) || (c.chapa||"").includes(buscaColab));
  const colsDepFilt = colaboradores
    .filter(c => c.cod_situacao !== "D")
    .filter(c => !buscaDep || norm(c.nome).includes(norm(buscaDep)) || (c.chapa||"").includes(buscaDep));

  const carregar = async () => {
    setLoading(true);
    try { const d = await api.listarPlanoSaude(); setLista(Array.isArray(d) ? d : []); }
    catch (e) { setMsg({ tipo:"erro", texto:"Erro: "+e.message }); }
    finally { setLoading(false); }
  };
  useEffect(() => { carregar(); }, []);

  const reset = () => {
    setColabSel(null); setBuscaColab(""); setMovimentacao("INCLUSAO");
    setDepTitularSel(null); setBuscaDep(""); setDepMov("INCLUSAO");
    setDep({ dep_cpf:"", dep_nome:"", dep_sexo:"M", dep_data_nasc:"", dep_estado_civil:"", dep_data_casamento:"", dep_grau_parentesco:"CONJUGE", dep_nome_mae:"" });
    setAnexos([]);
  };

  const onAnexo = (tipo_anexo) => (e) => {
    const file = e.target.files[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => setAnexos(prev => [...prev.filter(a=>a.tipo_anexo!==tipo_anexo), { nome_arquivo:file.name, tipo_anexo, dados_base64:ev.target.result.split(",")[1] }]);
    reader.readAsDataURL(file);
  };

  const FILIAIS_BLOQUEADAS = ["7"];
  const checarFilialBloqueada = (colab) => {
    if (colab && FILIAIS_BLOQUEADAS.includes(String(colab.cod_filial))) {
      setMsg({ tipo:"erro", texto:"⚠️ O plano Hapvida não atende a filial 7 — São Mateus. Solicitação não permitida." });
      return true;
    }
    return false;
  };

  const salvarTitular = async () => {
    if (!colabSel) { setMsg({ tipo:"erro", texto:"Selecione o colaborador." }); return; }
    if (checarFilialBloqueada(colabSel)) return;
    setSalvando(true);
    try {
      const novo = await api.criarPlanoSaude({ tipo:"TITULAR", movimentacao, colaborador_id:colabSel.id });
      for (const a of anexos) await api.addAnexoPlanoSaude(novo.id, a);
      setMsg({ tipo:"ok", texto:"Solicitação criada!" }); setTipo(null); reset(); carregar();
    } catch(e) { setMsg({ tipo:"erro", texto:e.message }); }
    finally { setSalvando(false); }
  };

  const salvarDependente = async () => {
    if (!depTitularSel) { setMsg({ tipo:"erro", texto:"Selecione o titular." }); return; }
    if (checarFilialBloqueada(depTitularSel)) return;
    if (!dep.dep_nome.trim()) { setMsg({ tipo:"erro", texto:"Informe o nome do dependente." }); return; }
    setSalvando(true);
    try {
      const novo = await api.criarPlanoSaude({ tipo:"DEPENDENTE", movimentacao:depMov, colaborador_id:depTitularSel.id, ...dep });
      for (const a of anexos) await api.addAnexoPlanoSaude(novo.id, a);
      setMsg({ tipo:"ok", texto:"Dependente registrado!" }); setTipo(null); reset(); carregar();
    } catch(e) { setMsg({ tipo:"erro", texto:e.message }); }
    finally { setSalvando(false); }
  };

  const imprimir = () => {
    const w = window.open("","_blank");
    w.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Plano de Saúde</title></head><body>${modalPreview}</body></html>`);
    w.document.close(); setTimeout(()=>{ w.focus(); w.print(); }, 400);
  };

  // ── Estilos compactos seguindo padrão do sistema ──────────────────────────
  const S = {
    page:   { padding:"16px 20px", maxWidth:960, margin:"0 auto" },
    header: { display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:16 },
    title:  { margin:0, fontSize:16, fontWeight:800, color:"#111827" },
    sub:    { margin:"2px 0 0", fontSize:11, color:"#6B7280" },
    btnP:   { background:"#0F2447", color:"#fff", border:"none", borderRadius:8, padding:"8px 18px", fontSize:12, fontWeight:700, cursor:"pointer" },
    btnS:   { background:"#F3F4F6", color:"#374151", border:"1px solid #D1D5DB", borderRadius:8, padding:"8px 14px", fontSize:12, fontWeight:600, cursor:"pointer" },
    card:   { background:"#fff", borderRadius:10, border:"1px solid #E5E7EB", padding:"10px 16px", marginBottom:8, display:"flex", alignItems:"center", justifyContent:"space-between" },
    inp:    { width:"100%", padding:"6px 10px", border:"1px solid #D1D5DB", borderRadius:6, fontSize:12, boxSizing:"border-box" },
    lbl:    { fontSize:11, fontWeight:600, color:"#374151", display:"block", marginBottom:3 },
    modal:  { position:"fixed", inset:0, background:"rgba(0,0,0,.5)", zIndex:1000, display:"flex", alignItems:"center", justifyContent:"center" },
    mbox:   { background:"#fff", borderRadius:14, padding:"24px 28px", width:"100%", maxWidth:680, maxHeight:"90vh", overflowY:"auto", boxShadow:"0 20px 60px rgba(0,0,0,.25)" },
  };

  // Seletor de tipo igual ao padrão Advertência/Suspensão
  const SeletorTipo = () => (
    <div style={S.modal}>
      <div style={{ ...S.mbox, maxWidth:420 }}>
        <h3 style={{ margin:"0 0 20px", fontSize:15, fontWeight:800, color:"#0F2447" }}>Nova Solicitação — Plano de Saúde</h3>
        <div style={{ display:"flex", gap:12, marginBottom:20 }}>
          <button
            onClick={() => setTipo("TITULAR")}
            style={{ flex:1, padding:"18px 12px", borderRadius:10, border:"2px solid #0F2447", background:"#EFF6FF", cursor:"pointer", textAlign:"center" }}>
            <div style={{ fontSize:22, marginBottom:6 }}>👤</div>
            <div style={{ fontSize:13, fontWeight:700, color:"#0F2447" }}>Titular</div>
            <div style={{ fontSize:11, color:"#6B7280", marginTop:2 }}>Inclusão do colaborador</div>
          </button>
          <button
            onClick={() => setTipo("DEPENDENTE")}
            style={{ flex:1, padding:"18px 12px", borderRadius:10, border:"2px solid #7C3AED", background:"#F5F3FF", cursor:"pointer", textAlign:"center" }}>
            <div style={{ fontSize:22, marginBottom:6 }}>👨‍👩‍👧</div>
            <div style={{ fontSize:13, fontWeight:700, color:"#7C3AED" }}>Dependente</div>
            <div style={{ fontSize:11, color:"#6B7280", marginTop:2 }}>Inclusão de dependente</div>
          </button>
        </div>
        <div style={{ textAlign:"right" }}>
          <button style={S.btnS} onClick={() => { setTipo(null); reset(); }}>Cancelar</button>
        </div>
      </div>
    </div>
  );

  const BuscaColab = ({ busca, setBusca, sel, onSel, lista, label }) => (
    <div style={{ marginBottom:14 }}>
      <label style={S.lbl}>{label} *</label>
      {sel ? (
        <div style={{ padding:"6px 10px", background:"#EFF6FF", borderRadius:6, fontSize:12, color:"#1E40AF", fontWeight:600, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          ✓ {sel.nome} — {sel.chapa}
          <button onClick={() => { onSel(null); setBusca(""); }} style={{ background:"none", border:"none", cursor:"pointer", color:"#6B7280", fontSize:14 }}>×</button>
        </div>
      ) : (
        <>
          <input style={S.inp} placeholder="Digite nome ou matrícula..." value={busca}
            onChange={e => setBusca(e.target.value)} autoFocus />
          {busca.length > 0 && lista.length > 0 && (
            <div style={{ border:"1px solid #E5E7EB", borderRadius:6, maxHeight:160, overflowY:"auto", marginTop:2, background:"#fff", boxShadow:"0 4px 12px rgba(0,0,0,.1)" }}>
              {lista.slice(0,8).map(c => (
                <div key={c.id} onClick={() => { onSel(c); setBusca(""); }}
                  style={{ padding:"7px 10px", cursor:"pointer", fontSize:12, borderBottom:"1px solid #F3F4F6" }}
                  onMouseEnter={e=>e.currentTarget.style.background="#F3F4F6"}
                  onMouseLeave={e=>e.currentTarget.style.background=""}>
                  <strong>{c.nome}</strong> <span style={{ color:"#6B7280" }}>• {c.chapa} • {c.funcao}</span>
                </div>
              ))}
            </div>
          )}
          {busca.length > 0 && lista.length === 0 && (
            <div style={{ padding:"8px 10px", fontSize:12, color:"#9CA3AF", border:"1px solid #E5E7EB", borderRadius:6, marginTop:2 }}>Nenhum resultado.</div>
          )}
        </>
      )}
    </div>
  );

  const InfoColab = ({ c }) => c ? (
    <div style={{ background:"#FFFBEB", border:"1px solid #FDE68A", borderRadius:8, padding:"10px 14px", marginBottom:14 }}>
      {["7"].includes(String(c.cod_filial)) && (
        <div style={{ background:"#FEE2E2", border:"1px solid #FECACA", borderRadius:6, padding:"8px 12px", marginBottom:10, fontSize:12, fontWeight:700, color:"#991B1B" }}>
          ⚠️ Filial 7 — São Mateus: o plano Hapvida não atende esta localidade. Solicitação não permitida.
        </div>
      )}
      <p style={{ margin:"0 0 8px", fontSize:11, fontWeight:700, color:"#92400E" }}>ℹ️ Dados no sistema — campos em vermelho aparecerão em branco no formulário</p>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:6, fontSize:11 }}>
        {[["CPF",c.cpf],["RG",c.rg],["PIS",c.pis],["CTPS",c.ctps],["Nome da Mãe",c.nome_mae],["Endereço",c.logradouro]].map(([k,v])=>(
          <div key={k} style={{ background:v?"#F0FDF4":"#FEF2F2", border:`1px solid ${v?"#BBF7D0":"#FECACA"}`, borderRadius:5, padding:"3px 8px" }}>
            <span style={{ color:"#6B7280" }}>{k}: </span>
            <strong style={{ color:v?"#065F46":"#991B1B" }}>{v||"Não informado"}</strong>
          </div>
        ))}
      </div>
    </div>
  ) : null;

  return (
    <div style={S.page}>
      {/* Header */}
      <div style={S.header}>
        <div>
          <h2 style={S.title}>💊 Solicitação de Plano de Saúde</h2>
          <p style={S.sub}>Proposta de Assistência Médica — Hapvida</p>
        </div>
        <button style={S.btnP} onClick={() => { reset(); setTipo("SELECIONAR"); }}>+ Nova Solicitação</button>
      </div>

      {/* Msg */}
      {msg && (
        <div style={{ padding:"8px 14px", borderRadius:7, marginBottom:12, background:msg.tipo==="ok"?"#D1FAE5":"#FEE2E2", color:msg.tipo==="ok"?"#065F46":"#991B1B", fontSize:12, fontWeight:600, display:"flex", justifyContent:"space-between" }}>
          {msg.texto}
          <button onClick={()=>setMsg(null)} style={{ background:"none", border:"none", cursor:"pointer", fontSize:14 }}>×</button>
        </div>
      )}

      {/* Lista */}
      {loading ? null : lista.length === 0 ? (
        <div style={{ textAlign:"center", padding:60, color:"#9CA3AF", fontSize:13 }}>Nenhuma solicitação registrada.</div>
      ) : lista.map(s => (
        <div key={s.id} style={S.card}>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <span style={{ fontSize:11, fontWeight:700, padding:"2px 8px", borderRadius:8, background:s.tipo==="TITULAR"?"#DBEAFE":"#EDE9FE", color:s.tipo==="TITULAR"?"#1E40AF":"#5B21B6" }}>{s.tipo}</span>
            <span style={{ fontSize:12, fontWeight:700, color:"#111827" }}>{s.colaborador_nome}</span>
            <span style={{ fontSize:11, color:"#6B7280" }}>#{s.chapa}</span>
            {s.tipo==="DEPENDENTE" && <span style={{ fontSize:11, color:"#7C3AED" }}>→ {s.dep_nome}</span>}
            <span style={{ fontSize:10, color:"#9CA3AF" }}>• {s.movimentacao} • {new Date(s.criado_em).toLocaleDateString("pt-BR")}</span>
          </div>
          <div style={{ display:"flex", gap:6 }}>
            <button style={{ ...S.btnS, padding:"4px 10px", fontSize:11 }}
              onClick={() => setModalPreview(s.tipo==="TITULAR" ? gerarHTMLTitular(s,s.movimentacao) : gerarHTMLDependente(s,s,s.movimentacao))}>
              🖨 Imprimir
            </button>
            <button style={{ ...S.btnS, padding:"4px 10px", fontSize:11 }} onClick={() => setAnexosModal(s)}>📎 Anexos</button>
          </div>
        </div>
      ))}

      {/* MODAL SELETOR TIPO */}
      {tipo === "SELECIONAR" && <SeletorTipo />}

      {/* MODAL TITULAR */}
      {tipo === "TITULAR" && (
        <div style={S.modal}>
          <div style={S.mbox}>
            <h3 style={{ margin:"0 0 16px", fontSize:15, fontWeight:800, color:"#0F2447" }}>Nova Solicitação — Titular</h3>
            <BuscaColab busca={buscaColab} setBusca={setBuscaColab} sel={colabSel} onSel={setColabSel} lista={colsFilt} label="Colaborador" />
            <InfoColab c={colabSel} />
            <div style={{ marginBottom:14 }}>
              <label style={S.lbl}>Movimentação *</label>
              <select style={S.inp} value={movimentacao} onChange={e=>setMovimentacao(e.target.value)}>
                <option value="INCLUSAO">Inclusão</option>
                <option value="NAO_OPTANTE">Não Optante</option>
                <option value="ALTERACAO">Alteração</option>
                <option value="EXCLUSAO">Exclusão</option>
              </select>
            </div>
            <button style={{ ...S.btnS, width:"100%", marginBottom:4 }}
              onClick={() => { if (!colabSel) { setMsg({tipo:"erro",texto:"Selecione o colaborador."}); return; } setModalPreview(gerarHTMLTitular(colabSel,movimentacao)); }}>
              👁 Visualizar / Imprimir Formulário
            </button>
            <p style={{ fontSize:10, color:"#6B7280", margin:"0 0 16px" }}>Após imprimir, o titular assina e data manualmente.</p>
            <div style={{ display:"flex", gap:8, justifyContent:"flex-end" }}>
              <button style={S.btnS} onClick={() => { setTipo(null); reset(); }}>Cancelar</button>
              <button style={S.btnP} onClick={salvarTitular} disabled={salvando}>{salvando?"Salvando...":"Registrar Solicitação"}</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL DEPENDENTE */}
      {tipo === "DEPENDENTE" && (
        <div style={S.modal}>
          <div style={S.mbox}>
            <h3 style={{ margin:"0 0 16px", fontSize:15, fontWeight:800, color:"#0F2447" }}>Nova Solicitação — Dependente</h3>
            <BuscaColab busca={buscaDep} setBusca={setBuscaDep} sel={depTitularSel} onSel={setDepTitularSel} lista={colsDepFilt} label="Titular (Colaborador)" />
            <div style={{ marginBottom:14 }}>
              <label style={S.lbl}>Movimentação *</label>
              <select style={S.inp} value={depMov} onChange={e=>setDepMov(e.target.value)}>
                <option value="INCLUSAO">Inclusão</option>
                <option value="ALTERACAO">Alteração</option>
                <option value="EXCLUSAO">Exclusão</option>
              </select>
            </div>
            <div style={{ background:"#F9FAFB", border:"1px solid #E5E7EB", borderRadius:8, padding:"12px 14px", marginBottom:14 }}>
              <p style={{ margin:"0 0 10px", fontSize:11, fontWeight:700, color:"#374151" }}>DADOS DO DEPENDENTE</p>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
                <div><label style={S.lbl}>CPF</label><input style={S.inp} value={dep.dep_cpf} onChange={e=>setDep(p=>({...p,dep_cpf:e.target.value}))} placeholder="000.000.000-00" /></div>
                <div><label style={S.lbl}>Nome *</label><input style={S.inp} value={dep.dep_nome} onChange={e=>setDep(p=>({...p,dep_nome:e.target.value}))} /></div>
                <div><label style={S.lbl}>Sexo</label>
                  <select style={S.inp} value={dep.dep_sexo} onChange={e=>setDep(p=>({...p,dep_sexo:e.target.value}))}>
                    <option value="M">Masculino</option><option value="F">Feminino</option>
                  </select>
                </div>
                <div><label style={S.lbl}>Data de Nascimento</label><input type="date" style={S.inp} value={dep.dep_data_nasc} onChange={e=>setDep(p=>({...p,dep_data_nasc:e.target.value}))} /></div>
                <div><label style={S.lbl}>Estado Civil</label>
                  <select style={S.inp} value={dep.dep_estado_civil} onChange={e=>setDep(p=>({...p,dep_estado_civil:e.target.value}))}>
                    <option value="">Selecione</option><option>Solteiro(a)</option><option>Casado(a)</option>
                    <option>Divorciado(a)</option><option>Viúvo(a)</option><option>União Estável</option>
                  </select>
                </div>
                <div><label style={S.lbl}>Data de Casamento</label><input type="date" style={S.inp} value={dep.dep_data_casamento} onChange={e=>setDep(p=>({...p,dep_data_casamento:e.target.value}))} /></div>
                <div style={{ gridColumn:"1/-1" }}><label style={S.lbl}>Grau de Parentesco</label>
                  <select style={S.inp} value={dep.dep_grau_parentesco} onChange={e=>setDep(p=>({...p,dep_grau_parentesco:e.target.value}))}>
                    <option value="CONJUGE">Cônjuge</option><option value="FILHO">Filho(a)</option>
                    <option value="COMPANHEIRO">Companheiro(a)</option><option value="OUTROS">Outros</option>
                  </select>
                </div>
                <div style={{ gridColumn:"1/-1" }}><label style={S.lbl}>Nome da Mãe do Dependente</label><input style={S.inp} value={dep.dep_nome_mae} onChange={e=>setDep(p=>({...p,dep_nome_mae:e.target.value}))} /></div>
              </div>
            </div>
            <div style={{ background:"#F9FAFB", border:"1px solid #E5E7EB", borderRadius:8, padding:"12px 14px", marginBottom:14 }}>
              <p style={{ margin:"0 0 10px", fontSize:11, fontWeight:700, color:"#374151" }}>📎 DOCUMENTOS</p>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:8 }}>
                {[
                  { key:"FORMULARIO_ASSINADO", label:"Formulário Assinado" },
                  { key:"RG_DEPENDENTE", label:"RG do Dependente" },
                  { key:dep.dep_grau_parentesco==="FILHO"?"CERTIDAO_NASCIMENTO":"CERTIDAO_CASAMENTO", label:dep.dep_grau_parentesco==="FILHO"?"Certidão de Nascimento":"Certidão de Casamento" },
                ].map(({key,label}) => {
                  const found = anexos.find(a=>a.tipo_anexo===key);
                  return (
                    <div key={key} style={{ border:`1px dashed ${found?"#34D399":"#D1D5DB"}`, borderRadius:7, padding:10, textAlign:"center", background:found?"#F0FDF4":"#fff" }}>
                      <p style={{ margin:"0 0 6px", fontSize:10, fontWeight:600, color:found?"#065F46":"#6B7280" }}>{label}</p>
                      {found ? (
                        <div>
                          <p style={{ margin:"0 0 3px", fontSize:10, color:"#065F46" }}>✓ {found.nome_arquivo}</p>
                          <button onClick={()=>setAnexos(prev=>prev.filter(a=>a.tipo_anexo!==key))} style={{ fontSize:10, color:"#991B1B", background:"none", border:"none", cursor:"pointer" }}>Remover</button>
                        </div>
                      ) : (
                        <label style={{ cursor:"pointer", fontSize:11, color:"#3B82F6" }}>
                          📁 Selecionar
                          <input type="file" style={{ display:"none" }} accept=".pdf,.jpg,.jpeg,.png" onChange={onAnexo(key)} />
                        </label>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
            <button style={{ ...S.btnS, width:"100%", marginBottom:4 }}
              onClick={() => { if (!depTitularSel) { setMsg({tipo:"erro",texto:"Selecione o titular."}); return; } setModalPreview(gerarHTMLDependente(depTitularSel,dep,depMov)); }}>
              👁 Visualizar / Imprimir Formulário
            </button>
            <p style={{ fontSize:10, color:"#6B7280", margin:"0 0 16px" }}>
              Imprima, assine e date manualmente. Anexe RG e {dep.dep_grau_parentesco==="FILHO"?"certidão de nascimento":"certidão de casamento"}.
            </p>
            <div style={{ display:"flex", gap:8, justifyContent:"flex-end" }}>
              <button style={S.btnS} onClick={() => { setTipo(null); reset(); }}>Cancelar</button>
              <button style={S.btnP} onClick={salvarDependente} disabled={salvando}>{salvando?"Salvando...":"Registrar Solicitação"}</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL PREVIEW */}
      {modalPreview && (
        <div style={{ ...S.modal, zIndex:1100 }}>
          <div style={{ background:"#fff", borderRadius:12, width:"100%", maxWidth:760, maxHeight:"90vh", overflowY:"auto", boxShadow:"0 20px 60px rgba(0,0,0,.3)" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"12px 20px", borderBottom:"1px solid #E5E7EB" }}>
              <h4 style={{ margin:0, fontSize:14, fontWeight:700, color:"#0F2447" }}>📄 Pré-visualização</h4>
              <div style={{ display:"flex", gap:8 }}>
                <button style={{ ...S.btnP, padding:"6px 14px" }} onClick={imprimir}>🖨 Imprimir</button>
                <button style={S.btnS} onClick={()=>setModalPreview(null)}>Fechar</button>
              </div>
            </div>
            <div dangerouslySetInnerHTML={{ __html:modalPreview }} style={{ padding:"12px 20px" }} />
          </div>
        </div>
      )}

      {/* MODAL ANEXOS */}
      {anexosModal && (
        <div style={{ ...S.modal, zIndex:1100 }}>
          <div style={{ background:"#fff", borderRadius:12, padding:"20px 24px", width:"100%", maxWidth:480 }}>
            <h4 style={{ margin:"0 0 12px", fontSize:14, fontWeight:700, color:"#0F2447" }}>📎 Anexos — #{anexosModal.id} {anexosModal.colaborador_nome}</h4>
            {[
              { key:"FORMULARIO_ASSINADO", label:"Formulário Assinado" },
              { key:"RG_DEPENDENTE", label:"RG do Dependente" },
              { key:"CERTIDAO_CASAMENTO", label:"Certidão de Casamento/Nascimento" },
            ].map(({key,label}) => (
              <div key={key} style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"8px 0", borderBottom:"1px solid #F3F4F6" }}>
                <span style={{ fontSize:12, color:"#374151" }}>{label}</span>
                <label style={{ cursor:"pointer", fontSize:11, color:"#3B82F6", fontWeight:600 }}>
                  📁 Enviar
                  <input type="file" style={{ display:"none" }} accept=".pdf,.jpg,.jpeg,.png"
                    onChange={async(e) => {
                      const file = e.target.files[0]; if (!file) return;
                      const reader = new FileReader();
                      reader.onload = async(ev) => {
                        try {
                          await api.addAnexoPlanoSaude(anexosModal.id, { nome_arquivo:file.name, tipo_anexo:key, dados_base64:ev.target.result.split(",")[1] });
                          setMsg({tipo:"ok",texto:`${label} enviado!`});
                        } catch(err) { setMsg({tipo:"erro",texto:err.message}); }
                      };
                      reader.readAsDataURL(file);
                    }}
                  />
                </label>
              </div>
            ))}
            <div style={{ marginTop:14, textAlign:"right" }}>
              <button style={S.btnS} onClick={()=>setAnexosModal(null)}>Fechar</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENTE: AtualizacaoCadastral
// ════════════════════════════════════════════════════════════════════════════

const DOMINIO_POSICAO_ESCALA = [
  { cod: "FA", desc: "Faltista" },
  { cod: "FE", desc: "Ferista" },
  { cod: "FO", desc: "Folguista" },
  { cod: "NA", desc: "Não Aplica" },
  { cod: "TI", desc: "Titular" },
];
const DOMINIO_SIM_NAO = [{ cod: "T", desc: "Sim" }, { cod: "F", desc: "Não" }];
const DOMINIO_MACACAO = ["PP","P","M","G","GG","EG","EEG"];
const DOMINIO_BOTA    = Array.from({ length: 15 }, (_, i) => String(34 + i));

const CAMPOS_CONFIG = {
  posicao_escala:  { label: "Posição Escala",  dominio: DOMINIO_POSICAO_ESCALA, tipo: "select_obj" },
  motorista_lider: { label: "Motorista Líder", dominio: DOMINIO_SIM_NAO,        tipo: "select_obj" },
  munkeiro:        { label: "Munkeiro",         dominio: DOMINIO_SIM_NAO,        tipo: "select_obj" },
  prancheiro:      { label: "Prancheiro",       dominio: DOMINIO_SIM_NAO,        tipo: "select_obj" },
  tamanho_macacao: { label: "Tamanho Macacão",  dominio: DOMINIO_MACACAO,        tipo: "select_str" },
  tamanho_bota:    { label: "Tamanho Bota",     dominio: DOMINIO_BOTA,           tipo: "select_str" },
};

const AC_STATUS_CONFIG = {
  solicitado:  { label: "Solicitado",  bg: "#FEF3C7", color: "#92400E" },
  em_analise:  { label: "Em Análise", bg: "#DBEAFE", color: "#1E40AF" },
  aprovado:    { label: "Aprovado",   bg: "#D1FAE5", color: "#065F46" },
  reprovado:   { label: "Reprovado",  bg: "#FEE2E2", color: "#991B1B" },
  finalizado:  { label: "Finalizado", bg: "#F3F4F6", color: "#374151" },
};

function labelValor(campo, val) {
  if (!val) return "—";
  const cfg = CAMPOS_CONFIG[campo];
  if (!cfg) return val;
  if (cfg.tipo === "select_obj") {
    const found = cfg.dominio.find(d => d.cod === val);
    return found ? `${found.cod} — ${found.desc}` : val;
  }
  return val;
}

function AtualizacaoCadastral({ user, colaboradores }) {
  const [aba, setAba]           = useState("colaboradores"); // "colaboradores" | "solicitacoes"
  const [solicitacoes, setSolicitacoes] = useState([]);
  const [loadingSols, setLoadingSols]   = useState(false);
  const [msg, setMsg]           = useState(null);
  const [salvando, setSalvando] = useState(false);

  // Filtros colaboradores
  const [fNome, setFNome]             = useState("");
  const [fNomeCompleto, setFNomeCompleto] = useState("");
  const [fFuncao, setFuncao]          = useState("");
  const [fFilial, setFFilial]         = useState("");

  // Filtros solicitações
  const [fStatus, setFStatus]   = useState("todos");
  const [fDataIni, setFDataIni] = useState("");
  const [fDataFim, setFDataFim] = useState("");
  const [fSolic, setFSolic]     = useState("");

  // Modal solicitação
  const [modalNova, setModalNova]   = useState(null); // colaborador selecionado
  const [itens, setItens]           = useState({});
  const [observacao, setObservacao] = useState("");

  // Modal detalhe
  const [modalDetalhe, setModalDetalhe] = useState(null);
  const [obsAprov, setObsAprov]         = useState("");

  const norm = s => (s || "").toLowerCase();
  const canAprovar = user?.perfil === "dp" || user?.perfil === "admin" || user?.perfil === "presidente";

  const colabsAtivos = colaboradores.filter(c => c.cod_situacao !== "D");
  const fmtFilial = (c) => {
    const f = c.descricao_filial || c.desc_cc || "";
    return f.replace(/^BENEL TRANSPORTES\s*[-–]\s*/i, "").trim();
  };

  const colabsFiltrados = colabsAtivos.filter(c =>
    (!fNome          || (c.chapa||"").toLowerCase().includes(fNome.toLowerCase())) &&
    (!fNomeCompleto  || norm(c.nome).includes(norm(fNomeCompleto))) &&
    (!fFuncao        || norm(c.funcao||"").includes(norm(fFuncao))) &&
    (!fFilial        || norm(fmtFilial(c)).includes(norm(fFilial)) || norm(c.desc_cc||"").includes(norm(fFilial)))
  );

  const carregarSols = async () => {
    setLoadingSols(true);
    try {
      const params = {};
      if (fStatus !== "todos") params.status = fStatus;
      if (fDataIni) params.data_inicio = fDataIni;
      if (fDataFim) params.data_fim = fDataFim;
      if (fSolic)   params.solicitante = fSolic;
      const data = await api.listarAtualizacaoCadastral(params);
      setSolicitacoes(Array.isArray(data) ? data : []);
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
    finally { setLoadingSols(false); }
  };

  useEffect(() => { if (aba === "solicitacoes") carregarSols(); }, [aba]);

  const salvar = async () => {
    if (!modalNova) return;
    const itensList = Object.entries(itens).filter(([,v]) => v).map(([campo, novo_valor]) => ({ campo, novo_valor }));
    if (itensList.length === 0) { setMsg({ tipo: "erro", texto: "Selecione ao menos um campo para alterar." }); return; }
    setSalvando(true);
    try {
      await api.criarAtualizacaoCadastral({ colaborador_id: modalNova.id, itens: itensList, observacao });
      setMsg({ tipo: "ok", texto: "Solicitação criada com sucesso!" });
      setModalNova(null); setItens({}); setObservacao("");
      if (aba === "solicitacoes") carregarSols();
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
    finally { setSalvando(false); }
  };

  const aprovar = async (acao) => {
    setSalvando(true);
    try {
      await api.aprovarAtualizacaoCadastral(modalDetalhe.id, acao, obsAprov);
      setMsg({ tipo: "ok", texto: `Solicitação ${acao === "aprovar" ? "aprovada" : "reprovada"}!` });
      setModalDetalhe(null); setObsAprov(""); carregarSols();
    } catch (e) { setMsg({ tipo: "erro", texto: e.message }); }
    finally { setSalvando(false); }
  };

  const S = {
    inp:  { width: "100%", padding: "6px 10px", border: "1px solid #D1D5DB", borderRadius: 6, fontSize: 12, boxSizing: "border-box" },
    lbl:  { fontSize: 11, fontWeight: 600, color: "#374151", display: "block", marginBottom: 3 },
    btnP: { background: "#0F2447", color: "#fff", border: "none", borderRadius: 8, padding: "8px 18px", fontSize: 12, fontWeight: 700, cursor: "pointer" },
    btnS: { background: "#F3F4F6", color: "#374151", border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer" },
    btnV: { background: "#059669", color: "#fff", border: "none", borderRadius: 8, padding: "8px 14px", fontSize: 12, fontWeight: 700, cursor: "pointer" },
    btnR: { background: "#DC2626", color: "#fff", border: "none", borderRadius: 8, padding: "8px 14px", fontSize: 12, fontWeight: 700, cursor: "pointer" },
    modal:{ position: "fixed", inset: 0, background: "rgba(0,0,0,.5)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" },
    mbox: { background: "#fff", borderRadius: 14, padding: "24px 28px", width: "100%", maxWidth: 700, maxHeight: "90vh", overflowY: "auto", boxShadow: "0 20px 60px rgba(0,0,0,.25)" },
    th:   { padding: "10px 10px", textAlign: "left", fontSize: 10, fontWeight: 700, color: "#6B7280", textTransform: "uppercase", letterSpacing: 0.5, whiteSpace: "nowrap" },
    td:   { padding: "9px 10px", fontSize: 11, borderBottom: "1px solid #F3F4F6" },
  };

  const SimNaoTag = ({ val }) => {
    if (!val) return <span style={{ color: "#9CA3AF" }}>—</span>;
    return <span style={{ padding: "2px 8px", borderRadius: 8, fontSize: 10, fontWeight: 700, background: val === "T" ? "#D1FAE5" : "#FEE2E2", color: val === "T" ? "#065F46" : "#991B1B" }}>{val === "T" ? "Sim" : "Não"}</span>;
  };

  return (
    <div style={{ padding: "16px 20px", maxWidth: 1200, margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: "#111827" }}>📝 Atualização de Dados Cadastrais</h2>
          <p style={{ margin: "2px 0 0", fontSize: 11, color: "#6B7280" }}>Solicitação de alteração com aprovação do DP</p>
        </div>
      </div>

      {/* Msg */}
      {msg && (
        <div style={{ padding: "8px 14px", borderRadius: 7, marginBottom: 12, background: msg.tipo === "ok" ? "#D1FAE5" : "#FEE2E2", color: msg.tipo === "ok" ? "#065F46" : "#991B1B", fontSize: 12, fontWeight: 600, display: "flex", justifyContent: "space-between" }}>
          {msg.texto}
          <button onClick={() => setMsg(null)} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 14 }}>×</button>
        </div>
      )}

      {/* Abas */}
      <div style={{ display: "flex", gap: 4, marginBottom: 16, borderBottom: "2px solid #E5E7EB" }}>
        {[["colaboradores","👥 Colaboradores"], ["solicitacoes","📋 Solicitações"]].map(([id, label]) => (
          <button key={id} onClick={() => setAba(id)} style={{
            padding: "8px 18px", fontSize: 12, fontWeight: 600, border: "none", cursor: "pointer",
            background: "none", borderBottom: aba === id ? "2px solid #0F2447" : "2px solid transparent",
            color: aba === id ? "#0F2447" : "#6B7280", marginBottom: -2
          }}>{label}</button>
        ))}
      </div>

      {/* ABA COLABORADORES */}
      {aba === "colaboradores" && (
        <>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", background: "#fff", borderRadius: 10, overflow: "hidden", border: "1px solid #E5E7EB", fontSize: 12 }}>
              <thead>
                <tr style={{ background: "#F9FAFB", borderBottom: "1px solid #E5E7EB" }}>
                  <th style={S.th}>Filial</th>
                  <th style={S.th}>Matrícula</th>
                  <th style={S.th}>Nome</th>
                  <th style={S.th}>Função</th>
                  <th style={S.th}>Pos. Escala</th>
                  <th style={S.th}>Mot. Líder</th>
                  <th style={S.th}>Munkeiro</th>
                  <th style={S.th}>Prancheiro</th>
                  <th style={S.th}>Macacão</th>
                  <th style={S.th}>Bota</th>
                  <th style={S.th}>Ação</th>
                </tr>
                <tr style={{ background: "#F9FAFB", borderBottom: "2px solid #E5E7EB" }}>
                  <td style={{ padding: "4px 6px" }}><input style={{ ...S.inp, fontSize: 11 }} placeholder="🔍 Filial" value={fFilial} onChange={e => setFFilial(e.target.value)} /></td>
                  <td style={{ padding: "4px 6px" }}><input style={{ ...S.inp, fontSize: 11 }} placeholder="🔍 Matrícula" value={fNome} onChange={e => setFNome(e.target.value)} /></td>
                  <td style={{ padding: "4px 6px" }}><input style={{ ...S.inp, fontSize: 11 }} placeholder="🔍 Nome" value={fNomeCompleto} onChange={e => setFNomeCompleto(e.target.value)} /></td>
                  <td style={{ padding: "4px 6px" }}><input style={{ ...S.inp, fontSize: 11 }} placeholder="🔍 Função" value={fFuncao} onChange={e => setFuncao(e.target.value)} /></td>
                  <td colSpan={6} style={{ padding: "4px 6px" }}>
                    <button onClick={() => { setFNome(""); setFNomeCompleto(""); setFuncao(""); setFFilial(""); }}
                      style={{ padding: "5px 12px", border: "1px solid #D1D5DB", borderRadius: 6, background: "#fff", color: "#374151", fontSize: 11, cursor: "pointer" }}>
                      × Limpar
                    </button>
                    <span style={{ marginLeft: 10, fontSize: 11, color: "#6B7280" }}>{colabsFiltrados.length} colaborador(es)</span>
                  </td>
                  <td></td>
                </tr>
              </thead>
              <tbody>
                {colabsFiltrados.slice(0, 100).map(c => (
                  <tr key={c.id} onMouseEnter={e => e.currentTarget.style.background = "#F9FAFB"} onMouseLeave={e => e.currentTarget.style.background = ""}>
                    <td style={S.td}>{fmtFilial(c)}</td>
                    <td style={{ ...S.td, fontWeight: 700 }}>{c.chapa}</td>
                    <td style={S.td}>{c.nome}</td>
                    <td style={{ ...S.td, color: "#6B7280" }}>{c.funcao}</td>
                    <td style={S.td}>{c.posicao_escala ? labelValor("posicao_escala", c.posicao_escala) : <span style={{ color: "#9CA3AF" }}>—</span>}</td>
                    <td style={S.td}><SimNaoTag val={c.motorista_lider} /></td>
                    <td style={S.td}><SimNaoTag val={c.munkeiro} /></td>
                    <td style={S.td}><SimNaoTag val={c.prancheiro} /></td>
                    <td style={S.td}>{c.tamanho_macacao || <span style={{ color: "#9CA3AF" }}>—</span>}</td>
                    <td style={S.td}>{c.tamanho_bota || <span style={{ color: "#9CA3AF" }}>—</span>}</td>
                    <td style={S.td}>
                      <button style={{ ...S.btnP, padding: "4px 10px", fontSize: 11 }}
                        onClick={() => { setModalNova(c); setItens({}); setObservacao(""); }}>
                        Solicitar
                      </button>
                    </td>
                  </tr>
                ))}
                {colabsFiltrados.length > 100 && (
                  <tr><td colSpan={11} style={{ ...S.td, textAlign: "center", color: "#6B7280" }}>
                    Mostrando 100 de {colabsFiltrados.length}. Use os filtros para refinar.
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* ABA SOLICITAÇÕES */}
      {aba === "solicitacoes" && (
        <>
          <div style={{ background: "#F9FAFB", border: "1px solid #E5E7EB", borderRadius: 10, padding: "12px 16px", marginBottom: 12 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr auto", gap: 10, alignItems: "end" }}>
              <div>
                <label style={S.lbl}>Status</label>
                <select style={S.inp} value={fStatus} onChange={e => setFStatus(e.target.value)}>
                  <option value="todos">Todos</option>
                  <option value="solicitado">Solicitado</option>
                  <option value="em_analise">Em Análise</option>
                  <option value="aprovado">Aprovado</option>
                  <option value="reprovado">Reprovado</option>
                  <option value="finalizado">Finalizado</option>
                </select>
              </div>
              <div><label style={S.lbl}>Data início</label><input type="date" style={S.inp} value={fDataIni} onChange={e => setFDataIni(e.target.value)} /></div>
              <div><label style={S.lbl}>Data fim</label><input type="date" style={S.inp} value={fDataFim} onChange={e => setFDataFim(e.target.value)} /></div>
              <div><label style={S.lbl}>Solicitante</label><input style={S.inp} placeholder="Nome..." value={fSolic} onChange={e => setFSolic(e.target.value)} /></div>
              <button style={S.btnP} onClick={carregarSols}>🔍 Filtrar</button>
            </div>
          </div>

          {loadingSols ? (
            <div style={{ textAlign: "center", padding: 40, color: "#9CA3AF" }}>Carregando...</div>
          ) : solicitacoes.length === 0 ? (
            <div style={{ textAlign: "center", padding: 60, color: "#9CA3AF" }}>Nenhuma solicitação encontrada.</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", background: "#fff", borderRadius: 10, overflow: "hidden", border: "1px solid #E5E7EB" }}>
              <thead>
                <tr style={{ background: "#F9FAFB", borderBottom: "2px solid #E5E7EB" }}>
                  {["Matrícula","Nome","Função","Admissão","Solicitante","Data","Status","Ações"].map(h => (
                    <th key={h} style={S.th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {solicitacoes.map(s => {
                  const stCfg = AC_STATUS_CONFIG[s.status] || {};
                  return (
                    <tr key={s.id} onMouseEnter={e => e.currentTarget.style.background = "#F9FAFB"} onMouseLeave={e => e.currentTarget.style.background = ""}>
                      <td style={{ ...S.td, fontWeight: 700 }}>{s.chapa}</td>
                      <td style={S.td}>{s.colaborador_nome}</td>
                      <td style={{ ...S.td, color: "#6B7280" }}>{s.funcao}</td>
                      <td style={{ ...S.td, color: "#6B7280" }}>{s.data_admissao ? new Date(s.data_admissao).toLocaleDateString("pt-BR") : "—"}</td>
                      <td style={S.td}>{s.usuario_solicitante_nome}</td>
                      <td style={{ ...S.td, color: "#6B7280" }}>{new Date(s.criado_em).toLocaleDateString("pt-BR")}</td>
                      <td style={S.td}>
                        <span style={{ padding: "2px 8px", borderRadius: 8, fontSize: 10, fontWeight: 700, background: stCfg.bg, color: stCfg.color }}>
                          {stCfg.label || s.status}
                        </span>
                      </td>
                      <td style={S.td}>
                        <button style={{ ...S.btnS, padding: "4px 10px", fontSize: 11 }} onClick={() => { setModalDetalhe(s); setObsAprov(""); }}>
                          Ver
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </>
      )}

      {/* MODAL SOLICITAR ALTERAÇÃO */}
      {modalNova && (
        <div style={S.modal}>
          <div style={S.mbox}>
            <h3 style={{ margin: "0 0 6px", fontSize: 15, fontWeight: 800, color: "#0F2447" }}>Solicitar Alteração Cadastral</h3>
            <div style={{ padding: "8px 12px", background: "#EFF6FF", borderRadius: 8, marginBottom: 16, fontSize: 12, color: "#1E40AF" }}>
              <strong>{fmtFilial(modalNova)}</strong> | {modalNova.chapa} | {modalNova.nome} | {modalNova.funcao} | {modalNova.data_admissao ? new Date(modalNova.data_admissao).toLocaleDateString("pt-BR") : "—"}
            </div>

            <div style={{ background: "#F9FAFB", border: "1px solid #E5E7EB", borderRadius: 8, padding: "14px", marginBottom: 14 }}>
              <p style={{ margin: "0 0 4px", fontSize: 11, fontWeight: 700, color: "#374151" }}>CAMPOS PARA ALTERAR</p>
              <p style={{ margin: "0 0 12px", fontSize: 11, color: "#6B7280" }}>Selecione apenas os campos que deseja alterar.</p>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                {Object.entries(CAMPOS_CONFIG).map(([campo, cfg]) => (
                  <div key={campo}>
                    <label style={S.lbl}>{cfg.label}</label>
                    <div style={{ fontSize: 10, color: "#6B7280", marginBottom: 4 }}>
                      Atual: <strong style={{ color: modalNova[campo] ? "#374151" : "#9CA3AF" }}>
                        {modalNova[campo] ? labelValor(campo, modalNova[campo]) : "Não informado"}
                      </strong>
                    </div>
                    <select style={S.inp} value={itens[campo] || ""} onChange={e => setItens(p => ({ ...p, [campo]: e.target.value || undefined }))}>
                      <option value="">— sem alteração —</option>
                      {cfg.tipo === "select_obj"
                        ? cfg.dominio.map(d => <option key={d.cod} value={d.cod}>{d.cod} — {d.desc}</option>)
                        : cfg.dominio.map(v => <option key={v} value={v}>{v}</option>)
                      }
                    </select>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={S.lbl}>Observação</label>
              <textarea style={{ ...S.inp, height: 56, resize: "vertical" }} value={observacao} onChange={e => setObservacao(e.target.value)} placeholder="Justificativa ou observação..." />
            </div>

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button style={S.btnS} onClick={() => setModalNova(null)}>Cancelar</button>
              <button style={S.btnP} onClick={salvar} disabled={salvando}>{salvando ? "Salvando..." : "Registrar Solicitação"}</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL DETALHE */}
      {modalDetalhe && (
        <div style={{ ...S.modal, zIndex: 1100 }}>
          <div style={{ ...S.mbox, maxWidth: 580 }}>
            <h3 style={{ margin: "0 0 4px", fontSize: 15, fontWeight: 800, color: "#0F2447" }}>Solicitação #{modalDetalhe.id}</h3>
            <p style={{ margin: "0 0 14px", fontSize: 11, color: "#6B7280" }}>{modalDetalhe.chapa} | {modalDetalhe.colaborador_nome}</p>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 14, fontSize: 12 }}>
              <div style={{ background: "#F9FAFB", borderRadius: 6, padding: "8px 10px" }}>
                <div style={{ fontSize: 10, color: "#6B7280", marginBottom: 2 }}>SOLICITANTE</div>
                <strong>{modalDetalhe.usuario_solicitante_nome}</strong>
              </div>
              <div style={{ background: "#F9FAFB", borderRadius: 6, padding: "8px 10px" }}>
                <div style={{ fontSize: 10, color: "#6B7280", marginBottom: 2 }}>DATA</div>
                <strong>{new Date(modalDetalhe.criado_em).toLocaleDateString("pt-BR")}</strong>
              </div>
              <div style={{ background: "#F9FAFB", borderRadius: 6, padding: "8px 10px" }}>
                <div style={{ fontSize: 10, color: "#6B7280", marginBottom: 2 }}>STATUS</div>
                <span style={{ padding: "2px 8px", borderRadius: 8, fontSize: 10, fontWeight: 700, background: AC_STATUS_CONFIG[modalDetalhe.status]?.bg, color: AC_STATUS_CONFIG[modalDetalhe.status]?.color }}>
                  {AC_STATUS_CONFIG[modalDetalhe.status]?.label}
                </span>
              </div>
            </div>

            <div style={{ background: "#F9FAFB", border: "1px solid #E5E7EB", borderRadius: 8, padding: "12px 14px", marginBottom: 14 }}>
              <p style={{ margin: "0 0 8px", fontSize: 11, fontWeight: 700, color: "#374151" }}>ALTERAÇÕES</p>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #E5E7EB" }}>
                    <th style={{ padding: "4px 8px", textAlign: "left", fontSize: 10, color: "#6B7280" }}>Campo</th>
                    <th style={{ padding: "4px 8px", textAlign: "left", fontSize: 10, color: "#6B7280" }}>Antes</th>
                    <th style={{ padding: "4px 8px", textAlign: "left", fontSize: 10, color: "#6B7280" }}>Depois</th>
                  </tr>
                </thead>
                <tbody>
                  {(modalDetalhe.itens || []).map((item, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid #F3F4F6" }}>
                      <td style={{ padding: "5px 8px", fontWeight: 600 }}>{CAMPOS_CONFIG[item.campo]?.label || item.campo}</td>
                      <td style={{ padding: "5px 8px", color: "#991B1B" }}>{labelValor(item.campo, item.valor_anterior)}</td>
                      <td style={{ padding: "5px 8px", color: "#065F46", fontWeight: 700 }}>{labelValor(item.campo, item.novo_valor)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {modalDetalhe.observacao && (
              <div style={{ background: "#FFFBEB", border: "1px solid #FDE68A", borderRadius: 6, padding: "8px 12px", marginBottom: 14, fontSize: 12 }}>
                <strong>Obs:</strong> {modalDetalhe.observacao}
              </div>
            )}

            {canAprovar && ["solicitado","em_analise"].includes(modalDetalhe.status) && (
              <div style={{ marginBottom: 14 }}>
                <label style={S.lbl}>Observação do aprovador</label>
                <textarea style={{ ...S.inp, height: 44, resize: "vertical" }} value={obsAprov} onChange={e => setObsAprov(e.target.value)} placeholder="Opcional..." />
              </div>
            )}

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button style={S.btnS} onClick={() => setModalDetalhe(null)}>Fechar</button>
              {canAprovar && ["solicitado","em_analise"].includes(modalDetalhe.status) && (
                <>
                  <button style={S.btnR} onClick={() => aprovar("reprovar")} disabled={salvando}>✗ Reprovar</button>
                  <button style={S.btnV} onClick={() => aprovar("aprovar")} disabled={salvando}>✓ Aprovar</button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


export default function App() {
  const [user, setUser] = useState(null);
  const [page, setPage] = useState("dashboard");

  // ── Estado global dos cadastros ──
  const [colaboradores, setColaboradores] = useState([]);
  const [eventos, setEventos] = useState([]);
  const [usuarios, setUsuarios] = useState([]);
  const [hierarquia, setHierarquia] = useState([]);
  const [alcadas, setAlcadas] = useState([]);
  const [solicitacoes, setSolicitacoes] = useState([]);
  const [blocos, setBlocos] = useState([]);
  const [sessao, setSessao] = useState(null);
  const [sessaoAviso, setSessaoAviso] = useState(false);

  // ── Carregar dados reais da API após login ────────────────────────────────
  const carregarDados = useCallback(async () => {
    try {
      const [cols, evts, blcs, usrs, hier, alcs] = await Promise.all([
        api.listarColaboradores().catch(() => null),
        api.listarEventos().catch(() => null),
        api.listarBlocos().catch(() => null),
        api.listarUsuarios().catch(() => null),
        api.listarHierarquia().catch(() => null),
        api.listarAlcadas().catch(() => null),
      ]);
      if (cols && cols.length > 0) setColaboradores(cols);
      if (evts && evts.length > 0) setEventos(evts);
      if (hier && hier.length > 0) setHierarquia(hier);
      if (alcs && alcs.length > 0) setAlcadas(alcs);
      if (usrs && usrs.length > 0) {
        const comAvatar = usrs.map(u => ({
          ...u,
          avatar: u.nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase()
        }));
        setUsuarios(comAvatar);
      }
      if (blcs && blcs.length > 0) {
        const evtsRef = evts || [];
        const colsRef = cols || [];
        const blocsNorm = blcs.map(b => {
          const ev = evtsRef.find(e => e.id === b.evento_id) || null;
          return {
            ...b,
            linhas: (b.linhas || []).map(l => ({
              ...l,
              colaborador: l.colaborador || colsRef.find(c => c.id === l.colaborador_id),
              evento: l.evento || ev,
            })),
            historico: b.historico || [],
            evento: ev,
            solicitante: b.solicitante_nome || b.solicitante || "",
          };
        });
        setBlocos(blocsNorm);
      }
    } catch (err) {
      console.warn("Usando dados locais — API indisponível:", err.message);
    }
  }, []);

  // Verificar expiração de sessão a cada minuto + registrar callback API
  useEffect(() => {
    if (!user) return;

    // Callback quando sessão expirar via API (401 sem refresh)
    onSessionExpired(() => {
      registrarAuditoria(sessao, ACOES.SESSAO_EXPIRADA, {});
      encerrarSessao();
      clearTokens();
      setUser(null);
      setSessao(null);
    });

    carregarDados();

    const interval = setInterval(() => {
      const s = obterSessao();
      if (!s) {
        registrarAuditoria(sessao, ACOES.SESSAO_EXPIRADA, {});
        setUser(null);
        setSessao(null);
      } else {
        const restante = 15 * 60 * 1000 - (Date.now() - s.ultimaAtividade);
        setSessaoAviso(restante < 5 * 60 * 1000);
      }
    }, 60000);
    return () => clearInterval(interval);
  }, [user, sessao, carregarDados]);

  const PAGE_TITLES = {
    dashboard:        { title: "Dashboard",               subtitle: "Visão geral das solicitações" },
    solicitacoes:     { title: "Solicitações de Pagamento", subtitle: "Registre e envie variáveis de pagamento para aprovação" },
    aprovacoes:       { title: "Aprovações",              subtitle: "Fila de aprovação por bloco" },
    exportacao:       { title: "Exportação TXT",          subtitle: "Geração do arquivo TOTVS RM" },
    cad_colaboradores:{ title: "Colaboradores",           subtitle: "Cadastros › Colaboradores" },
    cad_eventos:      { title: "Eventos da Folha",        subtitle: "Cadastros › Eventos" },
    cad_hierarquia:   { title: "Hierarquia de Aprovação", subtitle: "Cadastros › Hierarquia" },
    cad_alcadas:      { title: "Regras de Alçadas",       subtitle: "Cadastros › Alçadas" },
    cad_usuarios:     { title: "Usuários do Sistema",     subtitle: "Cadastros › Usuários" },
    auditoria:        { title: "Auditoria",               subtitle: "Log completo de ações" },
    plano_saude:      { title: "Benefícios",               subtitle: "" },
    desligamentos:    { title: "Solicitações de Desligamento",              subtitle: "Gerencie solicitações de desligamento de colaboradores" },
    atualizacao_cadastral: { title: "Atualização de Dados Cadastrais", subtitle: "Solicitação de alteração cadastral" },
    ocorrencias:      { title: "Solicitações de Advertências/Suspensões",   subtitle: "Registro de ocorrências disciplinares" },
    autorizacoes:     { title: "Autorização de Desconto",                   subtitle: "Autorização para desconto na folha de pagamento" },
  };

  if (!user) return <Login onLogin={(u, s) => { setUser(u); setSessao(s); setPage("solicitacoes"); }} />;

  const { title, subtitle } = PAGE_TITLES[page] || {};

  const solsParaDashboard = blocos.flatMap(b =>
    b.linhas.map(l => ({ ...l, status: b.status, tipo: l.evento?.descricao || "" }))
  );

  const solsParaExportacao = blocos
    .filter(b => b.status === "aprovado_final")
    .flatMap(b => b.linhas.map(l => ({ ...l, status: b.status, competencia: b.competencia })));

  return (
    <div style={{ display: "flex", minHeight: "100vh", fontFamily: "'DM Sans', sans-serif", background: "#F8FAFC" }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet" />
      <Sidebar active={page} onNav={setPage} user={user} />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <Topbar title={title} subtitle={subtitle} user={user} onLogout={async () => { registrarAuditoria(sessao, ACOES.LOGOUT, {}); try { await api.logout(); } catch(_) {} encerrarSessao(); clearTokens(); setUser(null); setSessao(null); }} />
        {sessaoAviso && (
          <div style={{
            background: "#FFFBEB", borderBottom: "1px solid #FCD34D",
            padding: "8px 28px", fontSize: 12, color: "#92400E",
            display: "flex", alignItems: "center", gap: 8
          }}>
            ⚠️ <b>Sua sessão expira em menos de 5 minutos</b> por inatividade. Salve seu trabalho.
          </div>
        )}
        <div style={{ flex: 1, overflowY: "auto" }}>
          {page === "dashboard"         && <Dashboard solicitacoes={solsParaDashboard} blocos={blocos} user={user} />}
          {page === "solicitacoes"      && <Solicitacoes solicitacoes={solicitacoes} setSolicitacoes={setSolicitacoes} blocos={blocos} setBlocos={setBlocos} user={user} colaboradores={colaboradores} eventos={eventos} recarregarDados={carregarDados} />}
          {page === "aprovacoes"        && <Aprovacoes blocos={blocos} setBlocos={setBlocos} user={user} recarregarDados={carregarDados} />}
          {page === "exportacao"        && <Exportacao solicitacoes={solsParaExportacao} blocos={blocos.filter(b => b.status === "aprovado_final")} />}
          {page === "cad_colaboradores" && <CadColaboradores colaboradores={colaboradores} setColaboradores={setColaboradores} />}
          {page === "cad_eventos"       && <CadEventos eventos={eventos} setEventos={setEventos} />}
          {page === "cad_hierarquia"    && <CadHierarquia hierarquia={hierarquia} setHierarquia={setHierarquia} usuarios={usuarios} />}
          {page === "cad_alcadas"       && <CadAlcadas alcadas={alcadas} setAlcadas={setAlcadas} eventos={eventos} />}
          {page === "cad_usuarios"      && <CadUsuarios usuarios={usuarios} setUsuarios={setUsuarios} />}
          {page === "desligamentos"     && <Desligamentos user={user} colaboradores={colaboradores} api={api} recarregarDados={carregarDados} />}
          {page === "auditoria"         && <Auditoria solicitacoes={solicitacoes} blocos={blocos} sessao={sessao} />}
          {page === "ocorrencias"       && <Ocorrencias user={user} colaboradores={colaboradores} />}
          {page === "autorizacoes"      && <Autorizacoes user={user} colaboradores={colaboradores} />}
          {page === "atualizacao_cadastral" && <AtualizacaoCadastral user={user} colaboradores={colaboradores} />}
          {page === "plano_saude" && <PlanoSaude user={user} colaboradores={colaboradores} />}
        </div>
      </div>
    </div>
  );
}
