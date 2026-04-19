import { useState, useContext, createContext, useEffect, useCallback } from "react";
import { api, setTokens, clearTokens, onSessionExpired } from "./api";

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY MODULE — DP Flow | Benel
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY MODULE — DP Flow | Benel Soluções em Transporte e Logística
// Implementação: Sanitização XSS, Rate Limiting, Validação de Schema TOTVS RM,
// Prevenção IDOR, Sessão com expiração, Audit Log, Content Security Policy
// ═══════════════════════════════════════════════════════════════════════════════

// ─── 1. SANITIZAÇÃO XSS ───────────────────────────────────────────────────────
// Remove tags HTML e caracteres perigosos de qualquer string
export function sanitize(value) {
  if (typeof value !== "string") return value;
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;")
    .replace(/`/g, "&#x60;")
    .replace(/=/g, "&#x3D;")
    .trim();
}

// Sanitiza objeto inteiro recursivamente
export function sanitizeObject(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const clean = {};
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    if (typeof val === "string") clean[key] = sanitize(val);
    else if (typeof val === "object") clean[key] = sanitizeObject(val);
    else clean[key] = val;
  }
  return clean;
}

// ─── 2. VALIDAÇÃO DE CAMPOS ────────────────────────────────────────────────────
// Padrões seguros para cada tipo de campo
const PATTERNS = {
  email:       /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/,
  chapa:       /^[0-9]{1,16}$/,
  codigoEvento:/^[a-zA-Z0-9]{1,4}$/,
  valor:       /^\d{1,12}(\.\d{1,2})?$/,
  data:        /^\d{4}-\d{2}-\d{2}$/,
  hora:        /^\d{1,3}:\d{2}$/,
  competencia: /^\d{6}$/,
  texto:       /^[^<>'"`;]{0,500}$/,
  senha:       /^.{3,128}$/,
};

export function validateField(tipo, valor) {
  if (!valor && valor !== 0) return { ok: false, erro: "Campo obrigatório" };
  const pattern = PATTERNS[tipo];
  if (!pattern) return { ok: true };
  if (!pattern.test(String(valor))) return { ok: false, erro: `Formato inválido para ${tipo}` };
  return { ok: true };
}

// ─── 3. VALIDAÇÃO DE SCHEMA TOTVS RM ──────────────────────────────────────────
// Valida linha antes de gerar o TXT — garante conformidade com layout RM Labore
export function validarSchemaTotvs(linha) {
  const erros = [];

  // Col 01-16: Chapa — obrigatória, numérica
  if (!linha.colaborador?.chapa) {
    erros.push("Chapa do colaborador obrigatória");
  } else if (!/^\d{1,16}$/.test(linha.colaborador.chapa)) {
    erros.push("Chapa inválida — deve ser numérica com até 16 dígitos");
  }

  // Col 25-28: Código do evento — obrigatório, alfanumérico 4 chars
  if (!linha.evento?.codigo) {
    erros.push("Código do evento obrigatório");
  } else if (!/^[a-zA-Z0-9]{1,4}$/.test(linha.evento.codigo)) {
    erros.push("Código do evento inválido — máximo 4 caracteres alfanuméricos");
  }

  // Col 17-24: Data — obrigatória, formato YYYY-MM-DD
  if (!linha.data) {
    erros.push("Data obrigatória");
  } else if (!/^\d{4}-\d{2}-\d{2}$/.test(linha.data)) {
    erros.push("Data inválida — use formato AAAA-MM-DD");
  } else {
    const d = new Date(linha.data);
    if (isNaN(d.getTime())) erros.push("Data inválida — data não existe");
  }

  // Col 29-34: Hora — formato HHH:MM
  if (linha.hora && !/^\d{1,3}:\d{2}$/.test(linha.hora)) {
    erros.push("Hora inválida — use formato HHH:MM (ex: 004:30)");
  }

  // Col 50-64: Valor — numérico positivo
  const val = parseFloat(linha.valor);
  if (isNaN(val) || val < 0) {
    erros.push("Valor inválido — deve ser número positivo");
  } else if (val > 999999999999.99) {
    erros.push("Valor excede limite máximo do TOTVS RM");
  }

  // Col 35-49: Referência — numérica se preenchida
  if (linha.referencia && isNaN(parseFloat(linha.referencia))) {
    erros.push("Referência inválida — deve ser numérica");
  }

  return { valido: erros.length === 0, erros };
}

// Valida bloco completo antes de exportar
export function validarBlocoParaExportacao(bloco) {
  const errosBloco = [];
  bloco.linhas.forEach((linha, i) => {
    const { valido, erros } = validarSchemaTotvs(linha);
    if (!valido) {
      erros.forEach(e => errosBloco.push(`Linha ${i + 1}: ${e}`));
    }
  });
  return { valido: errosBloco.length === 0, erros: errosBloco };
}

// ─── 4. RATE LIMITING (frontend) ──────────────────────────────────────────────
// Bloqueia tentativas excessivas de login — simula proteção por IP no cliente
const RATE_LIMIT = {
  MAX_TENTATIVAS: 5,
  JANELA_MS: 15 * 60 * 1000, // 15 minutos
  tentativas: {},
};

export function verificarRateLimit(identificador) {
  const agora = Date.now();
  const key = identificador.toLowerCase().trim();

  if (!RATE_LIMIT.tentativas[key]) {
    RATE_LIMIT.tentativas[key] = { count: 0, inicio: agora, bloqueadoAte: null };
  }

  const registro = RATE_LIMIT.tentativas[key];

  // Verificar se está bloqueado
  if (registro.bloqueadoAte && agora < registro.bloqueadoAte) {
    const restante = Math.ceil((registro.bloqueadoAte - agora) / 60000);
    return { permitido: false, erro: `Muitas tentativas. Tente novamente em ${restante} minuto(s).` };
  }

  // Resetar janela se expirou
  if (agora - registro.inicio > RATE_LIMIT.JANELA_MS) {
    registro.count = 0;
    registro.inicio = agora;
    registro.bloqueadoAte = null;
  }

  registro.count++;

  if (registro.count > RATE_LIMIT.MAX_TENTATIVAS) {
    registro.bloqueadoAte = agora + RATE_LIMIT.JANELA_MS;
    return { permitido: false, erro: `Conta bloqueada por 15 minutos após ${RATE_LIMIT.MAX_TENTATIVAS} tentativas.` };
  }

  const restante = RATE_LIMIT.MAX_TENTATIVAS - registro.count;
  return {
    permitido: true,
    aviso: restante <= 2 ? `Atenção: ${restante} tentativa(s) restante(s) antes do bloqueio.` : null
  };
}

export function resetarRateLimit(identificador) {
  const key = identificador.toLowerCase().trim();
  delete RATE_LIMIT.tentativas[key];
}

// ─── 5. SESSÃO COM EXPIRAÇÃO (JWT simulado) ────────────────────────────────────
// Gera token de sessão com expiração — simula JWT no frontend
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000; // 8 horas
const INACTIVITY_LIMIT_MS = 15 * 60 * 1000;      // 15 min inatividade

export function criarSessao(user) {
  const agora = Date.now();
  const sessao = {
    userId: user.id,
    perfil: user.perfil,
    email: user.email,
    nome: user.nome,
    avatar: user.avatar,
    criadaEm: agora,
    expiraEm: agora + SESSION_DURATION_MS,
    ultimaAtividade: agora,
    token: gerarToken(),
  };
  try {
    sessionStorage.setItem("dpflow_sessao", JSON.stringify(sessao));
  } catch (_) {}
  return sessao;
}

export function obterSessao() {
  try {
    const raw = sessionStorage.getItem("dpflow_sessao");
    if (!raw) return null;
    const sessao = JSON.parse(raw);
    const agora = Date.now();

    // Verificar expiração absoluta
    if (agora > sessao.expiraEm) {
      encerrarSessao();
      return null;
    }

    // Verificar inatividade
    if (agora - sessao.ultimaAtividade > INACTIVITY_LIMIT_MS) {
      encerrarSessao();
      return null;
    }

    // Atualizar última atividade
    sessao.ultimaAtividade = agora;
    sessionStorage.setItem("dpflow_sessao", JSON.stringify(sessao));
    return sessao;
  } catch (_) {
    return null;
  }
}

export function encerrarSessao() {
  try { sessionStorage.removeItem("dpflow_sessao"); } catch (_) {}
}

function gerarToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, "0")).join("");
}

// ─── 6. PREVENÇÃO IDOR ────────────────────────────────────────────────────────
// Verifica se o usuário tem permissão para acessar determinado recurso
export function verificarPermissaoBloco(bloco, sessao) {
  if (!sessao || !bloco) return false;
  if (sessao.perfil === "admin" || sessao.perfil === "dp") return true;
  if (sessao.perfil === "superior") {
    return bloco.status === "pendente_superior" ||
           bloco.status === "aprovado_final" ||
           bloco.status === "rejeitado";
  }
  if (sessao.perfil === "gestor") {
    return bloco.solicitante_id === sessao.userId ||
           bloco.gestor_id === sessao.userId;
  }
  return false;
}

export function filtrarBlocosPermitidos(blocos, sessao) {
  if (!sessao) return [];
  if (sessao.perfil === "admin" || sessao.perfil === "dp") return blocos;
  return blocos.filter(b => verificarPermissaoBloco(b, sessao));
}

// ─── 7. AUDIT LOG ─────────────────────────────────────────────────────────────
// Registra todas as ações críticas com timestamp
const AUDIT_LOG = [];

export function registrarAuditoria(sessao, acao, detalhes = {}) {
  const entrada = {
    id: Date.now() + Math.random(),
    timestamp: new Date().toISOString(),
    dataHora: new Date().toLocaleString("pt-BR"),
    usuario: sessao?.nome || "Anônimo",
    userId: sessao?.userId,
    perfil: sessao?.perfil,
    acao,
    detalhes: sanitizeObject(detalhes),
    token: sessao?.token?.slice(0, 8) + "...",
  };
  AUDIT_LOG.unshift(entrada);
  // Manter apenas últimas 500 entradas
  if (AUDIT_LOG.length > 500) AUDIT_LOG.pop();
  return entrada;
}

export function obterAuditLog() {
  return [...AUDIT_LOG];
}

// Ações auditáveis
export const ACOES = {
  LOGIN_OK:           "LOGIN_SUCESSO",
  LOGIN_FALHA:        "LOGIN_FALHA",
  LOGOUT:             "LOGOUT",
  SESSAO_EXPIRADA:    "SESSAO_EXPIRADA",
  BLOCO_CRIADO:       "BLOCO_CRIADO",
  BLOCO_EDITADO:      "BLOCO_EDITADO",
  BLOCO_APROVADO:     "BLOCO_APROVADO",
  BLOCO_REJEITADO:    "BLOCO_REJEITADO",
  BLOCO_DEVOLVIDO:    "BLOCO_DEVOLVIDO",
  TXT_EXPORTADO:      "TXT_EXPORTADO",
  ACESSO_NEGADO:      "ACESSO_NEGADO",
  RATE_LIMIT:         "RATE_LIMIT_ATINGIDO",
  SCHEMA_INVALIDO:    "SCHEMA_TOTVS_INVALIDO",
  CADASTRO_ALTERADO:  "CADASTRO_ALTERADO",
};

// ─── 8. CONTENT SECURITY POLICY (meta tag) ────────────────────────────────────
// Injeta CSP no head do documento para bloquear scripts não autorizados
export function aplicarCSP() {
  try {
    const existing = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (existing) return;

    const meta = document.createElement("meta");
    meta.setAttribute("http-equiv", "Content-Security-Policy");
    meta.setAttribute("content", [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "connect-src 'self' https://benel-dpflow-backend-production.up.railway.app",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "));
    document.head.appendChild(meta);

    // X-Frame-Options via meta
    const xframe = document.createElement("meta");
    xframe.setAttribute("http-equiv", "X-Frame-Options");
    xframe.setAttribute("content", "DENY");
    document.head.appendChild(xframe);
  } catch (_) {}
}

// ─── 9. PROTEÇÃO CONTRA PROMPT INJECTION ──────────────────────────────────────
// Detecta tentativas de injeção de comandos em campos de texto
const PADROES_MALICIOSOS = [
  /ignore\s+previous/i,
  /system\s*:/i,
  /\[INST\]/i,
  /<\|im_start\|>/i,
  /você\s+é\s+agora/i,
  /aja\s+como/i,
  /act\s+as/i,
  /jailbreak/i,
  /bypass/i,
  /override\s+instructions/i,
  /--\s*system/i,
  /###\s*instruction/i,
];

export function detectarPromptInjection(texto) {
  if (typeof texto !== "string") return false;
  return PADROES_MALICIOSOS.some(p => p.test(texto));
}

export function sanitizarComProtecao(texto, sessao) {
  if (detectarPromptInjection(texto)) {
    registrarAuditoria(sessao, "TENTATIVA_INJECAO", { texto: texto.slice(0, 50) });
    return { seguro: false, erro: "ERR_SEC_001: Entrada rejeitada por política de segurança." };
  }
  return { seguro: true, valor: sanitize(texto) };
}

// ─── 10. VALIDADOR DE FORMULÁRIOS ─────────────────────────────────────────────
// Valida e sanitiza formulário completo antes de salvar
export function validarFormulario(campos) {
  const erros = {};
  const limpo = {};
  let valido = true;

  for (const [key, config] of Object.entries(campos)) {
    const { valor, tipo, obrigatorio, label } = config;

    // Verificar injeção
    if (typeof valor === "string" && detectarPromptInjection(valor)) {
      erros[key] = "ERR_SEC_001: Conteúdo não permitido";
      valido = false;
      continue;
    }

    // Sanitizar
    const valorLimpo = typeof valor === "string" ? sanitize(valor) : valor;

    // Verificar obrigatoriedade
    if (obrigatorio && (!valorLimpo && valorLimpo !== 0)) {
      erros[key] = `${label || key} é obrigatório`;
      valido = false;
      continue;
    }

    // Validar formato
    if (valorLimpo && tipo) {
      const { ok, erro } = validateField(tipo, valorLimpo);
      if (!ok) {
        erros[key] = erro;
        valido = false;
        continue;
      }
    }

    limpo[key] = valorLimpo;
  }

  return { valido, erros, dados: limpo };
}


const LOGO_BENEL = "data:image/jpeg;base64,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";

// ─── CONTEXTO DE AUTH ────────────────────────────────────────────────────────
const AuthContext = createContext(null);

const MOCK_USERS = [
  { id: 1, nome: "Carlos Mendes", email: "gestor@dp.com", senha: "123", perfil: "gestor", avatar: "CM" },
  { id: 2, nome: "Ana Souza", email: "superior@dp.com", senha: "123", perfil: "superior", avatar: "AS" },
  { id: 3, nome: "Fernanda Lima", email: "dp@dp.com", senha: "123", perfil: "dp", avatar: "FL" },
  { id: 4, nome: "Admin", email: "admin@dp.com", senha: "123", perfil: "admin", avatar: "AD" },
];

const MOCK_COLABORADORES = [
  { id: 1, chapa: "0404", nome: "João Pedro Silva", funcao: "Analista", situacao: "Ativo", centro_custo: "001", desc_cc: "TI" },
  { id: 2, chapa: "0512", nome: "Maria Fernanda Costa", funcao: "Coordenadora", situacao: "Ativo", centro_custo: "002", desc_cc: "RH" },
  { id: 3, chapa: "0718", nome: "Roberto Alves", funcao: "Motorista", situacao: "Ativo", centro_custo: "003", desc_cc: "Logística" },
  { id: 4, chapa: "0321", nome: "Luciana Torres", funcao: "Técnica", situacao: "Ativo", centro_custo: "001", desc_cc: "TI" },
];

const MOCK_EVENTOS = [
  { id: 1, codigo: "1148", descricao: "Auxílio Quilometragem", tipo: "provento", forma: "valor" },
  { id: 2, codigo: "1150", descricao: "Ajuda de Custo", tipo: "provento", forma: "valor" },
  { id: 3, codigo: "1155", descricao: "Horas Extras 50%", tipo: "provento", forma: "hora" },
  { id: 4, codigo: "1160", descricao: "Diária de Viagem", tipo: "provento", forma: "referencia" },
  { id: 5, codigo: "2001", descricao: "Desconto Multa Trânsito", tipo: "desconto", forma: "valor" },
  { id: 6, codigo: "1175", descricao: "Sobreaviso", tipo: "provento", forma: "hora" },
];

const MOCK_SOLICITACOES_INIT = [
  {
    id: 1, colaborador_id: 1, evento_id: 1, tipo: "Auxílio Quilometragem",
    data: "2025-09-30", hora: "00:00", referencia: "", valor: "1190.47", valor_original: "1190.47",
    observacao: "Deslocamento filial sul", status: "aprovado_final", solicitante_id: 1,
    gestor_id: 1, superior_id: 2, competencia: "092025", criado_em: "2025-09-25",
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "2025-09-25 09:00", obs: "" },
      { acao: "aprovado_gestor", usuario: "Carlos Mendes", data: "2025-09-25 09:05", obs: "" },
      { acao: "aprovado_superior", usuario: "Ana Souza", data: "2025-09-26 10:00", obs: "" },
      { acao: "aprovado_dp", usuario: "Fernanda Lima", data: "2025-09-27 14:00", obs: "" },
    ]
  },
  {
    id: 2, colaborador_id: 3, evento_id: 3, tipo: "Horas Extras 50%",
    data: "2025-09-28", hora: "04:30", referencia: "", valor: "340.00", valor_original: "340.00",
    observacao: "Plantão final de semana", status: "pendente_gestor", solicitante_id: 1,
    gestor_id: 1, superior_id: 2, competencia: "092025", criado_em: "2025-09-28",
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "2025-09-28 08:00", obs: "" },
    ]
  },
  {
    id: 3, colaborador_id: 2, evento_id: 2, tipo: "Ajuda de Custo",
    data: "2025-09-20", hora: "", referencia: "", valor: "500.00", valor_original: "500.00",
    observacao: "Curso externo SP", status: "pendente_superior", solicitante_id: 1,
    gestor_id: 1, superior_id: 2, competencia: "092025", criado_em: "2025-09-20",
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "2025-09-20 10:00", obs: "" },
      { acao: "aprovado_gestor", usuario: "Carlos Mendes", data: "2025-09-20 10:30", obs: "" },
    ]
  },
  {
    id: 4, colaborador_id: 4, evento_id: 5, tipo: "Desconto Multa Trânsito",
    data: "2025-09-15", hora: "", referencia: "", valor: "293.47", valor_original: "293.47",
    observacao: "Multa via expressa", status: "devolvido", solicitante_id: 1,
    gestor_id: 1, superior_id: 2, competencia: "092025", criado_em: "2025-09-15",
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "2025-09-15 11:00", obs: "" },
      { acao: "devolvido", usuario: "Ana Souza", data: "2025-09-16 09:00", obs: "Falta comprovante da infração" },
    ]
  },
];

// ─── UTILITÁRIOS ─────────────────────────────────────────────────────────────
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
  gestor:    { label: "Gestor",    color: "#3B82F6" },
  superior:  { label: "Superior",  color: "#8B5CF6" },
  dp:        { label: "DP",        color: "#10B981" },
  admin:     { label: "Admin",     color: "#F59E0B" },
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

function formatReal(valor, tam) {
  // Formata número no padrão 999999999999.99 com tamanho fixo, sem ponto de milhar
  const num = parseFloat(valor || 0);
  const str = num.toFixed(2).replace(",", ".");
  // Remove ponto decimal para alinhar: ex "1190.47" -> padStart sem ponto
  return str.padStart(tam, " ");
}

function generateTXTLine(sol, colaboradores, eventos) {
  const colab = colaboradores.find(c => c.id === sol.colaborador_id);
  const evento = eventos.find(e => e.id === sol.evento_id);
  if (!colab || !evento) return "";

  // Col 01-16 (16): Chapa do Funcionário — alinhada à esquerda, preenchida com espaços à direita
  const chapa = (colab.chapa || "").padEnd(16, " ").slice(0, 16);

  // Col 17-24 (8): Data pagamento DDMMAAAA
  let dataTXT = "00000000";
  if (sol.data) {
    const parts = sol.data.split("-");
    if (parts.length === 3) dataTXT = parts[2] + parts[1] + parts[0];
  }
  const data = dataTXT.slice(0, 8);

  // Col 25-28 (4): Código do evento — alfanumérico, espaço à direita
  const codEvento = (evento.codigo || "").padEnd(4, " ").slice(0, 4);

  // Col 29-34 (6): Hora HHH:MM (ex: 004:30 ou 000:00)
  let horaTXT = "000:00";
  if (sol.hora) {
    const hParts = sol.hora.split(":");
    const hh = String(parseInt(hParts[0] || 0)).padStart(3, "0");
    const mm = String(parseInt(hParts[1] || 0)).padStart(2, "0");
    horaTXT = hh + ":" + mm;
  }
  const hora = horaTXT.slice(0, 6);

  // Col 35-49 (15): Referência — Real formatado
  const ref = formatReal(sol.referencia || sol.hora_decimal || 0, 15).slice(0, 15);

  // Col 50-64 (15): Valor
  const val = formatReal(sol.valor || 0, 15).slice(0, 15);

  // Col 65-79 (15): Valor original
  const valOrig = formatReal(sol.valor_original || sol.valor || 0, 15).slice(0, 15);

  // Col 80 (1): Alterado manualmente — N padrão
  const alterado = "N";

  // Col 81 (1): Dados de férias — N padrão
  const ferias = "N";

  const linha = chapa + data + codEvento + hora + ref + val + valOrig + alterado + ferias;
  return linha;
}

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

function Card({ children, style = {} }) {
  return (
    <div style={{
      background: "#fff", borderRadius: 12, border: "1px solid #E5E7EB",
      padding: "20px 24px", ...style
    }}>
      {children}
    </div>
  );
}

function Button({ children, onClick, variant = "primary", size = "md", disabled = false, style = {} }) {
  const variants = {
    primary: { background: "#1B3A6B", color: "#fff", border: "none" },
    secondary: { background: "#F3F4F6", color: "#374151", border: "1px solid #E5E7EB" },
    success: { background: "#10B981", color: "#fff", border: "none" },
    danger: { background: "#EF4444", color: "#fff", border: "none" },
    warning: { background: "#F59E0B", color: "#fff", border: "none" },
    ghost: { background: "transparent", color: "#1B3A6B", border: "1px solid #1B3A6B" },
  };
  const sizes = {
    sm: { padding: "5px 12px", fontSize: 12 },
    md: { padding: "8px 18px", fontSize: 13 },
    lg: { padding: "11px 24px", fontSize: 14 },
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        ...variants[variant], ...sizes[size],
        borderRadius: 8, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1, fontFamily: "inherit", transition: "all 0.15s",
        ...style
      }}
    >
      {children}
    </button>
  );
}

function Input({ label, value, onChange, type = "text", placeholder = "", required = false, style = {} }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      {label && (
        <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", letterSpacing: 0.3 }}>
          {label}{required && <span style={{ color: "#EF4444" }}> *</span>}
        </label>
      )}
      <input
        type={type} value={value} onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px",
          fontSize: 13, color: "#111827", outline: "none", fontFamily: "inherit",
          background: "#FAFAFA", ...style
        }}
      />
    </div>
  );
}

function Select({ label, value, onChange, options, required = false }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
      {label && (
        <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", letterSpacing: 0.3 }}>
          {label}{required && <span style={{ color: "#EF4444" }}> *</span>}
        </label>
      )}
      <select
        value={value} onChange={e => onChange(e.target.value)}
        style={{
          border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px",
          fontSize: 13, color: "#111827", outline: "none", fontFamily: "inherit",
          background: "#FAFAFA", cursor: "pointer"
        }}
      >
        <option value="">Selecione...</option>
        {options.map(o => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  );
}

function Modal({ open, onClose, title, children, width = 540 }) {
  if (!open) return null;
  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000
    }} onClick={onClose}>
      <div style={{
        background: "#fff", borderRadius: 14, width, maxWidth: "95vw",
        maxHeight: "90vh", overflowY: "auto", boxShadow: "0 20px 60px rgba(0,0,0,0.2)"
      }} onClick={e => e.stopPropagation()}>
        <div style={{
          padding: "18px 24px", borderBottom: "1px solid #F3F4F6",
          display: "flex", alignItems: "center", justifyContent: "space-between"
        }}>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: "#111827" }}>{title}</h3>
          <button onClick={onClose} style={{
            background: "none", border: "none", fontSize: 20, cursor: "pointer",
            color: "#6B7280", lineHeight: 1, padding: "0 4px"
          }}>×</button>
        </div>
        <div style={{ padding: "20px 24px" }}>{children}</div>
      </div>
    </div>
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

const NAV_ITEMS = [
  { id: "cadastros",   label: "Cadastros",              icon: "🗂",  perfis: ["dp","admin"], submenu: CADASTROS_SUBMENU },
  { id: "solicitacoes",label: "Solicitações",           icon: "≡",  perfis: ["gestor","superior","dp","admin"] },
  { id: "aprovacoes",  label: "Aprovações",             icon: "✓",  perfis: ["gestor","superior","dp","admin"] },
  { id: "dashboard",   label: "Dashboard",              icon: "◉",  perfis: ["gestor","superior","dp","admin"] },
  { id: "exportacao",  label: "Exportação TXT",         icon: "↓",  perfis: ["dp","admin"] },
  { id: "auditoria",   label: "Auditoria",              icon: "📜", perfis: ["dp","admin"] },
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
  const [cadastrosAberto, setCadastrosAberto] = useState(
    active && active.startsWith("cad_")
  );

  const isCadActive = active && active.startsWith("cad_");

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
            const isParentActive = isCadActive || active === "cadastros";
            return (
              <div key={item.id}>
                {/* Botão pai */}
                <button
                  onClick={() => setCadastrosAberto(o => !o)}
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
                    transform: cadastrosAberto ? "rotate(180deg)" : "rotate(0deg)",
                    color: "rgba(255,255,255,0.4)"
                  }}>▼</span>
                </button>

                {/* Submenu */}
                {cadastrosAberto && (
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
  const lines = text.trim().split("\n");
  const headers = lines[0].split(",").map(h => h.trim().replace(/"/g, ""));
  return lines.slice(1).map(line => {
    const vals = line.split(",").map(v => v.trim().replace(/"/g, ""));
    return Object.fromEntries(headers.map((h, i) => [h, vals[i] || ""]));
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
    reader.onload = ev => setTexto(ev.target.result);
    reader.readAsText(f, "UTF-8");
  };

  const processar = () => {
    try {
      const rows = parseCSV(texto);
      const erros = [];
      const validos = [];
      rows.forEach((row, i) => {
        const faltando = colunas.filter(c => c.obrigatorio && !row[c.campo]);
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

  const confirmar = () => {
    onImportar(resultado.validos);
    setTexto(""); setResultado(null); setArquivo(null);
    onClose();
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
            : <Button variant="success" onClick={confirmar} disabled={resultado.validos.length === 0}>
                Importar {resultado.validos.length} registros
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
  const [form, setForm] = useState({ chapa: "", nome: "", funcao: "", situacao: "Ativo", centro_custo: "", desc_cc: "" });

  const lista = colaboradores.filter(c =>
    c.nome.toLowerCase().includes(busca.toLowerCase()) || c.chapa.includes(busca)
  );

  const abrirNovo = () => { setForm({ chapa: "", nome: "", funcao: "", situacao: "Ativo", centro_custo: "", desc_cc: "" }); setModalForm("novo"); };
  const abrirEditar = (c) => { setForm({ ...c }); setModalForm("editar"); };

  const salvar = () => {
    if (!form.chapa || !form.nome) { alert("Chapa e Nome são obrigatórios."); return; }
    if (modalForm === "novo") {
      if (colaboradores.find(c => c.chapa === form.chapa)) { alert("Chapa já cadastrada."); return; }
      setColaboradores(p => [...p, { ...form, id: Date.now() }]);
    } else {
      setColaboradores(p => p.map(c => c.id === form.id ? { ...form } : c));
    }
    setModalForm(null);
  };

  const inativar = (id) => {
    setColaboradores(p => p.map(c => c.id === id ? { ...c, situacao: c.situacao === "Ativo" ? "Inativo" : "Ativo" } : c));
  };

  const onImportar = (rows) => {
    const novos = rows.map((r, i) => ({
      id: Date.now() + i,
      chapa: r.chapa || r.Chapa || "",
      nome: r.nome || r.Nome || "",
      funcao: r.funcao || r.Funcao || "",
      situacao: r.situacao || r.Situacao || "Ativo",
      centro_custo: r.centro_custo || r.CentroCusto || "",
      desc_cc: r.desc_cc || r.DescCC || "",
    })).filter(r => r.chapa && r.nome);
    setColaboradores(p => {
      const chapasExistentes = new Set(p.map(c => c.chapa));
      const inseridos = novos.filter(n => !chapasExistentes.has(n.chapa));
      const atualizados = p.map(c => {
        const upd = novos.find(n => n.chapa === c.chapa);
        return upd ? { ...c, ...upd } : c;
      });
      return [...atualizados, ...inseridos];
    });
  };

  const colunas = [
    { campo: "chapa", obrigatorio: true, exemplo: "0001" },
    { campo: "nome", obrigatorio: true, exemplo: "João da Silva" },
    { campo: "funcao", obrigatorio: false, exemplo: "Analista" },
    { campo: "situacao", obrigatorio: false, exemplo: "Ativo" },
    { campo: "centro_custo", obrigatorio: false, exemplo: "001" },
    { campo: "desc_cc", obrigatorio: false, exemplo: "TI" },
  ];

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: "#111827" }}>Colaboradores</h2>
          <p style={{ margin: "3px 0 0", fontSize: 12, color: "#6B7280" }}>{colaboradores.length} colaborador(es) cadastrado(s)</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <Button variant="secondary" onClick={() => setModalImport(true)}>⬆ Importar CSV</Button>
          <Button onClick={abrirNovo}>+ Novo Colaborador</Button>
        </div>
      </div>

      <Card style={{ marginBottom: 16, padding: "12px 16px" }}>
        <Input value={busca} onChange={setBusca} placeholder="Buscar por nome ou matrícula..." />
      </Card>

      <Card style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Matrícula", "Nome", "Função", "C. Custo", "Situação", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
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
                <td style={{ padding: "11px 16px", fontSize: 12, color: "#374151" }}>{c.funcao || "—"}</td>
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

  const abrirNovo = () => { setForm({ codigo: "", descricao: "", tipo: "provento", forma: "valor" }); setModalForm("novo"); };
  const abrirEditar = (e) => { setForm({ ...e }); setModalForm("editar"); };

  const salvar = () => {
    if (!form.codigo || !form.descricao) { alert("Código e Descrição são obrigatórios."); return; }
    if (modalForm === "novo") {
      if (eventos.find(e => e.codigo === form.codigo)) { alert("Código de evento já cadastrado."); return; }
      setEventos(p => [...p, { ...form, id: Date.now() }]);
    } else {
      setEventos(p => p.map(e => e.id === form.id ? { ...form } : e));
    }
    setModalForm(null);
  };

  const excluir = (id) => {
    if (window.confirm("Deseja excluir este evento?")) setEventos(p => p.filter(e => e.id !== id));
  };

  const onImportar = (rows) => {
    const novos = rows.map((r, i) => ({
      id: Date.now() + i,
      codigo: r.codigo || r.Codigo || "",
      descricao: r.descricao || r.Descricao || "",
      tipo: r.tipo || r.Tipo || "provento",
      forma: r.forma || r.Forma || "valor",
    })).filter(r => r.codigo && r.descricao);
    setEventos(p => {
      const codsExistentes = new Set(p.map(e => e.codigo));
      const inseridos = novos.filter(n => !codsExistentes.has(n.codigo));
      const atualizados = p.map(e => { const upd = novos.find(n => n.codigo === e.codigo); return upd ? { ...e, ...upd } : e; });
      return [...atualizados, ...inseridos];
    });
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
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: "#111827" }}>Eventos da Folha</h2>
          <p style={{ margin: "3px 0 0", fontSize: 12, color: "#6B7280" }}>{eventos.length} evento(s) cadastrado(s)</p>
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
          </thead>
          <tbody>
            {eventos.map((e, i) => (
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
const MOCK_HIERARQUIA_INIT = [
  { id: 1, gestor_id: 1, gestor_nome: "Carlos Mendes", superior_id: 2, superior_nome: "Ana Souza", centro_custo: "001", desc_cc: "TI", ativo: true },
  { id: 2, gestor_id: 1, gestor_nome: "Carlos Mendes", superior_id: 2, superior_nome: "Ana Souza", centro_custo: "003", desc_cc: "Logística", ativo: true },
];

function CadHierarquia({ hierarquia, setHierarquia, usuarios }) {
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [form, setForm] = useState({ gestor_id: "", superior_id: "", centro_custo: "", desc_cc: "" });

  const gestores = usuarios.filter(u => u.perfil === "gestor" || u.perfil === "admin");
  const superiores = usuarios.filter(u => u.perfil === "superior" || u.perfil === "admin");

  const abrirNovo = () => { setForm({ gestor_id: "", superior_id: "", centro_custo: "", desc_cc: "" }); setModalForm("novo"); };
  const abrirEditar = (h) => { setForm({ ...h }); setModalForm("editar"); };

  const salvar = () => {
    if (!form.gestor_id || !form.superior_id) { alert("Gestor e Superior são obrigatórios."); return; }
    const g = usuarios.find(u => u.id === parseInt(form.gestor_id));
    const s = usuarios.find(u => u.id === parseInt(form.superior_id));
    if (modalForm === "novo") {
      setHierarquia(p => [...p, { ...form, id: Date.now(), gestor_nome: g?.nome, superior_nome: s?.nome, ativo: true, gestor_id: parseInt(form.gestor_id), superior_id: parseInt(form.superior_id) }]);
    } else {
      setHierarquia(p => p.map(h => h.id === form.id ? { ...form, gestor_nome: g?.nome, superior_nome: s?.nome, gestor_id: parseInt(form.gestor_id), superior_id: parseInt(form.superior_id) } : h));
    }
    setModalForm(null);
  };

  const toggleAtivo = (id) => setHierarquia(p => p.map(h => h.id === id ? { ...h, ativo: !h.ativo } : h));

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
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: "#111827" }}>Hierarquia de Aprovação</h2>
          <p style={{ margin: "3px 0 0", fontSize: 12, color: "#6B7280" }}>Define quem aprova as solicitações de cada gestor</p>
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
              {["Gestor (1ª alçada)", "Superior (2ª alçada)", "Centro de Custo", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {hierarquia.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhuma regra cadastrada</td></tr>
            ) : hierarquia.map((h, i) => (
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
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>Gestor (1ª alçada) *</label>
            <select value={form.gestor_id} onChange={e => setForm(p => ({ ...p, gestor_id: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
              <option value="">Selecione...</option>
              {gestores.map(u => <option key={u.id} value={u.id}>{u.nome}</option>)}
            </select>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: "#374151" }}>Superior (2ª alçada) *</label>
            <select value={form.superior_id} onChange={e => setForm(p => ({ ...p, superior_id: e.target.value }))}
              style={{ border: "1px solid #D1D5DB", borderRadius: 8, padding: "8px 12px", fontSize: 13, fontFamily: "inherit", background: "#FAFAFA" }}>
              <option value="">Selecione...</option>
              {superiores.map(u => <option key={u.id} value={u.id}>{u.nome}</option>)}
            </select>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 12 }}>
            <Input label="Cód. Centro de Custo" value={form.centro_custo} onChange={v => setForm(p => ({ ...p, centro_custo: v }))} placeholder="001 (vazio = todos)" />
            <Input label="Descrição CC" value={form.desc_cc} onChange={v => setForm(p => ({ ...p, desc_cc: v }))} placeholder="TI, RH..." />
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
const MOCK_ALCADAS_INIT = [
  { id: 1, evento_id: 1, evento_nome: "Auxílio Quilometragem", num_alcadas: 2, exige_anexo: true, ativo: true },
  { id: 2, evento_id: 2, evento_nome: "Ajuda de Custo",        num_alcadas: 2, exige_anexo: true, ativo: true },
  { id: 3, evento_id: 3, evento_nome: "Horas Extras 50%",      num_alcadas: 1, exige_anexo: false, ativo: true },
  { id: 4, evento_id: 5, evento_nome: "Desconto Multa Trânsito", num_alcadas: 2, exige_anexo: true, ativo: true },
];

function CadAlcadas({ alcadas, setAlcadas, eventos }) {
  const [modalImport, setModalImport] = useState(false);
  const [modalForm, setModalForm] = useState(null);
  const [form, setForm] = useState({ evento_id: "", num_alcadas: 1, exige_anexo: false });

  const abrirNovo = () => { setForm({ evento_id: "", num_alcadas: 1, exige_anexo: false }); setModalForm("novo"); };
  const abrirEditar = (a) => { setForm({ ...a }); setModalForm("editar"); };

  const salvar = () => {
    if (!form.evento_id) { alert("Selecione o evento."); return; }
    const ev = eventos.find(e => e.id === parseInt(form.evento_id));
    if (modalForm === "novo") {
      if (alcadas.find(a => a.evento_id === parseInt(form.evento_id))) { alert("Regra já existe para este evento."); return; }
      setAlcadas(p => [...p, { ...form, id: Date.now(), evento_id: parseInt(form.evento_id), evento_nome: ev?.descricao, num_alcadas: parseInt(form.num_alcadas), ativo: true }]);
    } else {
      setAlcadas(p => p.map(a => a.id === form.id ? { ...form, evento_id: parseInt(form.evento_id), evento_nome: ev?.descricao, num_alcadas: parseInt(form.num_alcadas) } : a));
    }
    setModalForm(null);
  };

  const toggleAtivo = (id) => setAlcadas(p => p.map(a => a.id === id ? { ...a, ativo: !a.ativo } : a));

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
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: "#111827" }}>Regras de Alçadas</h2>
          <p style={{ margin: "3px 0 0", fontSize: 12, color: "#6B7280" }}>Define quantas aprovações cada tipo de evento exige</p>
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
          </thead>
          <tbody>
            {alcadas.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: 32, textAlign: "center", color: "#9CA3AF" }}>Nenhuma regra cadastrada</td></tr>
            ) : alcadas.map((a, i) => (
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
  const [form, setForm] = useState({ nome: "", email: "", perfil: "gestor", senha: "", ativo: true });

  const abrirNovo = () => { setForm({ nome: "", email: "", perfil: "gestor", senha: "", ativo: true }); setModalForm("novo"); };
  const abrirEditar = (u) => { setForm({ ...u, senha: "" }); setModalForm("editar"); };

  const salvar = () => {
    if (!form.nome || !form.email) { alert("Nome e E-mail são obrigatórios."); return; }
    if (modalForm === "novo") {
      if (usuarios.find(u => u.email === form.email)) { alert("E-mail já cadastrado."); return; }
      const av = form.nome.split(" ").map(p => p[0]).slice(0, 2).join("").toUpperCase();
      setUsuarios(p => [...p, { ...form, id: Date.now(), avatar: av, senha: form.senha || "123" }]);
    } else {
      setUsuarios(p => p.map(u => u.id === form.id ? { ...u, nome: form.nome, email: form.email, perfil: form.perfil, ativo: form.ativo } : u));
    }
    setModalForm(null);
  };

  const toggleAtivo = (id) => setUsuarios(p => p.map(u => u.id === id ? { ...u, ativo: u.ativo === false ? true : false } : u));

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
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: "#111827" }}>Usuários do Sistema</h2>
          <p style={{ margin: "3px 0 0", fontSize: 12, color: "#6B7280" }}>{usuarios.length} usuário(s) cadastrado(s)</p>
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
          </thead>
          <tbody>
            {usuarios.map((u, i) => (
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
                <option value="admin">Admin</option>
              </select>
            </div>
            {modalForm === "novo" && (
              <Input label="Senha inicial" value={form.senha} onChange={v => setForm(p => ({ ...p, senha: v }))} type="password" placeholder="(padrão: 123)" />
            )}
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
// ─── SOLICITAÇÕES EM BLOCO ────────────────────────────────────────────────────

const LINHA_VAZIA = () => ({
  _id: Date.now() + Math.random(),
  colaborador_id: "", colaborador: null, data: "", hora: "",
  valor: "", observacao: ""
});

function Solicitacoes({ solicitacoes, setSolicitacoes, blocos, setBlocos, user }) {
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
    const linhasValidas = editandoBloco.linhas.filter(l => l.colaborador_id && l.data && l.valor);
    if (!editandoBloco.evento_id) { alert("Selecione o Evento do Bloco."); return; }
    if (!editandoBloco.competencia) { alert("Selecione a Competência."); return; }
    if (linhasValidas.length === 0) { alert("Adicione ao menos uma linha com colaborador, data e valor."); return; }

    const ts = new Date().toLocaleString("pt-BR");
    const eventoObj = MOCK_EVENTOS.find(e => e.id === parseInt(editandoBloco.evento_id));

    const payload = {
      descricao: editandoBloco.descricao || ("Bloco " + new Date().toLocaleDateString("pt-BR")),
      competencia: editandoBloco.competencia,
      evento_id: parseInt(editandoBloco.evento_id),
      linhas: linhasValidas.map(l => ({
        colaborador_id: parseInt(l.colaborador_id),
        data: l.data,
        hora: l.hora || null,
        valor: parseFloat(l.valor),
        referencia: l.referencia ? parseFloat(l.referencia) : null,
        observacao: l.observacao || "",
      })),
    };

    try {
      if (editandoBloco.id) {
        // edição local por ora (backend não tem PUT /blocos/:id)
        setBlocos(prev => prev.map(b => b.id === editandoBloco.id ? {
          ...b,
          competencia: editandoBloco.competencia,
          descricao: editandoBloco.descricao,
          evento_id: editandoBloco.evento_id,
          evento: eventoObj,
          anexo_nome: editandoBloco.anexo_nome,
          anexo_tamanho: editandoBloco.anexo_tamanho,
          linhas: linhasValidas.map(l => ({ ...l, evento: eventoObj, colaborador: l.colaborador || MOCK_COLABORADORES.find(c => c.id === parseInt(l.colaborador_id)) })),
          historico: [...b.historico, { acao: "editado", usuario: user.nome, data: ts, obs: "Bloco editado pelo solicitante" }]
        } : b));
      } else {
        await api.criarBloco(payload);
        // Recarregar blocos da API
        const blcs = await api.listarBlocos();
        const blocsNorm = blcs.map(b => ({
          ...b,
          linhas: b.linhas || [],
          historico: b.historico || [],
          evento: eventoObj || MOCK_EVENTOS.find(e => e.id === b.evento_id),
          solicitante: b.solicitante_nome || b.solicitante || user.nome,
        }));
        setBlocos(blocsNorm);
      }
    } catch (err) {
      console.warn("API indisponível, salvando localmente:", err.message);
      if (editandoBloco.id) {
        setBlocos(prev => prev.map(b => b.id === editandoBloco.id ? {
          ...b,
          competencia: editandoBloco.competencia,
          descricao: editandoBloco.descricao,
          evento_id: editandoBloco.evento_id,
          evento: eventoObj,
          anexo_nome: editandoBloco.anexo_nome,
          anexo_tamanho: editandoBloco.anexo_tamanho,
          linhas: linhasValidas.map(l => ({ ...l, evento: eventoObj, colaborador: l.colaborador || MOCK_COLABORADORES.find(c => c.id === parseInt(l.colaborador_id)) })),
          historico: [...b.historico, { acao: "editado", usuario: user.nome, data: ts, obs: "Bloco editado pelo solicitante" }]
        } : b));
      } else {
        setBlocos(prev => [...prev, {
          id: Date.now(),
          descricao: editandoBloco.descricao || ("Bloco " + new Date().toLocaleDateString("pt-BR")),
          competencia: editandoBloco.competencia,
          evento_id: editandoBloco.evento_id,
          evento: eventoObj,
          anexo_nome: editandoBloco.anexo_nome,
          anexo_tamanho: editandoBloco.anexo_tamanho,
          status: "pendente_gestor",
          solicitante: user.nome,
          solicitante_id: user.id,
          criado_em: ts,
          linhas: linhasValidas.map(l => ({ ...l, evento: eventoObj, colaborador: l.colaborador || MOCK_COLABORADORES.find(c => c.id === parseInt(l.colaborador_id)) })),
          historico: [{ acao: "criado", usuario: user.nome, data: ts, obs: "Bloco enviado para aprovação" }]
        }]);
      }
    }
    setModalNovoBloco(false);
    setEditandoBloco(null);
  };

  const podeEditar = (bloco) => bloco.status === "pendente_gestor" || bloco.status === "devolvido";

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: "#111827" }}>Solicitações de Pagamento</h2>
          <p style={{ margin: "4px 0 0", fontSize: 12, color: "#6B7280" }}>Registre e envie variáveis de pagamento para aprovação</p>
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

function CelulaColaborador({ linha, idx, updateLinha }) {
  const [buscaNome, setBuscaNome] = useState(linha.colaborador?.nome || "");
  const [buscaChapa, setBuscaChapa] = useState(linha.colaborador?.chapa || "");
  const [sugestoesNome, setSugestoesNome] = useState([]);
  const [sugestoesChapa, setSugestoesChapa] = useState([]);

  const selecionarColaborador = (colab) => {
    setBuscaNome(colab.nome);
    setBuscaChapa(colab.chapa);
    setSugestoesNome([]);
    setSugestoesChapa([]);
    updateLinha(idx, "colaborador_id", colab.id);
    updateLinha(idx, "colaborador", colab);
  };

  const onChangeNome = (v) => {
    setBuscaNome(v);
    updateLinha(idx, "colaborador_id", "");
    updateLinha(idx, "colaborador", null);
    setBuscaChapa("");
    if (v.length >= 2) {
      setSugestoesNome(MOCK_COLABORADORES.filter(c => c.nome.toLowerCase().includes(v.toLowerCase())));
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
      setSugestoesChapa(MOCK_COLABORADORES.filter(c => c.chapa.includes(v)));
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

function ModalNovoBloco({ open, onClose, bloco, setBloco, onSalvar }) {
  const addLinha = () => setBloco(b => ({ ...b, linhas: [...b.linhas, LINHA_VAZIA()] }));
  const removeLinha = (idx) => setBloco(b => ({ ...b, linhas: b.linhas.filter((_, i) => i !== idx) }));
  const updateLinha = (idx, campo, val) => setBloco(b => ({
    ...b, linhas: b.linhas.map((l, i) => i === idx ? { ...l, [campo]: val } : l)
  }));

  const totalBloco = bloco.linhas.reduce((a, l) => a + parseFloat(l.valor || 0), 0);
  const eventoSelecionado = MOCK_EVENTOS.find(e => e.id === parseInt(bloco.evento_id));

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
              label="Descrição do Bloco"
              value={bloco.descricao}
              onChange={v => setBloco(b => ({ ...b, descricao: v }))}
              placeholder="Ex: Horas extras — Operação Sul"
            />

            {/* Competência — select de meses */}
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              <label style={{ fontSize: 12, fontWeight: 600, color: "#374151", letterSpacing: 0.3 }}>
                Competência <span style={{ color: "#EF4444" }}>*</span>
              </label>
              <select
                value={bloco.competencia}
                onChange={e => setBloco(b => ({ ...b, competencia: e.target.value }))}
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
                {MOCK_EVENTOS.map(e => (
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
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: 780 }}>
              <thead>
                <tr style={{ background: "#0F2447" }}>
                  {["Matrícula / Colaborador *", "Data *", "Hora", "Valor (R$) *", "Observação", ""].map(h => (
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
                    {/* Matrícula + Nome autocompletados */}
                    <td style={{ padding: "6px 8px", minWidth: 260 }}>
                      <CelulaColaborador linha={linha} idx={idx} updateLinha={updateLinha} />
                    </td>
                    <td style={{ padding: "6px 8px", minWidth: 120 }}>
                      <input type="date" value={linha.data} onChange={e => updateLinha(idx, "data", e.target.value)}
                        style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                    </td>
                    <td style={{ padding: "6px 8px", minWidth: 88 }}>
                      <input type="time" value={linha.hora} onChange={e => updateLinha(idx, "hora", e.target.value)}
                        style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                    </td>
                    <td style={{ padding: "6px 8px", minWidth: 100 }}>
                      <input type="number" step="0.01" value={linha.valor} onChange={e => updateLinha(idx, "valor", e.target.value)}
                        placeholder="0.00"
                        style={{ width: "100%", border: "1px solid #D1D5DB", borderRadius: 6, padding: "5px 7px", fontSize: 11, fontFamily: "inherit" }} />
                    </td>
                    <td style={{ padding: "6px 8px", minWidth: 160 }}>
                      <input value={linha.observacao} onChange={e => updateLinha(idx, "observacao", e.target.value)}
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
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: "#111827" }}>Exportação TOTVS RM Labore</h2>
          <p style={{ margin: "4px 0 0", fontSize: 12, color: "#6B7280" }}>
            Layout de Importação de Movimento — arquivo TXT posicional (81 caracteres/linha)
          </p>
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
        <h2 style={{ margin: "0 0 4px", fontSize: 18, fontWeight: 700, color: "#111827" }}>Auditoria</h2>
        <p style={{ margin: 0, fontSize: 12, color: "#6B7280" }}>Registro completo de todas as ações do sistema</p>
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
function Usuarios() {
  return (
    <div style={{ padding: 28 }}>
      <h2 style={{ margin: "0 0 20px", fontSize: 18, fontWeight: 700, color: "#111827" }}>Usuários do Sistema</h2>
      <Card style={{ padding: 0 }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ background: "#F9FAFB" }}>
              {["Avatar", "Nome", "E-mail", "Perfil", "Status", "Ações"].map(h => (
                <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {MOCK_USERS.map((u, i) => (
              <tr key={u.id} style={{ borderTop: "1px solid #F3F4F6", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                <td style={{ padding: "12px 16px" }}>
                  <div style={{
                    width: 32, height: 32, borderRadius: 8,
                    background: PERFIL_CONFIG[u.perfil]?.color,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 12, fontWeight: 700, color: "#fff"
                  }}>{u.avatar}</div>
                </td>
                <td style={{ padding: "12px 16px", fontSize: 13, fontWeight: 600, color: "#111827" }}>{u.nome}</td>
                <td style={{ padding: "12px 16px", fontSize: 12, color: "#374151" }}>{u.email}</td>
                <td style={{ padding: "12px 16px" }}>
                  <span style={{
                    padding: "2px 10px", borderRadius: 10, fontSize: 11, fontWeight: 600,
                    background: PERFIL_CONFIG[u.perfil]?.color + "22",
                    color: PERFIL_CONFIG[u.perfil]?.color
                  }}>{PERFIL_CONFIG[u.perfil]?.label}</span>
                </td>
                <td style={{ padding: "12px 16px" }}>
                  <span style={{ padding: "2px 10px", borderRadius: 10, fontSize: 11, fontWeight: 600, background: "#D1FAE5", color: "#065F46" }}>Ativo</span>
                </td>
                <td style={{ padding: "12px 16px" }}>
                  <Button variant="ghost" size="sm">Editar</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}


const MOCK_BLOCOS_INIT = [
  {
    id: 1,
    descricao: "Variáveis Setembro 2025",
    competencia: "092025",
    status: "aprovado_final",
    solicitante: "Carlos Mendes",
    solicitante_id: 1,
    criado_em: "25/09/2025 09:00:00",
    linhas: [
      { _id: 1, colaborador_id: 1, evento_id: 1, data: "2025-09-30", hora: "00:00", valor: "1190.47", observacao: "Deslocamento filial sul", colaborador: MOCK_COLABORADORES[0], evento: MOCK_EVENTOS[0] },
      { _id: 2, colaborador_id: 2, evento_id: 2, data: "2025-09-20", hora: "", valor: "500.00", observacao: "Curso externo SP", colaborador: MOCK_COLABORADORES[1], evento: MOCK_EVENTOS[1] },
    ],
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "25/09/2025 09:00:00", obs: "Bloco enviado para aprovação" },
      { acao: "aprovado_gestor", usuario: "Carlos Mendes", data: "25/09/2025 09:30:00", obs: "" },
      { acao: "aprovado_superior", usuario: "Ana Souza", data: "26/09/2025 10:00:00", obs: "" },
      { acao: "aprovado_dp", usuario: "Fernanda Lima", data: "27/09/2025 14:00:00", obs: "" },
    ]
  },
  {
    id: 2,
    descricao: "Horas Extras Operação",
    competencia: "092025",
    status: "pendente_gestor",
    solicitante: "Carlos Mendes",
    solicitante_id: 1,
    criado_em: "28/09/2025 08:00:00",
    linhas: [
      { _id: 3, colaborador_id: 3, evento_id: 3, data: "2025-09-28", hora: "04:30", valor: "340.00", observacao: "Plantão final de semana", colaborador: MOCK_COLABORADORES[2], evento: MOCK_EVENTOS[2] },
      { _id: 4, colaborador_id: 4, evento_id: 6, data: "2025-09-29", hora: "02:00", valor: "210.00", observacao: "", colaborador: MOCK_COLABORADORES[3], evento: MOCK_EVENTOS[5] },
    ],
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "28/09/2025 08:00:00", obs: "Bloco enviado para aprovação" },
    ]
  },
  {
    id: 3,
    descricao: "Ajudas de Custo Outubro",
    competencia: "102025",
    status: "devolvido",
    solicitante: "Carlos Mendes",
    solicitante_id: 1,
    criado_em: "01/10/2025 10:00:00",
    linhas: [
      { _id: 5, colaborador_id: 4, evento_id: 5, data: "2025-10-01", hora: "", valor: "293.47", observacao: "Multa via expressa", colaborador: MOCK_COLABORADORES[3], evento: MOCK_EVENTOS[4] },
    ],
    historico: [
      { acao: "criado", usuario: "Carlos Mendes", data: "01/10/2025 10:00:00", obs: "Bloco enviado para aprovação" },
      { acao: "devolvido", usuario: "Ana Souza", data: "02/10/2025 09:00:00", obs: "Falta comprovante da infração" },
    ]
  },
];

function Aprovacoes({ blocos, setBlocos, user }) {
  const [justificativa, setJustificativa] = useState("");
  const [modalAcao, setModalAcao] = useState(null);

  const getFilaParaUsuario = () => {
    if (user.perfil === "gestor") return blocos.filter(b => b.status === "pendente_gestor");
    if (user.perfil === "superior") return blocos.filter(b => b.status === "pendente_superior");
    if (user.perfil === "dp") return blocos.filter(b => b.status === "pendente_dp");
    if (user.perfil === "admin") return blocos.filter(b => b.status.startsWith("pendente"));
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
    } catch (err) {
      console.warn("API indisponível, ação aplicada localmente:", err.message);
    }

    setModalAcao(null);
    setJustificativa("");
  };

  return (
    <div style={{ padding: 28 }}>
      <h2 style={{ margin: "0 0 6px", fontSize: 18, fontWeight: 700, color: "#111827" }}>Fila de Aprovações</h2>
      <p style={{ margin: "0 0 20px", fontSize: 12, color: "#6B7280" }}>Aprovação por bloco completo de solicitações</p>

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



export default function App() {
  const [user, setUser] = useState(null);
  const [page, setPage] = useState("dashboard");

  // ── Estado global dos cadastros ──
  const [colaboradores, setColaboradores] = useState(MOCK_COLABORADORES);
  const [eventos, setEventos] = useState(MOCK_EVENTOS);
  const [usuarios, setUsuarios] = useState(MOCK_USERS);
  const [hierarquia, setHierarquia] = useState(MOCK_HIERARQUIA_INIT);
  const [alcadas, setAlcadas] = useState(MOCK_ALCADAS_INIT);
  const [solicitacoes, setSolicitacoes] = useState(MOCK_SOLICITACOES_INIT);
  const [blocos, setBlocos] = useState(MOCK_BLOCOS_INIT);
  const [sessao, setSessao] = useState(null);
  const [sessaoAviso, setSessaoAviso] = useState(false);

  // ── Carregar dados reais da API após login ────────────────────────────────
  const carregarDados = useCallback(async () => {
    try {
      const [cols, evts, blcs] = await Promise.all([
        api.listarColaboradores().catch(() => null),
        api.listarEventos().catch(() => null),
        api.listarBlocos().catch(() => null),
      ]);
      if (cols && cols.length > 0) setColaboradores(cols);
      if (evts && evts.length > 0) setEventos(evts);
      if (blcs && blcs.length > 0) {
        const evtsRef = evts || MOCK_EVENTOS;
        const blocsNorm = blcs.map(b => ({
          ...b,
          linhas: b.linhas || [],
          historico: b.historico || [],
          evento: evtsRef.find(e => e.id === b.evento_id) || null,
          solicitante: b.solicitante_nome || b.solicitante || "",
        }));
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
          {page === "solicitacoes"      && <Solicitacoes solicitacoes={solicitacoes} setSolicitacoes={setSolicitacoes} blocos={blocos} setBlocos={setBlocos} user={user} colaboradores={colaboradores} eventos={eventos} />}
          {page === "aprovacoes"        && <Aprovacoes blocos={blocos} setBlocos={setBlocos} user={user} />}
          {page === "exportacao"        && <Exportacao solicitacoes={solsParaExportacao} blocos={blocos.filter(b => b.status === "aprovado_final")} />}
          {page === "cad_colaboradores" && <CadColaboradores colaboradores={colaboradores} setColaboradores={setColaboradores} />}
          {page === "cad_eventos"       && <CadEventos eventos={eventos} setEventos={setEventos} />}
          {page === "cad_hierarquia"    && <CadHierarquia hierarquia={hierarquia} setHierarquia={setHierarquia} usuarios={usuarios} />}
          {page === "cad_alcadas"       && <CadAlcadas alcadas={alcadas} setAlcadas={setAlcadas} eventos={eventos} />}
          {page === "cad_usuarios"      && <CadUsuarios usuarios={usuarios} setUsuarios={setUsuarios} />}
          {page === "auditoria"         && <Auditoria solicitacoes={solicitacoes} blocos={blocos} sessao={sessao} />}
        </div>
      </div>
    </div>
  );
}
