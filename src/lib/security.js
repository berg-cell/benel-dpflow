// src/lib/security.js
// SECURITY MODULE — DP Flow | Benel Soluções em Transporte e Logística
// Extraído do App.jsx (Fase 1 do saneamento). Conteúdo idêntico ao original.
// Sanitização XSS, Rate Limiting, Validação de Schema TOTVS RM,
// Prevenção IDOR, Sessão com expiração, Audit Log, Content Security Policy.

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
  senha:       /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_\-#])[A-Za-z\d@$!%*?&_\-#]{8,128}$/,
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
      "connect-src 'self' https://benel-dpflow-backend.vercel.app",
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
