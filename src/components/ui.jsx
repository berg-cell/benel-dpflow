// src/components/ui.jsx
// Componentes de UI base do DP Flow — Benel (Fase 4 do saneamento).
// Extraído do App.jsx. Conteúdo idêntico ao original.
// Componentes puros de apresentação (sem hooks, sem estado, sem contexto).
// Badge permanece no App.jsx (depende de STATUS_CONFIG local).

export function Card({ children, style = {} }) {
  return (
    <div style={{
      background: "#fff", borderRadius: 12, border: "1px solid #E5E7EB",
      padding: "20px 24px", ...style
    }}>
      {children}
    </div>
  );
}

export function Button({ children, onClick, variant = "primary", size = "md", disabled = false, style = {} }) {
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

export function Input({ label, value, onChange, type = "text", placeholder = "", required = false, style = {} }) {
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

export function Select({ label, value, onChange, options, required = false }) {
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

export function Modal({ open, onClose, title, children, width = 540 }) {
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

export function verificarForcaSenha(senha) {
  const checks = [
    { ok: senha.length >= 8,                        label: "Mínimo 8 caracteres" },
    { ok: /[A-Z]/.test(senha),                       label: "Letra maiúscula" },
    { ok: /[a-z]/.test(senha),                       label: "Letra minúscula" },
    { ok: /\d/.test(senha),                          label: "Número" },
    { ok: /[@$!%*?&_\-#]/.test(senha),              label: "Caractere especial (@$!%*?&_-#)" },
  ];
  const score = checks.filter(c => c.ok).length;
  const forca = score <= 2 ? "fraca" : score <= 3 ? "média" : score === 4 ? "boa" : "forte";
  const cor   = score <= 2 ? "#EF4444" : score <= 3 ? "#F59E0B" : score === 4 ? "#3B82F6" : "#10B981";
  return { checks, score, forca, cor, valida: score === 5 };
}

export function IndicadorSenha({ senha }) {
  if (!senha) return null;
  const { checks, score, forca, cor } = verificarForcaSenha(senha);
  return (
    <div style={{ marginTop: 6 }}>
      <div style={{ display: "flex", gap: 4, marginBottom: 6 }}>
        {[1,2,3,4,5].map(i => (
          <div key={i} style={{
            flex: 1, height: 4, borderRadius: 2,
            background: i <= score ? cor : "#E5E7EB",
            transition: "background 0.2s"
          }} />
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: cor }}>Força: {forca}</span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "3px 12px" }}>
        {checks.map(c => (
          <span key={c.label} style={{ fontSize: 10, color: c.ok ? "#10B981" : "#9CA3AF" }}>
            {c.ok ? "✓" : "○"} {c.label}
          </span>
        ))}
      </div>
    </div>
  );
}

