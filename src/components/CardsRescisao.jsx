// src/components/CardsRescisao.jsx
// Sub-seção de Cards de Rescisão por filial — vai no TOPO da aba Desligamentos.
//
// USO no App.jsx (dentro da função Desligamentos, logo após `return ( <div style={{ padding: 28 }}>`):
//     <CardsRescisao user={user} />
//
// DEPENDE de dois métodos no api.js (ver bloco no final deste arquivo).
//
// Regra crítica (lição das sessões passadas): TODOS os useState no topo, guard depois.

import { useState, useEffect, useMemo, useRef } from "react";
import { api } from "../api";

const AZUL = "#0F2447";
const BORDA = "#E5E7EB";

const MESES = [
  "Janeiro","Fevereiro","Março","Abril","Maio","Junho",
  "Julho","Agosto","Setembro","Outubro","Novembro","Dezembro",
];

const brl = (n) =>
  Number(n || 0).toLocaleString("pt-BR", { style: "currency", currency: "BRL" });

// Converte "2819,25" (pt-BR, do RM) em número 2819.25
function parseNum(v) {
  if (v == null) return 0;
  const s = String(v).trim();
  if (!s) return 0;
  // remove separador de milhar "." e troca vírgula decimal por ponto
  const limpo = s.replace(/\./g, "").replace(",", ".");
  const n = parseFloat(limpo);
  return isNaN(n) ? 0 : n;
}

// Faz o parse do texto CSV do RM (separado por ;) e monta o payload do backend.
// Mapeia colunas do CSV -> campos que o importarLote espera.
function parseCsvRm(texto) {
  const linhas = texto
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (linhas.length < 2) return { registros: [], erro: "Arquivo vazio ou sem dados." };

  const header = linhas[0].split(";").map((h) => h.trim().toUpperCase());

  const idx = (nome) => header.indexOf(nome);
  const iChapa    = idx("CHAPA");
  const iNome     = idx("NOME");
  const iFilial   = idx("DES_FILIAL") !== -1 ? idx("DES_FILIAL") : idx("DESC_FILIAL_COMPLETA");
  const iLiquido  = idx("LIQUIDO");
  const iProv     = idx("PROVENTOS");
  const iDesc     = idx("DESCONTOS");
  const iFgts     = idx("FGTS_RESCISORIO");
  const iTotal    = idx("TOTAL");
  const iMes      = idx("MESCOMP");
  const iAno      = idx("ANOCOMP");

  if (iChapa === -1 || iMes === -1 || iAno === -1) {
    return {
      registros: [],
      erro: "Cabeçalho inválido. O CSV precisa ter as colunas CHAPA, MESCOMP e ANOCOMP (separador ; ).",
    };
  }

  const registros = [];
  for (let i = 1; i < linhas.length; i++) {
    const c = linhas[i].split(";");
    const chapa = (c[iChapa] || "").trim();
    if (!chapa) continue;

    registros.push({
      chapa,
      nome:             iNome    !== -1 ? (c[iNome] || "").trim() : "",
      filial:           iFilial  !== -1 ? (c[iFilial] || "").trim() : "",
      liquido:          iLiquido !== -1 ? parseNum(c[iLiquido]) : 0,
      proventos:        iProv    !== -1 ? parseNum(c[iProv]) : 0,
      descontos:        iDesc    !== -1 ? parseNum(c[iDesc]) : 0,
      fgts_rescisorio:  iFgts    !== -1 ? parseNum(c[iFgts]) : 0,
      valor_total:      iTotal   !== -1 ? parseNum(c[iTotal]) : 0,
      competencia_mes:  parseInt((c[iMes] || "").trim(), 10),
      competencia_ano:  parseInt((c[iAno] || "").trim(), 10),
    });
  }

  return { registros, erro: "" };
}

export default function CardsRescisao({ user }) {
  // ── TODOS os hooks ANTES de qualquer return condicional ──────────────────────
  const hoje = new Date();
  const [lista,       setLista]       = useState([]);
  const [carregando,  setCarregando]  = useState(true);
  const [erro,        setErro]        = useState("");
  const [msg,         setMsg]         = useState("");
  const [importando,  setImportando]  = useState(false);
  const [fMes,        setFMes]        = useState(0);                    // 0 = todos
  const [fAno,        setFAno]        = useState(hoje.getFullYear());
  const [aberto,      setAberto]      = useState(true);                // recolher/expandir
  const inputRef = useRef(null);

  const carregar = async () => {
    setCarregando(true);
    setErro("");
    try {
      const r = await api.listarRescisao();
      setLista(Array.isArray(r) ? r : (r?.data || []));
    } catch (e) {
      setErro(e.message || "Falha ao carregar valores de rescisão.");
    } finally {
      setCarregando(false);
    }
  };

  useEffect(() => { carregar(); }, []);

  // Anos disponíveis nos dados (para o dropdown) + ano atual
  const anos = useMemo(() => {
    const set = new Set(lista.map((r) => Number(r.competencia_ano)).filter(Boolean));
    set.add(hoje.getFullYear());
    return Array.from(set).sort((a, b) => b - a);
  }, [lista]);

  // Filtra por mês/ano
  const filtrada = useMemo(() => {
    return lista.filter((r) => {
      if (fAno && Number(r.competencia_ano) !== Number(fAno)) return false;
      if (fMes && Number(r.competencia_mes) !== Number(fMes)) return false;
      return true;
    });
  }, [lista, fMes, fAno]);

  // Agrupa por filial
  const porFilial = useMemo(() => {
    const map = new Map();
    for (const r of filtrada) {
      const key = r.filial || "Sem Filial";
      if (!map.has(key)) map.set(key, { filial: key, qtd: 0, total: 0 });
      const g = map.get(key);
      g.qtd += 1;
      g.total += Number(r.valor_total || 0);
    }
    return Array.from(map.values()).sort((a, b) => b.total - a.total);
  }, [filtrada]);

  const totalGeral = useMemo(
    () => filtrada.reduce((s, r) => s + Number(r.valor_total || 0), 0),
    [filtrada]
  );

  const onEscolherArquivo = () => {
    setErro(""); setMsg("");
    inputRef.current?.click();
  };

  const onArquivo = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setErro(""); setMsg("");

    const reader = new FileReader();
    reader.onload = async (ev) => {
      const texto = ev.target.result;
      const { registros, erro: erroParse } = parseCsvRm(texto);
      if (erroParse) { setErro(erroParse); e.target.value = ""; return; }
      if (registros.length === 0) { setErro("Nenhum registro válido no arquivo."); e.target.value = ""; return; }

      setImportando(true);
      try {
        // request() já retorna data.data desembrulhado → { inseridos, atualizados, erros, total }
        const d = (await api.importarRescisaoLote(registros)) || {};
        const ins = d.inseridos ?? 0;
        const att = d.atualizados ?? 0;
        const errs = d.erros?.length ?? 0;
        setMsg(`Importação concluída: ${ins} inserido(s), ${att} atualizado(s)${errs ? `, ${errs} com aviso` : ""}.`);
        await carregar();
      } catch (err) {
        setErro(err.message || "Falha ao importar o arquivo.");
      } finally {
        setImportando(false);
        e.target.value = ""; // permite reimportar o mesmo arquivo
      }
    };
    // RM exporta em windows-1252; ISO-8859-1 lê corretamente os acentos
    reader.readAsText(file, "ISO-8859-1");
  };

  // guard DEPOIS dos hooks — só dp/admin/presidente enxergam a seção
  if (!user || !["dp", "admin", "presidente"].includes(user.perfil)) return null;

  return (
    <div style={{ marginBottom: 24 }}>
      {/* Cabeçalho da seção */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12, flexWrap: "wrap", gap: 12 }}>
        <button
          onClick={() => setAberto((a) => !a)}
          style={{ display: "flex", alignItems: "center", gap: 8, background: "none", border: "none", cursor: "pointer", padding: 0, fontSize: 15, fontWeight: 700, color: AZUL }}
        >
          <span style={{ fontSize: 12, transform: aberto ? "rotate(90deg)" : "none", transition: "transform .15s" }}>▶</span>
          💰 Valores de Rescisão por Filial
        </button>

        {aberto && (
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <select value={fMes} onChange={(e) => setFMes(Number(e.target.value))}
              style={selStyle}>
              <option value={0}>Todos os meses</option>
              {MESES.map((m, i) => <option key={i} value={i + 1}>{m}</option>)}
            </select>
            <select value={fAno} onChange={(e) => setFAno(Number(e.target.value))}
              style={selStyle}>
              {anos.map((a) => <option key={a} value={a}>{a}</option>)}
            </select>
            <button onClick={onEscolherArquivo} disabled={importando}
              style={{ padding: "8px 16px", background: AZUL, color: "#fff", border: "none", borderRadius: 8, fontWeight: 600, fontSize: 13, cursor: importando ? "wait" : "pointer", opacity: importando ? 0.7 : 1 }}>
              {importando ? "Importando..." : "⬇️ Importar CSV"}
            </button>
            <input ref={inputRef} type="file" accept=".csv,text/csv" onChange={onArquivo} style={{ display: "none" }} />
          </div>
        )}
      </div>

      {aberto && (
        <>
          {erro && <div style={avisoStyle("#FEF2F2", "#FCA5A5", "#DC2626")}>⚠️ {erro}</div>}
          {msg  && <div style={avisoStyle("#F0FDF4", "#86EFAC", "#16A34A")}>✅ {msg}</div>}

          {carregando ? (
            <div style={{ color: "#6B7280", fontSize: 13, padding: "12px 0" }}>Carregando valores...</div>
          ) : filtrada.length === 0 ? (
            <div style={{ background: "#fff", border: `1px dashed ${BORDA}`, borderRadius: 12, padding: 24, textAlign: "center", color: "#6B7280", fontSize: 13 }}>
              Nenhum valor de rescisão para o período selecionado. Use <b>Importar CSV</b> para carregar os dados do RM.
            </div>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 12 }}>
              {/* Cards por filial */}
              {porFilial.map((g) => (
                <div key={g.filial} style={{ background: "#fff", border: `1px solid ${BORDA}`, borderRadius: 12, padding: 16 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: "#6B7280", textTransform: "uppercase", marginBottom: 6, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={g.filial}>
                    {g.filial}
                  </div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: AZUL, marginBottom: 4 }}>{brl(g.total)}</div>
                  <div style={{ fontSize: 12, color: "#6B7280" }}>{g.qtd} rescisã{g.qtd === 1 ? "o" : "ões"}</div>
                </div>
              ))}

              {/* Card total geral */}
              <div style={{ background: AZUL, borderRadius: 12, padding: 16, color: "#fff" }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#93C5FD", textTransform: "uppercase", marginBottom: 6 }}>Total Geral</div>
                <div style={{ fontSize: 20, fontWeight: 800, marginBottom: 4 }}>{brl(totalGeral)}</div>
                <div style={{ fontSize: 12, color: "#CBD5E1" }}>{filtrada.length} rescisã{filtrada.length === 1 ? "o" : "ões"}</div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

const selStyle = {
  padding: "8px 12px",
  border: `1px solid ${BORDA}`,
  borderRadius: 8,
  fontSize: 13,
  color: "#374151",
  background: "#fff",
  cursor: "pointer",
};

const avisoStyle = (bg, border, color) => ({
  background: bg,
  border: `1px solid ${border}`,
  borderRadius: 8,
  padding: "10px 16px",
  marginBottom: 12,
  color,
  fontSize: 13,
});

/* ─────────────────────────────────────────────────────────────────────────────
   MÉTODOS PARA ADICIONAR NO src/api.js (dentro do objeto `api`, junto dos demais):

     listarRescisao: () =>
       request(`/rescisao-valores`),

     importarRescisaoLote: (registros) =>
       request(`/rescisao-valores/importar-lote`, {
         method: "POST",
         body: JSON.stringify({ registros }),
       }),

   Obs.: o backend espera { registros: [...] } — o campo "registros" é obrigatório.
   ───────────────────────────────────────────────────────────────────────────── */
