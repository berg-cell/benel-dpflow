// src/lib/format.js
// Helpers de formatação puros do DP Flow — Benel (Fase 3a do saneamento).
// Extraído do App.jsx. Conteúdo idêntico ao original.
// Funções puras: recebem argumentos e retornam string, sem React nem constantes compartilhadas.

export function fmtDateLocal(val) {
  if (!val) return "";
  const d = new Date(val);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}-${String(d.getUTCDate()).padStart(2,"0")}`;
}

export function formatReal(valor, tam) {
  // Formata número no padrão 999999999999.99 com tamanho fixo, sem ponto de milhar
  const num = parseFloat(valor || 0);
  const str = num.toFixed(2).replace(",", ".");
  // Remove ponto decimal para alinhar: ex "1190.47" -> padStart sem ponto
  return str.padStart(tam, " ");
}

export function generateTXTLine(sol, colaboradores, eventos) {
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


export function valorPorExtenso(valor) {
  if (!valor || isNaN(valor)) return "";
  const n = parseFloat(valor);
  const inteiro = Math.floor(n);
  const centavos = Math.round((n - inteiro) * 100);
  const unidades = ["","um","dois","três","quatro","cinco","seis","sete","oito","nove","dez",
    "onze","doze","treze","quatorze","quinze","dezesseis","dezessete","dezoito","dezenove"];
  const dezenas = ["","","vinte","trinta","quarenta","cinquenta","sessenta","setenta","oitenta","noventa"];
  const centenas = ["","cem","duzentos","trezentos","quatrocentos","quinhentos","seiscentos","setecentos","oitocentos","novecentos"];
  function conv(n) {
    if (n === 0) return "";
    if (n === 100) return "cem";
    if (n < 20) return unidades[n];
    if (n < 100) return dezenas[Math.floor(n/10)] + (n%10 ? " e " + unidades[n%10] : "");
    return centenas[Math.floor(n/100)] + (n%100 ? " e " + conv(n%100) : "");
  }
  function convMilhar(n) {
    if (n === 0) return "zero";
    if (n < 1000) return conv(n);
    const mil = Math.floor(n/1000);
    const resto = n % 1000;
    return (mil === 1 ? "mil" : conv(mil) + " mil") + (resto ? " e " + conv(resto) : "");
  }
  let txt = convMilhar(inteiro) + (inteiro === 1 ? " real" : " reais");
  if (centavos > 0) txt += " e " + conv(centavos) + (centavos === 1 ? " centavo" : " centavos");
  return txt;
}

export function fmtDataPS(v) {
  if (!v) return "";
  try {
    const d = new Date(v.includes("T") ? v : v + "T12:00:00");
    return isNaN(d.getTime()) ? v : d.toLocaleDateString("pt-BR");
  } catch { return v; }
}
