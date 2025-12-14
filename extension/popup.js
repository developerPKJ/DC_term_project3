const listEl = document.getElementById("list");
const btnRefresh = document.getElementById("btnRefresh");
const btnClear = document.getElementById("btnClear");

function fmtTime(ts) {
  const d = new Date(ts);
  return d.toLocaleString();
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

async function render() {
  const { history } = await chrome.storage.local.get(["history"]);
  const arr = Array.isArray(history) ? history : [];

  if (arr.length === 0) {
    listEl.innerHTML = `<div style="opacity:.75; font-size:12px;">기록 없음</div>`;
    return;
  }

  listEl.innerHTML = arr.map(item => {
    const reasons = Array.isArray(item.reasons) ? item.reasons.slice(0, 3) : [];
    return `
      <div class="card">
        <div class="row1">
          <div class="verdict">${escapeHtml(item.verdict || "")}</div>
          <div class="score">${escapeHtml(item.risk_score)}%</div>
        </div>
        <div class="url">${escapeHtml(item.final_url || item.input_url || "")}</div>
        <div class="reasons">${reasons.map(r => "• " + escapeHtml(r)).join("<br>")}</div>
        <div class="meta">${fmtTime(item.ts)} · redirects: ${item.redirect_hops ?? 0}</div>
      </div>
    `;
  }).join("");
}

btnRefresh.addEventListener("click", () => render());
btnClear.addEventListener("click", async () => {
  await chrome.storage.local.set({ history: [] });
  render();
});

render();
