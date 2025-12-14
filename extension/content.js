let tip = null;
let hoverTimer = null;

function ensureTip() {
  if (tip) return tip;

  tip = document.createElement("div");
  tip.style.position = "fixed";
  tip.style.zIndex = "999999";
  tip.style.padding = "10px 12px";
  tip.style.borderRadius = "10px";
  tip.style.fontSize = "12px";
  tip.style.lineHeight = "1.35";
  tip.style.background = "rgba(0,0,0,0.88)";
  tip.style.color = "white";
  tip.style.maxWidth = "320px";
  tip.style.pointerEvents = "none";
  tip.style.display = "none";
  tip.style.boxShadow = "0 6px 20px rgba(0,0,0,0.25)";
  document.documentElement.appendChild(tip);
  return tip;
}

function showTipNear(el, html) {
  const t = ensureTip();
  t.innerHTML = html;

  const r = el.getBoundingClientRect();
  const left = Math.min(window.innerWidth - 340, Math.max(10, r.left));
  const top = Math.max(10, r.top - 60);

  t.style.left = `${left}px`;
  t.style.top = `${top}px`;
  t.style.display = "block";
}

function hideTip() {
  if (tip) tip.style.display = "none";
}

function formatResult(data) {
  const score = data.risk_score;
  const verdict = data.verdict;
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  const src = data.source ? `source: ${data.source}` : "";

  const lines = reasons.slice(0, 3).map(x => `• ${escapeHtml(x)}`).join("<br>");
  const hops = data.redirect_hops ?? 0;

  return `
    <div style="font-weight:700; font-size:13px;">
      ${verdict} · 위험도 ${score}%
    </div>
    <div style="margin-top:6px;">
      ${lines || "• 특이 신호 없음"}
    </div>
    <div style="margin-top:6px; opacity:0.85;">
      redirects: ${hops}
    </div>
    <div style="margin-top:6px; opacity:0.85;">
      redirects: ${hops} ${src ? "· " + src : ""}
    </div>
  `;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

// 이벤트 위임(성능 좋음)
document.addEventListener("mouseover", (e) => {
  const a = e.target?.closest?.("a[href]");
  if (!a) return;

  const url = a.href;
  clearTimeout(hoverTimer);

  // 디바운스: 스치듯 지나가는 링크는 호출하지 않기
  hoverTimer = setTimeout(() => {
    showTipNear(a, `<div>분석 중…</div>`);

    chrome.runtime.sendMessage({ type: "ANALYZE_URL", url }, (res) => {
      if (!res || !res.ok) {
        showTipNear(a, `<div style="font-weight:700;">분석 실패</div><div style="margin-top:6px;">${escapeHtml(res?.error || "")}</div>`);
        return;
      }
      showTipNear(a, formatResult(res.data));
    });
  }, 250);
}, true);

document.addEventListener("mouseout", () => {
  clearTimeout(hoverTimer);
  hideTip();
}, true);

document.addEventListener("scroll", () => hideTip(), true);
