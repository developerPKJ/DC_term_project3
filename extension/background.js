const API = "http://localhost:8000/analyze";
const TTL_MS = 10 * 60 * 1000;

const cache = new Map(); // url -> {ts, data}

async function pushHistory(item) {
  const key = "history";
  const res = await chrome.storage.local.get([key]);
  const arr = Array.isArray(res[key]) ? res[key] : [];
  arr.unshift(item);
  const trimmed = arr.slice(0, 50);
  await chrome.storage.local.set({ [key]: trimmed });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type !== "ANALYZE_URL") return;

  const url = msg.url;
  const now = Date.now();

  const hit = cache.get(url);
  if (hit && (now - hit.ts) < TTL_MS) {
    sendResponse({ ok: true, data: hit.data, cached: true });
    return true;
  }

  fetch(API, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, mode: "fast" })
  })
    .then(r => r.json())
    .then(async (data) => {
      cache.set(url, { ts: now, data });

      await pushHistory({
        ts: now,
        input_url: data.input_url,
        final_url: data.final_url,
        risk_score: data.risk_score,
        verdict: data.verdict,
        reasons: data.reasons,
        redirect_hops: data.redirect_hops
      });

      sendResponse({ ok: true, data, cached: false });
    })
    .catch(err => {
      sendResponse({ ok: false, error: String(err) });
    });

  return true; // async
});
