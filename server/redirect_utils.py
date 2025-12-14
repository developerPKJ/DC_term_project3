from dataclasses import dataclass
from typing import List, Optional
import requests


_SESSION = requests.Session()

@dataclass
class RedirectResult:
    final_url: str
    chain: List[str]
    hops: int
    error: Optional[str] = None

def trace_redirects(url: str, max_hops: int = 10, timeout: float = 6.0) -> RedirectResult:
    chain: List[str] = []
    try:
        # Redirect tracing doesn't need the response body.
        # Use stream=True to avoid downloading large HTML.
        headers = {"User-Agent": "phish-hover-agent/1.0"}
        # Separate connect/read timeouts to fail fast.
        req_timeout = (min(3.0, float(timeout)), float(timeout))

        # Enforce redirect cap via Session.max_redirects.
        _SESSION.max_redirects = max(1, int(max_hops))

        # Prefer HEAD first (often faster), fall back to GET.
        try:
            r = _SESSION.head(
                url,
                allow_redirects=True,
                timeout=req_timeout,
                headers=headers,
                stream=True,
            )
        except Exception:
            r = _SESSION.get(
                url,
                allow_redirects=True,
                timeout=req_timeout,
                headers=headers,
                stream=True,
            )

        # Close immediately to avoid reading body.
        try:
            r.close()
        except Exception:
            pass

        history = getattr(r, "history", []) or []
        chain = [url] + [h.url for h in history if getattr(h, "url", None)]
        final_url = r.url or url
        if not chain or chain[-1] != final_url:
            chain.append(final_url)

        hops = len(history)
        return RedirectResult(final_url=final_url, chain=chain, hops=hops)
    except Exception as e:
        return RedirectResult(final_url=url, chain=[url], hops=0, error=str(e))
