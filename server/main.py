# server/main.py
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from db import connect, init_db, find_url, find_domain, upsert_url, upsert_domain
from url_utils import (
    normalize_url,
    extract_registered_domain,
    host_of,
    looks_like_ip_host,
    is_suspicious_punycode,
    has_userinfo,
    has_nonstandard_port,
    is_https,
    count_subdomains,
    url_length,
    percent_encoded_count,
    count_query_params,
    suspicious_keyword_hit,
    is_known_shortener,
    has_non_ascii,
)
from redirect_utils import trace_redirects
from score_rules import score_url
from llm_agent import llm_plan_tools, llm_decide

# ✅ server/.env 강제 로드
load_dotenv(dotenv_path=Path(__file__).with_name(".env"), override=True)

DB_PATH = os.getenv("DB_PATH", "./kisa_phishing.db").strip()
USE_LLM = os.getenv("USE_LLM", "false").lower() == "true"
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*").strip()

# KISA 온디맨드(필요할 때만 API 조회 후 DB 캐시)
KISA_ONDEMAND = os.getenv("KISA_ONDEMAND", "true").lower() == "true"
KISA_ONDEMAND_MAX_PAGES = int(os.getenv("KISA_ONDEMAND_MAX_PAGES", "3"))
KISA_ONDEMAND_PER_PAGE = int(os.getenv("KISA_ONDEMAND_PER_PAGE", "1000"))
KISA_ONDEMAND_TIMEOUT = float(os.getenv("KISA_ONDEMAND_TIMEOUT", "3.5"))

ODCLOUD_API = os.getenv("ODCLOUD_PHISH_API_BASE", "").strip()
ODCLOUD_KEY = os.getenv("ODCLOUD_SERVICE_KEY", "").strip()

print("[BOOT] USE_LLM=", USE_LLM, "KISA_ONDEMAND=", KISA_ONDEMAND)

con = connect(DB_PATH)
init_db(con)

app = FastAPI(title="Phish Hover Agent API (LLM-based, no WHOIS)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[CORS_ALLOW_ORIGINS] if CORS_ALLOW_ORIGINS != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _is_local_or_private_host(url: str) -> bool:
    h = (host_of(url) or "").lower()
    if not h:
        return True
    if h in ("localhost",):
        return True
    if h.startswith("127.") or h.startswith("10.") or h.startswith("192.168."):
        return True
    if h.startswith("172."):
        # 172.16.0.0 ~ 172.31.255.255
        try:
            second = int(h.split(".")[1])
            if 16 <= second <= 31:
                return True
        except Exception:
            pass
    return False


def _fetch_odcloud_page(page: int, per_page: int) -> Dict[str, Any]:
    if not ODCLOUD_API or not ODCLOUD_KEY:
        raise RuntimeError("ODCLOUD_PHISH_API_BASE / ODCLOUD_SERVICE_KEY 설정이 필요합니다(.env).")

    params = {
        "page": page,
        "perPage": per_page,
        "returnType": "JSON",
        "serviceKey": ODCLOUD_KEY,
    }
    r = requests.get(
        ODCLOUD_API,
        params=params,
        timeout=KISA_ONDEMAND_TIMEOUT,
        headers={"User-Agent": "phish-hover-agent/1.0"},
    )
    r.raise_for_status()
    return r.json()


def kisa_lazy_cache(final_url: str, final_domain: str) -> Dict[str, Any]:
    """
    DB 미스일 때만:
    - OpenAPI 최근 N페이지를 스캔
    - 페이지 내 데이터는 DB에 upsert(캐시)
    - target URL/도메인 매칭되면 조기 종료
    """
    out = {"ran": False, "matched": False, "pages_scanned": 0, "error": None}

    if not KISA_ONDEMAND:
        return out
    if _is_local_or_private_host(final_url):
        return out
    if not ODCLOUD_API or not ODCLOUD_KEY:
        out["error"] = "odcloud_not_configured"
        return out

    target_url = normalize_url(final_url)
    target_domain = final_domain or extract_registered_domain(target_url)

    try:
        out["ran"] = True

        for page in range(1, KISA_ONDEMAND_MAX_PAGES + 1):
            out["pages_scanned"] = page
            j = _fetch_odcloud_page(page, KISA_ONDEMAND_PER_PAGE)
            rows = j.get("data", []) or []
            if not rows:
                break

            page_matched = False

            for row in rows:
                # KISA OpenAPI는 한글 필드명 사용: "홈페이지주소", "날짜"
                raw_url = (row.get("홈페이지주소") or row.get("URL") or row.get("url") or "").strip()
                date = (row.get("날짜") or row.get("DATE") or row.get("date") or None)

                if not raw_url:
                    continue

                nurl = normalize_url(raw_url)
                dom = extract_registered_domain(nurl)

                # 캐시 적재
                upsert_url(con, nurl, date)
                if dom:
                    upsert_domain(con, dom, date)

                # 매칭 확인
                if nurl == target_url:
                    page_matched = True
                if target_domain and dom and dom == target_domain:
                    page_matched = True

            con.commit()

            if page_matched:
                out["matched"] = True
                break

            if len(rows) < KISA_ONDEMAND_PER_PAGE:
                break

    except Exception as e:
        out["error"] = str(e)

    return out


@app.get("/")
def root():
    return {"ok": True, "hint": "Use POST /analyze or GET /docs"}


@app.post("/analyze")
def analyze(payload: dict):
    url = (payload.get("url") or "").strip()
    if not url:
        return {"risk_score": 5, "verdict": "SAFE", "reasons": ["url 없음", "추가 근거 부족"], "source": "rules"}

    original = normalize_url(url)
    original_domain = extract_registered_domain(original)

    # 1) 원본 기준: KISA 빠른 체크(DB)
    kisa0_url_date = find_url(con, original)
    kisa0_domain_date = find_domain(con, original_domain) if original_domain else None

    quick_signals = {
        "original_url": original,
        "domain": original_domain,
        "kisa_url_hit_original": kisa0_url_date is not None,
        "kisa_domain_hit_original": kisa0_domain_date is not None,
        "is_ip": looks_like_ip_host(original),
        "is_punycode": is_suspicious_punycode(original),
        "has_userinfo": has_userinfo(original),
        "is_https": is_https(original),
    }

    # 2) LLM Planner(redirect 실행 여부) - ✅ 인자 순서 실수 방지(키워드/단일 인자)
    plan = {"run_redirect": True}
    if USE_LLM:
        plan = llm_plan_tools(signals=quick_signals) or plan

    # 3) Redirect 추적
    rr = trace_redirects(original, max_hops=10, timeout=6.0) if plan.get("run_redirect", True) else None
    final_url = normalize_url(rr.final_url) if rr else original
    used_redirect = (rr.hops > 0) if rr else False
    redirect_hops = rr.hops if rr else 0
    redirect_chain = rr.chain if rr else [original]

    # 4) final 기준: KISA 재검사(DB)
    final_domain = extract_registered_domain(final_url)

    kisa_url_date = find_url(con, final_url)
    kisa_domain_date = find_domain(con, final_domain) if final_domain else None
    kisa_url_hit = kisa_url_date is not None
    kisa_domain_hit = kisa_domain_date is not None

    # 4-1) 미스면 온디맨드 API 스캔 + 캐시 후 재검사
    kisa_lazy = {"ran": False, "matched": False, "pages_scanned": 0, "error": None}
    if (not kisa_url_hit) and (not kisa_domain_hit):
        kisa_lazy = kisa_lazy_cache(final_url, final_domain)
        kisa_url_date = find_url(con, final_url)
        kisa_domain_date = find_domain(con, final_domain) if final_domain else None
        kisa_url_hit = kisa_url_date is not None
        kisa_domain_hit = kisa_domain_date is not None

    # 5) WHOIS는 완전 제거(항상 None)
    whois_days = None
    whois_err = "disabled"

    # 6) URL 특징 신호(최종 URL 기준)
    ip_host = looks_like_ip_host(final_url)
    puny = is_suspicious_punycode(final_url)
    userinfo = has_userinfo(final_url)
    nonstd_port = has_nonstandard_port(final_url)
    https = is_https(final_url)
    subdomains = count_subdomains(final_url)
    ulen = url_length(final_url)
    enc = percent_encoded_count(final_url)
    qn = count_query_params(final_url)
    kw = suspicious_keyword_hit(final_url)
    shortener = is_known_shortener(final_url)
    non_ascii = has_non_ascii(final_url)

    # 7) 리다이렉트 체인 도메인 변경 여부
    rd_set = set()
    for u in redirect_chain[:30]:
        rd = extract_registered_domain(normalize_url(u))
        if rd:
            rd_set.add(rd)
        else:
            h = host_of(u)
            if h:
                rd_set.add(h)

    domain_switch_count = len(rd_set) if rd_set else 1
    domain_switched = False
    if used_redirect:
        if original_domain and final_domain and original_domain != final_domain:
            domain_switched = True
        elif domain_switch_count >= 2:
            domain_switched = True

    # 8) 규칙 기반 점수(항상 baseline + fallback)
    ruled = score_url(
        kisa_url_hit=kisa_url_hit,
        kisa_domain_hit=(kisa_domain_hit and not kisa_url_hit),

        redirect_hops=redirect_hops,
        used_redirect=used_redirect,
        domain_switched=domain_switched,
        domain_switch_count=domain_switch_count,

        is_ip=ip_host,
        is_punycode=puny,
        has_userinfo=userinfo,
        nonstandard_port=nonstd_port,
        https=https,
        subdomains=subdomains,
        is_shortener=shortener,

        url_len=ulen,
        enc_count=enc,
        query_params=qn,
        keyword_hit=kw,
        has_non_ascii=non_ascii,

        whois_age_days=whois_days,
        whois_error=whois_err,
    )

    observations = {
        "original_url": original,
        "final_url": final_url,
        "redirect_hops": redirect_hops,
        "redirect_chain": redirect_chain,
        "domain": final_domain,
        "domain_switched": domain_switched,
        "domain_switch_count": domain_switch_count,

        "kisa_url_hit": kisa_url_hit,
        "kisa_url_date": kisa_url_date,
        "kisa_domain_hit": kisa_domain_hit,
        "kisa_domain_date": kisa_domain_date,
        "kisa_lazy": kisa_lazy,

        "whois_age_days": None,

        "is_ip": ip_host,
        "is_punycode": puny,
        "has_userinfo": userinfo,
        "nonstandard_port": nonstd_port,
        "https": https,
        "subdomains": subdomains,
        "url_len": ulen,
        "enc_count": enc,
        "query_params": qn,
        "keyword_hit": kw,
        "is_shortener": shortener,
        "has_non_ascii": non_ascii,

        "planner": plan,
    }

    rule_result = {"risk_score": ruled.score, "verdict": ruled.verdict, "reasons": ruled.reasons}

    # 9) LLM Decider - ✅ 인자 순서 실수 방지
    llm_out = llm_decide(signals=observations, rule_result=rule_result) if USE_LLM else None
    final = llm_out if llm_out else rule_result
    source = "llm" if llm_out else "rules"

    return {
        **observations,
        "risk_score": final["risk_score"],
        "verdict": final["verdict"],
        "reasons": final["reasons"],
        "source": source,
        "debug": ruled.debug,
        "whois_error": whois_err,
    }
