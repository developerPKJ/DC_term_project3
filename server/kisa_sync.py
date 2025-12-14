# server/kisa_sync.py
import os
import time
import requests
from typing import Optional, Dict, Any, Tuple

from db import upsert_url, upsert_domain, find_url, find_domain
from url_utils import normalize_url, extract_registered_domain as extract_domain

DEFAULT_BASE_URL = "https://api.odcloud.kr/api"
DEFAULT_DATASET_PATH = "/15109780/v1/uddi:707478dd-938f-4155-badb-fae6202ee7ed"


def _get_api_base_and_path() -> Tuple[str, str]:
    base = os.getenv("KISA_API_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    path = os.getenv("KISA_API_PATH", DEFAULT_DATASET_PATH)
    if not path.startswith("/"):
        path = "/" + path
    return base, path


def fetch_page(page: int, per_page: int, timeout: float = 8.0) -> Dict[str, Any]:
    """
    KISA(ODCLOUD) OpenAPI에서 page 단위로 가져오기.
    NOTE: 이 API는 보통 'serviceKey'와 page/perPage 정도만 제공해서,
    서버측 검색이 어려워 page를 순차적으로 스캔해야 하는 케이스가 많음.
    """
    service_key = os.getenv("KISA_SERVICE_KEY", "").strip()
    if not service_key:
        raise RuntimeError("KISA_SERVICE_KEY is not set")

    base, path = _get_api_base_and_path()
    url = f"{base}{path}"

    params = {
        "page": page,
        "perPage": per_page,
        "returnType": "JSON",
        # 많은 ODCLOUD API가 serviceKey 쿼리를 요구
        "serviceKey": service_key,
    }

    # 어떤 ODCLOUD는 Authorization 헤더도 허용/요구하는 경우가 있어 같이 넣음
    headers = {"Authorization": service_key}

    r = requests.get(url, params=params, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()


def lazy_lookup_and_cache(
    con,
    target_url: str,
    max_pages: int = 5,
    per_page: int = 1000,
    sleep_sec: float = 0.05,
) -> Dict[str, Any]:
    """
    1) DB에서 먼저 URL/도메인 매칭
    2) DB miss면 OpenAPI를 max_pages 만큼만 스캔하면서 캐시
    """
    norm_url = normalize_url(target_url)
    domain = extract_domain(norm_url)

    # 1) DB 먼저
    url_date = find_url(con, norm_url)
    dom_date = find_domain(con, domain)

    if url_date or dom_date:
        return {
            "kisa_url_hit": bool(url_date),
            "kisa_url_date": url_date,
            "kisa_domain_hit": bool(dom_date),
            "kisa_domain_date": dom_date,
            "pages_scanned": 0,
            "source": "db",
        }

    # 2) miss면 OpenAPI를 조금만 스캔
    pages_scanned = 0
    for page in range(1, max_pages + 1):
        pages_scanned += 1
        data = fetch_page(page=page, per_page=per_page)

        rows = data.get("data") or []
        if not rows:
            break

        # rows를 캐시에 넣으면서 동시에 타겟 매칭
        for row in rows:
            # KISA OpenAPI는 한글 필드명 사용: "홈페이지주소", "날짜"
            raw_url = (
                row.get("홈페이지주소")
                or row.get("URL")
                or row.get("url")
                or row.get("site_url")
                or row.get("phishing_url")
                or ""
            )
            raw_date = (
                row.get("날짜")
                or row.get("DATE")
                or row.get("date")
                or row.get("등록일")
                or row.get("reg_date")
                or row.get("created_at")
                or None
            )

            if not raw_url:
                continue

            n = normalize_url(raw_url)
            d = extract_domain(n)

            # 캐시 저장
            upsert_url(con, n, raw_date)
            upsert_domain(con, d, raw_date)

            # 매칭 체크
            if n == norm_url:
                url_date = raw_date or "unknown"
            if d == domain:
                dom_date = raw_date or "unknown"

        con.commit()

        # 이미 찾았으면 중단
        if url_date or dom_date:
            break

        # 너무 빡세게 요청하지 않도록 짧게 sleep
        if sleep_sec:
            time.sleep(sleep_sec)

        # 마지막 페이지 근처면 중단(데이터가 per_page보다 적게 오면 끝일 가능성)
        if len(rows) < per_page:
            break

    return {
        "kisa_url_hit": bool(url_date),
        "kisa_url_date": url_date,
        "kisa_domain_hit": bool(dom_date),
        "kisa_domain_date": dom_date,
        "pages_scanned": pages_scanned,
        "source": "lazy_api_cache",
    }
