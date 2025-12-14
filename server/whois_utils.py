from dataclasses import dataclass
from typing import Optional, Dict, Any
import os
import requests
from datetime import datetime, timezone

@dataclass
class WhoisInfo:
    creation_date: Optional[datetime]
    raw: Dict[str, Any]
    error: Optional[str] = None

def _parse_creation_date(obj: Any) -> Optional[datetime]:
    """
    WHOIS 응답 포맷이 제각각이라 “가급적 넓게” 처리.
    """
    if obj is None:
        return None
    if isinstance(obj, datetime):
        return obj
    if isinstance(obj, (int, float)):
        try:
            return datetime.fromtimestamp(obj, tz=timezone.utc)
        except Exception:
            return None
    if isinstance(obj, str):
        s = obj.strip()
        # 흔한 ISO/날짜 형태들
        for fmt in [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ]:
            try:
                dt = datetime.strptime(s, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass
    return None

def get_domain_creation_date(domain: str) -> WhoisInfo:
    """
    WHOIS_API_URL이 세팅되어 있으면 그 API를 호출하고,
    아니면 creation_date=None으로 리턴(= WHOIS 신호 미사용).
    """
    api_url = os.getenv("WHOIS_API_URL", "").strip()
    api_key = os.getenv("WHOIS_API_KEY", "").strip()
    if not api_url:
        return WhoisInfo(creation_date=None, raw={}, error="WHOIS_API_URL not set")

    key_in = os.getenv("WHOIS_API_KEY_IN", "header").strip().lower()  # header|query
    key_name = os.getenv("WHOIS_API_KEY_NAME", "Authorization").strip()

    params = {"domain": domain}
    headers = {"User-Agent": "phish-hover-agent/1.0"}

    if api_key:
        if key_in == "query":
            params[key_name] = api_key
        else:
            headers[key_name] = api_key

    try:
        r = requests.get(api_url, params=params, headers=headers, timeout=8)
        r.raise_for_status()
        data = r.json() if "application/json" in (r.headers.get("content-type", "")) else {"text": r.text}

        # 흔한 키 후보들에서 creation_date 찾기
        candidates = [
            data.get("creation_date"),
            data.get("created"),
            data.get("createdDate"),
            data.get("registeredDate"),
            (data.get("result") or {}).get("creation_date") if isinstance(data.get("result"), dict) else None,
        ]
        creation = None
        for c in candidates:
            creation = _parse_creation_date(c)
            if creation:
                break

        return WhoisInfo(creation_date=creation, raw=data)
    except Exception as e:
        return WhoisInfo(creation_date=None, raw={}, error=str(e))

def age_days(creation_date: Optional[datetime]) -> Optional[int]:
    if not creation_date:
        return None
    now = datetime.now(tz=timezone.utc)
    dt = creation_date.astimezone(timezone.utc)
    return max(0, (now - dt).days)
