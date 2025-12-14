# server/url_utils.py
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit, unquote

from urllib.parse import urlsplit

def extract_domain(url: str) -> str:
    """정규화된 URL에서 hostname(소문자)만 뽑는다."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


# ----------------------------
# 공통 URL 정규화/추출
# ----------------------------

_KR_THIRD_LEVEL = {
    # 한국에서 흔한 2단계 공공/기관 도메인(등록 도메인 계산용 단순 규칙)
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr",
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "update", "secure",
    "account", "payment", "wallet", "bank", "billing", "support"
}

SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly", "rb.gy"
}

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PERCENT_ENC_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def normalize_url(url: str) -> str:
    """
    - scheme 없으면 https 부여
    - fragment 제거
    - host는 소문자
    - path가 비면 '/'로
    - 필요 시 trailing slash 유지(데모 일관성)
    """
    url = (url or "").strip()
    if not url:
        return ""

    # scheme이 없으면 https:// 붙이기
    if "://" not in url:
        url = "https://" + url

    sp = urlsplit(url)
    scheme = (sp.scheme or "https").lower()

    # hostname은 소문자, netloc 원형을 최대한 유지(포트/유저정보 등)
    # urlsplit은 username/password/hostname/port로 분해해주므로 재조합
    username = sp.username or ""
    password = sp.password or ""
    host = (sp.hostname or "").lower()
    port = sp.port

    userinfo = ""
    if username:
        userinfo = username
        if password:
            userinfo += f":{password}"
        userinfo += "@"

    netloc = userinfo + host
    if port:
        netloc += f":{port}"

    path = sp.path or "/"
    query = sp.query or ""
    fragment = ""  # 제거

    # path가 도메인만 있을 때 /로 통일
    if path == "":
        path = "/"

    return urlunsplit((scheme, netloc, path, query, fragment))


def host_of(url: str) -> str:
    sp = urlsplit(url)
    return (sp.hostname or "").lower()


def extract_registered_domain(url: str) -> str:
    """
    완전한 PSL(공개 접미사) 처리는 아니고,
    데모/과제용으로 한국 도메인(co.kr 등)만 보정한 '단순' registered domain 추출.
    """
    host = host_of(url)
    if not host:
        return ""

    # IP면 도메인 없음 처리
    if _IPV4_RE.match(host) or ":" in host:
        return ""

    parts = host.split(".")
    if len(parts) < 2:
        return host

    tail2 = ".".join(parts[-2:])
    tail3 = ".".join(parts[-3:]) if len(parts) >= 3 else tail2

    # 예: something.co.kr -> registered = something.co.kr (3라벨)
    if tail2 in _KR_THIRD_LEVEL:
        return tail3

    # 일반적으로는 마지막 2라벨
    return tail2


def looks_like_ip_host(url: str) -> bool:
    host = host_of(url)
    if not host:
        return False
    # IPv4
    if _IPV4_RE.match(host):
        # 0~255 범위 간단 검증
        try:
            nums = [int(x) for x in host.split(".")]
            return all(0 <= n <= 255 for n in nums)
        except Exception:
            return False
    # IPv6 (대충 ':' 포함 여부)
    if ":" in host:
        return True
    return False


def is_suspicious_punycode(url: str) -> bool:
    host = host_of(url)
    return "xn--" in host


# ----------------------------
# 새 판정 요소들
# ----------------------------

def has_userinfo(url: str) -> bool:
    # http://example.com@evil.com 같은 형태
    sp = urlsplit(url)
    return bool(sp.username or sp.password)


def has_nonstandard_port(url: str) -> bool:
    sp = urlsplit(url)
    port = sp.port
    if port is None:
        return False
    scheme = (sp.scheme or "").lower()
    if scheme == "https":
        return port != 443
    if scheme == "http":
        return port != 80
    return True


def is_https(url: str) -> bool:
    return (urlsplit(url).scheme or "").lower() == "https"


def url_length(url: str) -> int:
    return len(url or "")


def count_subdomains(url: str) -> int:
    host = host_of(url)
    if not host or looks_like_ip_host(url):
        return 0
    parts = host.split(".")
    return max(0, len(parts) - 2)


def percent_encoded_count(url: str) -> int:
    return len(_PERCENT_ENC_RE.findall(url or ""))


def count_query_params(url: str) -> int:
    sp = urlsplit(url)
    q = sp.query or ""
    if not q:
        return 0
    # a=1&b=2 형태 기준으로 '&' 개수 + 1
    return q.count("&") + 1


def suspicious_keyword_hit(url: str) -> bool:
    sp = urlsplit(url)
    text = (sp.path or "") + " " + (sp.query or "")
    text = unquote(text).lower()
    return any(k in text for k in SUSPICIOUS_KEYWORDS)


def is_known_shortener(url: str) -> bool:
    return host_of(url) in SHORTENER_DOMAINS


def has_non_ascii(url: str) -> bool:
    # 호스트/경로/쿼리에 비ASCII가 섞이면(유니코드 혼용 등) 힌트로 사용
    try:
        url.encode("ascii")
        return False
    except Exception:
        return True
