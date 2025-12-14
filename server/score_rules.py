# server/score_rules.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Signal:
    name: str
    points: int
    reason: str


@dataclass
class ScoreResult:
    score: int
    verdict: str
    reasons: List[str]
    debug: Dict[str, Any]


def bucketize(raw: int, kisa_hit: bool) -> int:
    """
    최종 점수는 요구대로 3단계 고정:
    SAFE=5, SUSP=60, DANGER=90
    """
    if kisa_hit:
        return 90
    if raw >= 80:
        return 90
    if raw >= 35:
        return 60
    return 5


def verdict_from_bucket(score: int) -> str:
    if score >= 90:
        return "DANGEROUS"
    if score >= 60:
        return "SUSPICIOUS"
    return "SAFE"


def score_url(
    *,
    # KISA 매칭
    kisa_url_hit: bool,
    kisa_domain_hit: bool,

    # 리다이렉트
    redirect_hops: int,
    used_redirect: bool,
    domain_switched: bool,          # 리다이렉트로 등록도메인이 바뀌었는지
    domain_switch_count: int,       # 고유 registered domain 개수(>=2면 변경)

    # 도메인/호스트
    is_ip: bool,
    is_punycode: bool,
    has_userinfo: bool,
    nonstandard_port: bool,
    https: bool,
    subdomains: int,
    is_shortener: bool,

    # URL 문자열 패턴
    url_len: int,
    enc_count: int,
    query_params: int,
    keyword_hit: bool,
    has_non_ascii: bool,

    # WHOIS(선택)
    whois_age_days: Optional[int],
    whois_error: Optional[str],
) -> ScoreResult:
    signals: List[Signal] = []

    # ---- 0) KISA (가장 강력) ----
    kisa_hit = bool(kisa_url_hit or kisa_domain_hit)
    if kisa_url_hit:
        signals.append(Signal("kisa_url", 100, "KISA 피싱 URL 목록과 정확히 일치"))
    elif kisa_domain_hit:
        signals.append(Signal("kisa_domain", 95, "KISA 피싱 도메인 목록과 일치"))

    # ---- 1) URL 단축 도메인 ----
    if is_shortener:
        signals.append(Signal("shortener", 25, "URL 단축 도메인 사용(최종 목적지 은닉 가능)"))

    # ---- 2) 리다이렉트 ----
    if used_redirect:
        if redirect_hops >= 5:
            signals.append(Signal("redirect_very_many", 45, f"리다이렉트가 {redirect_hops}회로 매우 과다함"))
        elif redirect_hops >= 3:
            signals.append(Signal("redirect_many", 30, f"리다이렉트가 {redirect_hops}회로 과다함"))
        elif redirect_hops >= 1:
            signals.append(Signal("redirect_some", 12, f"리다이렉트가 {redirect_hops}회 발생"))

    # ---- 3) 리다이렉트 중 도메인 변경 ----
    if domain_switched and domain_switch_count >= 2:
        # 도메인이 바뀌면 “은닉/우회” 시나리오에서 자주 보임
        # 단, 정상 리다이렉트도 있으니 너무 과격하진 않게
        signals.append(Signal("domain_switched", 18, f"리다이렉트 체인에서 등록도메인이 변경됨({domain_switch_count}개)"))

    # ---- 4) 호스트/전송 보안 ----
    if is_ip:
        signals.append(Signal("ip_host", 45, "도메인 대신 IP로 직접 접속 형태"))
    if has_userinfo:
        signals.append(Signal("userinfo", 25, "URL에 userinfo(@) 포함(주소 혼동 유발 가능)"))
    if nonstandard_port:
        signals.append(Signal("nonstandard_port", 15, "비표준 포트를 사용"))
    if not https:
        signals.append(Signal("no_https", 20, "HTTPS가 아닌 연결"))

    # ---- 5) 문자/도메인 이상 ----
    if is_punycode:
        signals.append(Signal("punycode", 30, "Punycode 도메인(유사문자 위장 가능)"))
    if subdomains >= 4:
        signals.append(Signal("many_subdomains", 12, f"서브도메인이 과다함({subdomains})"))
    if has_non_ascii:
        signals.append(Signal("non_ascii", 10, "URL에 비ASCII 문자가 포함됨(유니코드 혼용 가능)"))

    # ---- 6) 난독화/패턴 ----
    if url_len >= 140:
        signals.append(Signal("long_url", 12, f"URL이 비정상적으로 김({url_len}자)"))
    if enc_count >= 8:
        signals.append(Signal("encoded_many", 12, f"URL 인코딩(%xx)이 과다함({enc_count}개)"))
    if query_params >= 10:
        signals.append(Signal("many_query_params", 12, f"쿼리 파라미터가 과다함({query_params}개)"))
    if keyword_hit:
        signals.append(Signal("keyword_hit", 10, "login/verify/update 등 의심 키워드 포함"))

    # ---- 7) WHOIS (있으면 보조 신호) ----
    if whois_age_days is not None:
        if whois_age_days < 30:
            signals.append(Signal("new_domain", 30, f"도메인이 매우 최근 생성됨({whois_age_days}일)"))
        elif whois_age_days < 180:
            signals.append(Signal("young_domain", 15, f"도메인이 비교적 최근 생성됨({whois_age_days}일)"))

    # ---- raw 점수 계산 ----
    # KISA는 버킷으로 바로 DANGER(90)로 보내기 때문에 raw에선 제외해도 됨
    raw = sum(s.points for s in signals if s.points < 90)

    score = bucketize(raw, kisa_hit)
    verdict = verdict_from_bucket(score)

    # reasons는 상위 2~3개
    top = sorted(signals, key=lambda x: x.points, reverse=True)
    reasons = [s.reason for s in top[:3]]

    # reasons 보정: 최소 2개는 보이게
    if len(reasons) == 0:
        reasons = ["특이 신호 없음", "추가 근거 부족으로 기본 안전 판정"]
    elif len(reasons) == 1:
        reasons.append("추가 근거가 부족하여 규칙 기반 결과를 따름")

    debug = {
        "raw": raw,
        "signals": [{"name": s.name, "points": s.points, "reason": s.reason} for s in signals],
        "whois_error": whois_error,
    }
    return ScoreResult(score=score, verdict=verdict, reasons=reasons[:3], debug=debug)
