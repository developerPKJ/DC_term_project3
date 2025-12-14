# server/llm_agent.py
from __future__ import annotations

import os
import json
import re
import requests
from typing import Any, Dict, Optional

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

SAFE_SCORE = 5
SUSP_SCORE = 60
DANGER_SCORE = 90


def _model_name(model: object) -> str:
    """model이 dict/None 등으로 들어와도 최대한 문자열로 강제."""
    if isinstance(model, str):
        return model.strip()
    if isinstance(model, dict):
        for k in ("name", "model", "id"):
            v = model.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return str(model)
    return str(model).strip()


def _extract_json_object(text: str) -> str:
    """
    LLM이 JSON 이외 텍스트를 섞어도 첫 { ... } 블록을 추출해서 파싱 시도.
    """
    s = text.strip()

    # ```json ... ``` 처리
    if s.startswith("```"):
        s = s.strip("`").strip()
        if s.lower().startswith("json"):
            s = s[4:].strip()

    # 가장 바깥 { ... } 추출
    m = re.search(r"\{.*\}", s, flags=re.DOTALL)
    if not m:
        raise ValueError("No JSON object found in LLM output")
    return m.group(0)


def _safe_json_loads(txt: str) -> Dict[str, Any]:
    obj_text = _extract_json_object(txt)
    return json.loads(obj_text)


def _ollama_chat(messages, *, model: object = OLLAMA_MODEL) -> str:
    base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    timeout = float(os.getenv("LLM_TIMEOUT_SEC", "12"))

    model_str = _model_name(model)
    if not model_str:
        raise RuntimeError("OLLAMA_MODEL is empty")

    payload = {
        "model": model_str,     # ✅ 반드시 문자열
        "messages": messages,
        "stream": False,
        # ❌ "format": "json" (Ollama 0.13.3에서 400 나는 케이스가 있어 제거)
    }

    r = requests.post(f"{base}/api/chat", json=payload, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f'Ollama /api/chat error {r.status_code}: {r.text}')

    j = r.json()
    return j.get("message", {}).get("content", "")


def llm_plan_tools(signals: Dict[str, Any], *, model: str = OLLAMA_MODEL) -> Optional[Dict[str, Any]]:
    """
    ✅ WHOIS 제거 버전: Planner는 redirect만 결정(기본 true)
    """
    system = """너는 피싱 URL 위험도를 평가하는 보안 에이전트의 Planner다.
다음 도구 실행 여부를 결정해라:
- run_redirect: 리다이렉트 체인 추적

출력은 JSON만:
{"run_redirect": true/false}

규칙:
- 애매하거나 근거가 부족하면 true(추적)로.
- KISA URL/도메인 히트가 있으면 redirect는 굳이 안 해도 되지만(성능), 기본은 true로 둬도 된다.
"""

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(signals, ensure_ascii=False)},
    ]

    try:
        txt = _ollama_chat(messages, model=model)
        obj = _safe_json_loads(txt)
        return {"run_redirect": bool(obj.get("run_redirect", True))}
    except Exception as e:
        print("[LLM Planner ERROR]", e)
        return None


def llm_decide(
    signals: Dict[str, Any],
    rule_result: Dict[str, Any],
    *,
    model: str = OLLAMA_MODEL
) -> Optional[Dict[str, Any]]:
    """
    signals: 관찰값(redirect/kisa/url features 등)
    rule_result: 규칙 기반 결과(백업)

    ✅ 출력 점수는 요구사항대로 3단계 고정:
    SAFE=5, SUSP=60, DANGER=90
    """
    system = """너는 피싱 URL 위험도를 최종 판정하는 Decider다.
반드시 JSON만 출력해라:
{"verdict":"SAFE|SUSPICIOUS|DANGEROUS","reasons":["..","..",".."]}

하드룰:
1) kisa_url_hit == true 이면 verdict는 무조건 DANGEROUS
2) kisa_domain_hit == true 이면 verdict는 최소 SUSPICIOUS 이상
3) 불확실하면 rule_result를 따른다

reasons는 2~3개, 짧고 근거 중심으로.
"""

    user = {
        "signals": signals,
        "rule_result": rule_result,
        "required_output_example": {"verdict": "SUSPICIOUS", "reasons": ["KISA 도메인 히트", "리다이렉트 과다"]},
    }

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
    ]

    try:
        txt = _ollama_chat(messages, model=model)
        obj = _safe_json_loads(txt)

        verdict = str(obj.get("verdict", "")).strip().upper()
        reasons = obj.get("reasons", [])

        if verdict not in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
            return None
        if not isinstance(reasons, list) or len(reasons) == 0:
            return None

        # 하드룰 강제
        if signals.get("kisa_url_hit"):
            verdict = "DANGEROUS"
            if "KISA URL 목록 일치" not in reasons:
                reasons.insert(0, "KISA URL 목록 일치")
        elif signals.get("kisa_domain_hit") and verdict == "SAFE":
            verdict = "SUSPICIOUS"
            if "KISA 도메인 목록 일치" not in reasons:
                reasons.insert(0, "KISA 도메인 목록 일치")

        # 점수 3단계 고정
        if verdict == "SAFE":
            score = SAFE_SCORE
        elif verdict == "SUSPICIOUS":
            score = SUSP_SCORE
        else:
            score = DANGER_SCORE

        # reasons 정리(최소 2개 보장)
        reasons = [str(r)[:120] for r in reasons if str(r).strip()][:3]
        if len(reasons) < 2:
            extra = (rule_result.get("reasons") or [])
            for r in extra:
                r = str(r).strip()
                if r and r not in reasons:
                    reasons.append(r[:120])
                if len(reasons) >= 2:
                    break
        reasons = reasons[:3]

        return {"risk_score": score, "verdict": verdict, "reasons": reasons}

    except Exception as e:
        print("[LLM Decider ERROR]", e)
        return None
