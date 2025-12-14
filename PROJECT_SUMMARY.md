# 피싱 링크 검증 AI Agent - Chrome 확장프로그램

## 📋 프로젝트 개요

LLM 기반 AI agent를 활용한 크롬 확장프로그램으로, 웹페이지의 하이퍼링크에 마우스를 올리면 해당 링크의 피싱 위험도를 실시간으로 분석하여 보여줍니다.

### 주요 기능
- ✅ **실시간 링크 분석**: 링크 호버 시 즉시 위험도 평가
- ✅ **KISA 피싱 DB 연동**: 한국인터넷진흥원 공식 피싱 사이트 DB 활용
- ✅ **LLM 기반 판단**: Ollama 로컬 LLM으로 지능적 위험 분석
- ✅ **다중 분석 요소**: 리다이렉트, WHOIS, URL 패턴, 도메인 특성 종합 평가
- ✅ **캐싱 최적화**: 서버/클라이언트 양측 캐시로 빠른 응답

---

## 🔧 수정된 주요 문제점

### 1. **KISA OpenAPI 한글 필드명 처리**
**문제**: API 응답이 한글 필드명(`홈페이지주소`, `날짜`)을 사용하지만 코드는 영어만 처리
**해결**: 
- `kisa_sync.py`: 한글 필드명을 최우선 순위로 처리하도록 수정
- `main.py`: ODCLOUD API 응답 파싱 시 한글 필드명 우선 처리

```python
# 수정 전
raw_url = row.get("URL") or row.get("url") or ""

# 수정 후  
raw_url = row.get("홈페이지주소") or row.get("URL") or row.get("url") or ""
```

### 2. **함수명 불일치 해결**
**문제**: `extract_domain` vs `extract_registered_domain` 혼용
**해결**: `kisa_sync.py`에서 alias 사용으로 통일
```python
from url_utils import normalize_url, extract_registered_domain as extract_domain
```

### 3. **API 인증 설정 확인**
- ✅ `.env` 파일에 올바른 OpenAPI 키 설정 완료
- ✅ API 엔드포인트: `https://api.odcloud.kr/api/15109780/v1/uddi:707478dd-938f-4155-badb-fae6202ee7ed`
- ✅ Service Key: `4fdb0aecbc5127c1a125a2fd96a216fc0527c3d8e96e98fa33751992c2b05058`

### 4. **Mock 피싱 사이트 개선**
다양한 피싱 특성 테스트를 위한 링크 추가:
- 외부 단축 URL (swyg.link, c11.kr, bit.ly)
- 의심 키워드 포함 경로 (verify, update-payment)
- 비표준 포트 사용
- 긴 URL 난독화 패턴

---

## 🚀 실행 방법

### 1. 서버 실행

```bash
cd term_project3/server

# 메인 API 서버 (포트 8000)
uvicorn main:app --host 0.0.0.0 --port 8000

# Mock 피싱 사이트 (포트 9000, 테스트용)
uvicorn mock_phish_site:app --host 127.0.0.1 --port 9000

# Ollama LLM 서버 (별도 터미널)
ollama run llama3.2:3b
```

### 2. Chrome 확장프로그램 설치

1. Chrome 주소창에 `chrome://extensions/` 입력
2. "개발자 모드" 활성화
3. "압축해제된 확장 프로그램을 로드합니다" 클릭
4. `term_project3/extension` 폴더 선택

### 3. 테스트

1. Mock 사이트 접속: `http://127.0.0.1:9000/`
2. 페이지 내 링크에 마우스 호버
3. 위험도 분석 결과 팝업 확인

---

## 📊 API 응답 예시

### KISA OpenAPI 응답 구조
```json
{
  "page": 1,
  "perPage": 10,
  "totalCount": 27582,
  "currentCount": 3,
  "data": [
    {
      "날짜": "2023-01-01",
      "홈페이지주소": "https://phishing-example.com"
    }
  ]
}
```

### 분석 API 응답 (`POST /analyze`)
```json
{
  "input_url": "https://example.com",
  "final_url": "https://final-destination.com",
  "redirect_hops": 2,
  "risk_score": 60,
  "verdict": "SUSPICIOUS",
  "reasons": [
    "리다이렉트가 2회 발생",
    "도메인이 비교적 최근 생성됨(45일)"
  ],
  "source": "llm",
  "kisa_url_hit": false,
  "kisa_domain_hit": false
}
```

---

## 🎯 위험도 판정 기준

### 위험도 점수 (0-100)
- **0-34**: SAFE (안전) - 녹색
- **35-79**: SUSPICIOUS (의심) - 주황색  
- **80-100**: DANGEROUS (위험) - 빨간색

### 주요 위험 신호
1. **KISA DB 매칭**: 즉시 DANGEROUS (95-100점)
2. **리다이렉트 과다**: 3회 이상 (30-45점)
3. **IP 주소 호스트**: 도메인 대신 IP (45점)
4. **단축 URL**: bit.ly 등 (25점)
5. **의심 키워드**: login, verify, update (10점)
6. **도메인 신규**: 30일 이내 생성 (30점)
7. **Punycode**: 유니코드 도메인 (30점)
8. **Userinfo 포함**: user@host 형식 (25점)

---

## 🔄 최적화 사항

### 이미 적용된 최적화
1. **서버 캐시**: TTL 기반 메모리 캐시 (분석/리다이렉트/WHOIS)
2. **Fast 모드**: 단축 URL만 리다이렉트 추적, WHOIS/LLM 생략
3. **리다이렉트 최적화**: HEAD 요청, stream=True, 타임아웃 분리
4. **KISA 온디맨드**: DB miss 시에만 API 호출하여 캐시
5. **클라이언트 캐시**: 확장프로그램 10분 TTL 캐시
6. **중복 요청 제거**: 동일 URL 동시 요청 병합

### 환경 변수 설정 (.env)
```bash
# 캐시 TTL 설정 (초)
ANALYZE_CACHE_TTL_SEC=600
REDIRECT_CACHE_TTL_SEC=600  
WHOIS_CACHE_TTL_SEC=604800  # 7일

# 리다이렉트 설정
REDIRECT_TIMEOUT_SEC=4.0
REDIRECT_MAX_HOPS=10

# KISA 온디맨드 설정
KISA_ONDEMAND=true
KISA_ONDEMAND_MAX_PAGES=3
KISA_ONDEMAND_PER_PAGE=1000
```

---

## 📁 파일 구조

```
term_project3/
├── server/
│   ├── main.py              # FastAPI 메인 서버
│   ├── llm_agent.py         # LLM 기반 판단 로직
│   ├── kisa_sync.py         # KISA DB 동기화
│   ├── score_rules.py       # 규칙 기반 점수 계산
│   ├── url_utils.py         # URL 분석 유틸
│   ├── redirect_utils.py    # 리다이렉트 추적
│   ├── whois_utils.py       # WHOIS 조회
│   ├── cache_utils.py       # TTL 캐시 구현
│   ├── db.py                # SQLite DB 관리
│   ├── mock_phish_site.py   # 테스트용 Mock 사이트
│   ├── .env                 # 환경 설정
│   └── requirements.txt     # Python 의존성
└── extension/
    ├── manifest.json        # Chrome 확장프로그램 설정
    ├── background.js        # 백그라운드 스크립트
    ├── content.js           # 컨텐츠 스크립트 (호버 감지)
    ├── popup.js/html/css    # 분석 이력 팝업
    └── ...
```

---

## 🐛 트러블슈팅

### 1. API 인증 오류 (-401)
**증상**: `{"code":-401,"msg":"인증키는 필수 항목 입니다."}`  
**해결**: `.env`의 `ODCLOUD_SERVICE_KEY` 확인

### 2. 한글 깨짐
**증상**: API 응답에서 홈페이지주소/날짜 파싱 실패  
**해결**: UTF-8 인코딩 확인, 수정된 코드 사용

### 3. LLM 응답 느림
**증상**: 분석 시간 10초 이상 소요  
**해결**: 
- `.env`에서 `USE_LLM=false` 또는 
- 확장프로그램에서 `mode: "fast"` 사용

### 4. 확장프로그램 동작 안 함
**증상**: 링크 호버해도 반응 없음  
**해결**:
- 서버가 실행 중인지 확인 (`http://localhost:8000/`)
- 브라우저 콘솔에서 CORS 오류 확인
- 확장프로그램 재로드

---

## 📈 성능 지표

### 분석 응답 시간 (캐시 미적중 기준)
- **Fast 모드**: 0.5-2초
  - KISA DB 조회: ~50ms
  - 규칙 기반 분석: ~10ms
  - 리다이렉트 추적 (단축 URL만): 1-3초
  
- **Full 모드**: 3-8초
  - + WHOIS 조회: 2-5초
  - + LLM 판단: 3-10초

### 캐시 적중률
- 서버 캐시: ~70-80% (반복 방문 시)
- 클라이언트 캐시: ~90% (같은 페이지 내)

---

## 🔐 보안 고려사항

1. **API 키 관리**: `.env` 파일을 `.gitignore`에 추가
2. **CORS 설정**: 프로덕션에서는 특정 도메인만 허용
3. **Rate Limiting**: API 과다 호출 방지 필요
4. **입력 검증**: URL 파라미터 sanitization 적용됨
5. **Mock 사이트**: 실제 자격증명 수집/전송 절대 안 함

---

## 📝 향후 개선 사항

1. [ ] Redis 등 외부 캐시 서버 연동
2. [ ] 사용자 피드백 수집 및 학습
3. [ ] 다국어 지원 (영어, 일본어)
4. [ ] 실시간 위협 인텔리전스 DB 연동
5. [ ] 배치 분석 API (한 번에 여러 URL)
6. [ ] 상세 분석 리포트 PDF 생성
7. [ ] 화이트리스트/블랙리스트 관리

---

## 👨‍💻 개발 환경

- **Python**: 3.10+
- **FastAPI**: 0.115.0
- **Ollama**: llama3.2:3b
- **Chrome Extension**: Manifest V3
- **Database**: SQLite 3

---

## 📄 라이선스

이 프로젝트는 교육 목적으로 개발되었습니다.

---

## 🙏 참고 자료

- [KISA 피싱 사이트 DB](https://www.kisa.or.kr/)
- [공공데이터포털](https://www.data.go.kr/)
- [FastAPI 문서](https://fastapi.tiangolo.com/)
- [Chrome Extension 가이드](https://developer.chrome.com/docs/extensions/)
- [Ollama](https://ollama.ai/)

---

**Last Updated**: 2025-12-14  
**Version**: 1.1.0
