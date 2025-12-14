from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse

app = FastAPI(title="Mock Phish-like Site (Safe)")

@app.get("/", response_class=HTMLResponse)
def home():
    # 일부러 “수상해 보이는” 링크들(로컬로만)
    html = """
    <!doctype html><meta charset="utf-8">
    <h2>테스트용(안전) 피싱-유사 링크 모음</h2>
    <p>이 페이지는 악성행위 없이 '특성'만 흉내냅니다. (자격증명 수집/전송 없음)</p>

    <h3>1) 리다이렉트 체인</h3>
    <a href="http://127.0.0.1:9000/short">/short → /r1 → /r2 → /login</a><br><br>

    <h3>2) 리다이렉트 과다(여러 홉)</h3>
    <a href="http://127.0.0.1:9000/chain/6">/chain/6 (6번 리다이렉트)</a><br><br>

    <h3>3) IP 호스트(도메인 대신 IP)</h3>
    <a href="http://127.0.0.1:9000/login">IP host login</a><br><br>

    <h3>4) URL 난독화 느낌(긴 경로/쿼리)</h3>
    <a href="http://127.0.0.1:9000/login?session=AAABBBCCC111222333&continue=%2Fsecure%2Faccount%2Fupdate%3Fid%3D9999">
      long query / encoded params
    </a><br><br>

    <h3>5) userinfo 트릭 느낌(앞에 도메인처럼 보이게)</h3>
    <p>
      아래는 브라우저 주소창에서 혼동을 주는 형태 테스트용입니다.<br>
      실제 접속 대상은 127.0.0.1 이고, 앞의 example.com은 userinfo 파트입니다.
    </p>
    <a href="http://example.com@127.0.0.1:9000/login">http://example.com@127.0.0.1:9000/login</a><br><br>

    <h3>6) 외부 단축 링크 샘플</h3>
    <a href="https://swyg.link/c9QF1">https://swyg.link/c9QF1</a><br>
    <a href="https://c11.kr/19er7">https://c11.kr/19er7</a><br>
    <a href="https://bit.ly/3xyz">bit.ly 단축 URL</a><br><br>

    <h3>7) 의심스러운 키워드 포함</h3>
    <a href="http://127.0.0.1:9000/secure/account/verify">account/verify 경로</a><br>
    <a href="http://127.0.0.1:9000/update-payment">update-payment</a><br><br>

    <h3>8) 비표준 포트</h3>
    <a href="http://127.0.0.1:8888/login">포트 8888</a><br><br>

    <h3>9) 긴 URL (난독화 시도)</h3>
    <a href="http://127.0.0.1:9000/path/very/long/url/with/many/segments/to/confuse/users/about/the/actual/destination/login">
      긴 경로 URL
    </a><br><br>
    """
    return html

@app.get("/short")
def short():
    return RedirectResponse(url="/r1", status_code=302)

@app.get("/r1")
def r1():
    return RedirectResponse(url="/r2", status_code=302)

@app.get("/r2")
def r2():
    return RedirectResponse(url="/login", status_code=302)

@app.get("/chain/{n}")
def chain(n: int):
    # n번 리다이렉트 후 /login
    n = max(0, min(20, n))
    if n == 0:
        return RedirectResponse(url="/login", status_code=302)
    return RedirectResponse(url=f"/chain/{n-1}", status_code=302)

@app.get("/login", response_class=HTMLResponse)
def login():
    # 절대 실제 계정정보 수집/전송하지 않는 “모양만” 페이지
    html = """
    <!doctype html><meta charset="utf-8">
    <h2>Secure Login (Mock)</h2>
    <p style="color:#666">테스트 목적의 가짜 로그인 UI입니다. 입력값은 어디에도 전송되지 않습니다.</p>
    <form onsubmit="event.preventDefault(); alert('테스트 페이지: 전송되지 않음');">
      <input placeholder="Email" style="padding:8px; width:260px"><br><br>
      <input type="password" placeholder="Password" style="padding:8px; width:260px"><br><br>
      <button type="submit" style="padding:8px 14px">Sign in</button>
    </form>
    """
    return html
@app.get("/secure/account/verify", response_class=HTMLResponse)
def verify():
    return login()

@app.get("/update-payment", response_class=HTMLResponse)
def update_payment():
    return login()

@app.get("/path/very/long/url/with/many/segments/to/confuse/users/about/the/actual/destination/login", response_class=HTMLResponse)
def long_path():
    return login()
@app.get("/robots.txt")
def robots():
    return PlainTextResponse("User-agent: *\nDisallow: /")

@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)
