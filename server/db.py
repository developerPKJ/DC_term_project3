import sqlite3
from pathlib import Path
from typing import Optional, Tuple

def connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    return con

def init_db(con: sqlite3.Connection) -> None:
    con.execute("""
    CREATE TABLE IF NOT EXISTS phishing_url (
      url TEXT PRIMARY KEY,
      date TEXT
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS phishing_domain (
      domain TEXT PRIMARY KEY,
      first_seen_date TEXT
    );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_phishing_domain_domain ON phishing_domain(domain);")
    con.commit()

def upsert_url(con: sqlite3.Connection, url: str, date: Optional[str]) -> None:
    con.execute("INSERT OR REPLACE INTO phishing_url(url, date) VALUES (?, ?)", (url, date))

def upsert_domain(con: sqlite3.Connection, domain: str, date: Optional[str]) -> None:
    # first_seen_date는 “최초 탐지일” 느낌으로 유지하고 싶으면 MIN 로직이 맞지만,
    # 여기선 단순 upsert(데모/과제용)로 둠.
    con.execute(
        "INSERT OR REPLACE INTO phishing_domain(domain, first_seen_date) VALUES (?, ?)",
        (domain, date),
    )

def find_url(con: sqlite3.Connection, url: str) -> Optional[str]:
    cur = con.execute("SELECT date FROM phishing_url WHERE url=?", (url,))
    row = cur.fetchone()
    return row[0] if row else None

def find_domain(con: sqlite3.Connection, domain: str) -> Optional[str]:
    cur = con.execute("SELECT first_seen_date FROM phishing_domain WHERE domain=?", (domain,))
    row = cur.fetchone()
    return row[0] if row else None
