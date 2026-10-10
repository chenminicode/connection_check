#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
链接有效性检查器 —— 本地服务端
零依赖，仅使用 Python 标准库。

功能：
- 即时批量检查（/check，NDJSON 流式返回）
- 定时监控（/monitor/start|stop|check_now，间隔可设置）
- 历史数据 SQLite 持久化（/history），服务重启后自动恢复监控

用法:
    python3 server.py          # 默认端口 8000
    python3 server.py 9000     # 指定端口
"""
import contextlib
import hashlib
import hmac
import json
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from urllib import error as urlerror
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

try:
    from http.server import ThreadingHTTPServer
except ImportError:  # Python < 3.7
    from http.server import HTTPServer as ThreadingHTTPServer
from http.server import BaseHTTPRequestHandler

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "monitor.db"
DEFAULT_PORT = 8000
CONCURRENCY = 15            # 同时检查的链接数
TIMEOUT = 10                # 单个链接超时（秒）
MAX_URLS = 2000             # 单次最多检查的链接数
MAX_BODY = 5 * 1024 * 1024  # 请求体上限 5MB
RETENTION_DAYS = 30         # 历史数据保留天数
HISTORY_ROUNDS = 300        # /history 最多返回的轮数
MAX_LINKS_TEXT = 200_000    # /links 保存的输入框文本上限（字符）
SCRYPT_N, SCRYPT_R, SCRYPT_P = 16384, 8, 1   # 密码 scrypt 哈希参数
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 "
      "Safari/537.36 LinkChecker/1.0")

# 常见 HTTP 错误码 → 中文说明
HTTP_REASONS = {
    400: "请求错误", 401: "需要认证", 403: "无访问权限",
    404: "页面不存在", 405: "请求方法不允许", 408: "请求超时",
    410: "内容已删除", 429: "请求过于频繁", 451: "因法律原因不可用",
    500: "服务器内部错误", 501: "功能未实现", 502: "网关错误",
    503: "服务不可用", 504: "网关超时",
}


def friendly_error(exc):
    """把底层异常转换成一句人能看懂的中文。"""
    reason = getattr(exc, "reason", None)
    err = reason if isinstance(reason, Exception) else exc
    if isinstance(err, ssl.SSLError):
        return "SSL 证书验证失败"
    if isinstance(err, socket.gaierror):
        return "域名无法解析"
    if isinstance(err, (socket.timeout, TimeoutError)):
        return "连接超时"
    if isinstance(err, ConnectionRefusedError):
        return "连接被拒绝"
    if isinstance(err, ConnectionResetError):
        return "连接被重置"
    if isinstance(err, KeyError):
        return "重定向响应异常"
    text = str(err) or type(err).__name__
    return text[:200]


def check_one(url, name="", ignore_ssl=False):
    """检查单个链接，返回结果字典。"""
    result = {"name": name, "url": url, "ok": False, "status": None,
              "final_url": url, "time_ms": None, "error": None}

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        result["error"] = "不是有效的 http(s) 链接"
        return result

    context = ssl._create_unverified_context() if ignore_ssl else None
    started = time.time()
    try:
        req = Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
        with urlopen(req, timeout=TIMEOUT, context=context) as resp:
            code = resp.getcode()
            result["status"] = code
            result["final_url"] = resp.geturl()
            result["ok"] = 200 <= code < 400
    except urlerror.HTTPError as e:
        result["status"] = e.code
        try:
            result["final_url"] = e.geturl() or url
        except Exception:
            result["final_url"] = url
        result["error"] = HTTP_REASONS.get(e.code, str(e.reason)[:200]) if e.reason else None
    except Exception as e:  # DNS / SSL / 超时 / 连接被拒等
        result["error"] = friendly_error(e)
    result["time_ms"] = round((time.time() - started) * 1000)
    return result


def parse_items(items):
    """把请求中的链接条目统一解析为 (name, url) 列表。

    兼容两种写法：纯字符串 url，或 {"name": 名称, "url": 链接} 对象；按 url 去重。
    """
    out, seen = [], set()
    for it in items:
        if isinstance(it, str):
            name, url = "", it.strip()
        elif isinstance(it, dict):
            name = str(it.get("name") or "").strip()
            url = str(it.get("url") or "").strip()
        else:
            continue
        if url and url not in seen:
            seen.add(url)
            out.append((name, url))
    return out[:MAX_URLS]


# ---------- 用户与密码 ----------

def hash_password(password):
    """生成 scrypt 密码哈希：scrypt$n$r$p$盐$摘要（后两者为十六进制）。

    参数写进哈希串里，将来调参时旧哈希仍可校验。
    """
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    """校验密码；哈希格式不合法或密码错误都返回 False。"""
    try:
        algo, n, r, p, salt_hex, hash_hex = stored.split("$")
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                                n=int(n), r=int(r), p=int(p), dklen=len(hash_hex) // 2)
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, AttributeError, TypeError):
        return False


def check_credentials(username, password):
    """注册/登录输入校验，通过返回空串，否则返回中文错误。"""
    if not (2 <= len(username) <= 32) or any(c.isspace() for c in username):
        return "用户名需为 2-32 个字符，且不含空格"
    if not (6 <= len(password) <= 128):
        return "密码长度需在 6-128 个字符之间"
    return ""


def monitor_key(uid):
    """监控配置在 config 表中的 key（游客 = monitor，用户 = monitor:uid）。"""
    return f"monitor:{uid}" if uid else "monitor"


def links_key(uid):
    """输入框链接文本的 key（游客 = links，用户 = links:uid）。"""
    return f"links:{uid}" if uid else "links"


class Store:
    """SQLite 存储：检查历史 + 监控配置。"""

    def __init__(self, path):
        self.path = path

    @contextlib.contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init(self):
        with self.connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                checked_at REAL NOT NULL,
                ok INTEGER NOT NULL,
                status INTEGER,
                time_ms INTEGER,
                error TEXT)""")
            # 旧库迁移：早期版本没有 name 列
            cols = [r[1] for r in conn.execute("PRAGMA table_info(checks)").fetchall()]
            if "name" not in cols:
                conn.execute("ALTER TABLE checks ADD COLUMN name TEXT NOT NULL DEFAULT ''")
            # 多用户迁移：checks 增加 user_id 列（NULL = 游客，老数据自然归属游客）
            if "user_id" not in cols:
                conn.execute("ALTER TABLE checks ADD COLUMN user_id INTEGER")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_checks_time ON checks(checked_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_checks_url_time ON checks(url, checked_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_checks_user_time ON checks(user_id, checked_at)")
            conn.execute("""CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY, value TEXT)""")
            # 用户与登录会话
            conn.execute("""CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at REAL NOT NULL)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at REAL NOT NULL)""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")

    def get_config(self, key, default=None):
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_config(self, key, value):
        with self.connect() as conn:
            conn.execute("INSERT INTO config(key,value) VALUES(?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (key, json.dumps(value, ensure_ascii=False)))

    def insert_round(self, checked_at, results, user_id=None):
        rows = [(r["url"], r.get("name", ""), checked_at, int(r["ok"]),
                 r["status"], r["time_ms"], r["error"], user_id)
                for r in results]
        with self.connect() as conn:
            conn.executemany("INSERT INTO checks(url, name, checked_at, ok, status, time_ms, error, user_id) "
                             "VALUES(?,?,?,?,?,?,?,?)", rows)

    def prune(self):
        cutoff = time.time() - RETENTION_DAYS * 86400
        with self.connect() as conn:
            conn.execute("DELETE FROM checks WHERE checked_at < ?", (cutoff,))

    def history(self, limit=HISTORY_ROUNDS, user_id=None):
        """按轮返回某个身份最近的历史记录（user_id=None 表示游客）。"""
        limit = max(1, min(limit, 1000))
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT url, name, checked_at, ok, status, time_ms, error FROM checks "
                "WHERE user_id IS ? "  # IS ? 同时适配 NULL 与整数
                "ORDER BY checked_at DESC, id DESC LIMIT ?",
                (user_id, limit * 100 + 1000)).fetchall()
        rounds = []
        for url, name, t, ok, status, time_ms, err in reversed(rows):
            if not rounds or rounds[-1]["t"] != t:
                rounds.append({"t": t, "results": []})
            rounds[-1]["results"].append({
                "url": url, "name": name, "ok": bool(ok), "status": status,
                "time_ms": time_ms, "error": err,
            })
        return rounds[-limit:]

    # ---------- 用户与会话 ----------

    def create_user(self, username, password_hash):
        """创建用户，返回 id；用户名已存在（含大小写变体）返回 None。"""
        try:
            with self.connect() as conn:
                cur = conn.execute("INSERT INTO users(username, password_hash, created_at) "
                                   "VALUES(?,?,?)", (username, password_hash, time.time()))
                return cur.lastrowid
        except sqlite3.IntegrityError:
            return None

    def user_by_name(self, username):
        with self.connect() as conn:
            row = conn.execute("SELECT id, username, password_hash FROM users WHERE username=?",
                               (username,)).fetchone()
        return {"id": row[0], "username": row[1], "password_hash": row[2]} if row else None

    def user_by_token(self, token):
        """按 token 取用户；token 无效返回 None。"""
        with self.connect() as conn:
            row = conn.execute("SELECT u.id, u.username FROM sessions s "
                               "JOIN users u ON u.id = s.user_id WHERE s.token=?",
                               (token,)).fetchone()
        return {"id": row[0], "username": row[1]} if row else None

    def create_session(self, user_id):
        token = secrets.token_urlsafe(32)
        with self.connect() as conn:
            conn.execute("INSERT INTO sessions(token, user_id, created_at) VALUES(?,?,?)",
                         (token, user_id, time.time()))
        return token

    def delete_session(self, token):
        with self.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))

    def running_monitor_uids(self):
        """列出所有处于运行状态的监控配置对应的身份：None=游客，其余为 uid。"""
        with self.connect() as conn:
            rows = conn.execute("SELECT key, value FROM config "
                                "WHERE key='monitor' OR key LIKE 'monitor:%'").fetchall()
        out = []
        for key, value in rows:
            try:
                state = json.loads(value)
            except ValueError:
                continue
            if not state.get("running") or not (state.get("urls") or []):
                continue
            if key == "monitor":
                out.append(None)
            else:
                try:
                    out.append(int(key.split(":", 1)[1]))
                except ValueError:
                    continue
        return out


class Monitor:
    """定时监控调度器（每个身份一个实例，各自后台守护线程）。"""

    def __init__(self, store, user_id=None):
        self.store = store
        self.user_id = user_id                # None = 游客
        self.cfg_key = monitor_key(user_id)   # 配置持久化用的 config key
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = None
        self.running = False
        self.interval_minutes = 5.0
        self.urls = []
        self.started_at = None
        self.last_check_at = None
        self.next_check_at = None
        self.rounds_completed = 0
        self._resume()

    def _resume(self):
        """服务重启后自动恢复监控。"""
        state = self.store.get_config(self.cfg_key, {})
        if state.get("running"):
            self.interval_minutes = state.get("interval_minutes", 5.0)
            # 兼容旧配置：早期版本的 urls 是纯字符串列表
            self.urls = [u if isinstance(u, dict) else {"name": "", "url": u}
                         for u in state.get("urls", [])]
            self.started_at = state.get("started_at")
            self.last_check_at = state.get("last_check_at")
            self.rounds_completed = state.get("rounds_completed", 0)
            if self.urls:
                self._start_thread()

    def _save(self):
        self.store.set_config(self.cfg_key, {
            "running": self.running,
            "interval_minutes": self.interval_minutes,
            "urls": self.urls,
            "started_at": self.started_at,
            "last_check_at": self.last_check_at,
            "rounds_completed": self.rounds_completed,
        })

    def _start_thread(self):
        self._stop.clear()
        self._wake.clear()
        self.running = True
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def start(self, urls, interval_minutes):
        """启动监控（若已在监控则先停止并替换配置）。urls 为 (name, url) 列表。"""
        with self._lock:
            self._stop_thread()
            self.urls = [{"name": n, "url": u} for n, u in urls]
            self.interval_minutes = interval_minutes
            self.started_at = time.time()
            self.rounds_completed = 0
            self.last_check_at = None
            self._save()
            self._start_thread()

    def stop(self):
        with self._lock:
            self._stop_thread()
            self._save()

    def _stop_thread(self):
        self.running = False
        self._stop.set()
        self._wake.set()  # 唤醒等待中的线程
        thread = self._thread
        self._thread = None
        if thread and thread.is_alive():
            thread.join(timeout=2)

    def check_now(self, urls=None):
        """立即执行一轮检查（不改变调度状态）。urls 为 (name, url) 列表。"""
        with self._lock:
            if urls:
                self.urls = [{"name": n, "url": u} for n, u in urls]
            target = list(self.urls)
        if not target:
            return
        threading.Thread(target=self._run_round, args=(target,), daemon=True).start()

    def _worker(self):
        while not self._stop.is_set():
            self._run_round(list(self.urls))
            # 等待下一个间隔 / 停止信号 / 立即检查信号
            self._wake.wait(timeout=self.interval_minutes * 60)
            self._wake.clear()

    def _run_round(self, urls):
        if not urls:
            return
        started = time.time()
        worker = partial(check_one, ignore_ssl=False)
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            results = list(pool.map(worker,
                                    [it["url"] for it in urls],
                                    [it.get("name", "") for it in urls]))
        self.store.insert_round(started, results, self.user_id)
        self.store.prune()
        with self._lock:
            self.last_check_at = started
            if self.running:
                self.rounds_completed += 1
                self.next_check_at = started + self.interval_minutes * 60
            self._save()

    def status(self):
        with self._lock:
            return {
                "running": self.running,
                "interval_minutes": self.interval_minutes,
                "urls": list(self.urls),
                "started_at": self.started_at,
                "last_check_at": self.last_check_at,
                "next_check_at": self.next_check_at,
                "rounds_completed": self.rounds_completed,
            }


STORE = None
MONITORS = {}            # {None: 游客 Monitor, uid: 用户 Monitor}
_monitors_lock = threading.Lock()
AUTH_FAIL = object()     # _auth_user 的哨兵：token 无效且已发 401


def get_monitor(uid):
    """按身份取 Monitor（懒创建，构造时会自动恢复已保存的监控状态）。"""
    with _monitors_lock:
        m = MONITORS.get(uid)
        if m is None:
            m = Monitor(STORE, uid)
            MONITORS[uid] = m
        return m


def recover_monitors():
    """服务启动时恢复所有处于运行状态的监控（游客 + 各用户）。"""
    for uid in STORE.running_monitor_uids():
        get_monitor(uid)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _cors(self):
        # 允许直接双击打开 index.html（file://）也能调用本服务
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, path):
        try:
            data = path.read_bytes()
        except OSError:
            self.send_error(404, "File not found")
            return
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        """读取请求体并解析 JSON；失败时已发送错误响应并返回 None。"""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            self._send_json({"error": "请求体过大"}, 413)
            return None
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError, ConnectionResetError):
            self._send_json({"error": "请求体不是合法的 JSON"}, 400)
            return None

    def _query_param(self, name, default):
        values = parse_qs(urlparse(self.path).query).get(name)
        return values[0] if values else default

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _auth_user(self):
        """解析登录态：无 token → None（游客）；有 token 但无效 → 发 401 并返回 AUTH_FAIL。"""
        auth = self.headers.get("Authorization") or ""
        if not auth.lower().startswith("bearer "):
            return None
        token = auth[7:].strip()
        user = STORE.user_by_token(token) if token else None
        if not user:
            self._send_json({"error": "登录已过期，请重新登录"}, 401)
            return AUTH_FAIL
        return user

    def _bearer_token(self):
        auth = self.headers.get("Authorization") or ""
        return auth[7:].strip() if auth.lower().startswith("bearer ") else ""

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send_file(ROOT / "index.html")
            return
        if path == "/auth/me":
            self._handle_me()
            return
        me = self._auth_user()
        if me is AUTH_FAIL:
            return
        uid = me["id"] if me else None
        if path == "/monitor/status":
            self._send_json(get_monitor(uid).status())
        elif path == "/history":
            try:
                limit = int(self._query_param("limit", str(HISTORY_ROUNDS)))
            except ValueError:
                limit = HISTORY_ROUNDS
            self._send_json({"rounds": STORE.history(limit, uid)})
        elif path == "/links":
            self._send_json({"text": STORE.get_config(links_key(uid), "") or ""})
        else:
            self._send_json({"error": "Not Found"}, 404)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/check":
            self._handle_check()  # 不鉴权、不落库
            return
        if path == "/auth/register":
            self._handle_register()
            return
        if path == "/auth/login":
            self._handle_login()
            return
        if path == "/auth/logout":
            self._handle_logout()
            return
        me = self._auth_user()
        if me is AUTH_FAIL:
            return
        uid = me["id"] if me else None
        if path == "/links":
            self._handle_links_save(uid)
        elif path == "/monitor/start":
            self._handle_monitor_start(uid)
        elif path == "/monitor/stop":
            self._handle_monitor_stop(uid)
        elif path == "/monitor/check_now":
            self._handle_monitor_check_now(uid)
        else:
            self._send_json({"error": "Not Found"}, 404)

    def _handle_check(self):
        payload = self._read_json()
        if payload is None:
            return
        items = parse_items(payload.get("urls", []))
        if not items:
            self._send_json({"error": "没有可检查的链接"}, 400)
            return
        ignore_ssl = bool(payload.get("ignore_ssl"))

        # 流式返回：每检查完一条就写一行 JSON（NDJSON），前端实时显示
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        worker = partial(check_one, ignore_ssl=ignore_ssl)
        executor = ThreadPoolExecutor(max_workers=CONCURRENCY)
        try:
            for result in executor.map(worker,
                                       [u for _, u in items],
                                       [n for n, _ in items]):
                line = (json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8")
                try:
                    self.wfile.write(line)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break  # 客户端已断开（如点击“停止”）
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def _handle_monitor_start(self, uid):
        payload = self._read_json()
        if payload is None:
            return
        items = parse_items(payload.get("urls", []))
        if not items:
            self._send_json({"error": "没有可监控的链接"}, 400)
            return
        try:
            interval = float(payload.get("interval_minutes", 5))
        except (TypeError, ValueError):
            self._send_json({"error": "间隔时间格式不正确"}, 400)
            return
        interval = min(max(interval, 0.1), 1440)
        m = get_monitor(uid)
        m.start(items, interval)
        self._send_json({"ok": True, **m.status()})

    def _handle_monitor_stop(self, uid):
        payload = self._read_json()
        if payload is None:
            return
        m = get_monitor(uid)
        m.stop()
        self._send_json({"ok": True, **m.status()})

    def _handle_monitor_check_now(self, uid):
        payload = self._read_json()
        if payload is None:
            return
        items = parse_items(payload.get("urls", []))
        get_monitor(uid).check_now(items if items else None)
        self._send_json({"ok": True})

    def _handle_register(self):
        payload = self._read_json()
        if payload is None:
            return
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        err = check_credentials(username, password)
        if err:
            self._send_json({"error": err}, 400)
            return
        uid = STORE.create_user(username, hash_password(password))
        if uid is None:
            self._send_json({"error": "用户名已被注册"}, 409)
            return
        token = STORE.create_session(uid)
        self._send_json({"ok": True, "token": token, "user_id": uid, "username": username})

    def _handle_login(self):
        payload = self._read_json()
        if payload is None:
            return
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        user = STORE.user_by_name(username)
        if not user or not verify_password(password, user["password_hash"]):
            self._send_json({"error": "用户名或密码错误"}, 401)
            return
        token = STORE.create_session(user["id"])
        self._send_json({"ok": True, "token": token,
                         "user_id": user["id"], "username": user["username"]})

    def _handle_logout(self):
        token = self._bearer_token()
        if token:
            STORE.delete_session(token)  # 幂等：token 不存在也无妨
        self._send_json({"ok": True})

    def _handle_me(self):
        me = self._auth_user()
        if me is AUTH_FAIL:
            return
        if me is None:
            self._send_json({"error": "未登录"}, 401)
            return
        self._send_json({"ok": True, "user_id": me["id"], "username": me["username"]})

    def _handle_links_save(self, uid):
        payload = self._read_json()
        if payload is None:
            return
        text = str(payload.get("text") or "")
        if len(text) > MAX_LINKS_TEXT:
            self._send_json({"error": f"文本过长（上限 {MAX_LINKS_TEXT // 1000}K 字符）"}, 413)
            return
        STORE.set_config(links_key(uid), text)
        self._send_json({"ok": True})

    def log_message(self, fmt, *args):
        pass  # 保持控制台清爽


def main():
    global STORE
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"无效端口: {sys.argv[1]}", file=sys.stderr)
            sys.exit(1)
    STORE = Store(DB_PATH)
    STORE.init()
    recover_monitors()
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        print(f"无法监听端口 {port}: {e}", file=sys.stderr)
        print("可以换个端口试试: python3 server.py 9000", file=sys.stderr)
        sys.exit(1)
    print(f"链接检查服务已启动 → http://localhost:{port}")
    running = [uid for uid, m in MONITORS.items() if m.running]
    if running:
        names = ["游客" if uid is None else f"用户{uid}" for uid in running]
        print(f"已恢复 {len(running)} 个定时监控（{'、'.join(names)}）")
    print("按 Ctrl+C 停止服务")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
