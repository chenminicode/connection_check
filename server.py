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
import json
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_checks_time ON checks(checked_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_checks_url_time ON checks(url, checked_at)")
            conn.execute("""CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY, value TEXT)""")

    def get_config(self, key, default=None):
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_config(self, key, value):
        with self.connect() as conn:
            conn.execute("INSERT INTO config(key,value) VALUES(?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (key, json.dumps(value, ensure_ascii=False)))

    def insert_round(self, checked_at, results):
        rows = [(r["url"], r.get("name", ""), checked_at, int(r["ok"]),
                 r["status"], r["time_ms"], r["error"])
                for r in results]
        with self.connect() as conn:
            conn.executemany("INSERT INTO checks(url, name, checked_at, ok, status, time_ms, error) "
                             "VALUES(?,?,?,?,?,?,?)", rows)

    def prune(self):
        cutoff = time.time() - RETENTION_DAYS * 86400
        with self.connect() as conn:
            conn.execute("DELETE FROM checks WHERE checked_at < ?", (cutoff,))

    def history(self, limit=HISTORY_ROUNDS):
        """按轮返回最近的历史记录（每轮一个时间戳 + 各链接结果）。"""
        limit = max(1, min(limit, 1000))
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT url, name, checked_at, ok, status, time_ms, error FROM checks "
                "ORDER BY checked_at DESC, id DESC LIMIT ?",
                (limit * 100 + 1000,)).fetchall()
        rounds = []
        for url, name, t, ok, status, time_ms, err in reversed(rows):
            if not rounds or rounds[-1]["t"] != t:
                rounds.append({"t": t, "results": []})
            rounds[-1]["results"].append({
                "url": url, "name": name, "ok": bool(ok), "status": status,
                "time_ms": time_ms, "error": err,
            })
        return rounds[-limit:]


class Monitor:
    """定时监控调度器（单实例，后台守护线程）。"""

    def __init__(self, store):
        self.store = store
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
        state = self.store.get_config("monitor", {})
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
        self.store.set_config("monitor", {
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
        self.store.insert_round(started, results)
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
MONITOR = None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _cors(self):
        # 允许直接双击打开 index.html（file://）也能调用本服务
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

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

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send_file(ROOT / "index.html")
        elif path == "/monitor/status":
            self._send_json(MONITOR.status())
        elif path == "/history":
            try:
                limit = int(self._query_param("limit", str(HISTORY_ROUNDS)))
            except ValueError:
                limit = HISTORY_ROUNDS
            self._send_json({"rounds": STORE.history(limit)})
        else:
            self._send_json({"error": "Not Found"}, 404)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/check":
            self._handle_check()
        elif path == "/monitor/start":
            self._handle_monitor_start()
        elif path == "/monitor/stop":
            self._handle_monitor_stop()
        elif path == "/monitor/check_now":
            self._handle_monitor_check_now()
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

    def _handle_monitor_start(self):
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
        MONITOR.start(items, interval)
        self._send_json({"ok": True, **MONITOR.status()})

    def _handle_monitor_stop(self):
        payload = self._read_json()
        if payload is None:
            return
        MONITOR.stop()
        self._send_json({"ok": True, **MONITOR.status()})

    def _handle_monitor_check_now(self):
        payload = self._read_json()
        if payload is None:
            return
        items = parse_items(payload.get("urls", []))
        MONITOR.check_now(items if items else None)
        self._send_json({"ok": True})

    def log_message(self, fmt, *args):
        pass  # 保持控制台清爽


def main():
    global STORE, MONITOR
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"无效端口: {sys.argv[1]}", file=sys.stderr)
            sys.exit(1)
    STORE = Store(DB_PATH)
    STORE.init()
    MONITOR = Monitor(STORE)
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        print(f"无法监听端口 {port}: {e}", file=sys.stderr)
        print("可以换个端口试试: python3 server.py 9000", file=sys.stderr)
        sys.exit(1)
    print(f"链接检查服务已启动 → http://localhost:{port}")
    if MONITOR.running:
        print(f"已恢复定时监控（每 {MONITOR.interval_minutes} 分钟检查 {len(MONITOR.urls)} 条链接）")
    print("按 Ctrl+C 停止服务")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
