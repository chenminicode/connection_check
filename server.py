#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
链接有效性检查器 —— 本地服务端
零依赖，仅使用 Python 标准库。

用法:
    python3 server.py          # 默认端口 8000
    python3 server.py 9000     # 指定端口
"""
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from urllib import error as urlerror
from urllib.parse import urlparse
from urllib.request import Request, urlopen

try:
    from http.server import ThreadingHTTPServer
except ImportError:  # Python < 3.7
    from http.server import HTTPServer as ThreadingHTTPServer
from http.server import BaseHTTPRequestHandler

ROOT = Path(__file__).resolve().parent
DEFAULT_PORT = 8000
CONCURRENCY = 15            # 同时检查的链接数
TIMEOUT = 10                # 单个链接超时（秒）
MAX_URLS = 2000             # 单次最多检查的链接数
MAX_BODY = 5 * 1024 * 1024  # 请求体上限 5MB
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


def check_one(url, ignore_ssl=False):
    """检查单个链接，返回结果字典。"""
    result = {"url": url, "ok": False, "status": None,
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

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send_file(ROOT / "index.html")
        else:
            self._send_json({"error": "Not Found"}, 404)

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/check":
            self._send_json({"error": "Not Found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            self._send_json({"error": "请求体过大"}, 413)
            return
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError, ConnectionResetError):
            self._send_json({"error": "请求体不是合法的 JSON"}, 400)
            return
        urls = [u for u in payload.get("urls", [])
                if isinstance(u, str) and u.strip()][:MAX_URLS]
        if not urls:
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
            for result in executor.map(worker, urls):
                line = (json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8")
                try:
                    self.wfile.write(line)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break  # 客户端已断开（如点击“停止”）
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def log_message(self, fmt, *args):
        pass  # 保持控制台清爽


def main():
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"无效端口: {sys.argv[1]}", file=sys.stderr)
            sys.exit(1)
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        print(f"无法监听端口 {port}: {e}", file=sys.stderr)
        print("可以换个端口试试: python3 server.py 9000", file=sys.stderr)
        sys.exit(1)
    print(f"链接检查服务已启动 → http://localhost:{port}")
    print("按 Ctrl+C 停止服务")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
