# 🔗 链接有效性检查器

批量检查链接是否可访问的本地网页工具。零依赖，仅需 Python 3。

## 使用

```bash
cd /Users/chenmin/Documents/ChatGPT/connection_check
python3 server.py          # 默认 http://localhost:8000
python3 server.py 9000     # 自定义端口
```

浏览器打开 **http://localhost:8000**，粘贴 / 导入 / 拖拽链接后点击「开始检查」。

## 功能

- 导入：直接粘贴（自动识别文本中的 http/https 链接）、上传文件（.txt / .csv / .html，含浏览器书签导出）、拖拽文件，自动去重
- 检查：并发检查（默认 15 个同时进行），跟随重定向，实时显示进度，可随时停止
- 结果：状态码、最终链接（重定向后）、响应耗时、错误原因；支持按 有效 / 无效 / 无法访问 筛选
- 导出：结果可导出为 CSV（Excel 可直接打开）
- 判定：2xx / 3xx 为有效；4xx / 5xx 为无效；DNS 失败、超时、SSL 错误等为无法访问

## 说明

- 服务只监听 `127.0.0.1`，不会暴露到局域网
- 直接双击打开 `index.html` 也可以使用（页面会自动请求本地服务）
