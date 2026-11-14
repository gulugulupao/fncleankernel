#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fncleankernel Web 后端：零第三方依赖，复用宿主 Python3。"""
import json
import os
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(WEB)
ENGINE = os.path.join(APP, 'bin', 'kernel_clean.py')
VAR = os.environ.get('TRIM_PKGVAR') or '/vol1/@appdata/fncleankernel'
STATE = os.path.join(VAR, 'last_result.json')
HISTORY = os.path.join(VAR, 'history.jsonl')
LOGFILE = os.path.join(VAR, 'log', 'clean.log')
PORT = int(os.environ.get('SERVICE_PORT') or
           os.environ.get('TRIM_SERVICE_PORT') or 8097)
# 飞牛应用中心 ui/config 是 type:url + protocol:http + port:8097，
# 浏览器直连该端口（实测 80 端口无对应反代路径）。默认保持 0.0.0.0 以免
# 应用打不开；可用 FNCLEAN_BIND=127.0.0.1 切换为仅本机可连（会牺牲直连入口）。
BIND = os.environ.get('FNCLEAN_BIND') or '0.0.0.0'

BUSY = threading.Lock()
MIME = {'.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.png': 'image/png',
        '.json': 'application/json; charset=utf-8'}

# 清理项白名单：前端传来的 items 只认这几个，其余静默丢弃
ALLOWED_ITEMS = {'old_kernel', 'apt_cache', 'syslog_rotated',
                 'log_force_rotate', 'cron_mail', 'mon_residue', 'journal'}

# 静态资源白名单：只放行这几个文件，杜绝目录穿越
STATIC = {
    '/': 'index.html',
    '/index.html': 'index.html',
    '/style.css': 'style.css',
    '/app.js': 'app.js',
    '/images/wechat-promo.png': 'images/wechat-promo.png',
    '/images/icon_64.png': 'images/icon_64.png',
}


def run_engine(args, timeout=1300):
    env = os.environ.copy()
    env.setdefault('TRIM_APPDEST', APP)
    env.setdefault('TRIM_PKGVAR', VAR)
    try:
        p = subprocess.run([sys.executable, ENGINE] + args,
                           capture_output=True, text=True, timeout=timeout,
                           env=env, errors='replace')
        out = (p.stdout or '').strip()
        try:
            return json.loads(out[out.find('{'):out.rfind('}') + 1])
        except Exception:
            return dict(status='ERROR', status_text='引擎输出解析失败',
                        warnings=[(p.stderr or '')[-800:], out[-800:]],
                        log=[], grub=dict(executed=False))
    except subprocess.TimeoutExpired:
        return dict(status='ERROR', status_text='执行超时', warnings=['引擎执行超时'],
                    log=[], grub=dict(executed=False))
    except Exception as e:
        return dict(status='ERROR', status_text='引擎启动失败',
                    warnings=[repr(e)], log=[], grub=dict(executed=False))


def _host_of(value):
    """从 Origin URL 或 Host 头里取主机名（去 scheme / 端口，兼容 IPv6）。"""
    if not value:
        return ''
    v = value.strip()
    if '://' in v:
        try:
            return (urllib.parse.urlsplit(v).hostname or '').lower()
        except Exception:
            return ''
    if v.startswith('['):
        return v[1:v.find(']')].lower() if ']' in v else v.lower()
    return v.split(':')[0].lower()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _write_allowed(self):
        """写接口同源校验（纵深防御，不依赖 Host/Origin 严格相等以兼容各种入口）。

        1) 自定义头：跨站 <form> 无法携带；跨站 fetch 带自定义头会先发 CORS
           预检，本服务未实现 OPTIONS，浏览器不会发出实际请求。
        2) Sec-Fetch-Site：浏览器明确标记跨站时直接拒绝。
        3) Origin 主机名比对：仅在浏览器未标记 same-origin 时启用，
           避免误挡经由代理进入的请求。
        """
        if (self.headers.get('X-Fnclean-Client') or '') != 'web':
            return False, '缺少同源标记（X-Fnclean-Client）'
        sec = (self.headers.get('Sec-Fetch-Site') or '').lower()
        if sec and sec not in ('same-origin', 'none'):
            return False, '跨站请求被拒绝（Sec-Fetch-Site=%s）' % sec
        origin = self.headers.get('Origin')
        if origin and sec != 'same-origin':
            oh = _host_of(origin)
            hh = _host_of(self.headers.get('Host') or '')
            if oh and hh and oh != hh:
                return False, 'Origin 与 Host 不一致'
        return True, ''

    def _send(self, code, body, ctype='application/json; charset=utf-8'):
        data = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def do_GET(self):
        path = self.path.split('?')[0]
        if path in STATIC:
            return self._static(STATIC[path])
        if path == '/api/scan':
            return self._json(run_engine(['--scan'], timeout=180))
        if path == '/api/last':
            try:
                with open(STATE, 'r', encoding='utf-8') as f:
                    return self._json(json.load(f))
            except Exception:
                return self._json(dict(status='SCAN', status_text='尚无执行记录',
                                       notes=['点击「扫描」查看当前内核状态。'],
                                       kernels=[], warnings=[], log=[]))
        if path == '/api/health':
            return self._json(dict(ok=True, app='fncleankernel', port=PORT))
        if path == '/api/log':
            try:
                with open(LOGFILE, 'r', encoding='utf-8', errors='replace') as f:
                    return self._json(dict(log=f.read()[-30000:]))
            except Exception:
                return self._json(dict(log=''))
        if path == '/api/history':
            rows = []
            try:
                with open(HISTORY, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rows.append(json.loads(line))
                        except Exception:
                            pass
            except Exception:
                pass
            return self._json(dict(rows=rows[-40:]))
        return self._send(404, 'not found', 'text/plain; charset=utf-8')

    def _fix_cron(self):
        """堵 cron 邮件源头。只有 confirm=true 才会真正改 crontab。"""
        try:
            n = int(self.headers.get('Content-Length') or 0)
            raw = self.rfile.read(n).decode('utf-8', 'replace') if n > 0 else ''
            data = json.loads(raw) if raw else {}
        except Exception:
            data = {}
        confirmed = data.get('confirm') is True
        args = ['--fix-cron-mail']
        if confirmed:
            args.append('--confirm')
        R = run_engine(args, timeout=180)
        if not confirmed:
            # 未确认时不再回显 crontab 原文，只回数量（原文已由 /api/scan
            # 的 cron_source 提供给前端确认弹窗）
            R['row_count'] = len(R.get('rows', []))
            R.pop('rows', None)
            R.pop('after', None)
        return self._json(R)

    def do_POST(self):
        ok, why = self._write_allowed()
        if not ok:
            return self._json(dict(status='ERROR', status_text='请求被拒绝',
                                   warnings=[why], log=[],
                                   grub=dict(executed=False)), 403)
        path = self.path.split('?')[0]
        if path == '/api/fix-cron-mail':
            return self._fix_cron()
        if path != '/api/clean':
            return self._send(404, 'not found', 'text/plain; charset=utf-8')
        if not BUSY.acquire(blocking=False):
            return self._json(dict(status='ERROR', status_text='已有清理任务在执行',
                                   warnings=['请等待上一次任务结束。'],
                                   log=[], grub=dict(executed=False)), 429)
        try:
            try:
                n = int(self.headers.get('Content-Length') or 0)
                raw = self.rfile.read(n).decode('utf-8', 'replace') if n > 0 else ''
                data = json.loads(raw) if raw else {}
            except Exception:
                data = {}
            if data.get('confirm') is not True:
                return self._json(dict(status='ERROR',
                                       status_text='缺少执行确认',
                                       warnings=['请从应用页面执行清理。'],
                                       log=[], grub=dict(executed=False)), 403)
            args = ['--clean']
            items = data.get('items')
            if isinstance(items, list):
                safe = [str(x).strip() for x in items
                        if str(x).strip() in ALLOWED_ITEMS]
                args.append('--items=' + ','.join(safe))
            return self._json(run_engine(args))
        finally:
            BUSY.release()

    def _static(self, name):
        p = os.path.normpath(os.path.join(WEB, name))
        if not p.startswith(WEB + os.sep):
            return self._send(404, 'not found', 'text/plain; charset=utf-8')
        try:
            with open(p, 'rb') as f:
                data = f.read()
            ext = os.path.splitext(name)[1]
            return self._send(200, data, MIME.get(ext, 'application/octet-stream'))
        except Exception:
            return self._send(404, 'not found', 'text/plain; charset=utf-8')


def main():
    os.makedirs(os.path.join(VAR, 'log'), exist_ok=True)
    os.makedirs(os.path.join(VAR, 'run'), exist_ok=True)
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    srv.daemon_threads = True
    srv.serve_forever()


if __name__ == '__main__':
    main()
