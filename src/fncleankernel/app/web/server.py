#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fncleankernel Web 后端：零第三方依赖，复用宿主 Python3。

v1.5.5 安全加固：
  S1 Host 白名单 —— 挡 DNS rebinding（Origin/Host 只互相比较不足以证明可信）
  S2 GET /api/scan 节流 + 独立锁 —— 挡跨站 <img> 触发的重子进程 DoS；支持 ?force=1
  S3 跨站 GET 一律拒绝（Sec-Fetch-Site）—— cron_source / 日志不再被外部网页拉取
  S4 请求体上限 + 连接超时 + 写接口统一串行锁
  保持用户已拍板的基线：默认 0.0.0.0 无认证、不改绑、不加登录。
"""
import io
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(WEB)
ENGINE = os.path.join(APP, 'bin', 'kernel_clean.py')
VAR = os.environ.get('TRIM_PKGVAR') or '/vol1/@appdata/fncleankernel'
STATE = os.path.join(VAR, 'last_result.json')
HISTORY = os.path.join(VAR, 'history.jsonl')
LOGFILE = os.path.join(VAR, 'log', 'clean.log')
# v1.6.0：写接口被拒的结构化访问日志。403 发生在引擎之外，clean.log /
# history.jsonl 都覆盖不到，导致"请求被拒绝"事后无任何痕迹可查。
# 只记录被拒请求（成功的不记，避免噪音）；诊断包只读汇总最近若干条。
ACCESS_LOG = os.path.join(VAR, 'access.jsonl')
ACCESS_LOCK = threading.Lock()
ACCESS_MAX = 200
PORT = int(os.environ.get('SERVICE_PORT') or
           os.environ.get('TRIM_SERVICE_PORT') or 8097)
# 飞牛应用中心 ui/config 是 type:url + protocol:http + port:8097，
# 浏览器直连该端口（实测 80 端口无对应反代路径）。默认保持 0.0.0.0 以免
# 应用打不开；可用 FNCLEAN_BIND=127.0.0.1 切换为仅本机可连（会牺牲直连入口）。
BIND = os.environ.get('FNCLEAN_BIND') or '0.0.0.0'

BUSY = threading.Lock()          # 所有写操作（clean / fix-cron）共用，串行化
SCAN_BUSY = threading.Lock()     # scan 独立锁，避免并发起多个重引擎进程
SCAN_TTL = 20                    # 秒；无 force 的 scan 在窗口内复用上次结果
_SCAN_CACHE = {'at': 0.0, 'data': None}
MAX_BODY = 64 * 1024
CONN_TIMEOUT = 15
MIME = {'.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.png': 'image/png',
        '.json': 'application/json; charset=utf-8'}

# S1：可信主机集合。本机名 / 本机所有 IP / 回环，外加 FNCLEAN_ALLOWED_HOSTS
# 环境变量（逗号分隔，供 DDNS 域名等自定义入口使用）。
_ALLOWED_HOSTS_EXTRA = set(
    x.strip().lower() for x in
    os.environ.get('FNCLEAN_ALLOWED_HOSTS', '').split(',') if x.strip())

# v1.7.2：反向代理 / 办公平台内嵌场景的可信 Origin。
# 场景：页面在 https://office.example.com 下，反代到 NAS 的 http://192.168.x.x:8097，
# 浏览器发出的 Host 是 NAS IP（可信），但 Origin 是入口域名（原本不在白名单，被拒）。
# 由部署者在应用环境变量里显式登记入口域名，多个用逗号分隔，支持精确域名与
# *.example.com 后缀。不默认放行任意域名——否则任何站点都能诱导用户点清理，
# 那才是真的安全漏洞。Host 必须可信这道防线始终保留。
_ALLOWED_ORIGINS_EXTRA = set(
    x.strip().lower() for x in
    os.environ.get('FNCLEAN_ALLOWED_ORIGINS', '').split(',') if x.strip())


# v1.7.2：settings.json 由应用中心「设置」页（wizard/config）写入。
# 用 mtime 检测变化热重载——用户在应用中心点保存后无需重启即生效。
_SETTINGS = {'origins': set(_ALLOWED_ORIGINS_EXTRA), 'mode': '', 'mtime': None}
_SETTINGS_LOCK = threading.Lock()
_SETTINGS_FILE = os.path.join(VAR, 'trusted_origins.txt')
_MODE_FILE = os.path.join(VAR, 'security_mode')


def _reload_settings_if_changed():
    """每次写请求校验时调用：文件 mtime 变了就重载，避免重启应用。"""
    try:
        stamps = []
        for p in (_SETTINGS_FILE, _MODE_FILE):
            try:
                stamps.append(os.path.getmtime(p))
            except OSError:
                stamps.append(None)
        with _SETTINGS_LOCK:
            if stamps == _SETTINGS['mtime']:
                return
            origins = set(_ALLOWED_ORIGINS_EXTRA)   # 环境变量基线始终保留
            try:
                with open(_SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.split('#', 1)[0].strip().lower()
                        if line and '://' not in line:
                            origins.add(line)
            except (IOError, OSError):
                pass
            mode = ''
            try:
                with open(_MODE_FILE, 'r', encoding='utf-8') as f:
                    candidate = f.read().strip().lower()
                if candidate in ('loose', 'strict'):
                    mode = candidate
            except (IOError, OSError):
                pass
            _SETTINGS['origins'] = origins
            _SETTINGS['mode'] = mode
            _SETTINGS['mtime'] = stamps
    except Exception:
        pass    # 配置重载失败绝不影响主请求，按上次的有效配置继续


_reload_settings_if_changed()


def _trusted_origin(value):
    """Origin 可信判定：先走 Host 那套规则，再叠加显式登记的入口域名。"""
    if _trusted_host(value):
        return True
    h = _host_of(value)
    if not h:
        return False
    for entry in _SETTINGS['origins']:
        if entry.startswith('*.') and h.endswith(entry[1:]):
            return True
        if h == entry:
            return True
    return False

# v1.5.8：飞牛官方域名后缀默认可信。FN Connect 远程访问的地址是
# <FN ID>.fnos.net / appXXX.fnos.net（官方帮助中心与论坛实际用法），
# 官方主站/论坛/帮助为 fnnas.com 及其子域。此前 Host 白名单只认本机名/IP，
# 走这些官方域名打开应用页时写接口会被误判为不可信（"Host 不在允许列表"），
# 导致远程场景下一键清理整个失败。这里只额外放行官方后缀的域名：
# 攻击者的 evil.example 之类仍被拒，DNS rebinding 防护（S1）保留。
# 用户自己的 DDNS 域名 continue 可用 FNCLEAN_ALLOWED_HOSTS 环境变量追加。
FNCLEAN_TRUSTED_SUFFIXES = ('fnos.net', 'fnnas.com')


def _under_official_domain(host):
    """host 是否飞牛官方域及其子域（精确后缀边界，防 evilfnos.net 绕过）。"""
    for suf in FNCLEAN_TRUSTED_SUFFIXES:
        if host == suf or host.endswith('.' + suf):
            return True
    return False


def _local_hosts():
    names = {'localhost', '127.0.0.1', '::1', '[::1]'}
    try:
        names.add(socket.gethostname().lower())
    except Exception:
        pass
    try:
        names.add(socket.getfqdn().lower())
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            names.add(info[4][0].split('%')[0].lower())
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        names.add(s.getsockname()[0].lower())
        s.close()
    except Exception:
        pass
    names.update(_ALLOWED_HOSTS_EXTRA)
    return names


LOCAL_HOSTS = _local_hosts()

# 清理项白名单：前端传来的 items 只认这几个，其余静默丢弃
# v1.5.9：补上 app_logs（第三方应用大日志）——v1.5.7 引入该清理项时
# 只改了前端与引擎，漏了这里，导致勾选后被静默丢弃、引擎收到空项报 NO_TARGET。
ALLOWED_ITEMS = {'old_kernel', 'apt_cache', 'syslog_rotated',
                 'log_force_rotate', 'cron_mail', 'mon_residue', 'journal',
                 'app_logs'}

# 静态资源白名单：只放行这几个文件，杜绝目录穿越
STATIC = {
    '/': 'index.html',
    '/index.html': 'index.html',
    '/compat.html': 'compat.html',
    '/style.css': 'style.css',
    '/app.js': 'app.js',
    '/images/wechat-promo.png': 'images/wechat-promo.png',
    '/images/icon_64.png': 'images/icon_64.png',
}


WEB_LOG = os.path.join(VAR, 'log', 'web.log')


def _web_log(kind, detail):
    """v1.7：Web 层异常落盘。此前 web.log 一直是 0 字节，报 500 / 引擎超时
    时查不到任何线索。只记录异常，不记成功请求（避免噪音）。全程 try/except，
    日志失败绝不影响主请求。"""
    try:
        line = '%s  %s  %s' % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                              kind, _redact(str(detail))[:500])
        with open(WEB_LOG, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
        # 简单轮转：超过 2000 行只留后 1000 行
        with open(WEB_LOG, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()
        if len(lines) > 2000:
            with open(WEB_LOG, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines[-1000:]) + '\n')
    except Exception:
        pass


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
            _web_log('ENGINE_PARSE_FAIL',
                     'stderr=%s | stdout=%s' % ((p.stderr or '')[-400:], out[-400:]))
            return dict(status='ERROR', status_text='引擎输出解析失败',
                        warnings=[(p.stderr or '')[-800:], out[-800:]],
                        log=[], grub=dict(executed=False))
    except subprocess.TimeoutExpired:
        _web_log('ENGINE_TIMEOUT', 'args=%s timeout=%s' % (args, timeout))
        return dict(status='ERROR', status_text='执行超时', warnings=['引擎执行超时'],
                    log=[], grub=dict(executed=False))
    except Exception as e:
        _web_log('ENGINE_START_FAIL', repr(e))
        return dict(status='ERROR', status_text='引擎启动失败',
                    warnings=[repr(e)], log=[], grub=dict(executed=False))


def _redact(value):
    """访问日志脱敏：Host/Origin 保留可读域名，但去掉 userinfo 与超长串。"""
    if not value:
        return ''
    v = str(value)
    v = re.sub(r'(://)[^/@]+@', r'\1<已脱敏>@', v)   # URL 里的 user:pass@
    v = re.sub(r'([A-Za-z0-9+/]{40,}={0,2})', '<长串已脱敏>', v)
    return v[:300]


def _log_denied(handler, reason):
    """v1.6.0：记录一条被拒的写请求，供事后排查"为什么点清理没反应"。

    只记录拒绝，不记成功（成功走引擎 clean.log），避免日志噪音。
    字段：时间、方法、路径、Host、Origin、Sec-Fetch-Site、客户端、原因。
    全程 try/except：日志失败绝不影响主请求的处理。"""
    try:
        # v1.6.3：补 UA 与关键头的有无标记——这是判断"是不是 App 内置浏览器"
        # 的决定性证据。此前只有 Host/Origin/Sec，遇到 App 里报"Host 不在允许
        # 列表"时无法区分 Origin 是无、是 null、还是别的，只能猜。
        def has(name):
            return handler.headers.get(name) is not None
        row = dict(
            time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            method=getattr(handler, 'command', ''),
            path=(getattr(handler, 'path', '') or '').split('?')[0],
            host=_redact(handler.headers.get('Host')),
            origin=_redact(handler.headers.get('Origin')),
            sec=(handler.headers.get('Sec-Fetch-Site') or '').lower(),
            client=(getattr(handler, 'client_address', ('', 0)) or [''])[0],
            reason=reason,
            ua=_redact(handler.headers.get('User-Agent')),
            headers_present=dict(
                origin=has('Origin'), sec=has('Sec-Fetch-Site'),
                referer=has('Referer'), custom=has('X-Fnclean-Client')))
        with ACCESS_LOCK:
            os.makedirs(os.path.dirname(ACCESS_LOG), exist_ok=True)
            lines = []
            if os.path.exists(ACCESS_LOG):
                with open(ACCESS_LOG, 'r', encoding='utf-8') as f:
                    lines = f.read().splitlines()[-ACCESS_MAX + 1:]
            lines.append(json.dumps(row, ensure_ascii=False))
            tmp = ACCESS_LOG + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines) + '\n')
            os.replace(tmp, ACCESS_LOG)
    except Exception:
        pass


def _read_access_log(limit=30):
    """读最近的被拒写请求记录（诊断包用），倒序返回，失败返回空。"""
    try:
        with ACCESS_LOCK:
            if not os.path.exists(ACCESS_LOG):
                return []
            with open(ACCESS_LOG, 'r', encoding='utf-8') as f:
                rows = [json.loads(x) for x in f.read().splitlines() if x.strip()]
        return rows[-limit:][::-1]
    except Exception:
        return []


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


def _trusted_host(value):
    """S1：Host/Origin 必须是本机名、本机 IP、回环，或显式配置的域名。

    DNS rebinding 让 evil.example 解析到 NAS 内网 IP，浏览器发出的
    Origin/Host 都是 evil.example —— 只比较两者相等会放行；这里改为
    与「可信集合」比对。IP 字面量一律放行（避免枚举不到多网卡地址时
    误挡正常入口），带名称的主机必须在集合内。"""
    h = _host_of(value)
    if not h:
        return True
    if h in LOCAL_HOSTS:
        return True
    try:
        ipaddress.ip_address(h)      # IP 字面量：放行
        return True
    except ValueError:
        pass
    if _under_official_domain(h):    # v1.5.8：飞牛官方域名（FN Connect 等）
        return True
    return False


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        # S4：每条连接设超时，Slowloris 变体无法长期占住线程
        try:
            self.connection.settimeout(CONN_TIMEOUT)
        except Exception:
            pass
        BaseHTTPRequestHandler.setup(self)

    def log_message(self, fmt, *args):
        return

    def _write_allowed(self):
        """写接口校验（纵深防御，不依赖 Host/Origin 严格相等以兼容各种入口）。

        1) 自定义头：跨站 <form> 无法携带；跨站 fetch 带自定义头会先发 CORS
           预检，本服务未实现 OPTIONS，浏览器不会发出实际请求。
        2) Sec-Fetch-Site：浏览器明确标记跨站时直接拒绝。
        3) Host / Origin 与可信主机集合比对（S1，挡 DNS rebinding）。

        v1.6.0：任何拒绝都写一条 access.jsonl，事后可从诊断包看到
        "谁在何时用什么 Host/Origin 撞了哪条规则"，解决被拒无痕迹的问题。
        """
        ok, why = self._write_check()
        if not ok:
            _log_denied(self, why)
        return ok, why

    def _write_check(self):
        _reload_settings_if_changed()
        if (self.headers.get('X-Fnclean-Client') or '') != 'web':
            return False, '缺少同源标记（X-Fnclean-Client）'
        sec = (self.headers.get('Sec-Fetch-Site') or '').lower()
        if sec and sec not in ('same-origin', 'none'):
            return False, '跨站请求被拒绝（Sec-Fetch-Site=%s）' % sec

        origin = (self.headers.get('Origin') or '').strip().lower()
        host = self.headers.get('Host') or ''
        app_context = (not origin) or (origin == 'null')
        oh = _host_of(origin) if origin and origin != 'null' else ''
        hh = _host_of(host)
        # same_origin：浏览器直接访问 NAS（IP / DDNS / FN Connect / 本机名），
        # Host 与 Origin 指向同一个域。这是绝大多数正常入口。
        same_origin = bool(oh and hh and oh == hh)
        # 严格模式：FNCLEAN_STRICT_ORIGIN=1 时恢复「所有域名都要登记」的旧行为。
        # 普通用户不必开——代价是自建 DDNS 也要手工登记。
        strict = (os.environ.get('FNCLEAN_STRICT_ORIGIN') == '1' or
                  _SETTINGS['mode'] == 'strict')

        # v1.7.2：默认放行「同源且 Host 是 IP 字面量」的直连请求（局域网 / DDNS
        # 解析到 IP 后直连的常见入口，零配置）。带名称的域名（无论是否同源）
        # 仍走可信判定——因为 DNS rebinding 攻击恰好也是「Host==Origin」（两者
        # 都是 evil.example），只看同源会把它一起放行，这是真实漏洞。
        #
        # 入口分类：
        # - 本机 IP / 回环 / IP 字面量：一律可信（直连）
        # - FN Connect 官方域 / 已登记域名：可信
        # - 自建 DDNS 域名：需在 trusted_origins.txt 登记（或开宽松模式）
        # - 反代场景 Host≠Origin：Origin 必须登记
        #
        # 宽松模式 FNCLEAN_LOOSE_ORIGIN=1：放宽到「同源即放行」，覆盖自建 DDNS
        # 零配置，但放弃 rebinding 防护——只在可信网络环境下使用。
        loose = (os.environ.get('FNCLEAN_LOOSE_ORIGIN') == '1' or
                 _SETTINGS['mode'] == 'loose')

        if origin and origin != 'null':
            origin_ok = _trusted_origin(origin)
            if loose and same_origin:
                origin_ok = True   # 宽松模式：同源即放行，放弃 rebinding 防护
            if not origin_ok:
                return False, 'Origin 不在允许列表（严格模式）' if strict \
                              else 'Origin 不在允许列表'

        if not app_context and host and not _trusted_host(host):
            # 走到这：Host 带名称且不在白名单。只有宽松模式 + 同源才放行。
            if not (loose and same_origin):
                return False, 'Host 不在允许列表'
        return True, ''

    def _get_allowed(self):
        """S3：跨站 GET 一律拒绝。

        <img src="http://NAS:8097/api/scan"> 会带 Sec-Fetch-Site: cross-site，
        据此挡掉外部网页对 /api/scan、/api/log、cron_source 的探测与副作用。
        本机脚本 / curl 不发送该头，仍按已接受的「直连无认证」基线放行。"""
        sec = (self.headers.get('Sec-Fetch-Site') or '').lower()
        if sec and sec not in ('same-origin', 'none', 'same-site'):
            return False, '跨站 GET 被拒绝（Sec-Fetch-Site=%s）' % sec
        return True, ''

    def _read_body(self):
        """S4：请求体上限，超限返回 None（调用方回 413）。"""
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except Exception:
            return {}
        if n < 0 or n > MAX_BODY:
            return None
        try:
            raw = self.rfile.read(n).decode('utf-8', 'replace') if n > 0 else ''
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    def _send(self, code, body, ctype='application/json; charset=utf-8'):
        data = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def do_GET(self):
        ok, why = self._get_allowed()
        if not ok:
            return self._json(dict(status='ERROR', status_text='请求被拒绝',
                                   warnings=[why], log=[],
                                   grub=dict(executed=False)), 403)
        path_only = self.path.split('?')[0]
        if path_only in STATIC:
            return self._static(STATIC[path_only])
        if path_only == '/api/scan':
            return self._scan()
        if path_only == '/api/last':
            try:
                with open(STATE, 'r', encoding='utf-8') as f:
                    return self._json(json.load(f))
            except Exception:
                return self._json(dict(status='SCAN', status_text='尚无执行记录',
                                       notes=['点击「扫描」查看当前内核状态。'],
                                       kernels=[], warnings=[], log=[]))
        if path_only == '/api/health':
            return self._json(dict(ok=True, app='fncleankernel', port=PORT))
        if path_only == '/api/selfcheck':
            # v1.7 F1：只读安全自检，独立于 scan 缓存，每次真跑
            if not SCAN_BUSY.acquire(blocking=False):
                return self._json(dict(ok=False, mode='selfcheck',
                                       verdict='忙：请等上一次扫描/自检结束',
                                       checks=[]), 429)
            try:
                return self._json(run_engine(['--selfcheck'], timeout=180))
            finally:
                SCAN_BUSY.release()
        if path_only == '/api/diagnose':
            return self._diagnose_zip()
        if path_only == '/api/log':
            try:
                with open(LOGFILE, 'r', encoding='utf-8', errors='replace') as f:
                    return self._json(dict(log=f.read()[-30000:]))
            except Exception:
                return self._json(dict(log=''))
        if path_only == '/api/history':
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

    def _diagnose_zip(self):
        """只读诊断采集 → 内存 zip 下载。不清理、不改系统。

        zip 内含人可读的 诊断报告.txt（按分区逐节）和原始 诊断数据.json，
        用户在飞牛网页点「导出诊断包」即可下载，发给作者排查。
        诊断本身可能较慢（du/dmesg/journalctl），最长 5 分钟。"""
        D = run_engine(['--diagnose'], timeout=300)
        if not isinstance(D, dict) or 'sections' not in D:
            _web_log('DIAGNOSE_FAIL', str(D)[:500])
            return self._json(dict(error='诊断采集失败', raw=str(D)[:500]), 500)
        # v1.6.0：把 Web 层记录的"被拒写请求"并入诊断，事后可查
        # "谁在何时用什么 Host/Origin 被哪条规则挡下"。引擎看不到这些 403。
        access_rows = _read_access_log(limit=30)
        D['access_log'] = access_rows
        buf = io.BytesIO()
        try:
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
                secs = D.get('sections', {})
                # 人可读报告
                lines = ['系统盘清理助手 · 只读诊断报告',
                         '生成时间: ' + str(D.get('time', '-')),
                         '说明: 全部为只读采集，未删除/修改任何系统文件。',
                         '']
                # v1.7 P1-3：采集异常显式置顶，避免藏在报告末尾被忽略
                if D.get('errors'):
                    lines.append('⚠ 采集异常 %d 项（详见报告末尾「采集异常」节）：' %
                                 len(D['errors']))
                    lines.extend('  · ' + str(x) for x in D['errors'])
                    lines.append('')
                # v1.6.4：头部直接给出设备身份，不再需要从 uname 猜机型
                dev = D.get('device') or {}
                if dev:
                    lines.append('===== 设备身份 =====')
                    lines.append('机型: %s（ID: %s）' %
                                 (dev.get('model_name') or '-',
                                  dev.get('model_id') or '-'))
                    lines.append('SoC: %s ｜ 架构: %s ｜ 飞牛版本: %s ｜ 内核: %s' %
                                 (dev.get('soc') or '-', dev.get('arch') or '-',
                                  dev.get('fnos') or '-', dev.get('kernel') or '-'))
                    lines.append('hostname: %s ｜ compatible: %s' %
                                 (dev.get('hostname') or '-',
                                  ', '.join(dev.get('compat_items') or []) or '-'))
                    lines.append('')
                wild = D.get('wild_kernel_dirs') or []
                lines.append('===== 关键结论 =====')
                lines.append('当前运行内核: ' + str(D.get('current_kernel', '-')))
                lines.append('dpkg 登记的内核版本: ' +
                             ', '.join(D.get('dpkg_kernel_versions') or []) or '(无)')
                lines.append('疑似野生内核目录(dpkg 未登记且非当前): ' +
                             (', '.join(wild) if wild else '无'))
                al = D.get('app_logs') or {}
                if al.get('count'):
                    lines.append('第三方应用大日志: %d 个合计 %s' %
                                 (al['count'],
                                  '%.0f MB' % (al.get('bytes', 0) / 1048576.0)))
                    for f in al.get('files', [])[:10]:
                        lines.append('  · %s  %s' % (f.get('size_str', ''),
                                                     f.get('path', '')))
                lines.append('')
                # 被拒写请求历史：排查"点了清理没反应"的关键证据
                lines.append('===== 被拒写请求记录（最近 %d 条）=====' % len(access_rows))
                if access_rows:
                    for r in access_rows:
                        lines.append('%s | %s %s | Host=%s | Origin=%s | '
                                     'Sec-Fetch-Site=%s | 来自=%s | 原因=%s' % (
                                         r.get('time', '-'), r.get('method', ''),
                                         r.get('path', ''), r.get('host', '') or '-',
                                         r.get('origin', '') or '-',
                                         r.get('sec', '') or '-',
                                         r.get('client', '') or '-',
                                         r.get('reason', '')))
                        hp = r.get('headers_present') or {}
                        lines.append('    头携带: Origin=%s Sec=%s Referer=%s 自定义=%s | UA=%s' % (
                            hp.get('origin', '?'), hp.get('sec', '?'),
                            hp.get('referer', '?'), hp.get('custom', '?'),
                            r.get('ua', '') or '-'))
                else:
                    lines.append('(无记录 — 没有写请求被安全规则拦下)')
                lines.append('')
                for name in ['uname', 'os_version', 'uptime', 'date', 'df',
                             'df_k', 'df_inode', 'usr_top', 'var_top', 'usr_lib_top',
                             'big_files', 'app_big_logs', 'modules_dirs', 'modules_list', 'src_dirs',
                             'boot_files', 'dpkg_kernels', 'apt_hold', 'apt_cache',
                             'bootloader', 'journal_err', 'dmesg_tail', 'syslog_tail',
                             'journal_err_7d', 'journal_warn_7d', 'journal_7d_count',
                             'syslog_7d_keywords', 'lscpu', 'meminfo', 'zram_swap',
                             'thermal', 'cpu_freq', 'storage_devices', 'mmc_info',
                             'network', 'gpu_npu_nodes', 'loadavg_procs', 'time_sync']:
                    if name == 'journal_err_7d':
                        # v1.7 P1-2：明确告知截断，避免作者误以为"没错误"
                        total = (secs.get('journal_7d_count') or '').strip()
                        lines.append('===== 7 天日志说明 =====')
                        lines.append('7 天日志总行数: %s 行；'
                                     '下列错误/警告段各只取最近 300/150 行，'
                                     '并非全量——若错误集中在更早时间，本包不含。'
                                     % (total or '未知'))
                        lines.append('')
                    lines.append('===== %s =====' % name)
                    lines.append(str(secs.get(name, '(空)')))
                    lines.append('')
                # v1.7 P0：工具自身运行痕迹也写进人可读报告
                for key in ('tool_info', 'tool_clean_log', 'tool_web_log',
                            'tool_last_result', 'tool_history'):
                    v = D.get(key)
                    if v is not None:
                        lines.append('===== %s =====' % key)
                        lines.append(str(v))
                        lines.append('')
                if D.get('errors'):
                    lines.append('===== 采集异常 =====')
                    lines.extend(str(x) for x in D['errors'])
                z.writestr('诊断报告.txt', '\n'.join(lines).encode('utf-8'))
                z.writestr('诊断数据.json',
                           json.dumps(D, ensure_ascii=False, indent=2).encode('utf-8'))
        except Exception as ex:
            _web_log('ZIP_FAIL', repr(ex))
            return self._json(dict(error='打包失败', detail=repr(ex)), 500)
        data = buf.getvalue()
        # 固定文件名，避免中文/时间导致部分浏览器下载异常
        fname = 'fncleankernel-diagnose.zip'
        self.send_response(200)
        self.send_header('Content-Type', 'application/zip')
        self.send_header('Content-Disposition', 'attachment; filename="%s"' % fname)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _scan(self):
        """S2：节流 + 独立锁。?force=1 穿透节流并让引擎强制重算 du 缓存。"""
        query = urllib.parse.urlsplit(self.path).query
        force = any(p.split('=', 1)[0] == 'force' for p in query.split('&') if p)
        now = time.time()
        if (not force and _SCAN_CACHE['data'] is not None and
                now - _SCAN_CACHE['at'] < SCAN_TTL):
            return self._json(_SCAN_CACHE['data'])
        if not SCAN_BUSY.acquire(blocking=False):
            if _SCAN_CACHE['data'] is not None:
                return self._json(_SCAN_CACHE['data'])
            return self._json(dict(status='ERROR', status_text='扫描进行中',
                                   warnings=['请稍候重试。'], log=[],
                                   grub=dict(executed=False)), 429)
        try:
            args = ['--scan', '--force'] if force else ['--scan']
            R = run_engine(args, timeout=180)
            _SCAN_CACHE['at'] = time.time()
            _SCAN_CACHE['data'] = R
            return self._json(R)
        finally:
            SCAN_BUSY.release()

    def _fix_cron_with(self, data):
        """堵 cron 邮件源头。只有 confirm=true 才会真正改 crontab。"""
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
            # v1.6.3：拒绝原因后附 Host/Origin 实值（脱敏），用户直接截图即可
            # 提供排障证据，不必再导出诊断包——之前有用户只发截图没诊断包，
            # 导致只能猜是哪个来源字段被拒。
            diag = 'Host=%s；Origin=%s' % (
                _redact(self.headers.get('Host')) or '(未发送)',
                _redact(self.headers.get('Origin')) or '(未发送)')
            return self._json(dict(status='ERROR', status_text='请求被拒绝',
                                   warnings=[why, '诊断信息：' + diag], log=[],
                                   grub=dict(executed=False)), 403)
        path_only = self.path.split('?')[0]
        if path_only not in ('/api/fix-cron-mail', '/api/clean'):
            return self._send(404, 'not found', 'text/plain; charset=utf-8')
        # S4：所有写操作统一串行锁（原 fix-cron 无锁，与 clean 并发会竞态）
        if not BUSY.acquire(blocking=False):
            _log_denied(self, '已有任务在执行（并发写被拒）')
            return self._json(dict(status='ERROR', status_text='已有任务在执行',
                                   warnings=['请等待上一次任务结束。'],
                                   log=[], grub=dict(executed=False)), 429)
        try:
            data = self._read_body()
            if data is None:
                _log_denied(self, '请求体过大')
                return self._send(413, 'body too large',
                                  'text/plain; charset=utf-8')
            if path_only == '/api/fix-cron-mail':
                return self._fix_cron_with(data)
            if data.get('confirm') is not True:
                _log_denied(self, '缺少执行确认')
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
