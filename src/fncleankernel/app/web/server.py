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
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import zipfile
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
        """
        if (self.headers.get('X-Fnclean-Client') or '') != 'web':
            return False, '缺少同源标记（X-Fnclean-Client）'
        sec = (self.headers.get('Sec-Fetch-Site') or '').lower()
        if sec and sec not in ('same-origin', 'none'):
            return False, '跨站请求被拒绝（Sec-Fetch-Site=%s）' % sec
        host = self.headers.get('Host') or ''
        if host and not _trusted_host(host):
            return False, 'Host 不在允许列表'
        origin = self.headers.get('Origin')
        if origin:
            if not _trusted_host(origin):
                return False, 'Origin 不在允许列表'
            if sec != 'same-origin':
                oh = _host_of(origin)
                hh = _host_of(host)
                if oh and hh and oh != hh:
                    return False, 'Origin 与 Host 不一致'
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
            return self._json(dict(error='诊断采集失败', raw=str(D)[:500]), 500)
        buf = io.BytesIO()
        try:
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
                secs = D.get('sections', {})
                # 人可读报告
                lines = ['系统盘清理助手 · 只读诊断报告',
                         '生成时间: ' + str(D.get('time', '-')),
                         '说明: 全部为只读采集，未删除/修改任何系统文件。',
                         '']
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
                for name in ['uname', 'os_version', 'uptime', 'date', 'df',
                             'df_k', 'df_inode', 'usr_top', 'var_top', 'usr_lib_top',
                             'big_files', 'app_big_logs', 'modules_dirs', 'modules_list', 'src_dirs',
                             'boot_files', 'dpkg_kernels', 'apt_hold', 'apt_cache',
                             'bootloader', 'journal_err', 'dmesg_tail', 'syslog_tail']:
                    lines.append('===== %s =====' % name)
                    lines.append(str(secs.get(name, '(空)')))
                    lines.append('')
                if D.get('errors'):
                    lines.append('===== 采集异常 =====')
                    lines.extend(str(x) for x in D['errors'])
                z.writestr('诊断报告.txt', '\n'.join(lines).encode('utf-8'))
                z.writestr('诊断数据.json',
                           json.dumps(D, ensure_ascii=False, indent=2).encode('utf-8'))
        except Exception as ex:
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
            return self._json(dict(status='ERROR', status_text='请求被拒绝',
                                   warnings=[why], log=[],
                                   grub=dict(executed=False)), 403)
        path_only = self.path.split('?')[0]
        if path_only not in ('/api/fix-cron-mail', '/api/clean'):
            return self._send(404, 'not found', 'text/plain; charset=utf-8')
        # S4：所有写操作统一串行锁（原 fix-cron 无锁，与 clean 并发会竞态）
        if not BUSY.acquire(blocking=False):
            return self._json(dict(status='ERROR', status_text='已有任务在执行',
                                   warnings=['请等待上一次任务结束。'],
                                   log=[], grub=dict(executed=False)), 429)
        try:
            data = self._read_body()
            if data is None:
                return self._send(413, 'body too large',
                                  'text/plain; charset=utf-8')
            if path_only == '/api/fix-cron-mail':
                return self._fix_cron_with(data)
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
