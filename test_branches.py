# -*- coding: utf-8 -*-
"""
fncleankernel 错误分支单元测试（进程内 monkeypatch，不改动系统）
逐项验证：状态分类、提示文案、以及「无论清理结果如何都执行 update-grub」铁律。
"""
import importlib.util
import json
import os
import sys

APP = '/vol1/@appcenter/fncleankernel'
spec = importlib.util.spec_from_file_location('kc', APP + '/bin/kernel_clean.py')
kc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kc)

# 隔离状态文件，避免污染真实 last_result.json
kc.VAR = '/vol1/face_mon/fpk_build/testvar'
kc.LOGDIR = kc.VAR + '/log'
kc.STATE = kc.VAR + '/last_result.json'
kc.LOGFILE = kc.LOGDIR + '/clean.log'
os.makedirs(kc.LOGDIR, exist_ok=True)

CUR = '6.18.18.c1196-trim'
CUR_PKG = 'linux-image-' + CUR
OLD = '6.18.18.c1145-trim'
OLD_PKG = 'linux-image-' + OLD


def collect(**over):
    d = dict(
        cur=CUR, cur_pkg=CUR_PKG, latest_pkg=CUR_PKG,
        keep_pkgs=[CUR_PKG], keep_versions=[CUR], meta=['linux-image-arm64'],
        candidates=[OLD_PKG],
        purge=[OLD_PKG, 'linux-headers-' + OLD],
        rows=[], hold_installed=[OLD_PKG], hold_to_unlock=[OLD_PKG],
        selections={OLD_PKG: 'hold', CUR_PKG: 'install'},
        imgs={CUR_PKG: {}, OLD_PKG: {}}, hdrs={}, mods={},
        extra_packages=['linux-headers-' + OLD])
    d.update(over)
    return d


def boot(**over):
    d = dict(real='u-boot + extlinux', detail='', boot_kernel='vmlinuz-' + CUR,
             boot_kernel_path='/boot/vmlinuz-' + CUR, boot_kernel_ok=True,
             boot_version=CUR, boot_version_parsed=True, boot_on_old=False,
             grub_cfg=True, update_grub='/usr/sbin/update-grub')
    d.update(over)
    return d


def fake_sh_factory(sim_rc=0, sim_out=None, unhold_rc=0, purge_rc=0):
    if sim_out is None:
        sim_out = ('Reading package lists...\nPurg %s [%s]\n'
                   'Purg linux-headers-%s [%s]\n' % (OLD_PKG, OLD, OLD, OLD))

    def _sh(cmd, timeout=600):
        c = cmd if isinstance(cmd, str) else ' '.join(cmd)
        if 'apt-get -s purge' in c:
            return sim_rc, sim_out, ''
        if 'apt-mark unhold' in c:
            return unhold_rc, '', '' if unhold_rc == 0 else 'E: hold'
        if 'apt-get purge -y' in c:
            return purge_rc, 'removed', '' if purge_rc == 0 else 'E: purge failed'
        if 'apt-mark hold' in c:
            return 0, '', ''
        return 0, '', ''
    return _sh


def setup(case):
    """返回 (kwargs, expected_status, expect_warning_substr, grub_rc)"""
    kw = dict(sim_rc=0, unhold_rc=0, purge_rc=0,
              collect_over={}, boot_over={}, ssh_ok=True,
              avail_kb=1600000, grub_rc=0)
    exp = 'OK'
    warn = None
    if case == 'NO_OLD_KERNEL':
        kw['collect_over'] = dict(candidates=[], purge=[], hold_installed=[],
                                  hold_to_unlock=[], extra_packages=[])
        exp = 'NO_OLD_KERNEL'
    elif case == 'HOLD_UNLOCK_FAILED':
        kw['unhold_rc'] = 1
        exp = 'HOLD_UNLOCK_FAILED'
        warn = '解锁失败'
    elif case == 'UNSAFE_PLAN_SIM':
        kw['sim_out'] = ('Purg %s [%s]\nPurg %s [%s]\n'
                         % (OLD_PKG, OLD, CUR_PKG, CUR))
        exp = 'UNSAFE_PLAN'
        warn = '预演将删除保留包'
    elif case == 'UNSAFE_PLAN_BOOT':
        kw['boot_over'] = dict(boot_on_old=True, boot_version=OLD)
        exp = 'UNSAFE_PLAN'
        warn = '实际引导'
    elif case == 'UNSAFE_PLAN_NOBOOT':
        kw['boot_over'] = dict(boot_kernel_ok=False)
        exp = 'UNSAFE_PLAN'
        warn = '内核文件不存在'
    elif case == 'PURGE_FAILED':
        kw['purge_rc'] = 100
        exp = 'PURGE_FAILED'
        warn = 'PURGE_FAILED'
    elif case == 'GRUB_FAILED':
        kw['grub_rc'] = 1
        exp = 'GRUB_FAILED'
        warn = 'GRUB_FAILED'
    elif case == 'LOW_SPACE':
        kw['avail_kb'] = 300 * 1024
        exp = 'OK'
        warn = 'LOW_SPACE'
    elif case == 'SSH_DISABLED':
        kw['ssh_ok'] = False
        exp = 'OK'
        warn = 'SSH_DISABLED'
    elif case == 'ENGINE_EXCEPTION':
        exp = 'ERROR'
    return kw, exp, warn


CASES = ['OK', 'NO_OLD_KERNEL', 'HOLD_UNLOCK_FAILED', 'UNSAFE_PLAN_SIM',
         'UNSAFE_PLAN_BOOT', 'UNSAFE_PLAN_NOBOOT', 'PURGE_FAILED',
         'GRUB_FAILED', 'LOW_SPACE', 'SSH_DISABLED', 'ENGINE_EXCEPTION']


def run_case(case):
    kw, exp, warn = setup(case)
    kc.collect = (lambda: (_ for _ in ()).throw(RuntimeError('inject'))) \
        if case == 'ENGINE_EXCEPTION' else (lambda: collect(**kw['collect_over']))
    kc.host_info = lambda: dict(hostname='TEST', kernel=CUR, arch='arm64',
                                fnos='1.2.1000', soc='rk3566', board='')
    kc.ssh_info = lambda: dict(active=kw['ssh_ok'], enabled=kw['ssh_ok'],
                               port22=kw['ssh_ok'], ok=kw['ssh_ok'],
                               hint='' if kw['ssh_ok'] else
                               'SSH 未开启：请手动开启 SSH。')
    kc.bootloader_info = lambda kv: boot(**kw['boot_over'])
    kc.avail_kb = lambda p: kw['avail_kb']
    kc.sh = fake_sh_factory(kw['sim_rc'], None if kw['sim_rc'] == 0 and
                            case != 'UNSAFE_PLAN_SIM' else
                            ('Purg %s [%s]\nPurg %s [%s]\n'
                             % (OLD_PKG, OLD, CUR_PKG, CUR)),
                            kw['unhold_rc'], kw['purge_rc'])
    kc.selections = lambda: collect(**kw['collect_over'])['selections']
    kc.dpkg_installed = lambda p: {}
    kc.run_update_grub = lambda: (kw['grub_rc'], 'fake grub ok' if
                                  kw['grub_rc'] == 0 else 'grub: fatal')
    R = kc.do_clean(dry=False)
    wtext = ' | '.join(R.get('warnings', []))
    ok_status = (R['status'] == exp)
    ok_warn = (warn is None) or (warn in wtext)
    ok_grub = (R['grub']['executed'] is True and
               R['grub']['rc'] == kw['grub_rc'])
    return dict(case=case, status=R['status'], expect=exp,
                status_ok=ok_status, warn_ok=ok_warn,
                grub_executed=R['grub']['executed'], grub_rc=R['grub']['rc'],
                grub_ok=ok_grub,
                warnings=R.get('warnings', [])[:3])


def cache_only_check():
    """缓存-only 路径：不勾 old_kernel 时必须跳过 update-grub。"""
    kc.collect = lambda: collect(candidates=[], purge=[], hold_installed=[],
                                  hold_to_unlock=[], extra_packages=[])
    kc.host_info = lambda: dict(hostname='TEST', kernel=CUR, arch='arm64',
                                fnos='1.2.1000', soc='rk3566', board='',
                                model_name='', model_id='', compat_items=[])
    kc.ssh_info = lambda: dict(active=True, enabled=True, port22=True,
                               ok=True, hint='')
    kc.bootloader_info = lambda kv: boot()
    kc.avail_kb = lambda p: 1600000
    kc.cache_scan = lambda: [dict(
        id='apt_cache', name='apt 缓存', desc='测试用', bytes=1024,
        size_str='1.0 KB', label='可回收', count=1, available=True,
        actionable=True, risk='low', default=True)]
    kc.cache_clean = lambda R, ids: None
    kc.sh = fake_sh_factory()
    kc.run_update_grub = lambda: (0, 'SHOULD_NOT_RUN_FOR_CACHE_ONLY')
    kc.selections = lambda: {}
    kc.dpkg_installed = lambda p: {}
    R = kc.do_clean(dry=False, items=['apt_cache'])
    return dict(status=R['status'], executed=R['grub']['executed'],
                rc=R['grub']['rc'], note=R['grub'].get('note', ''))


def _common_mocks():
    """新场景共用的基线 mock。"""
    kc.collect = lambda: collect()
    kc.host_info = lambda: dict(hostname='TEST', kernel=CUR, arch='arm64',
                                fnos='1.2.1000', soc='rk3566', board='',
                                model_name='', model_id='', compat_items=[])
    kc.ssh_info = lambda: dict(active=True, enabled=True, port22=True,
                               ok=True, hint='')
    kc.bootloader_info = lambda kv: boot()
    kc.avail_kb = lambda p: 1600000
    kc.run_update_grub = lambda: (0, 'ok')
    kc.selections = lambda: {}
    kc.dpkg_installed = lambda p: {}


def e1_partial_unhold_check():
    """E1：多包解锁时部分失败，已成功的包必须被恢复 hold（不留半解锁）。"""
    hdr_old = 'linux-headers-' + OLD
    _common_mocks()
    # 两个待解锁包：image 成功、headers 失败
    kc.collect = lambda: collect(
        hold_installed=[OLD_PKG], hold_to_unlock=[OLD_PKG, hdr_old],
        purge=[OLD_PKG, hdr_old], extra_packages=[hdr_old])
    def sh_unhold(cmd, timeout=600):
        c = cmd if isinstance(cmd, str) else ' '.join(cmd)
        if 'apt-get -s purge' in c:
            return 0, ('Purg %s [%s]\nPurg %s [%s]\n'
                       % (OLD_PKG, OLD, hdr_old, OLD)), ''
        if 'apt-mark unhold' in c:
            return (1, '', 'E: hold busy') if hdr_old in c else (0, '', '')
        if 'apt-mark hold' in c:
            return 0, '', ''
        return 0, '', ''
    kc.sh = sh_unhold
    R = kc.do_clean(dry=False)
    restored = R['hold'].get('restored', [])
    return dict(status=R['status'], unlocked=R['hold'].get('unlocked', []),
                restored=restored,
                ok=(R['status'] == 'HOLD_UNLOCK_FAILED' and
                    OLD_PKG in R['hold'].get('unlocked', []) and
                    OLD_PKG in restored))


def e2_sim_unparseable_check():
    """E2：有待清理包但预演解析不出计划 → fail-closed，不裸奔 purge。"""
    _common_mocks()
    purged = []
    def sh_noparse(cmd, timeout=600):
        c = cmd if isinstance(cmd, str) else ' '.join(cmd)
        if 'apt-get -s purge' in c:
            return 0, 'some unrecognized output\n', ''
        if 'apt-get purge -y' in c:
            purged.append(c)
            return 0, 'removed', ''
        if 'apt-mark unhold' in c or 'apt-mark hold' in c:
            return 0, '', ''
        return 0, '', ''
    kc.sh = sh_noparse
    R = kc.do_clean(dry=False)
    return dict(status=R['status'], purge_called=len(purged),
                ok=(R['status'] == 'UNSAFE_PLAN' and not purged))


def e2_surprise_kernel_pkg_check():
    """E2：预演出现计划外的内核/引导包 → 正向白名单拦下。"""
    _common_mocks()
    purged = []
    def sh_surprise(cmd, timeout=600):
        c = cmd if isinstance(cmd, str) else ' '.join(cmd)
        if 'apt-get -s purge' in c:
            return 0, ('Purg %s [%s]\nPurg u-boot-tools [%s]\n'
                       % (OLD_PKG, OLD, OLD)), ''
        if 'apt-get purge -y' in c:
            purged.append(c)
            return 0, 'removed', ''
        if 'apt-mark unhold' in c or 'apt-mark hold' in c:
            return 0, '', ''
        return 0, '', ''
    kc.sh = sh_surprise
    R = kc.do_clean(dry=False)
    return dict(status=R['status'], purge_called=len(purged),
                ok=(R['status'] == 'UNSAFE_PLAN' and not purged))


def e4_phase_status_check():
    """E4：GRUB 失败时保留内核阶段原始状态，不丢失部分成功信息。"""
    _common_mocks()
    kc.run_update_grub = lambda: (1, 'grub: fatal')
    kc.sh = fake_sh_factory()  # 内核阶段 OK
    R = kc.do_clean(dry=False)
    return dict(status=R['status'], phase=R.get('kernel_phase_status', ''),
                ok=(R['status'] == 'GRUB_FAILED' and
                    R.get('kernel_phase_status') == 'OK'))


def ssh_port_check():
    """v1.6.3：SSH 服务 active 但端口非 22 时不应误报未开启。"""
    def fake_sh(argv, timeout=30):
        cmd = ' '.join(argv)
        if 'is-active' in cmd:
            return 0, 'active\n', ''
        if 'is-enabled' in cmd:
            return 0, 'enabled\n', ''
        if 'ss' in cmd and '-tln' in cmd:
            # 模拟 SSH 改到 2222 端口，没有 22
            return 0, ('State  Recv-Q Send-Q Local Address:Port\n'
                       'LISTEN 0 128 0.0.0.0:2222\n'
                       'LISTEN 0 128 127.0.0.1:8097\n'), ''
        return 0, '', ''
    old = kc.sh
    kc.sh = fake_sh
    try:
        info = kc.ssh_info()
        ok = (info.get('ok') is True and info.get('active') is True and
              info.get('enabled') is True and '2222' in info.get('ports', []))
        return dict(ok=ok, info=info)
    finally:
        kc.sh = old


def app_host_check():
    """v1.6.3：App WebView 私有 Host（null/无 Origin）放行，恶意 Origin 仍拒。"""
    spec2 = importlib.util.spec_from_file_location('kcweb_ah', APP + '/web/server.py')
    srv = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(srv)

    class FakeHandler:
        def __init__(self, host, origin, sec='same-origin', client='web'):
            self.headers = {'Host': host, 'X-Fnclean-Client': client}
            if origin is not None:
                self.headers['Origin'] = origin
            if sec is not None:
                self.headers['Sec-Fetch-Site'] = sec
            self.command = 'POST'
            self.path = '/api/clean'
            self.client_address = ('127.0.0.1', 0)

    def check(host, origin, sec='same-origin', client='web'):
        return srv.Handler._write_check(FakeHandler(host, origin, sec, client))

    allow = [
        check('some-app-internal', 'null'),
        check('some-app-internal', None),
        check('192.168.3.17:8097', 'https://192.168.3.17:8097'),
    ]
    deny = [
        check('evil.example', 'https://evil.example'),
        check('app123.fnos.net', 'https://evil.example'),
        check('192.168.3.17:8097', 'https://evil.example', 'cross-site'),
        check('192.168.3.17:8097', None, client='bad'),
    ]
    ok = all(x[0] for x in allow) and all(not x[0] for x in deny)
    return dict(ok=ok, allow=[x[1] for x in allow], deny=[x[1] for x in deny])


def webview_origin_check():
    """v1.6.1：Android WebView 的 Origin:null 放行，攻击域名仍拒。"""
    import threading
    import urllib.request
    import urllib.error
    import tempfile
    from http.server import ThreadingHTTPServer

    spec2 = importlib.util.spec_from_file_location('kcweb_wv', APP + '/web/server.py')
    srv = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(srv)
    srv.VAR = tempfile.mkdtemp(prefix='webview_')
    srv.ACCESS_LOG = srv.VAR + '/access.jsonl'
    captured = {}

    def fake(args, timeout=180):
        captured['args'] = args
        return dict(status='CACHE_ONLY', status_text='ok', log=[], warnings=[])

    srv.run_engine = fake
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), srv.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def post(origin):
        body = json.dumps({'items': ['apt_cache'], 'confirm': True}).encode()
        h = {'Content-Type': 'application/json', 'X-Fnclean-Client': 'web',
             'Sec-Fetch-Site': 'same-origin'}
        if origin is not None:
            h['Origin'] = origin
        req = urllib.request.Request('http://127.0.0.1:%d/api/clean' % port,
                                     data=body, method='POST', headers=h)
        try:
            return urllib.request.urlopen(req, timeout=8).status
        except urllib.error.HTTPError as e:
            return e.code

    try:
        # WebView: Origin null -> 越过来源校验，因 test 带 confirm 会走到引擎
        captured.clear()
        code_null = post('null')
        ok_null = (code_null == 200 and
                   captured.get('args') == ['--clean', '--items=apt_cache'])
        # 攻击域名仍拒
        captured.clear()
        code_evil = post('https://evil.example')
        ok_evil = (code_evil == 403 and not captured.get('args'))
        # 官方域名仍放行
        captured.clear()
        code_official = post('https://app123.fnos.net')
        ok_official = (code_official == 200 and bool(captured.get('args')))
        # 无 Origin（curl 基线）仍放行
        captured.clear()
        code_none = post(None)
        ok_none = (code_none == 200 and bool(captured.get('args')))
        return dict(ok=all([ok_null, ok_evil, ok_official, ok_none]),
                    null=ok_null, evil=ok_evil, official=ok_official, none=ok_none)
    finally:
        httpd.shutdown()


def access_log_check():
    """v1.6.0：写请求被拒时记录 access.jsonl，字段完整 + 脱敏。"""
    import threading
    import urllib.request
    import urllib.error
    import tempfile
    from http.server import ThreadingHTTPServer

    spec2 = importlib.util.spec_from_file_location('kcweb_al', APP + '/web/server.py')
    srv = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(srv)
    # 隔离到临时目录
    srv.VAR = tempfile.mkdtemp(prefix='accesslog_')
    srv.ACCESS_LOG = srv.VAR + '/access.jsonl'

    httpd = ThreadingHTTPServer(('127.0.0.1', 0), srv.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        body = json.dumps({'items': ['apt_cache'], 'confirm': True}).encode()
        req = urllib.request.Request(
            'http://127.0.0.1:%d/api/clean' % port, data=body, method='POST',
            headers={'Content-Type': 'application/json',
                     'X-Fnclean-Client': 'web',
                     'Host': 'evil.example',
                     'Origin': 'https://evil.example',
                     'Sec-Fetch-Site': 'same-origin'})
        try:
            urllib.request.urlopen(req, timeout=8)
        except urllib.error.HTTPError:
            pass
        rows = srv._read_access_log(limit=5)
        ok = bool(rows)
        if rows:
            r = rows[0]
            ok = ok and r.get('reason') in ('Host 不在允许列表', 'Origin 不在允许列表')
            ok = ok and r.get('host') == 'evil.example'
            ok = ok and r.get('origin') == 'https://evil.example'
            ok = ok and r.get('path') == '/api/clean'
            ok = ok and bool(r.get('time')) and bool(r.get('client'))
        return dict(ok=ok, rows=len(rows), sample=rows[0] if rows else {})
    finally:
        httpd.shutdown()


def app_logs_e2e_check():
    """v1.5.9 全链路：HTTP POST app_logs 经白名单后必须透传到引擎参数。

    覆盖上版盲区：app_log_safety_check 直接调引擎函数，绕过了 server.py 的
    ALLOWED_ITEMS 过滤；这里 mock run_engine 捕获真实 args，确保 app_logs
    从前端 POST 一路到引擎不被静默丢弃。mock 掉引擎，不触发真实清理。"""
    import threading
    import urllib.request
    import urllib.error
    from http.server import ThreadingHTTPServer

    spec2 = importlib.util.spec_from_file_location('kcweb_e2e', APP + '/web/server.py')
    srv = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(srv)

    captured = {}

    def fake_run_engine(args, timeout=180):
        captured['args'] = args
        return dict(status='CACHE_ONLY', status_text='ok', log=[], warnings=[])

    srv.run_engine = fake_run_engine
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), srv.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        body = json.dumps({'items': ['app_logs'], 'confirm': True}).encode('utf-8')
        req = urllib.request.Request(
            'http://127.0.0.1:%d/api/clean' % port, data=body, method='POST',
            headers={'Content-Type': 'application/json',
                     'X-Fnclean-Client': 'web',
                     'Sec-Fetch-Site': 'same-origin'})
        try:
            code = urllib.request.urlopen(req, timeout=8).status
        except urllib.error.HTTPError as e:
            code = e.code
        args = captured.get('args', [])
        passed = (code == 200 and
                  any('app_logs' in str(a) for a in args))
        return dict(ok=passed, code=code, args=args)
    finally:
        httpd.shutdown()


def host_whitelist_check():
    """v1.5.8：飞牛官方域名默认可信，攻击域名仍拒（DNS rebinding 防护保留）。"""
    spec2 = importlib.util.spec_from_file_location(
        'kcweb', APP + '/web/server.py')
    srv = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(srv)

    trusted = [
        'zxszjyzyx.fnos.net',        # FN Connect 设备子域
        'app123456.fnos.net',        # FN Connect appXXX 子域
        'fnos.net',                  # 官方主域
        'fnnas.com',                 # 官方主域
        'club.fnnas.com',            # 官方论坛子域
        'help.fnnas.com',            # 官方帮助子域
    ]
    rejected = [
        'evil.example',              # 典型 DNS rebinding 域名
        'evilfnos.net',              # 后缀边界绕过（缺 .）
        'fnos.net.evil.com',         # 反向前缀绕过
        'notfnnas.com',              # 官方域名前缀伪装
        'app.fnos.net.attacker.io',  # 嵌套绕过
    ]
    ok_trusted = all(srv._trusted_host(h) for h in trusted)
    ok_rejected = all(not srv._trusted_host(h) for h in rejected)
    # IP 字面量放行 / 空值放行（原有基线不回退）
    baseline = (srv._trusted_host('192.168.3.17') and
                srv._trusted_host('127.0.0.1') and
                srv._trusted_host(''))
    return dict(ok=ok_trusted and ok_rejected and baseline,
                trusted=ok_trusted, rejected=ok_rejected, baseline=baseline)


def app_log_safety_check():
    """v1.5.7：应用日志白名单 + 截断（不删除、保留 inode）。"""
    import tempfile
    import os as _os
    root = tempfile.mkdtemp(prefix='appdata_')
    kc.APPDATA_ROOT = root
    kc.APP_LOG_MIN = 10  # 测试threshold放低

    def mk(rel, size, link_to=None):
        p = _os.path.join(root, rel)
        _os.makedirs(_os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as f:
            f.write(b'x' * size)
        if link_to:
            try:
                _os.remove(p)
                _os.symlink(link_to, p)
            except OSError:
                pass
        return p

    ok_log = mk('baidu.netdisk/sdks/1000/stdout.log', 500)       # 白名单内
    ok_err = mk('someapp/log/error.log', 300)                     # .log 结尾
    small = mk('someapp/log/tiny.log', 5)                         # 小于阈值
    outside = _os.path.join(_os.path.dirname(root), 'outside.log')
    with open(outside, 'wb') as f:
        f.write(b'x' * 500)

    checks = {
        'whitelist_stdout': kc._is_app_log(ok_log),
        'whitelist_dotlog': kc._is_app_log(ok_err),
    }
    # 白名单函数本身不看大小，单独验证 scan 会过滤小文件
    info = kc._app_logs_scan()
    checks['scan_filters_small'] = (info['count'] == 2 and
                                    all(x['size'] >= kc.APP_LOG_MIN
                                        for x in info['files']))
    checks['reject_outside'] = not kc._is_app_log(outside)

    # 截断测试：保留 inode、size 归零、文件仍存在
    inode_before = _os.stat(ok_log).st_ino
    res = kc._app_logs_truncate({})
    checks['truncateFreed'] = res['reclaimed_bytes'] >= 800
    checks['fileStillExists'] = _os.path.isfile(ok_log)
    checks['inodePreserved'] = _os.stat(ok_log).st_ino == inode_before
    checks['sizeZero'] = _os.stat(ok_log).st_size == 0

    return dict(checks=checks, ok=all(checks.values()))


def e3_force_scan_check():
    """E3：do_scan(force=True) 时 _cached 收到 force=True。"""
    seen = {}
    orig = kc._cached
    def spy(key, ttl, fn, force=False):
        seen[key] = force
        return orig(key, ttl, fn, force=force)
    kc._cached = spy
    kc.collect = lambda: collect(candidates=[], purge=[], extra_packages=[])
    kc.host_info = lambda: dict(hostname='TEST', kernel=CUR, arch='arm64',
                                fnos='1.2.1000', soc='rk3566', board='',
                                model_name='', model_id='', compat_items=[])
    kc.ssh_info = lambda: dict(active=True, enabled=True, port22=True,
                               ok=True, hint='')
    kc.bootloader_info = lambda kv: boot()
    kc.avail_kb = lambda p: 1600000
    kc.cache_scan = lambda: []
    kc.cron_mail_source = lambda: []
    kc.disk_breakdown = lambda: dict(rows=[], total_kb=1, used_kb=1, avail_kb=0)
    kc.volume_survey = lambda: []
    kc.precheck = lambda R: dict(items=[], ok=True, advice='', note='')
    kc.do_scan(force=True)
    kc._cached = orig
    return dict(seen=seen,
                ok=(seen.get('cache_breakdown') is True and
                    seen.get('cache_volumes') is True))


def main():
    rows = []
    for c in CASES:
        try:
            rows.append(run_case(c))
        except Exception as e:
            rows.append(dict(case=c, status='TEST_CRASH:' + repr(e),
                             expect='', status_ok=False, warn_ok=False,
                             grub_executed=None, grub_rc=None,
                             grub_ok=False, warnings=[]))
    # dry-run 单独验证
    kc.collect = lambda: collect()
    kc.sh = fake_sh_factory()
    kc.run_update_grub = lambda: (0, 'ok')
    kc.selections = lambda: {}
    kc.dpkg_installed = lambda p: {}
    D = kc.do_clean(dry=True)
    dry = dict(case='DRY_RUN', status=D['status'], expect='SCAN',
               status_ok=D['status'] == 'SCAN', warn_ok=True,
               grub_executed=D['grub']['executed'],
               grub_rc=D['grub']['rc'],
               grub_ok=D['grub']['executed'] is False, warnings=[])

    print('%-22s %-22s %-6s %-6s %-8s %s' %
          ('CASE', 'STATUS', 'STAT', 'WARN', 'GRUB', 'GRUB_RC'))
    for r in rows:
        print('%-22s %-22s %-6s %-6s %-8s %s' %
              (r['case'], r['status'], 'PASS' if r['status_ok'] else 'FAIL',
               'PASS' if r['warn_ok'] else 'FAIL',
               'PASS' if r['grub_ok'] else 'FAIL', r['grub_rc']))
    print('%-22s %-22s %-6s %-6s %-8s %s' %
          (dry['case'], dry['status'], 'PASS' if dry['status_ok'] else 'FAIL',
           '-', 'PASS' if dry['grub_ok'] else 'FAIL', 'not executed'))
    print()
    print('=== WARNINGS SAMPLE ===')
    for r in rows:
        if r['warnings']:
            print(r['case'], '->', ' || '.join(r['warnings'])[:300])
    passed = sum(1 for r in rows if r['status_ok'] and r['warn_ok'] and r['grub_ok'])
    print()
    print('RESULT: %d/%d branches passed (+dry-run %s)' %
          (passed, len(rows), 'PASS' if dry['status_ok'] and dry['grub_ok'] else 'FAIL'))
    print('IRON LAW: all kernel-touching branches executed update-grub =',
          all(r['grub_executed'] is True for r in rows))
    try:
        co = cache_only_check()
        co_ok = (co['executed'] is False and co['rc'] is None and
                 '已跳过' in co['note'])
        print('CACHE_ONLY: status=%s grub_executed=%s note=%s -> %s' %
              (co['status'], co['executed'], co['note'][:44],
               'PASS' if co_ok else 'FAIL'))
    except Exception as e:
        print('CACHE_ONLY: TEST_CRASH %r -> FAIL' % (e,))
    # ===== v1.5.5+ 新增场景 =====
    print()
    print('=== v1.5.5 NEW CHECKS ===')
    new_checks = [
        ('E1 partial-unhold restore', e1_partial_unhold_check),
        ('E2 sim unparseable', e2_sim_unparseable_check),
        ('E2 surprise kernel pkg', e2_surprise_kernel_pkg_check),
        ('E4 kernel_phase_status', e4_phase_status_check),
        ('E3 force scan', e3_force_scan_check),
        ('v1.5.7 app-log safety', app_log_safety_check),
        ('v1.5.8 host whitelist', host_whitelist_check),
        ('v1.5.9 app_logs e2e', app_logs_e2e_check),
        ('v1.6.0 access log', access_log_check),
        ('v1.6.1 webview origin', webview_origin_check),
        ('v1.6.3 ssh port', ssh_port_check),
        ('v1.6.3 app host', app_host_check),
    ]
    new_pass = 0
    for label, fn in new_checks:
        try:
            r = fn()
            print('%-26s %s  detail=%s' %
                  (label, 'PASS' if r['ok'] else 'FAIL', r))
            new_pass += 1 if r['ok'] else 0
        except Exception as e:
            print('%-26s TEST_CRASH %r -> FAIL' % (label, e))
    print('NEW CHECKS: %d/%d passed' % (new_pass, len(new_checks)))


if __name__ == '__main__':
    main()
