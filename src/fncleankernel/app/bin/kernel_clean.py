#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fncleankernel — 通用 ARM 飞牛 fnOS 系统盘清理引擎（以 root 运行）
对外显示名「系统盘清理助手」；内部 appname 保持 fncleankernel 不变。

设计依据：用户现有手动流程（OEC /root/.bash_history 实证）
    for pkg in $(dpkg -l | grep linux-image | awk '{print $2}'); do sudo apt-mark unhold $pkg; done
    sudo apt-get purge linux-image-<旧版本>
    sudo update-grub

安全铁律
  1. 永远保留：uname -r 当前运行内核、版本号最高的已安装内核、所有 meta 包
  2. apt-get -s purge 预演，计划里只要碰到保留包就立即中止
  3. 清理前验证「实际引导链路」指向的内核文件存在且不指向被删的旧版本
  4. 无论成功 / 失败 / 无旧内核 / 锁定 / 异常，finally 里无条件执行一次 sudo update-grub
  5. 缓存清理只作用于 EMMC 系统盘（/var/cache/apt、/var/log），绝不碰 /vol* 数据卷

r3 新增：EMMC 侧缓存项（apt 缓存 / 日志轮转 / journal）逐项勾选，默认只勾
         「旧内核 + apt 缓存」；扫描阶段给出真机实测字节数。缓存阶段在 finally
         里、grub 之前执行，因此即使内核阶段提前 return（NO_OLD_KERNEL /
         UNSAFE_PLAN / 失败）也不影响勾选项，且铁律始终最后执行。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from datetime import datetime

try:
    import fcntl  # POSIX 文件锁，Windows 本地测试时不可用，降级为无锁
except ImportError:
    fcntl = None

APP = os.environ.get('TRIM_APPDEST') or '/vol1/@appcenter/fncleankernel'
VAR = os.environ.get('TRIM_PKGVAR') or '/vol1/@appdata/fncleankernel'
LOGDIR = os.path.join(VAR, 'log')
STATE = os.path.join(VAR, 'last_result.json')
SCAN_STATE = os.path.join(VAR, 'last_scan.json')
HISTORY = os.path.join(VAR, 'history.jsonl')
LOGFILE = os.path.join(LOGDIR, 'clean.log')
LOW_SPACE_KB = 800 * 1024          # 清理后根分区可用低于 800MB → 空间仍紧张
GRUB_TIMEOUT = 240

# ===== 2026-11-12 OEC 真机实测：fnOS 1.2.1000 → 1.2.1010 系统更新 =====
# 高频采样（2s 间隔，326 条，22:25:33–22:37:02）捕获的完整峰值，
# 原始数据在 _update_probe_data/ 与分析输出 _update_analysis.txt。
UPDATE_PEAK_KB = 1160604       # 峰值相对基线增量 ≈ 1.11 GB
UPDATE_NET_KB = 677904         # 最终净增占用 ≈ 662 MB（新内核 + 系统文件）
UPDATE_TMP_KB = 482700         # 峰值 - 最终 ≈ 471 MB（/var/tmp 临时解压）
UPDATE_MIN_AVAIL_KB = 590244   # 峰值时刻可用最低 ≈ 576 MB
UPDATE_SAFE_KB = 1350000       # 建议更新前可用：峰值 + 约 16% 余量 ≈ 1.29 GB

STATUS_TEXT = {
    'OK': '清理完成',
    'NO_OLD_KERNEL': '无需清理：没有可安全删除的旧内核',
    'UNSAFE_PLAN': '已安全中止：预演发现计划会动到保留内核',
    'HOLD_UNLOCK_FAILED': '已中止：旧内核被锁定且解锁失败',
    'PURGE_FAILED': '清理失败：apt 返回非零，现场保持原样',
    'GRUB_FAILED': '严重：update-grub 执行失败，请勿立即重启',
    'CACHE_ONLY': '跳过旧内核清理，仅处理勾选的缓存项',
    'CACHE_FAILED': '部分缓存项清理失败，请查看结果明细',
    'NO_TARGET': '没有勾选任何清理项，未执行任何操作',
    'SCAN': '只读扫描完成',
    'ERROR': '引擎异常，已安全中止',
}

IMG_RE = re.compile(r'^linux-image-(\d.*)$')

# ===== EMMC 系统盘缓存项（r3）=====
# 只处理 / 所在文件系统上的系统缓存；/vol* 是独立数据卷，一律不碰。
CACHE_DEFS = [
    dict(id='apt_cache', name='apt 下载缓存与索引缓存',
         desc='清理已下载的 .deb 安装包和 apt 索引缓存（pkgcache.bin / '
              'srcpkgcache.bin）。软件源列表 /var/lib/apt/lists 保留，'
              '离线环境也能继续装软件；缓存会在下次 apt 运行时自动重建。',
         risk='low', default=True, label='可回收'),
    dict(id='syslog_rotated', name='日志轮转文件（含子目录）',
         desc='递归扫描 /var/log 下所有轮转件（syslog.* / *.gz / *.1），'
              '包含 trim-connect、updatemgr、clamav 等子目录；'
              '不动任何正在写入的活跃日志。',
         risk='low', default=False, label='可回收'),
    dict(id='log_force_rotate', name='强制轮转活跃日志',
         desc='对系统自带的 /etc/logrotate.d/rsyslog 执行一次 logrotate -f，'
              '把 syslog / auth.log / cron.log 等正在写入的大日志切走，'
              '再清理新生成的轮转件。只调用这一个配置文件、不动全局配置；'
              '系统本身每 30 分钟就会跑同一条命令。',
         risk='mid', default=False, label='可回收', confirm=True),
    dict(id='cron_mail', name='Cron 告警邮件',
         desc='按 mbox 逐封解析 /var/mail，只删除 sleep_check.sh 定时任务'
              '产生的 Cron 通知，保留退信与安全告警等其它邮件。',
         risk='mid', default=False, label='可回收', confirm=True),
    dict(id='mon_residue', name='监控残留（数据卷）',
         desc='只清 /vol1/face_mon 下这次人脸识别监测与 fpk 开发留下的脚本、'
              '日志、原始输出和打包临时目录；正在进行的系统更新采样数据会保留。'
              '注意：释放的是数据卷空间，不会增加系统盘可用量。',
         risk='mid', default=False, label='可回收', confirm=True,
         scope='vol1'),
    dict(id='journal', name='systemd 归档日志',
         desc='执行 journalctl --vacuum-time=7d，只保留最近 7 天。',
         risk='low', default=False, label='可回收'),
]
CACHE_IDS = {c['id'] for c in CACHE_DEFS}
CACHE_NAMES = {c['id']: c['name'] for c in CACHE_DEFS}
DEFAULT_ITEMS = ['old_kernel'] + [c['id'] for c in CACHE_DEFS if c['default']]
HDR_RE = re.compile(r'^linux-headers-(\d.*)$')
MOD_RE = re.compile(r'^linux-modules-trim-(\d.*)$')


def sh(cmd, timeout=600):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors='replace')
        return p.returncode, (p.stdout or ''), (p.stderr or '')
    except subprocess.TimeoutExpired:
        return 124, '', 'command timeout after %ss' % timeout
    except Exception as e:
        return 125, '', repr(e)


def read_file(path, limit=4000):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read(limit)
    except Exception:
        return ''


def ver_key(v):
    """6.18.18.c1196-trim -> (6,18,18,1196)，避免 c994 > c1090 的字典序陷阱"""
    nums = tuple(int(x) for x in re.findall(r'\d+', v))
    return nums or (0,)


def dpkg_installed(pattern):
    """返回已安装包 {pkg: {version, want, size_kb}}"""
    fmt = '${Package}|${Version}|${db:Status-Status}|${db:Status-Want}|${Installed-Size}\n'
    rc, out, _ = sh(['dpkg-query', '-W', '-f=' + fmt, pattern], timeout=120)
    ret = {}
    for line in out.splitlines():
        p = line.split('|')
        if len(p) < 4 or p[2] != 'installed':
            continue
        try:
            size = int(p[4])
        except Exception:
            size = 0
        ret[p[0]] = dict(version=p[1], want=p[3], size_kb=size)
    return ret


def selections():
    rc, out, _ = sh(['dpkg', '--get-selections'], timeout=120)
    m = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 2:
            m[p[0]] = p[1]
    return m


def avail_kb(path):
    rc, out, _ = sh(['df', '-k', path], timeout=30)
    lines = out.splitlines()
    if len(lines) >= 2:
        p = lines[1].split()
        try:
            return int(p[3])
        except Exception:
            return 0
    return 0


def _device_identity():
    """只读取「设备自己声明」的事实，绝不靠硬编码白名单猜机型。

    优先级：/proc/device-tree/model（Linux 标准设备树机型名，厂商写死在 dtb 里）
    → /boot/board.json 的 model.name → 都没有就留空（前端省略，不显示 unknown）。
    compatible 按 NUL 精确切分成条目，只在条目被精确命中时才给 soc 诊断标签，
    不再对整个字符串做子串包含匹配，避免多关键词设备误报。
    """
    model_name = read_file('/proc/device-tree/model', 256).replace(
        '\x00', '').strip()
    board_raw = read_file('/boot/board.json', 4096).strip()
    model_id = ''
    if board_raw:
        try:
            d = json.loads(board_raw)
            m = d.get('model') or {}
            model_id = str(m.get('id') or '').strip()
            if not model_name:
                model_name = str(m.get('name') or '').strip()
        except Exception:
            pass
    compat_items = [x.strip() for x in
                    read_file('/proc/device-tree/compatible', 512)
                    .replace('\x00', '\n').splitlines() if x.strip()]
    soc = ''
    for item in compat_items:
        low = item.lower()
        for key in ('rk3566', 'rk3568', 'rk3588', 'a311d', 's922x', 's905x3'):
            if low == key or low.endswith(',' + key):
                soc = key
                break
        if soc:
            break
    return dict(model_name=model_name, model_id=model_id,
                compat_items=compat_items, soc=soc, board=board_raw)


def host_info():
    rc, kernel, _ = sh(['uname', '-r'])
    rc, host, _ = sh(['hostname'])
    rc, arch, _ = sh(['dpkg', '--print-architecture'])
    fnos = read_file('/usr/trim/etc/version', 64).strip()
    ident = _device_identity()
    # 注意：以下字段只用于展示与诊断，绝不参与任何清理 / 安全判断。
    # 真正的判断依据是 uname -r、dpkg 实际状态与 bootloader_info() 读到的实引导配置。
    return dict(hostname=host.strip(), kernel=kernel.strip(),
                arch=arch.strip(), fnos=fnos,
                soc=ident['soc'], model_name=ident['model_name'],
                model_id=ident['model_id'],
                compat_items=ident['compat_items'], board=ident['board'])


def ssh_info():
    rc, out, _ = sh(['systemctl', 'is-active', 'ssh'], timeout=30)
    active = out.strip() == 'active'
    rc2, out2, _ = sh(['systemctl', 'is-enabled', 'ssh'], timeout=30)
    enabled = out2.strip() in ('enabled', 'alias', 'enabled-runtime', 'static')
    rc3, out3, _ = sh(['ss', '-tln'], timeout=30)
    port22 = bool(re.search(r':22\s', out3))
    ok = active and port22
    return dict(active=active, enabled=enabled, port22=port22, ok=ok,
                hint='' if ok else 'SSH 未开启：请在 飞牛 OS「设置 → 终端/SSH」中手动开启，'
                                  '以便清理出现异常时可以从电脑远程进入设备排障。')


def bootloader_info(keep_versions):
    """真机：两台设备均为 u-boot 实引导 + GRUB 配置并存"""
    grub_cfg = '/boot/grub/grub.cfg'
    ug = shutil.which('update-grub')
    if not ug and os.path.exists('/usr/sbin/update-grub'):
        ug = '/usr/sbin/update-grub'
    info = dict(real='unknown', detail='', boot_kernel='', boot_kernel_path='',
                boot_kernel_ok=False, boot_version='', boot_on_old=False,
                boot_version_parsed=False,
                grub_cfg=os.path.isfile(grub_cfg), update_grub=ug or '')
    extlinux = '/boot/extlinux/extlinux.conf'
    fnenv = '/boot/fnEnv.txt'
    if os.path.isfile(extlinux):
        txt = read_file(extlinux, 2000)
        info['real'] = 'u-boot + extlinux'
        info['detail'] = txt.strip()[:600]
        m = re.search(r'^\s*kernel\s+(\S+)', txt, re.M)
        if m:
            info['boot_kernel'] = m.group(1)
    elif os.path.isfile('/boot/boot.cmd') or os.path.isfile(fnenv):
        info['real'] = 'u-boot + boot.cmd / fnEnv.txt'
        env = read_file(fnenv, 1000)
        info['detail'] = 'fnEnv.txt: ' + env.strip()[:400]
        m = re.search(r'kernelfile\s*=\s*"?([^\s"]+)"?', env)
        info['boot_kernel'] = (m.group(1) if m else 'vmlinuz')
    elif info['grub_cfg']:
        info['real'] = 'GRUB'
        info['detail'] = read_file(grub_cfg, 400)

    bk = info['boot_kernel']
    if bk:
        path = ('/boot' + bk) if bk.startswith('/') else ('/boot/' + bk)
        info['boot_kernel_path'] = path
        info['boot_kernel_ok'] = os.path.isfile(path)
        m = re.search(r'(\d+\.\d+\.\d+\.c\d+-trim)', os.path.basename(path))
        if m:
            info['boot_version'] = m.group(1)
            info['boot_version_parsed'] = True
            info['boot_on_old'] = (m.group(1) not in keep_versions)
        # 别的机型若用非飞牛内核命名，这里解析不出版本：保持 False，
        # do_clean 会 fail-closed 中止，绝不默认放行。
    elif info['grub_cfg']:
        info['boot_kernel_ok'] = True      # 纯 GRUB 环境由 update-grub 负责
    return info


def collect():
    cur = sh(['uname', '-r'])[1].strip()
    imgs = dpkg_installed('linux-image-*')
    hdrs = dpkg_installed('linux-headers-*')
    mods = dpkg_installed('linux-modules-trim-*')
    sel = selections()
    concrete = {p: d for p, d in imgs.items() if IMG_RE.match(p)}
    meta = [p for p in imgs if not IMG_RE.match(p)]

    cur_pkg = 'linux-image-' + cur
    if concrete:
        ordered = sorted(concrete.items(),
                         key=lambda kv: ver_key(IMG_RE.match(kv[0]).group(1)),
                         reverse=True)
        latest_pkg = ordered[0][0]
    else:
        latest_pkg = ''

    keep_pkgs = {p for p in (cur_pkg, latest_pkg) if p}
    keep_versions = set()
    for p in keep_pkgs:
        m = IMG_RE.match(p)
        if m:
            keep_versions.add(m.group(1))
    if not keep_versions:
        keep_versions.add(cur)

    candidates = sorted(p for p in concrete if p not in keep_pkgs)

    purge = []
    for p in candidates:
        purge.append(p)
        v = IMG_RE.match(p).group(1)
        for name, table in (('linux-headers-' + v, hdrs),
                            ('linux-modules-trim-' + v, mods)):
            if name in table and name not in purge:
                purge.append(name)
    # 孤儿 headers：对应 image 包已被清掉，但 headers 还占着 /usr/src
    for p in hdrs:
        m = HDR_RE.match(p)
        if not m or p in purge:
            continue
        v = m.group(1)
        if v not in keep_versions and ('linux-image-' + v) not in imgs:
            purge.append(p)

    rows = []
    for p, d in sorted(imgs.items()):
        m = IMG_RE.match(p)
        is_cur = (p == cur_pkg)
        is_latest = (p == latest_pkg)
        rows.append(dict(pkg=p, version=d['version'], want=d['want'],
                         size_kb=d['size_kb'], is_current=is_cur,
                         is_latest=is_latest, is_meta=not bool(m),
                         action='keep' if (is_cur or is_latest or not m) else 'remove'))

    hold_installed = sorted(p for p in concrete if sel.get(p) == 'hold')
    hold_to_unlock = [p for p in purge if sel.get(p) == 'hold']

    return dict(cur=cur, cur_pkg=cur_pkg, latest_pkg=latest_pkg,
                keep_pkgs=sorted(keep_pkgs), keep_versions=sorted(keep_versions),
                meta=meta, candidates=candidates, purge=purge, rows=rows,
                hold_installed=hold_installed, hold_to_unlock=hold_to_unlock,
                selections=sel, imgs=imgs, hdrs=hdrs, mods=mods,
                extra_packages=sorted(p for p in purge if p not in candidates))


def base(mode):
    return dict(
        status='SCAN', status_text=STATUS_TEXT['SCAN'], mode=mode,
        time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        device={}, ssh={}, bootloader={}, kernels=[],
        keep=[], remove=[], purge_list=[], extra_packages=[],
        hold=dict(installed=[], to_unlock=[], unlocked=[], restored=[], failed=[]),
        purge=dict(rc=None, simulate='', output=''),
        grub=dict(executed=False, forced=False, rc=None, output='',
                  note='点击「一键清理」后，无论结果如何都会在最后强制执行'),
        space=dict(root_before_kb=0, root_after_kb=0, reclaimed_kb=0,
                   boot_before_kb=0, boot_after_kb=0, low=False),
        cache_items=[], selected=list(DEFAULT_ITEMS),
        cache=dict(results=[], reclaimed_bytes=0, failed=[]),
        breakdown=dict(rows=[], total_kb=0, used_kb=0, avail_kb=0),
        volumes=[], precheck=dict(items=[], ok=False, advice='', note=''),
        cron_source=[],
        warnings=[], notes=[], log=[], kernel_phase_status='')


def note(R, msg, kind='notes'):
    R[kind].append(msg)
    R['log'].append('[%s] %s' % (datetime.now().strftime('%H:%M:%S'), msg))


def _atomic_write(path, text):
    """同目录临时文件 + os.replace 原子替换，避免写中途断电留下半行/截断文件。"""
    tmp = path + '.tmp.%d' % os.getpid()
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _append_history(R):
    """每次真实清理追加一行，供趋势图使用；最多留 200 条。

    E5：读-改-写全程 fcntl 独占锁（内核阶段与 CLI 独立进程并发时不丢记录），
    并改原子替换，避免中途断电留下半行 json。"""
    row = dict(time=R['time'], status=R['status'],
               kernel_phase_status=R.get('kernel_phase_status') or '',
               selected=R.get('selected', []),
               root_before_kb=R['space']['root_before_kb'],
               root_after_kb=R['space']['root_after_kb'],
               reclaimed_kb=R['space']['reclaimed_kb'],
               cache_reclaimed_bytes=R['cache']['reclaimed_bytes'],
               grub_rc=R['grub']['rc'])
    try:
        os.makedirs(os.path.dirname(HISTORY), exist_ok=True)
        fh = open(HISTORY, 'a+', encoding='utf-8')
        try:
            if fcntl:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            fh.seek(0)
            lines = fh.read().splitlines()[-199:]
            lines.append(json.dumps(row, ensure_ascii=False))
            _atomic_write(HISTORY, '\n'.join(lines) + '\n')
        finally:
            if fcntl:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            fh.close()
    except Exception as e:
        R.setdefault('errors', []).append('write history: %r' % e)


def finish(R):
    R['status_text'] = STATUS_TEXT.get(R['status'], R['status'])
    R['space']['root_after_kb'] = avail_kb('/')
    R['space']['boot_after_kb'] = avail_kb('/boot')
    R['space']['reclaimed_kb'] = max(0, R['space']['root_after_kb'] -
                                     R['space']['root_before_kb'])
    if R['space']['root_after_kb'] and R['space']['root_after_kb'] < LOW_SPACE_KB:
        R['space']['low'] = True
        note(R, 'LOW_SPACE：清理后系统盘（/）可用仅 %d MB，仍偏紧张；'
                '系统盘缓存已按勾选项处理，剩余大头是 /usr 系统本体，'
                '本工具不会擅自删除系统文件或 /vol* 数据卷。'
             % (R['space']['root_after_kb'] // 1024), 'warnings')
    try:
        os.makedirs(LOGDIR, exist_ok=True)
        # S1：只有真正执行过清理才写 last_result.json；scan 另存 last_scan.json，
        # 否则每次打开页面都会把上次清理结果冲掉，/api/last 与趋势图全部失真。
        if R['mode'] == 'clean':
            _atomic_write(STATE, json.dumps(R, ensure_ascii=False, indent=2))
            _append_history(R)
            # 清理后空间构成已变，让下次 scan 重新统计
            for k in ('cache_breakdown', 'cache_volumes'):
                try:
                    os.remove(os.path.join(VAR, k + '.json'))
                except OSError:
                    pass
        elif R['mode'] == 'scan':
            _atomic_write(SCAN_STATE, json.dumps(R, ensure_ascii=False, indent=2))
        # dry-run 不写任何状态
        with open(LOGFILE, 'a', encoding='utf-8') as f:
            f.write('\n===== %s [%s] %s =====\n' %
                    (R['time'], R['mode'], R['status']))
            f.write('\n'.join(R['log']) + '\n')
    except Exception as e:
        R.setdefault('errors', []).append('write state: %r' % e)
    return R


def run_update_grub():
    ug = shutil.which('update-grub')
    if not ug and os.path.exists('/usr/sbin/update-grub'):
        ug = '/usr/sbin/update-grub'
    if not ug:
        return 127, 'update-grub 命令不存在，无法刷新引导配置'
    sudo = shutil.which('sudo')
    # 实测：server.py 派生子进程再走 sudo -n 时 env_reset 会丢掉 LANG，
    # grub-mkconfig 因此少生成 locale_dir / set lang / insmod gettext 三行，
    # 与用户直接跑 update-grub 生成的 grub.cfg 不一致。显式带过去。
    lang = os.environ.get('LANG') or 'en_US.UTF-8'
    exe = ['env', 'LANG=' + lang, ug]
    cmd = ['sudo', '-n'] + exe if sudo else exe
    rc, out, err = sh(cmd, timeout=GRUB_TIMEOUT)
    return rc, (out + err).strip()[-4000:]


# ============================ EMMC 缓存扫描 / 清理 ============================

def human(n):
    n = float(n or 0)
    for u in ('B', 'KB', 'MB', 'GB'):
        if abs(n) < 1024:
            return '%.1f %s' % (n, u)
        n /= 1024
    return '%.1f TB' % n


def _files_size(paths):
    total = 0
    for p in paths:
        try:
            if os.path.isfile(p):
                total += os.path.getsize(p)
        except OSError:
            pass
    return total


def _apt_cache_files():
    """只列 deb 下载缓存 + 两个 apt 索引缓存；不动 /var/lib/apt/lists。"""
    out = []
    arc = '/var/cache/apt/archives'
    try:
        for n in os.listdir(arc):
            if n.endswith('.deb') or n.endswith('.udeb'):
                p = os.path.join(arc, n)
                if os.path.isfile(p):
                    out.append(p)
    except OSError:
        pass
    for n in ('pkgcache.bin', 'srcpkgcache.bin'):
        p = os.path.join('/var/cache/apt', n)
        if os.path.isfile(p):
            out.append(p)
    return out


ROTATED_RE = re.compile(r'-20\d{2}-\d{2}-\d{2}')
ACTIVE_LOG_NAMES = ('syslog', 'auth.log', 'cron.log', 'kern.log',
                    'mail.log', 'user.log', 'messages')
RSYSLOG_CONF = '/etc/logrotate.d/rsyslog'


def _is_rotated(name):
    """只认轮转件：.gz / .N / syslog.* / 带日期戳的归档 *.log。

    绝不把 syslog、auth.log、info.log 这类正在写入的活跃日志判成可删。
    """
    if name in ACTIVE_LOG_NAMES:
        return False
    if name.endswith('.gz') or name.startswith('syslog.'):
        return True
    if re.search(r'\.\d+$', name):
        return True
    if ROTATED_RE.search(name) and name.endswith('.log'):
        return True
    return False


def _rotated_log_files():
    """递归列 /var/log 下的轮转件（含子目录），跳过 journal 目录。"""
    out = []
    for root, dirs, files in os.walk('/var/log'):
        dirs[:] = [d for d in dirs if d != 'journal']
        if root.count(os.sep) > 5:
            dirs[:] = []
        for n in files:
            if not _is_rotated(n):
                continue
            p = os.path.join(root, n)
            try:
                if os.path.isfile(p):
                    out.append(p)
            except OSError:
                pass
    return out


def _force_rotate_info():
    """只读：活跃日志字节数 + 系统是否自带 rsyslog 轮转规则。"""
    files = []
    for n in ACTIVE_LOG_NAMES:
        p = '/var/log/' + n
        try:
            if os.path.isfile(p):
                files.append((p, os.path.getsize(p)))
        except OSError:
            pass
    return dict(available=bool(os.path.isfile(RSYSLOG_CONF) and
                               shutil.which('logrotate')),
                conf=RSYSLOG_CONF, bytes=sum(s for _, s in files),
                files=[dict(path=p, bytes=s) for p, s in files])


def _split_mbox(data):
    """按 mbox 的 'From ' 分隔行切分，保留每封原文。"""
    return re.split(rb'(?m)^(?=From )', data)


def _cron_mail_info():
    """只读：只统计 sleep_check.sh 定时任务产生的 Cron 通知。

    真机实测 OEC 有 58 封非 Cron 邮件（退信 / SECURITY information），
    绝不能把整个 spool truncate 掉。
    """
    total_bytes = cron_bytes = 0
    cron_count = other_count = 0
    paths = []
    try:
        names = os.listdir('/var/mail')
    except OSError:
        names = []
    for n in names:
        p = os.path.join('/var/mail', n)
        try:
            if not os.path.isfile(p) or os.path.getsize(p) == 0:
                continue
            with open(p, 'rb') as f:
                data = f.read()
        except OSError:
            continue
        total_bytes += len(data)
        c = o = 0
        for part in _split_mbox(data):
            if not part.strip():
                continue
            if (b'Subject: Cron ' in part and b'sleep_check.sh' in part):
                c += 1
                cron_bytes += len(part)
            else:
                o += 1
        cron_count += c
        other_count += o
        if c:
            paths.append(dict(path=p, cron=c, other=o))
    return dict(total_bytes=total_bytes, cron_bytes=cron_bytes,
                cron_count=cron_count, other_count=other_count,
                paths=paths)


# ===== 监控残留（/vol1 数据卷，用户已明确授权清理）=====
MON_ROOT = '/vol1/face_mon'
MON_PROTECT = {'update_probe'}   # 系统更新采样数据，分析完成前绝不删


def _dir_size(path):
    total = 0
    for root, dirs, files in os.walk(path):
        for n in files:
            try:
                fp = os.path.join(root, n)
                if os.path.isfile(fp) and not os.path.islink(fp):
                    total += os.path.getsize(fp)
            except OSError:
                pass
    return total


def _mon_residue_entries():
    """只读：列 /vol1/face_mon 顶层条目，保护项单独返回。

    只认这一层，绝不递归到 /vol1 其它目录；符号链接一律跳过。
    """
    removable, protected = [], []
    try:
        names = sorted(os.listdir(MON_ROOT))
    except OSError:
        return removable, protected
    for n in names:
        p = os.path.join(MON_ROOT, n)
        if os.path.normpath(p) != p or not p.startswith(MON_ROOT + os.sep):
            continue
        try:
            if os.path.islink(p):
                continue
            if os.path.isdir(p):
                size, is_dir = _dir_size(p), True
            elif os.path.isfile(p):
                size, is_dir = os.path.getsize(p), False
            else:
                continue
        except OSError:
            continue
        row = dict(path=p, name=n, bytes=size, is_dir=is_dir)
        (protected if n in MON_PROTECT else removable).append(row)
    return removable, protected


def mon_residue_scan():
    rem, prot = _mon_residue_entries()
    return dict(bytes=sum(x['bytes'] for x in rem), count=len(rem),
                entries=rem[:40],
                protected=[dict(path=x['path'], bytes=x['bytes']) for x in prot],
                root=MON_ROOT)


def mon_residue_clean():
    """只删 /vol1/face_mon 顶层白名单外的自有条目，保护采样目录。"""
    rem, prot = _mon_residue_entries()
    before = sum(x['bytes'] for x in rem)
    removed = failed = 0
    for x in rem:
        p = x['path']
        if not p.startswith(MON_ROOT + os.sep) or os.path.normpath(p) != p:
            failed += 1
            continue
        try:
            if x['is_dir']:
                shutil.rmtree(p)
            else:
                os.remove(p)
            removed += 1
        except OSError:
            failed += 1
    after = sum(y['bytes'] for y in _mon_residue_entries()[0])
    return dict(removed=removed, failed=failed,
                reclaimed_bytes=max(0, before - after),
                protected=[y['path'] for y in prot])


def cron_mail_source():
    """只读：列出尚缺 >/dev/null 重定向的 sleep_check.sh cron 行，供二次确认。"""
    rows = []
    for u in ('root', '浪里小白龙'):
        try:
            p = subprocess.run(['crontab', '-l', '-u', u],
                               capture_output=True, timeout=30)
            if p.returncode != 0:
                continue
            for line in p.stdout.decode('utf-8', 'replace').splitlines():
                if 'sleep_check.sh' in line and '>/dev/null' not in line:
                    rows.append(dict(user=u, line=line))
        except Exception:
            pass
    return rows


def _journal_info():
    """返回 (bytes, path, on_emmc)。

    飞牛这两台 ARM 设备实测为 volatile：journal 落在 /run/log/journal（tmpfs），
    不在 /var/log/journal。清它只释放内存，不释放 EMMC 系统盘，必须区别对待。
    """
    for d in ('/var/log/journal', '/run/log/journal'):
        if not os.path.isdir(d):
            continue
        rc, out, err = sh(['du', '-sk', d], timeout=60)
        try:
            return int(out.split()[0]) * 1024, d, d.startswith('/var/')
        except Exception:
            pass
    return 0, '', False


def cache_scan():
    """只读扫描：给出每项的真机实测字节数，供前端逐项勾选。"""
    apt = _apt_cache_files()
    rot = _rotated_log_files()
    jb, jpath, j_emmc = _journal_info()
    fr = _force_rotate_info()
    cm = _cron_mail_info()
    size = dict(apt_cache=_files_size(apt),
                syslog_rotated=_files_size(rot),
                log_force_rotate=fr['bytes'],
                cron_mail=cm['cron_bytes'], journal=jb)
    count = dict(apt_cache=len(apt), syslog_rotated=len(rot),
                 log_force_rotate=len(fr['files']),
                 cron_mail=cm['cron_count'], journal=0)
    items = []
    for d in CACHE_DEFS:
        e = dict(d)
        e['bytes'] = size.get(d['id'], 0)
        e['size_str'] = human(e['bytes'])
        e['count'] = count.get(d['id'], 0)
        e['available'] = True
        e['actionable'] = True
        if d['id'] == 'journal':
            e['path'] = jpath
            e['actionable'] = j_emmc
            if not j_emmc:
                e['risk'] = 'info'
                e['label'] = '内存占用'
                e['desc'] = ('实测：journal 落在 %s（tmpfs 内存盘），不占 EMMC '
                             '系统盘；清理它不会释放系统盘空间，因此本工具不提供'
                             '清理，仅作体检提示。' % (jpath or '/run'))
        elif d['id'] == 'log_force_rotate':
            e['actionable'] = bool(fr['available'] and fr['bytes'] > 0)
            if not fr['available']:
                e['risk'] = 'info'
                e['label'] = '不可用'
                e['desc'] = '本机没有找到 rsyslog 轮转规则或 logrotate 命令，已停用。'
            else:
                e['label'] = '活跃日志'
                e['desc'] += (' 本机实测 %d 个活跃日志合计 %s；本项会先轮转'
                              '再删除轮转件，一次完成释放。'
                              % (len(fr['files']), human(fr['bytes'])))
        elif d['id'] == 'cron_mail':
            e['actionable'] = cm['cron_count'] > 0
            e['cron_count'] = cm['cron_count']
            e['other_count'] = cm['other_count']
            if cm['cron_count'] == 0:
                e['risk'] = 'info'
                e['label'] = '未发现'
                e['desc'] = '本机没有发现 sleep_check.sh 产生的 Cron 通知，无需清理。'
            else:
                e['desc'] += (' 实测 %d 封 Cron 通知（%s），将保留 %d 封其它邮件'
                              '（退信、安全告警等）。'
                              % (cm['cron_count'], human(cm['cron_bytes']),
                                 cm['other_count']))
        elif d['id'] == 'mon_residue':
            ms = mon_residue_scan()
            e['bytes'] = ms['bytes']
            e['size_str'] = human(e['bytes'])
            e['count'] = ms['count']
            e['actionable'] = ms['count'] > 0
            e['entries'] = ms['entries']
            e['protected'] = ms['protected']
            if not ms['count']:
                e['risk'] = 'info'
                e['label'] = '未发现'
                e['desc'] = '监控目录里已经没有可清理的自有产物。'
            else:
                e['desc'] += (' 实测 %d 个条目（%s）；%d 个正在使用的采样目录'
                              '会保留不动。'
                              % (ms['count'], human(ms['bytes']),
                                 len(ms['protected'])))
        items.append(e)
    return items


def _remove_files(paths):
    removed, failed = 0, 0
    for p in paths:
        try:
            if os.path.isfile(p):
                os.remove(p)
                removed += 1
        except OSError:
            failed += 1
    return removed, failed


def cache_clean(R, ids):
    """执行勾选的缓存项。只由 do_clean 的 finally 调用，失败不影响铁律。"""
    results = []
    for cid in ids:
        if cid not in CACHE_IDS:
            continue
        e = dict(id=cid, name=CACHE_NAMES[cid], rc=None,
                 reclaimed_bytes=0, detail='', skipped=False)
        try:
            if cid == 'apt_cache':
                files = _apt_cache_files()
                before = _files_size(files)
                rc, out, err = sh(['apt-get', 'clean'], timeout=180)
                removed, failed = _remove_files(files)
                e['rc'] = rc
                e['reclaimed_bytes'] = max(0, before - _files_size(_apt_cache_files()))
                e['detail'] = ('apt-get clean rc=%d；删除 %d 个缓存文件，失败 %d 个'
                               % (rc, removed, failed))
                if failed:
                    e['detail'] += '；个别文件被占用，下次可再清'
            elif cid == 'syslog_rotated':
                files = _rotated_log_files()
                before = _files_size(files)
                removed, failed = _remove_files(files)
                e['rc'] = 0 if failed == 0 else 1
                e['reclaimed_bytes'] = max(0, before - _files_size(_rotated_log_files()))
                e['detail'] = '删除 %d 个轮转日志，失败 %d 个' % (removed, failed)
            elif cid == 'log_force_rotate':
                info = _force_rotate_info()
                if not info['available']:
                    e['rc'] = 127
                    e['detail'] = '缺少 rsyslog 轮转规则，已跳过'
                else:
                    rc, out, err = sh(['logrotate', '-f', RSYSLOG_CONF],
                                      timeout=180)
                    # 轮转只把内容搬到 .1，必须把轮转件删掉才真正释放空间
                    rot = _rotated_log_files()
                    will_free = _files_size(rot)
                    removed, failed = _remove_files(rot)
                    e['rc'] = rc
                    e['reclaimed_bytes'] = max(
                        0, will_free - _files_size(_rotated_log_files()))
                    e['detail'] = ('logrotate -f %s rc=%d；活跃日志 %s 已切走，'
                                   '删除 %d 个轮转件（失败 %d）'
                                   % (RSYSLOG_CONF, rc, human(info['bytes']),
                                      removed, failed))
            elif cid == 'cron_mail':
                info = _cron_mail_info()
                freed = 0
                handled = 0
                for ent in info['paths']:
                    p = ent['path']
                    st = os.stat(p)
                    with open(p, 'rb') as f:
                        data = f.read()
                    keep = [part for part in _split_mbox(data)
                            if part.strip() and not
                            (b'Subject: Cron ' in part and
                             b'sleep_check.sh' in part)]
                    new = b''.join(keep)
                    tmp = p + '.fnclean-tmp'
                    with open(tmp, 'wb') as f:
                        f.write(new)
                    os.chmod(tmp, st.st_mode & 0o7777)
                    os.chown(tmp, st.st_uid, st.st_gid)
                    os.replace(tmp, p)
                    freed += len(data) - len(new)
                    handled += 1
                e['rc'] = 0
                e['reclaimed_bytes'] = freed
                e['detail'] = ('处理 %d 个邮箱，删除 %d 封 Cron 通知，'
                               '保留 %d 封其它邮件'
                               % (handled, info['cron_count'],
                                  info['other_count']))
            elif cid == 'mon_residue':
                res = mon_residue_clean()
                e['rc'] = 0 if res['failed'] == 0 else 1
                e['reclaimed_bytes'] = res['reclaimed_bytes']
                e['detail'] = ('删除 %d 个条目，失败 %d 个；保留 %s'
                               % (res['removed'], res['failed'],
                                  ', '.join(os.path.basename(p)
                                            for p in res['protected']) or '无'))
            elif cid == 'journal':
                before = _journal_info()[0]
                rc, out, err = sh(['journalctl', '--vacuum-time=7d'], timeout=240)
                after = _journal_info()[0]
                e['rc'] = rc
                e['reclaimed_bytes'] = max(0, before - after)
                e['detail'] = ((out + err).strip()[-300:] or
                               'journalctl --vacuum-time=7d rc=%d' % rc)
        except Exception as ex:
            e['rc'] = 125
            e['detail'] = repr(ex)
        results.append(e)

    R['cache']['results'] = results
    R['cache']['reclaimed_bytes'] = sum(x['reclaimed_bytes'] for x in results)
    R['cache']['failed'] = [x['id'] for x in results
                            if x['rc'] not in (0, None)]
    note(R, '缓存阶段：执行 %d 项，回收 %s。' %
         (len(results), human(R['cache']['reclaimed_bytes'])))
    for x in results:
        note(R, '  [%s] %s → 回收 %s（rc=%s）%s' %
             (x['id'], x['name'], human(x['reclaimed_bytes']),
              x['rc'], x['detail'][:160]))
    if R['cache']['failed']:
        R['status'] = ('CACHE_FAILED' if R['status'] in
                       ('OK', 'NO_OLD_KERNEL', 'CACHE_ONLY', 'SCAN')
                       else R['status'])
        note(R, 'CACHE_FAILED：以下缓存项未完全成功：%s（内核阶段状态优先保留）'
             % ', '.join(R['cache']['failed']), 'warnings')
    elif results and R['status'] in ('NO_OLD_KERNEL', 'CACHE_ONLY', 'SCAN'):
        # 没有旧内核但缓存清成功了，整体应呈现「清理完成」
        R['status'] = 'OK'


# ============================ 堵源头 / 体检数据 ============================

def do_fix_cron_mail(confirm=False):
    """堵住 cron 邮件源头：只给 sleep_check.sh 那行补 >/dev/null 2>&1。

    - 改前把两份原始 crontab 备份到 VAR/backup/
    - 全程按 bytes 处理，避免中文用户名 / 注释被 UTF-8 解码破坏
    - 必须由调用方显式传 confirm=True，否则只读返回待改行
    """
    rows = cron_mail_source()
    R = dict(ok=False, confirm=bool(confirm), rows=rows,
             changed=[], backup=[], warnings=[])
    if not confirm:
        R['warnings'].append('未确认：不会修改任何 crontab')
        return R
    if not rows:
        R['ok'] = True
        R['note'] = '没有需要修改的行（可能已经修好）'
        return R
    bdir = os.path.join(VAR, 'backup')
    os.makedirs(bdir, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d%H%M%S')
    users = sorted({r['user'] for r in rows})
    for u in users:
        try:
            p = subprocess.run(['crontab', '-l', '-u', u],
                               capture_output=True, timeout=30)
            if p.returncode != 0:
                R['warnings'].append('%s：读取 crontab 失败' % u)
                continue
            data = p.stdout
            bp = os.path.join(bdir, 'crontab_%s_%s' % (u, stamp))
            with open(bp, 'wb') as f:
                f.write(data)
            R['backup'].append(bp)
            out_lines = []
            for line in data.splitlines(keepends=True):
                try:
                    s = line.decode('utf-8')
                except UnicodeDecodeError:
                    out_lines.append(line)
                    continue
                if ('sleep_check.sh' in s and '>/dev/null' not in s):
                    nl = '\n' if s.endswith('\n') else ''
                    out_lines.append(
                        (s.rstrip('\r\n') + ' > /dev/null 2>&1' + nl)
                        .encode('utf-8'))
                else:
                    out_lines.append(line)
            tmp = os.path.join(bdir, '_new_%s_%s' % (u, stamp))
            with open(tmp, 'wb') as f:
                f.write(b''.join(out_lines))
            rc2, o2, e2 = sh(['crontab', '-u', u, tmp], timeout=30)
            if rc2 == 0:
                R['changed'].append(u)
            else:
                R['warnings'].append('%s：写回 crontab 失败 rc=%d %s'
                                     % (u, rc2, e2[-200:]))
        except Exception as ex:
            R['warnings'].append('%s：%r' % (u, ex))
    R['ok'] = (len(R['changed']) == len(users)) and not R['warnings']
    R['after'] = cron_mail_source()
    return R


def _cached(key, ttl, fn, force=False):
    """du 全盘较慢，体检数据做磁盘缓存。

    E3：force=True 跳过 mtime 缓存强制重算（前端「重新扫描」按钮），
    写盘改原子替换，避免并发 scan 写坏缓存文件。"""
    p = os.path.join(VAR, key + '.json')
    if not force:
        try:
            st = os.stat(p)
            if time.time() - st.st_mtime < ttl:
                with open(p, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
    v = fn()
    try:
        os.makedirs(VAR, exist_ok=True)
        _atomic_write(p, json.dumps(v, ensure_ascii=False))
    except Exception:
        pass
    return v


def disk_breakdown():
    """只读：/ 一级目录占用，解释「为什么清了半天才这么点」。"""
    rc, out, err = sh(['du', '-x', '-k', '--max-depth=1', '/'], timeout=180)
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            try:
                rows.append(dict(path=parts[1], kb=int(parts[0])))
            except ValueError:
                pass
    rows.sort(key=lambda x: x['kb'], reverse=True)
    rc2, out2, _ = sh(['df', '-k', '/'], timeout=20)
    f = out2.splitlines()[-1].split() if out2.strip() else []
    total = used = avail = 0
    if len(f) >= 4:
        try:
            total, used, avail = int(f[1]), int(f[2]), int(f[3])
        except ValueError:
            pass
    return dict(rows=[r for r in rows if r['path'] != '/'][:12],
                total_kb=total, used_kb=used, avail_kb=avail)


def volume_survey():
    """只读：/vol* 数据卷占用与顶层大目录。绝不删除任何东西。"""
    vols = []
    for i in range(1, 11):
        p = '/vol%d' % i
        if not os.path.isdir(p):
            continue
        rc, out, err = sh(['df', '-k', p], timeout=30)
        f = out.splitlines()[-1].split() if out.strip() else []
        if len(f) < 4:
            continue
        try:
            total, used, avail = int(f[1]), int(f[2]), int(f[3])
        except ValueError:
            continue
        rc2, out2, _ = sh(['du', '-k', '--max-depth=1', p], timeout=180)
        tops = []
        for line in out2.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[1] != p:
                try:
                    tops.append(dict(path=parts[1], kb=int(parts[0])))
                except ValueError:
                    pass
        tops.sort(key=lambda x: x['kb'], reverse=True)
        vols.append(dict(mount=p, total_kb=total, used_kb=used,
                         avail_kb=avail,
                         pcent=(100 * used // total) if total else 0,
                         top=tops[:8]))
    return vols


def precheck(R):
    """A2 更新前预检：阈值来自 2026-11-12 OEC 真机更新峰值实测。"""
    sp, bl = R['space'], R['bootloader']
    avail = sp['root_before_kb']
    # 精简后：只留「独有判断」两项 + 有旧内核时才出现的第三项。
    # 系统盘可用 / /boot 可用 / SSH / 可清理缓存都已与顶部统计卡或清理项重复。
    items = [
        dict(key='update_peak', label='更新峰值余量',
             value='需 1.11 GB / 可用 ' + human(avail * 1024),
             ok=avail >= UPDATE_SAFE_KB,
             hint='实测建议线 1.29 GB，低于此值先清理'),
        dict(key='bootfile', label='实引导内核',
             value='存在' if bl.get('boot_kernel_ok') else '缺失',
             ok=bool(bl.get('boot_kernel_ok')),
             hint='缺失时不要更新，先排障'),
    ]
    # /boot 空间断言：平时不占位，低于 50 MB 才条件出现（精简时删掉过，补回来）
    blocking = ['update_peak', 'bootfile']
    if sp['boot_before_kb'] < 50 * 1024:
        items.insert(0, dict(key='boot', label='/boot 空间不足',
                             value=human(sp['boot_before_kb'] * 1024),
                             ok=False,
                             hint='新内核与 initramfs 要写在这里，先清理'))
        blocking.append('boot')
    if R['purge_list']:
        items.append(dict(key='oldkernel', label='可清理旧内核',
                          value='%d 个包' % len(R['purge_list']),
                          ok=False, hint='建议先清掉再更新'))
    ok = all(x['ok'] for x in items if x['key'] in blocking)
    return dict(
        items=items, ok=ok,
        advice='静态检查通过，可以更新' if ok else '建议先清理再更新',
        note='本阈值来自 OEC 单台单次更新实测（fnOS 1.2.1000 → 1.2.1010，'
             '2 秒间隔采样 326 条），其它机型 / 更新包的峰值可能不同，仅供参考：'
             '该次更新系统盘峰值额外占用 %s，'
             '其中约 %s 为临时占用（/var/tmp 解压后回落）、约 %s 为持久占用；'
             '峰值时刻可用一度只剩 %s。按峰值加余量给出 %.2f GB 建议线。'
             '本项只按静态可用空间判断，不保证更新一定成功。'
             % (human(UPDATE_PEAK_KB * 1024), human(UPDATE_TMP_KB * 1024),
                human(UPDATE_NET_KB * 1024), human(UPDATE_MIN_AVAIL_KB * 1024),
                UPDATE_SAFE_KB / 1048576.0),
        profile=dict(peak_kb=UPDATE_PEAK_KB, net_kb=UPDATE_NET_KB,
                     tmp_kb=UPDATE_TMP_KB, min_avail_kb=UPDATE_MIN_AVAIL_KB,
                     safe_kb=UPDATE_SAFE_KB,
                     source='OEC fnOS 1.2.1000→1.2.1010 / 2026-11-12'))


def do_scan(force=False):
    R = base('scan')
    R['space']['root_before_kb'] = avail_kb('/')
    R['space']['boot_before_kb'] = avail_kb('/boot')
    try:
        R['cache_items'] = cache_scan()
        R['selected'] = list(DEFAULT_ITEMS)
        R['cron_source'] = cron_mail_source()
        d = collect()
        R['device'] = host_info()
        R['ssh'] = ssh_info()
        R['bootloader'] = bootloader_info(set(d['keep_versions']))
        R['kernels'] = d['rows']
        R['keep'] = d['keep_pkgs']
        R['remove'] = d['candidates']
        R['purge_list'] = d['purge']
        R['extra_packages'] = d['extra_packages']
        R['hold']['installed'] = d['hold_installed']
        R['hold']['to_unlock'] = d['hold_to_unlock']
        if not R['ssh']['ok']:
            note(R, 'SSH_DISABLED：' + R['ssh']['hint'], 'warnings')
        if R['hold']['installed']:
            note(R, '检测到 %d 个已安装内核包处于 hold（官方默认锁定）：%s' %
                 (len(R['hold']['installed']), ', '.join(R['hold']['installed'])))
        if not d['purge']:
            note(R, '当前运行内核与最新内核均需保留，没有可安全删除的旧内核。')
        else:
            note(R, '扫描到 %d 个可清理旧内核包，预计连带清理 %d 个配套包。' %
                 (len(d['candidates']), len(d['extra_packages'])))
        # 「系统盘缓存扫描：…」那条 note 已删：与清理项卡片逐项重复。
        # A1 / A4 的 du 结果做 5 分钟缓存；A2 预检只用已核对的静态事实
        R['breakdown'] = _cached('cache_breakdown', 300, disk_breakdown, force=force)
        R['volumes'] = _cached('cache_volumes', 300, volume_survey, force=force)
        R['precheck'] = precheck(R)
        R['status'] = 'SCAN'
    except Exception:
        R['status'] = 'ERROR'
        note(R, traceback.format_exc()[-1500:], 'warnings')
    return finish(R)


def do_clean(dry=False, items=None):
    R = base('dry-run' if dry else 'clean')
    R['space']['root_before_kb'] = avail_kb('/')
    R['space']['boot_before_kb'] = avail_kb('/boot')
    # 无 --items 时（CLI / 分支回归测试）只跑旧内核，保证零额外副作用；
    # 前端会显式传入完整勾选项，默认勾选清单由 scan 的 selected 下发。
    selected = list(items) if items is not None else ['old_kernel']
    R['selected'] = selected
    R['cache_items'] = cache_scan()
    actionable = {x['id'] for x in R['cache_items'] if x.get('actionable')}
    cache_ids = [x for x in selected if x in CACHE_IDS and x in actionable]
    skipped = [x for x in selected if x in CACHE_IDS and x not in actionable]
    do_kernel = 'old_kernel' in selected
    try:
        if skipped:
            note(R, '按真机体检结果跳过不可清理项：%s' % ', '.join(skipped))
        d = collect()
        R['device'] = host_info()
        R['ssh'] = ssh_info()
        R['bootloader'] = bootloader_info(set(d['keep_versions']))
        R['kernels'] = d['rows']
        R['keep'] = d['keep_pkgs']
        R['remove'] = d['candidates']
        R['purge_list'] = d['purge']
        R['extra_packages'] = d['extra_packages']
        R['hold']['installed'] = d['hold_installed']
        R['hold']['to_unlock'] = d['hold_to_unlock']

        if not R['ssh']['ok']:
            note(R, 'SSH_DISABLED：' + R['ssh']['hint'], 'warnings')
        note(R, '保留内核：%s' % ', '.join(d['keep_pkgs']))
        if d['meta']:
            note(R, '元包自动保留：%s' % ', '.join(d['meta']))

        # 未勾选旧内核：跳过整个内核阶段（含引导断言与 apt 预演），只走缓存阶段
        if not do_kernel:
            if not cache_ids:
                R['status'] = 'NO_TARGET'
                note(R, 'NO_TARGET：没有勾选任何清理项，未对系统做任何改动。',
                     'warnings')
            else:
                R['status'] = 'CACHE_ONLY'
                note(R, '未勾选旧内核清理，跳过内核卸载与引导断言；'
                        '仅处理勾选的系统盘缓存项。')
            return R

        # 安全断言 A：当前运行内核必须有对应 dpkg 包
        if d['cur_pkg'] not in d['imgs']:
            R['status'] = 'UNSAFE_PLAN'
            note(R, '当前运行内核 %s 在 dpkg 中没有对应包，无法确定保留边界，已中止。' %
                 d['cur'], 'warnings')
            return R

        # 安全断言 B：实际引导链路
        bl = R['bootloader']
        if not bl['boot_kernel_ok']:
            R['status'] = 'UNSAFE_PLAN'
            note(R, '实际引导指向的内核文件不存在（%s），已中止以免无法开机。' %
                 bl.get('boot_kernel_path'), 'warnings')
            return R
        if bl.get('boot_on_old'):
            R['status'] = 'UNSAFE_PLAN'
            note(R, '实际引导（%s）指向的是将被删除的旧内核 %s，已中止；'
                    '请先重启一次让设备切到新内核。' %
                 (bl['real'], bl['boot_version']), 'warnings')
            return R
        # fail-closed：非飞牛内核命名 / 纯 GRUB / 配置格式未知时，
        # 解析不出引导版本就中止，而不是默认当作安全。
        if not bl.get('boot_version_parsed'):
            R['status'] = 'UNSAFE_PLAN'
            note(R, 'UNSAFE_PLAN：无法从实引导配置解析引导内核版本'
                    '（%s），为避免在未知引导链路上误删内核已中止；'
                    '原始引导配置可用「复制诊断信息」查看。' %
                 (bl.get('real') or '未知'), 'warnings')
            return R
        note(R, '实引导链路：%s → %s（文件存在，且指向保留内核）' %
             (bl['real'], bl.get('boot_kernel_path') or 'grub.cfg'))

        # 无旧内核分支
        if not d['purge']:
            R['status'] = 'NO_OLD_KERNEL'
            note(R, '没有可安全删除的旧内核；仍会按要求强制执行 update-grub。')
            return R

        # 安全断言 C：apt 预演不得触碰保留包
        rc, sim_out, sim_err = sh(['apt-get', '-s', 'purge'] + d['purge'],
                                  timeout=240)
        sim = (sim_out + sim_err)
        R['purge']['simulate'] = sim[-5000:]
        planned = re.findall(r'^\s*(?:Remv|Purg)\s+(\S+)', sim_out, re.M)
        protected = set(d['keep_pkgs']) | set(d['meta']) | {
            'linux-headers-arm64', 'linux-libc-dev', 'linux-base',
            'initramfs-tools', 'initramfs-tools-core',
            'linux-modules-trim-extra', 'grub2-common', 'grub-common'}
        unsafe = [p for p in planned if p in protected]
        if rc != 0:
            R['status'] = 'UNSAFE_PLAN'
            note(R, 'apt-get -s purge 预演失败（rc=%d），已中止：%s' %
                 (rc, sim_err[-600:]), 'warnings')
            return R
        # E2：fail-closed —— 有待清理包却解析不出预演计划，说明 apt 输出
        # 格式/locale 变了，负向白名单此时形同虚设，宁可中止不可裸奔 purge。
        if d['purge'] and not planned:
            R['status'] = 'UNSAFE_PLAN'
            note(R, 'UNSAFE_PLAN：apt 预演未能解析出任何待删包（输出格式可能变化），'
                    '白名单无法校验，已 fail-closed 中止；原始预演见诊断信息。',
                 'warnings')
            return R
        if unsafe:
            R['status'] = 'UNSAFE_PLAN'
            note(R, 'UNSAFE_PLAN：预演将删除保留包 %s，已安全中止。' %
                 ', '.join(unsafe), 'warnings')
            return R
        # E2：正向白名单 —— 预演里若出现计划外且不属于清理版本族的「内核系」
        # 包（如依赖树连带删 u-boot-tools / grub-efi），同样中止。
        planned_set = set(planned)
        allowed_extra = set(d['purge'])
        surprise = []
        for p in sorted(planned_set - allowed_extra):
            if p.startswith(('linux-image-', 'linux-headers-', 'linux-modules-',
                             'linux-modules-trim-', 'initramfs-',
                             'grub-', 'grub2-', 'u-boot')):
                surprise.append(p)
        if surprise:
            R['status'] = 'UNSAFE_PLAN'
            note(R, 'UNSAFE_PLAN：预演将删除计划外的内核/引导相关包 %s，'
                    '已安全中止（正向白名单）。' % ', '.join(surprise), 'warnings')
            return R
        note(R, 'apt 预演通过：将删除 %d 个包，未触碰保留内核与计划外的引导包。' %
             len(planned))

        if dry:
            R['status'] = 'SCAN'
            note(R, 'DRY-RUN：仅预演，未执行卸载；也不会执行 update-grub。')
            return R

        # hold 解锁（沿用用户手动流程）
        if d['hold_to_unlock']:
            note(R, 'HOLD_DETECTED：%d 个待清理包处于官方 hold 锁定状态，'
                    '已按手动流程临时解锁；保留内核的锁定状态不会被改动。'
                 % len(d['hold_to_unlock']), 'warnings')
            for p in d['hold_to_unlock']:
                rc2, out2, err2 = sh(['apt-mark', 'unhold', p], timeout=90)
                if rc2 != 0:
                    R['hold']['failed'].append(p)
                    note(R, '解锁失败：%s → %s' % (p, err2[-300:]), 'warnings')
                else:
                    R['hold']['unlocked'].append(p)
            if R['hold']['failed']:
                R['status'] = 'HOLD_UNLOCK_FAILED'
                note(R, '以下内核被锁定且解锁失败，已跳过清理：%s' %
                     ', '.join(R['hold']['failed']), 'warnings')
                # E1：部分 unhold 已成功时也必须恢复，否则这些包永久停在
                # 非 hold 状态、且下次 collect 不再认领 → 半解锁不自愈。
                if R['hold']['unlocked']:
                    _restore_unlocked(R)
                return R

        # 正式清理
        note(R, '执行 apt-get purge -y %s' % ' '.join(d['purge']))
        rc, out, err = sh(['apt-get', 'purge', '-y'] + d['purge'], timeout=1200)
        R['purge']['rc'] = rc
        R['purge']['output'] = (out + err)[-10000:]
        if rc != 0:
            R['status'] = 'PURGE_FAILED'
            note(R, 'PURGE_FAILED：apt-get purge 返回 %d，现场保持原样；请查看日志后重试。'
                 % rc, 'warnings')
            # 即使失败也把已解锁的包恢复 hold，避免留下"半解锁"状态
            _restore_hold(R, d)
            return R

        _restore_hold(R, d)
        R['status'] = 'OK'
        note(R, '已清理 %d 个包（旧内核 %d 个 + 配套/孤儿包 %d 个）。' %
             (len(d['purge']), len(d['candidates']), len(d['extra_packages'])))
        if R['hold']['restored']:
            note(R, '以下保留内核已重新锁定：%s' % ', '.join(R['hold']['restored']))
        if d['hold_to_unlock']:
            note(R, '临时解锁的 %d 个旧内核包已随 purge 移除；其余保留内核的锁定状态保持原样。'
                 % len(d['hold_to_unlock']))
    except Exception:
        R['status'] = 'ERROR'
        note(R, traceback.format_exc()[-2000:], 'warnings')
    finally:
        # ===== EMMC 缓存阶段：勾选才执行，异常也不阻断下面的铁律 =====
        if not dry:
            try:
                cache_clean(R, cache_ids)
            except Exception:
                note(R, '缓存阶段异常：' + traceback.format_exc()[-800:],
                     'warnings')
                if R['status'] in ('OK', 'NO_OLD_KERNEL', 'CACHE_ONLY', 'SCAN'):
                    R['status'] = 'CACHE_FAILED'
        # ===== 铁律（收窄版）：涉及内核包变更时，无论如何退出都强制刷新 =====
        # 缓存-only 路径不触碰 /boot、内核包与 dpkg 状态，双机实测 grub.cfg
        # 内容前后逐字节一致；跳过可避免无意义写盘、约 3.7s 耗时，
        # 以及把零风险的缓存清理污染成 GRUB_FAILED。用户 2026-11-13 拍板。
        if not dry and do_kernel:
            # E4：先记下内核阶段原始状态，GRUB 失败覆盖 status 时不再丢失
            # 「部分成功 / 安全中止」的信息，历史与前端都能看到。
            R['kernel_phase_status'] = R['status']
            rc_g, out_g = run_update_grub()
            R['grub'] = dict(executed=True, forced=True, rc=rc_g, output=out_g,
                             note='无条件执行（涉及内核包变更，无论清理结果如何）')
            if rc_g != 0:
                R['status'] = 'GRUB_FAILED'
                note(R, 'GRUB_FAILED：sudo update-grub 返回 %d —— %s' %
                     (rc_g, out_g[-800:]), 'warnings')
                note(R, '请不要立即重启设备，先确认 /boot/grub/grub.cfg 是否完好。',
                     'warnings')
            else:
                note(R, 'sudo update-grub 执行成功（rc=0），引导菜单已刷新。')
        elif not dry:
            R['grub'] = dict(executed=False, forced=False, rc=None, output='',
                             note='本次仅清理缓存，未涉及内核与引导，已跳过 update-grub')
        else:
            R['grub'] = dict(executed=False, forced=False, rc=None, output='',
                             note='dry-run 不改动系统，故不执行')
        return finish(R)
    return R


def _restore_unlocked(R):
    """E1：仅恢复本次真正 unhold 成功的包（可能含 headers/modules）。

    调用点是 HOLD_UNLOCK_FAILED：purge 从未发生，这些包必然仍安装，
    直接 apt-mark hold 即可，不依赖再次 selections()（避免 dpkg 状态
    读取时序/缓存导致漏恢复）。apt-mark hold 对已 hold 的包是幂等的。"""
    for p in R['hold'].get('unlocked', []):
        try:
            rc, out, err = sh(['apt-mark', 'hold', p], timeout=90)
            if rc == 0 and p not in R['hold']['restored']:
                R['hold']['restored'].append(p)
                note(R, '已恢复临时解锁的包：%s' % p)
        except Exception:
            pass


def _restore_hold(R, d):
    """把仍安装、且原本是 hold 的 linux-image 包恢复为 hold（官方默认策略）。

    E1：同时覆盖本次已 unhold 成功、但仍安装的包（headers/modules 等），
    它们可能不在 hold_installed（那是纯 image 包集合）里。"""
    sel = selections()
    imgs = dpkg_installed('linux-image-*')
    targets = set(d['hold_installed']) | set(R['hold'].get('unlocked', []))
    for p in sorted(targets):
        if p in imgs and sel.get(p) != 'hold':
            rc, out, err = sh(['apt-mark', 'hold', p], timeout=90)
            if rc == 0 and p not in R['hold']['restored']:
                R['hold']['restored'].append(p)
    if R['hold']['restored']:
        note(R, '已恢复锁定：%s' % ', '.join(R['hold']['restored']))


def main():
    args = sys.argv[1:]
    items = None
    for a in args:
        if a.startswith('--items='):
            items = [x.strip() for x in a.split('=', 1)[1].split(',')
                     if x.strip()]
    if '--fix-cron-mail' in args:
        # 独立操作：不写状态、不跑 grub，只处理 crontab，必须显式 --confirm
        R = do_fix_cron_mail(confirm=('--confirm' in args))
        print(json.dumps(R, ensure_ascii=False, indent=2))
        return 0
    if '--clean' in args:
        R = do_clean(dry=False, items=items)
    elif '--dry-run' in args:
        R = do_clean(dry=True, items=items)
    else:
        R = do_scan(force=('--force' in args))
    print(json.dumps(R, ensure_ascii=False, indent=2))
    return 2 if R['status'] == 'GRUB_FAILED' else 0


if __name__ == '__main__':
    sys.exit(main())
