# -*- coding: utf-8 -*-
"""上传 fpk 工程 → 两台设备只读验证(scan/dry-run) → OEC 上 fnpack build → 回传并解包核验。"""
import io
import os
import sys
import tarfile
import traceback

import paramiko

PW = sys.argv[1]
USER = '浪里小白龙'
HOSTS = [('OEC', '192.168.110.171'), ('OES', '192.168.110.10')]
BASE = r'E:\WorkBuddy产物\2026-11-02-23-07-59\旧内核清理fpk'
LOCAL = os.path.join(BASE, 'src', 'fncleankernel')


def manifest_version():
    """从 manifest 读取 version，用于给 fpk 文件名加版本号（每个版本都备注）。"""
    try:
        with open(os.path.join(LOCAL, 'manifest'), 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip().startswith('version'):
                    return line.split('=', 1)[1].strip()
    except Exception:
        pass
    return ''


VER = manifest_version()
FPK_NAME = 'fncleankernel-V%s.fpk' % VER if VER else 'fncleankernel.fpk'
OUT = os.path.join(BASE, FPK_NAME)
RR = '/vol1/face_mon/fpk_build'
REMOTE = RR + '/fncleankernel'
RVAR = RR + '/var'

TEXT_EXT = {'.py', '.sh', '.js', '.css', '.html', '.json', '.txt', '.ini', '.md'}
NO_EXT_TEXT = {
    'manifest', 'config', 'privilege', 'resource', 'kclean', 'LICENSE',
    'LICENSE.txt',
    'main', 'install_init', 'install_callback', 'uninstall_init',
    'uninstall_callback', 'upgrade_init', 'upgrade_callback',
    'config_init', 'config_callback',
}
EXEC_REL = {'app/bin/kclean', 'app/bin/kernel_clean.py', 'app/web/server.py'}


def is_text(path):
    n = os.path.basename(path)
    return n in NO_EXT_TEXT or os.path.splitext(n)[1].lower() in TEXT_EXT


def run(c, cmd, timeout=600):
    i, o, e = c.exec_command(cmd, timeout=timeout)
    rc = o.channel.recv_exit_status()
    return rc, o.read().decode('utf-8', 'replace'), e.read().decode('utf-8', 'replace')


def mkdirs(sftp, path):
    cur = ''
    for p in path.strip('/').split('/'):
        cur += '/' + p
        try:
            sftp.stat(cur)
        except IOError:
            try:
                sftp.mkdir(cur)
            except IOError:
                pass
        # SFTP 新建目录默认可能落在 000，安装后应用用户会无法遍历，统一 755
        try:
            sftp.chmod(cur, 0o755)
        except IOError:
            pass


def upload(sftp):
    run_dirs = set()
    n = 0
    for root, dirs, files in os.walk(LOCAL):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for fn in files:
            if fn.endswith('.pyc'):
                continue
            lp = os.path.join(root, fn)
            rel = os.path.relpath(lp, LOCAL).replace('\\', '/')
            rp = REMOTE + '/' + rel
            mkdirs(sftp, os.path.dirname(rp))
            if is_text(lp):
                with open(lp, 'r', encoding='utf-8') as f:
                    data = f.read().replace('\r\n', '\n').encode('utf-8')
            else:
                with open(lp, 'rb') as f:
                    data = f.read()
            with sftp.open(rp, 'wb') as f:
                f.write(data)
            mode = 0o755 if (rel.startswith('cmd/') or rel in EXEC_REL) else 0o644
            try:
                sftp.chmod(rp, mode)
            except IOError:
                pass
            n += 1
    return n


def verify_on(c, sftp, tag):
    """只读验证：--scan 与 --dry-run（不卸载、不执行 update-grub）"""
    for mode, label in (('--scan', 'scan'), ('--dry-run', 'dryrun')):
        outp = '%s/%s_%s.out' % (RVAR, label, tag)
        cmd = ("echo '%s' | sudo -S -p '' env TRIM_APPDEST=%s TRIM_PKGVAR=%s "
               "/usr/bin/python3 %s/app/bin/kernel_clean.py %s > %s 2>&1; echo RC=$?"
               % (PW, REMOTE, RVAR, REMOTE, mode, outp))
        rc, o, e = run(c, cmd, timeout=420)
        try:
            with sftp.open(outp, 'r') as f:
                data = f.read().decode('utf-8', 'replace')
        except Exception as ex:
            data = 'READ FAIL %r' % ex
        with open(os.path.join(BASE, 'verify_%s_%s.json' % (label, tag)),
                  'w', encoding='utf-8') as f:
            f.write(data)
        print('  [%s/%s] rc=%s %s bytes=%d' % (tag, label, o.strip(), e.strip(), len(data)))
        # 摘要
        import json as _j
        try:
            R = _j.loads(data)
            print('    status=%s keep=%s remove=%s purge=%s hold=%s ssh=%s grub=%s' % (
                R.get('status'), R.get('keep'), R.get('remove'),
                R.get('purge_list'), R.get('hold', {}).get('installed'),
                R.get('ssh', {}).get('ok'), R.get('bootloader', {}).get('real')))
        except Exception as ex:
            print('    !! not JSON:', data[-600:])


def build(c, sftp):
    cmd = ("cd %s && rm -f *.fpk && echo '%s' | sudo -S -p '' fnpack build -d fncleankernel "
           "> %s/build.log 2>&1; echo RC=$?; cat %s/build.log; "
           "find %s -maxdepth 2 -name '*.fpk' -printf '%%p %%s\\n'"
           % (RR, PW, RR, RR, RR))
    rc, o, e = run(c, cmd, timeout=420)
    print('=== fnpack build ===')
    print(o[:4000])
    print(e[:1000])
    path = None
    for line in o.splitlines():
        if line.endswith('.fpk') or '.fpk ' in line:
            p = line.split()[0]
            if p.endswith('.fpk'):
                path = p
    if not path:
        path = RR + '/' + FPK_NAME
    return path


def fetch_and_verify(c, sftp, remote_fpk):
    with sftp.open(remote_fpk, 'rb') as f:
        data = f.read()
    with open(OUT, 'wb') as f:
        f.write(data)
    print('=== downloaded', OUT, len(data), 'bytes ===')
    with tarfile.open(OUT, 'r:gz') as t:
        outer = t.getnames()
        print('OUTER MEMBERS:')
        for m in t.getmembers():
            print('   ', oct(m.mode), m.name)
        member = [m for m in outer if m.endswith('app.tgz')]
        if not member:
            print('!! NO app.tgz -- 打包异常')
            return
        inner_data = t.extractfile(member[0]).read()
    with tarfile.open(fileobj=io.BytesIO(inner_data), mode='r:gz') as it:
        inner = it.getnames()
        modes = {m.name: m.mode for m in it.getmembers()}
    print('INNER MEMBERS (%d):' % len(inner))
    for n in sorted(inner):
        print('   ', oct(modes.get(n, 0)), n)
    required = ['kernel_clean.py', 'kclean', 'server.py', 'index.html',
                'compat.html', 'app.js', 'style.css', 'ui/config',
                'icon_64.png', 'icon_256.png', 'wechat-promo.png']
    print('=== 关键文件核验 ===')
    for key in required:
        hit = [n for n in inner if key in n]
        print('  %-20s %s' % (key, 'OK ' + hit[0] if hit else '!! MISSING'))
    return inner


def main():
    for tag, host in HOSTS:
        print('=' * 74)
        print('###', tag, host)
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, port=22, username=USER, password=PW, timeout=15,
                  look_for_keys=False, allow_agent=False)
        sftp = c.open_sftp()
        try:
            run(c, 'mkdir -p %s %s && echo ok' % (RR, RVAR))
            n = upload(sftp)
            print('  uploaded %d files (LF normalized)' % n)
            verify_on(c, sftp, tag)
            if tag == 'OEC':
                fpk = build(c, sftp)
                fetch_and_verify(c, sftp, fpk)
        except Exception:
            traceback.print_exc()
        finally:
            sftp.close()
            c.close()


if __name__ == '__main__':
    main()
