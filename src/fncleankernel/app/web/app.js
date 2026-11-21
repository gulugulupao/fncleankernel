/* fncleankernel 前端 · 零依赖 */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var lastScan = null;

  function mb(kb) {
    if (!kb && kb !== 0) return '—';
    return kb >= 1024 * 1024
      ? (kb / 1024 / 1024).toFixed(2) + ' GB'
      : Math.round(kb / 1024) + ' MB';
  }
  function bytesText(n) {
    n = Number(n) || 0;
    if (n >= 1073741824) return (n / 1073741824).toFixed(2) + ' GB';
    if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
    if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
    return n + ' B';
  }
  function pill(cls, txt) {
    var e = $('pill-status');
    e.className = 'pill ' + (cls || '');
    e.textContent = txt;
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }
  function findItem(id) {
    var list = (lastScan && lastScan.cache_items) || [];
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) return list[i];
    }
    return null;
  }

  function renderDevice(R) {
    var d = R.device || {};
    var parts = [];
    // 只显示设备自己声明的事实：hostname 来自 /etc/hostname，
    // 机型名来自 /proc/device-tree/model（回退 board.json model.name）。
    // 拿不到就省略，绝不显示 unknown 或靠白名单猜。
    if (d.hostname) parts.push('<span>设备 <b>' + esc(d.hostname) + '</b></span>');
    if (d.model_name) parts.push('<span>机型 <b>' + esc(d.model_name) + '</b></span>');
    if (d.fnos) parts.push('<span>fnOS <b>' + esc(d.fnos) + '</b></span>');
    if (d.kernel) parts.push('<span>内核 <b>' + esc(d.kernel) + '</b></span>');
    var s = R.ssh || {};
    // SSH 恒 True 时不占位置，未开启才提示（横幅有完整说明）
    if (s.ok === false) parts.push('<span class="dev-warn">SSH 未开启</span>');
    $('devbar').innerHTML = parts.join('') || '<span>设备信息不可用</span>';

    var banner = $('ssh-banner');
    if (s.ok === false) {
      banner.hidden = false;
      $('ssh-banner-text').textContent = s.hint ||
        '请在 飞牛 OS「设置 → 终端/SSH」中手动开启 SSH，以便清理异常时能从电脑远程进入设备排障。清理本身不依赖 SSH。';
    } else {
      banner.hidden = true;
    }
  }

  /* ===== A1 系统盘空间构成 ===== */
  function renderBreakdown(R) {
    var b = R.breakdown || {};
    var rows = b.rows || [];
    var total = Number(b.total_kb) || 0;
    if (!total) {
      $('breakdown-bar').innerHTML = '<div class="empty">未读取到空间构成</div>';
      return;
    }
    var usr = 0, varKb = 0, other = 0;
    for (var i = 0; i < rows.length; i++) {
      var k = Number(rows[i].kb) || 0;
      if (rows[i].path === '/usr') usr += k;
      else if (rows[i].path === '/var') varKb += k;
      else other += k;
    }
    // v1.6.2：free 必须用引擎从 df 读到的 avail_kb，不能用 total - du 之和。
    // du 统计的是文件逻辑占用，btrfs 的块分配/稀疏文件会让它远大于 df 的实际
    // 可用量；此前在 OES 上 du 合计 6.12G/总 6.15G，算出"可用 27MB"，而 df
    // 真实可用 1.48G，构成条显示几乎满、误导用户。
    var free = Number(b.avail_kb);
    if (!isFinite(free) || free < 0) free = Math.max(0, total - usr - varKb - other);
    if (free > total) free = total;
    var duSum = usr + varKb + other;
    // 条形宽度：free 用 df 真值；du 三段按比例缩放到"已用"额度(total-free)，
    // 保证四段相加恰好 100%（否则 du 之和 + free 会超过 total 导致溢出）。
    var usedReal = Math.max(0, total - free);
    var scale = duSum > 0 ? usedReal / duSum : 0;
    function seg(cls, kb, name, widthKb) {
      return '<div class="seg ' + cls + '" style="width:' +
        (Math.max(0, widthKb) / total * 100).toFixed(2) + '%" title="' +
        esc(name) + ' ' + mb(kb) + '"></div>';
    }
    $('breakdown-bar').innerHTML =
      seg('seg-usr', usr, '/usr 系统本体', usr * scale) +
      seg('seg-var', varKb, '/var 日志与缓存', varKb * scale) +
      seg('seg-other', other, '其它系统目录', other * scale) +
      seg('seg-free', free, '可用空间', free);
    $('bar-label').innerHTML = '系统盘共 <b>' + mb(total) + '</b> · 已用 <b>' +
      mb(usedReal) + '</b> · 可用 <b>' + mb(free) + '</b>。其中 <b>/usr 占 ' +
      mb(usr) + '</b>（按文件计），是系统本体，任何清理项都不会动它。';
    $('breakdown-legend').innerHTML =
      '<span class="legend-item"><i class="swatch seg-usr"></i>/usr ' + mb(usr) + '</span>' +
      '<span class="legend-item"><i class="swatch seg-var"></i>/var ' + mb(varKb) + '</span>' +
      '<span class="legend-item"><i class="swatch seg-other"></i>其它 ' + mb(other) + '</span>' +
      '<span class="legend-item"><i class="swatch seg-free"></i>可用 ' + mb(free) + '（df 实测）</span>';
  }

  /* ===== A2 更新前预检 ===== */
  function renderPrecheck(R) {
    var p = R.precheck || {};
    var list = p.items || [];
    $('precheck-list').innerHTML = list.map(function (x) {
      return '<div class="checkrow' + (x.ok ? '' : ' bad') + '">' +
        '<span class="ck">' + (x.ok ? '通过' : '留意') + '</span>' +
        '<span class="cl">' + esc(x.label) + '</span>' +
        '<span class="cv">' + esc(x.value) + '</span>' +
        '<span class="ch">' + esc(x.hint) + '</span></div>';
    }).join('');
    var pp = $('precheck-pill');
    pp.className = 'pill ' + (p.ok ? 'ok' : 'warn');
    pp.textContent = p.advice || '检查中';
    $('precheck-note').textContent = p.note || '';
  }

  /* ===== 清理项逐项勾选 ===== */
  function cacheItemHtml(o) {
    var cls = 'cacheitem' + (o.disabled ? ' muted' : (o.checked ? ' checked' : ''));
    var tag = o.core ? '<span class="tag tag-new">核心功能</span>'
      : (o.disabled ? '<span class="tag tag-info">只读体检</span>'
        : (o.risk === 'mid' ? '<span class="tag tag-mid">需确认</span>'
          : (o.risk === 'info' ? '<span class="tag tag-info">提示</span>'
            : '<span class="tag tag-low">低风险</span>')));
    return '<label class="' + cls + '" data-id="' + esc(o.id) + '">' +
      '<input type="checkbox" value="' + esc(o.id) + '"' +
      (o.checked ? ' checked' : '') + (o.disabled ? ' disabled' : '') + '>' +
      '<span class="c-body">' +
      '<span class="c-name">' + esc(o.name) + ' ' + tag + '</span>' +
      '<span class="c-desc">' + esc(o.desc) + '</span>' +
      '</span>' +
      '<span class="c-size' + (o.disabled ? ' muted' : '') + '">' +
      '<b>' + esc(o.size) + '</b><small>' + esc(o.label) + '</small></span>' +
      '</label>';
  }

  function selectedItems() {
    var out = [];
    var boxes = document.querySelectorAll('#cachelist input[type="checkbox"]');
    for (var i = 0; i < boxes.length; i++) {
      if (boxes[i].checked && !boxes[i].disabled) out.push(boxes[i].value);
    }
    return out;
  }

  function itemLabel(id) {
    if (id === 'old_kernel') return '旧内核及配套包';
    var x = findItem(id);
    return x ? x.name : id;
  }

  // 底部提示与确认弹窗按勾选项动态生成：只有涉及内核包变更才提 update-grub
  function actionNote(sel) {
    return sel.indexOf('old_kernel') >= 0
      ? '清理结束后会强制执行 update-grub'
      : '本次不涉及内核，不会刷新引导菜单';
  }

  function updateSelection() {
    var sel = selectedItems();
    var total = 0, volTotal = 0;
    var items = (lastScan && lastScan.cache_items) || [];
    var skipLabels = ['内存占用', '未发现', '不可用'];
    for (var i = 0; i < items.length; i++) {
      if (sel.indexOf(items[i].id) >= 0 && items[i].actionable !== false &&
          skipLabels.indexOf(items[i].label) < 0) {
        var b = Number(items[i].bytes) || 0;
        // 数据卷项单独统计，绝不混入「系统盘可回收」预估
        if (items[i].scope === 'vol1') volTotal += b;
        else total += b;
      }
    }
    var cards = document.querySelectorAll('#cachelist .cacheitem');
    for (var j = 0; j < cards.length; j++) {
      var box = cards[j].querySelector('input');
      if (box && box.checked && !box.disabled) cards[j].classList.add('checked');
      else cards[j].classList.remove('checked');
    }
    var purgeN = ((lastScan && lastScan.purge_list) || []).length;
    var hasWork = purgeN > 0 || total > 0 || volTotal > 0;
    var eb = $('empty-banner');
    if (!hasWork) {
      eb.hidden = false;
      eb.innerHTML = '<b>系统盘现在很干净。</b> 没有可安全删除的旧内核，' +
        '可清理缓存也是 0，这次打开只做体检即可，不必再点清理。' +
        '上次清理结果见下方「历史记录」。';
    } else {
      eb.hidden = true;
    }
    $('cache-total').innerHTML = '已选 <b>' + sel.length + '</b> 项 · ' +
      '预计可回收系统盘空间 <b>' + bytesText(total) + '</b>' +
      (volTotal > 0 ? '　·　另有数据卷 <b>' + bytesText(volTotal) +
        '</b>（不计入系统盘）' : '');
    $('btn-clean').disabled = sel.length === 0 || !hasWork;
    $('action-note').textContent = actionNote(sel);
  }

  function renderCache(R) {
    var pl = R.purge_list || [];
    var sel = R.selected || ['old_kernel', 'apt_cache'];
    var html = cacheItemHtml({
      id: 'old_kernel', name: '旧内核及配套包', core: true,
      desc: pl.length
        ? '将清理 ' + pl.length + ' 个包；当前运行内核与最新版本内核始终保留，清理前做 apt 预演与实引导断言。'
        : '当前没有可安全删除的旧内核，勾选也不会产生任何删除动作。',
      size: pl.length + ' 个包', label: '待清理',
      checked: sel.indexOf('old_kernel') >= 0, disabled: false, risk: 'low'
    });
    var items = R.cache_items || [];
    var volHeader = false;
    var readonly = [];
    for (var i = 0; i < items.length; i++) {
      var x = items[i];
      // 只读 / 无内容项不再占主列表一整行，收进「体检详情」折叠；
      // 条件满足（例如邮件重新堆积、journal 改为持久化）时会自动回到主列表。
      if (x.actionable === false) {
        readonly.push('<div class="readonly-item" title="' + esc(x.desc) + '">' +
          '<b>' + esc(x.name) + '</b>' +
          '<span>' + esc(String(x.desc).slice(0, 58)) + '…</span>' +
          '<span class="ro-size">' + esc(x.size_str) + '</span></div>');
        continue;
      }
      if (x.scope === 'vol1' && !volHeader) {
        html += '<div class="group-hd">数据卷 · 释放的是数据盘，不影响系统盘可用量</div>';
        volHeader = true;
      }
      html += cacheItemHtml({
        id: x.id, name: x.name, desc: x.desc, size: x.size_str, label: x.label,
        checked: !!x.default && sel.indexOf(x.id) >= 0,
        disabled: false, risk: x.risk
      });
    }
    $('cachelist').innerHTML = html;
    var rf = $('readonly-fold');
    if (readonly.length) {
      $('readonly-list').innerHTML = readonly.join('');
      rf.hidden = false;
    } else {
      rf.hidden = true;
    }
    var boxes = document.querySelectorAll('#cachelist input[type="checkbox"]');
    for (var j = 0; j < boxes.length; j++) {
      boxes[j].addEventListener('change', updateSelection);
    }
    updateSelection();
  }

  /* ===== S4 cron 堵源 ===== */
  function renderCronFix(R) {
    var rows = R.cron_source || [];
    var box = $('cronfix');
    if (!rows.length) { box.hidden = true; return; }
    box.hidden = false;
    $('cronfix-txt').innerHTML = '检测到 <b>' + rows.length +
      '</b> 个定时任务仍在往系统邮箱写信（每分钟一次）。' +
      '只清存量过一阵还会涨回来，可以顺手堵住源头。';
    $('cron-rows').textContent = rows.map(function (r) {
      return '[' + r.user + ']  ' + r.line + '\n     →  ' + r.line + ' > /dev/null 2>&1';
    }).join('\n\n');
  }

  /* ===== A4 数据卷只读体检 ===== */
  function renderVolumes(R) {
    var vols = R.volumes || [];
    if (!vols.length) {
      $('volume-list').innerHTML = '<div class="empty">未检测到数据卷</div>';
      return;
    }
    var mon = null;
    var ci = (R.cache_items || []);
    for (var k = 0; k < ci.length; k++) {
      if (ci[k].id === 'mon_residue') { mon = ci[k]; break; }
    }
    var prefix = '';
    if (mon && mon.actionable && mon.bytes > 0) {
      prefix = '<div class="volnote-box">检测到我们自己留下的监控产物 <b>' +
        esc(mon.size_str) + '</b>（' + (mon.count || 0) +
        ' 个条目）。这一项已获授权，可在上方「清理项」里勾选删除；' +
        '本页其它内容仍全部只读。</div>';
    }
    $('volume-list').innerHTML = prefix + vols.map(function (v) {
      var pct = Number(v.pcent) || 0;
      var tops = (v.top || []).slice(0, 6).map(function (t) {
        var parts = String(t.path).split('/');
        return '<span>' + esc(parts[parts.length - 1] || t.path) +
          ' <b>' + mb(t.kb) + '</b></span>';
      }).join('');
      return '<div class="volcard">' +
        '<div class="volhd"><b>' + esc(v.mount) + '</b><span>可用 ' +
        mb(v.avail_kb) + ' / 共 ' + mb(v.total_kb) + ' · 已用 ' + pct + '%</span></div>' +
        '<div class="volbar"><i style="width:' + Math.min(100, pct) + '%"></i></div>' +
        '<div class="voltop">' + tops + '</div>' +
        '<div class="volnote">只读展示。这里是用户数据与系统模型，本工具不会删除；' +
        '清理系统盘也不会释放这里的空间。</div></div>';
    }).join('');
  }

  /* ===== A3 历史趋势 / S5 上次结果与日志 ===== */
  function loadHistory() {
    fetch('/api/history', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (D) {
        var rows = (D.rows || []).slice(-16);
        if (!rows.length) {
          $('history-chart').innerHTML =
            '<div class="empty">还没有清理记录，执行一次清理后这里会出现趋势。</div>';
          $('history-summary').textContent = '累计 0 次清理';
          return;
        }
        var max = 1;
        var sum = 0;
        for (var i = 0; i < rows.length; i++) {
          var k = Math.max(0, Number(rows[i].reclaimed_kb) || 0);
          if (k > max) max = k;
          sum += k;
        }
        $('history-chart').innerHTML = rows.map(function (x) {
          var k = Math.max(0, Number(x.reclaimed_kb) || 0);
          var h = Math.max(3, Math.round(k / max * 62));
          return '<div class="hcol" title="' + esc(x.time) + ' · ' +
            esc(x.status) + ' · 释放 ' + mb(k) + '">' +
            '<div class="hbar' + (k ? '' : ' zero') + '" style="height:' + h + 'px"></div>' +
            '<div class="hcap">' + esc(String(x.time || '').slice(11, 16)) + '</div></div>';
        }).join('');
        $('history-summary').innerHTML = '最近 ' + rows.length +
          ' 次累计释放系统盘 <b>' + mb(sum) + '</b>';
      })
      .catch(function () {
        $('history-chart').innerHTML = '<div class="empty">历史记录读取失败</div>';
      });
  }

  function loadLast() {
    fetch('/api/last', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (R) {
        if (!R || !R.time) {
          $('last-result').textContent = '尚无执行记录。';
          return;
        }
        $('last-result').innerHTML = '上次执行：<b>' + esc(R.time) + '</b> · ' +
          esc(R.status_text || R.status) + ' · 系统盘释放 <b>' +
          mb(R.space && R.space.reclaimed_kb) + '</b> · 缓存回收 <b>' +
          bytesText(R.cache && R.cache.reclaimed_bytes) + '</b>';
      })
      .catch(function () { $('last-result').textContent = '上次执行结果读取失败。'; });
  }

  function loadLog() {
    fetch('/api/log', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (D) {
        $('full-log').textContent = D.log || '（无日志）';
        var d = $('log-details');
        d.hidden = false;
        d.open = true;
        var fold = $('fold-history');
        if (fold) fold.open = true;   // 外层折叠也要展开，否则日志看不见
      });
  }

  function copyDiag() {
    var R = lastScan || {}, d = R.device || {}, sp = R.space || {}, b = R.bootloader || {};
    var prof = (R.precheck || {}).profile || {};
    var lines = [
      '系统盘清理助手 · 诊断信息',
      '时间: ' + (R.time || '-'),
      '设备(hostname): ' + (d.hostname || '-'),
      '机型(设备树): ' + (d.model_name || '未识别（设备未提供 /proc/device-tree/model）'),
      '机型依据: board.model.id=' + (d.model_id || '-') +
        ' / compatible=' + ((d.compat_items || []).join(',') || '-'),
      'SoC 诊断标签: ' + (d.soc || '无（未做机型归类，识别字段不参与清理判断）'),
      '架构: ' + (d.arch || '-'),
      'fnOS: ' + (d.fnos || '-') + '  内核: ' + (d.kernel || '-'),
      '系统盘可用: ' + mb(sp.root_before_kb) + '  /boot 可用: ' + mb(sp.boot_before_kb),
      '实引导: ' + (b.real || '-') + ' → ' + (b.boot_kernel_path || '-'),
      '引导版本解析: ' + (b.boot_version_parsed ? '成功' : '失败（清理会安全中止）'),
      '实引导原始配置: ' + String(b.detail || '-').replace(/\s+/g, ' ').slice(0, 180),
      '峰值阈值来源: ' + (prof.source || '-') + '（单台单次实测，其它机型仅供参考）',
      'SSH: ' + ((R.ssh || {}).ok ? '已开启' : '未开启'),
      '可清理旧内核: ' + ((R.purge_list || []).length) + ' 个包',
      '清理项:'
    ];
    ((R.cache_items || [])).forEach(function (x) {
      lines.push('  ' + x.name + ' = ' + x.size_str +
        (x.actionable === false ? '（只读）' : ''));
    });
    var ta = document.createElement('textarea');
    ta.value = lines.join('\n');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      pill('ok', '诊断信息已复制');
    } catch (e) {
      pill('warn', '复制失败');
    }
    document.body.removeChild(ta);
    // v1.6.2：此前这里写死 pill('', '内核已是最新')，有旧内核时会误报"已是最新"。
    // 恢复成与当前扫描一致的状态（同 renderScan 末尾口径）。
    setTimeout(function () {
      if (lastScan) {
        var olds = (lastScan.kernels || []).filter(function (k) {
          return k.action === 'remove';
        });
        var pl = lastScan.purge_list || [];
        pill('', pl.length ? '发现 ' + olds.length + ' 个旧内核' : '内核已是最新');
      }
    }, 2500);
  }

  function renderBoot(R) {
    var b = R.bootloader || {};
    var bits = [];
    bits.push('<b>实际引导：</b>' + esc(b.real || '未知'));
    if (b.boot_kernel_path) {
      bits.push('<b>引导内核文件：</b>' + esc(b.boot_kernel_path) +
        ' <span style="color:' + (b.boot_kernel_ok ? '#2b8a3e' : '#c92a2a') + '">' +
        (b.boot_kernel_ok ? '存在' : '缺失') + '</span>');
    }
    bits.push('<b>grub.cfg：</b>' + (b.grub_cfg ? '存在' : '不存在'));
    bits.push('<b>update-grub：</b>' + esc(b.update_grub || '未找到'));
    $('bootinfo').innerHTML = bits.join('<br>');
  }

  function renderScan(R) {
    lastScan = R;
    renderDevice(R);
    renderBoot(R);

    var sp = R.space || {};
    $('s-root').textContent = mb(sp.root_before_kb || sp.root_after_kb);
    $('s-boot').textContent = mb(sp.boot_before_kb || sp.boot_after_kb);
    var d = R.device || {};
    $('s-kernel').textContent = d.kernel || '—';
    var newest = (R.kernels || []).filter(function (k) { return k.is_latest; })[0];
    $('s-latest').textContent = '最新版本 ' + (newest ? newest.version : '—');

    var olds = (R.kernels || []).filter(function (k) { return k.action === 'remove'; });
    // 第 4 张卡改为「更新前建议线」，数值来自真机实测 profile，不写死
    var prof = (R.precheck || {}).profile || {};
    $('s-safe').textContent = prof.safe_kb ? mb(prof.safe_kb) : '1.29 GB';
    $('s-safe').title = '来自 OEC fnOS 1.2.1000→1.2.1010 单次实测，其它机型仅供参考';
    $('s-safe-foot').textContent = prof.peak_kb
      ? '更新峰值参考 ' + mb(prof.peak_kb) : '更新峰值参考 1.11 GB';

    var rows = R.kernels || [];
    if (!rows.length) {
      $('kbody').innerHTML = '<tr><td colspan="6" class="empty">未读取到已安装的内核包</td></tr>';
    } else {
      $('kbody').innerHTML = rows.map(function (k) {
        var tags = '';
        if (k.is_current) tags += '<span class="tag tag-cur">运行中</span>';
        if (k.is_latest) tags += '<span class="tag tag-new">最新</span>';
        if (k.is_meta) tags += '<span class="tag tag-meta">元包</span>';
        if (!tags) tags = '<span style="color:#8b949e">—</span>';
        var hold = k.want === 'hold' ? '<span class="tag tag-hold">hold</span>' : '<span style="color:#8b949e">否</span>';
        var act = k.action === 'remove'
          ? '<span class="act-remove">清理</span>'
          : '<span class="act-keep">保留</span>';
        return '<tr><td class="mono">' + esc(k.pkg) + '</td>' +
          '<td class="mono">' + esc(k.version) + '</td>' +
          '<td>' + tags + '</td><td>' + hold + '</td>' +
          '<td>' + (k.size_kb ? Math.round(k.size_kb / 1024) + ' MB' : '—') + '</td>' +
          '<td>' + act + '</td></tr>';
      }).join('');
    }

    var pl = R.purge_list || [];
    if (!pl.length) {
      $('plan').innerHTML = '<b>清理计划：</b>没有可安全删除的旧内核，当前运行内核与最新版本内核均需保留。';
    } else {
      $('plan').innerHTML = '<b>清理计划（' + pl.length + ' 个包）：</b><br><span class="mono">' +
        esc(pl.join('  ')) + '</span>';
    }
    renderCache(R);
    pill('', pl.length ? '发现 ' + olds.length + ' 个旧内核' : '内核已是最新');
  }

  function renderResult(R) {
    $('result-card').hidden = false;
    $('r-time').textContent = R.time || '';
    var st = R.status;
    var bad = ['GRUB_FAILED', 'PURGE_FAILED', 'ERROR', 'UNSAFE_PLAN',
               'HOLD_UNLOCK_FAILED', 'CACHE_FAILED'].indexOf(st) >= 0;
    var mid = ['NO_OLD_KERNEL', 'NO_TARGET', 'CACHE_ONLY'].indexOf(st) >= 0;
    var head = $('r-head');
    head.className = 'result-head' + (bad ? ' bad' : (mid ? ' mid' : ''));
    $('r-title').textContent = R.status_text || st;
    // E4：GRUB 失败覆盖了内核阶段原始状态时，把「原本的结果」显示出来，
    // 避免把「安全中止啥也没删」和「删了内核但引导失败」混为一谈。
    var phase = R.kernel_phase_status || '';
    var PHASE_LABEL = {
      OK: '清理成功', NO_OLD_KERNEL: '无旧内核可清', NO_TARGET: '无目标',
      CACHE_ONLY: '仅缓存清理', UNSAFE_PLAN: '安全中止',
      HOLD_UNLOCK_FAILED: '解锁失败', PURGE_FAILED: '卸载失败',
      ERROR: '引擎异常'
    };
    var phaseTip = (st === 'GRUB_FAILED' && phase && phase !== st)
      ? '（内核阶段：' + (PHASE_LABEL[phase] || phase) +
        '。引导刷新失败不改变这一结果，请先确认 grub.cfg 再决定是否重启。）' : '';
    // v1.6.0：描述必须与引导实际状态一致。此前 ERROR（如请求被拒、
    // 引擎异常）也会显示"引导配置仍已强制刷新"，但 grub.executed=false
    // 时引擎压根没启动、什么都没刷新——红字报错配绿字"已刷新"自相矛盾。
    var grubExec = !!(R.grub && R.grub.executed);
    var desc;
    if (!grubExec && (st === 'ERROR' || st === 'NO_TARGET')) {
      // 请求被拒 / 无任何可执行项：如实说没动系统
      desc = '本次未执行清理，系统文件与引导配置均未改动。';
    } else if (st === 'OK') {
      desc = '选中项已处理完成；保留内核与锁定状态均已复核，引导配置已强制刷新。';
    } else if (bad) {
      desc = grubExec
        ? '详情见下方提示与日志；引导配置已按铁律强制刷新。'
        : '详情见下方提示与日志；本次未刷新引导配置。';
    } else {
      desc = grubExec
        ? '本次没有内核包被删除，但已按要求强制刷新引导配置。'
        : '本次没有内核包被删除，引导配置未刷新。';
    }
    $('r-desc').textContent = desc + phaseTip;
    pill(bad ? 'danger' : (mid ? 'warn' : 'ok'), R.status_text || st);

    var g = R.grub || {};
    var gb = $('r-grub');
    var gok = g.executed && g.rc === 0;
    gb.className = 'grubbox' + (g.executed && !gok ? ' bad' : '');
    // 铁律必须展示，但成功时压成一行；失败才展开完整输出与「请勿重启」
    $('r-grub-text').textContent = g.executed
      ? (gok ? '引导菜单已强制刷新（rc=0）'
             : '刷新失败 rc=' + g.rc + '，请勿立即重启：' +
               String(g.output || '').replace(/\s+/g, ' ').slice(0, 220))
      : (g.note || '本次未执行');

    var ws = R.warnings || [];
    $('r-warn').innerHTML = ws.map(function (w) {
      var danger = /GRUB_FAILED|PURGE_FAILED|请勿立即重启/.test(w);
      return '<div class="warnitem' + (danger ? ' danger' : '') + '">' + esc(w) + '</div>';
    }).join('') || '<div style="color:#8b949e;font-size:12.5px">无警告。</div>';

    // 步骤日志已从结果区移除：用户只看状态 / 空间 / 缓存明细，
    // 完整过程仍在下方「查看完整执行日志」与 /api/log 里可查。
    var sp = R.space || {};
    $('r-space').innerHTML = '系统盘可用：<b>' + mb(sp.root_before_kb) + '</b> → <b>' +
      mb(sp.root_after_kb) + '</b>（释放 ' + mb(sp.reclaimed_kb) + '）　·　/boot 可用：<b>' +
      mb(sp.boot_before_kb) + '</b> → <b>' + mb(sp.boot_after_kb) + '</b>' +
      (sp.low ? '　<span style="color:#d9480f">空间仍偏紧张</span>' : '');

    var ch = R.cache || {};
    var cr = ch.results || [];
    var scopeMap = {};
    (R.cache_items || []).forEach(function (it) {
      if (it.scope) scopeMap[it.id] = it.scope;
    });
    var chtml = '<strong>缓存清理明细</strong>';
    if (!cr.length) {
      chtml += '<div class="cacheline">本次没有勾选可清理的缓存项。</div>';
    } else {
      for (var ci = 0; ci < cr.length; ci++) {
        var x = cr[ci];
        var cbad = (x.rc !== 0 && x.rc !== null);
        chtml += '<div class="cacheline' + (cbad ? ' bad' : '') + '">' +
          esc(x.name) + '：回收 <b>' + bytesText(x.reclaimed_bytes) + '</b>' +
          (scopeMap[x.id] === 'vol1' ? ' <span class="scope-tag">数据卷</span>' : '') +
          (cbad ? '（rc=' + x.rc + '，失败）' : '') +
          (x.detail ? ' · ' + esc(String(x.detail).slice(0, 160)) : '') + '</div>';
      }
      chtml += '<div class="cache-sum">缓存合计回收 ' +
        bytesText(ch.reclaimed_bytes) + '</div>';
    }
    $('r-cache').innerHTML = chtml;

    var log = (R.log || []).slice();
    var po = R.purge && R.purge.output;
    if (po) log.push('---- apt-get 输出 ----', String(po));
    var go = g.output;
    if (go) log.push('---- update-grub 输出 ----', String(go));
    $('r-log').textContent = log.join('\n') || '（无日志）';
    $('result-card').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function scan(force) {
    pill('busy', '扫描中');
    $('btn-scan').disabled = true;
    // E3：「重新扫描」按钮穿透服务端节流与 du 缓存，首屏加载走缓存。
    fetch(force ? '/api/scan?force=1' : '/api/scan', { cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (R) {
        renderScan(R);
        renderBreakdown(R);
        renderPrecheck(R);
        renderCronFix(R);
        renderVolumes(R);
        loadHistory();
        loadLast();
        if (R.status === 'ERROR') renderResult(R);
      })
      .catch(function (e) { pill('danger', '扫描失败'); $('plan').textContent = String(e); })
      .finally(function () { $('btn-scan').disabled = false; });
  }

  function clean() {
    var sel = selectedItems();
    if (!sel.length) return;
    var lines = sel.map(function (id) {
      var x = findItem(id);
      return '· ' + itemLabel(id) + (x ? '（' + x.size_str + '）' : '');
    });
    var tail = sel.indexOf('old_kernel') >= 0
      ? '当前运行内核与最新版本内核始终保留。\n清理结束后将强制执行 sudo update-grub。'
      : '本次只清缓存，不涉及内核与引导，不会执行 update-grub。';
    if (!window.confirm('即将执行以下 ' + sel.length + ' 项清理：\n\n' +
      lines.join('\n') + '\n\n' + tail + '\n\n确认继续？')) return;
    // 中风险项需要第二次确认
    var risky = sel.filter(function (id) { var x = findItem(id); return x && x.risk === 'mid'; });
    if (risky.length) {
      var names = risky.map(function (id) { return '· ' + itemLabel(id); });
      if (!window.confirm('以下项目需要额外确认：\n\n' + names.join('\n') +
        '\n\n它们会调用系统日志轮转 / 按邮件逐封过滤 / 把第三方应用大日志截断为 0 字节' +
        '（文件保留、不删除），请确认已看过上方每项的说明。\n\n继续？')) return;
    }
    var btn = $('btn-clean');
    btn.disabled = true;
    btn.textContent = '清理中…（约 1–3 分钟）';
    pill('busy', '清理执行中');
    $('action-note').textContent = '正在执行，请勿关闭页面';
    fetch('/api/clean', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json',
                 'X-Fnclean-Client': 'web' },
      body: JSON.stringify({ items: sel, confirm: true })
    })
      .then(function (r) { return r.json(); })
      .then(function (R) {
        renderResult(R);
        setTimeout(scan, 1200);
      })
      .catch(function (e) {
        renderResult({ status: 'ERROR', status_text: '请求失败',
          warnings: [String(e)], log: [], grub: { executed: false },
          space: {}, cache: { results: [], reclaimed_bytes: 0 } });
      })
      .finally(function () {
        btn.textContent = '一键清理选中项';
        updateSelection();   // 内部会按当前勾选项恢复底部提示文案
      });
  }

  /* ===== 公众号二维码灯箱（照搬 FnSmartdisk 原版交互 + 键盘可达） ===== */
  var qrModal = $('qrModal');
  function qrOpen() { if (qrModal) qrModal.classList.remove('hidden'); }
  function qrClose() { if (qrModal) qrModal.classList.add('hidden'); }
  var qrTrigger = $('qrTrigger');
  if (qrTrigger) {
    qrTrigger.addEventListener('click', qrOpen);
    qrTrigger.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); qrOpen(); }
    });
  }
  $('qrClose').addEventListener('click', qrClose);
  $('qrBackdrop').addEventListener('click', qrClose);
  if (qrModal) qrModal.addEventListener('click', function (e) {
    if (e.target === qrModal) qrClose();
  });

  /* ===== cron 堵源：自定义弹窗 + 再一层确认 ===== */
  var cronModal = $('cronModal');
  function cronOpen() { if (cronModal) cronModal.classList.remove('hidden'); }
  function cronClose() { if (cronModal) cronModal.classList.add('hidden'); }
  $('btn-cron-fix').addEventListener('click', cronOpen);
  $('cronClose').addEventListener('click', cronClose);
  $('cronCancel').addEventListener('click', cronClose);
  $('cronBackdrop').addEventListener('click', cronClose);
  if (cronModal) cronModal.addEventListener('click', function (e) {
    if (e.target === cronModal) cronClose();
  });
  $('cronConfirm').addEventListener('click', function () {
    var rows = (lastScan && lastScan.cron_source) || [];
    if (!window.confirm('再次确认：将修改 ' + rows.length +
      ' 份定时任务，只补输出重定向，改前自动备份原始配置。\n\n继续？')) return;
    cronClose();
    fetch('/api/fix-cron-mail', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json',
                 'X-Fnclean-Client': 'web' },
      body: JSON.stringify({ confirm: true })
    })
      .then(function (r) { return r.json(); })
      .then(function (D) {
        if (D.ok) {
          pill('ok', '已堵住邮件源头');
          $('cronfix-txt').innerHTML = '<b>已修改 ' + (D.changed || []).length +
            ' 份定时任务</b>，原始配置已备份。之后不会再产生新的 Cron 邮件。';
        } else {
          pill('warn', '操作未完全成功');
          $('cronfix-txt').innerHTML = '<b>未完成：</b>' +
            esc((D.warnings || []).join('；') || '未知原因');
        }
        setTimeout(scan, 800);
      })
      .catch(function (e) {
        $('cronfix-txt').textContent = '请求失败：' + e;
      });
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { qrClose(); cronClose(); }
  });

  $('btn-scan').addEventListener('click', function () { scan(true); });
  $('btn-clean').addEventListener('click', clean);
  $('btn-load-log').addEventListener('click', loadLog);
  $('btn-copy-diag').addEventListener('click', copyDiag);
  // v1.6.2：统一用 fetch 等服务端采集真正完成（诊断要几十秒，早前 WebView 分支
  // 用 iframe + 固定 1.5s 定时器，采集没完就报"已发起下载"，是假成功）。
  // 拿到 blob 后：优先用系统分享（App WebView 里最可靠），否则 a.download；
  // 都不支持则明确提示用"复制诊断信息"兜底，不再谎报成功。
  function inAppWebView() {
    var ua = navigator.userAgent || '';
    var standalone = (window.navigator.standalone === true ||
                      (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches));
    return standalone || (/Mobile/i.test(ua) && !/MicroMessenger/i.test(ua));
  }
  $('btn-export-diag').addEventListener('click', function () {
    var btn = $('btn-export-diag');
    btn.disabled = true;
    pill('busy', '正在采集诊断（约需几十秒）');
    fetch('/api/diagnose', { cache: 'no-store' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.blob();
      })
      .then(function (blob) {
        var file = new File([blob], 'fncleankernel-diagnose.zip',
                            { type: 'application/zip' });
        // App/WebView：优先系统分享面板，用户可存到文件/发给作者
        if (inAppWebView() && navigator.canShare && navigator.canShare({ files: [file] })) {
          return navigator.share({ files: [file], title: '诊断包' }).then(function () {
            pill('ok', '诊断包已生成，请在分享面板中保存或发送');
          });
        }
        // 桌面/普通浏览器：a.download
        if (!inAppWebView()) {
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url;
          a.download = 'fncleankernel-diagnose.zip';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          setTimeout(function () { URL.revokeObjectURL(url); }, 3000);
          pill('ok', '诊断包已导出');
          return;
        }
        // WebView 既无分享也无下载能力：如实说明，给兜底路径
        pill('warn', '诊断包已生成，但此 App 不支持直接保存；请用「复制诊断信息」发给作者');
      })
      .catch(function (e) { pill('danger', '导出失败：' + String(e)); })
      .finally(function () { btn.disabled = false; });
  });
  scan();
})();
