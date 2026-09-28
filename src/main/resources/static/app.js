const $ = (s, el=document) => el.querySelector(s);
const api = async (path, opts={}) => {
  const r = await fetch(path, {headers:{'Content-Type':'application/json'}, ...opts});
  if (!r.ok) throw new Error((await r.json().catch(()=>({}))).error || r.statusText);
  return r.json();
};
const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const hex = v => v;
let state = { files: [], snapshots: [], detailFile: null, tab: 'compass' };

const tabs = $('#tabs');
tabs.addEventListener('click', e => {
  if (e.target.dataset.tab) {
    state.tab = e.target.dataset.tab;
    [...tabs.children].forEach(b => b.classList.toggle('active', b === e.target));
    render();
  }
});

async function refresh() {
  state.files = await api('/api/files');
  state.snapshots = await api('/api/snapshots');
  render();
}

function render() { renderers[state.tab](); }

const renderers = {};

// ---------- Compass ----------
renderers.compass = () => {
  $('#view').innerHTML = `
  <div class="card">
    <h2>批量粘贴栈地址</h2>
    <div class="row" style="margin-bottom:10px">
      <select id="snapSel" style="width:280px"><option value="">无快照（相对地址 / bias=0）</option>
        ${state.snapshots.map(s=>`<option value="${s.id}">#${s.id} ${esc(s.name)}${s.fixed?'（已固定）':''}</option>`).join('')}
      </select>
      <button class="ghost" id="saveCrashBtn">存为崩溃记录</button>
    </div>
    <textarea id="tokens" placeholder="每行一个地址，支持 0x.. 与 seg:addr，例如：&#10;0x40117a&#10;1:0x7f8012345678"></textarea>
    <div style="margin-top:10px"><button class="act" id="resolveBtn">解析地址</button></div>
  </div>
  <div id="results"></div>`;
  $('#resolveBtn').onclick = async () => {
    const tokens = $('#tokens').value.split(/\s+/).filter(Boolean);
    const snapshotId = $('#snapSel').value ? Number($('#snapSel').value) : null;
    const data = await api('/api/resolve', {method:'POST', body:JSON.stringify({tokens, snapshotId})});
    $('#results').innerHTML = data.results.map(renderResolution).join('');
  };
  $('#saveCrashBtn').onclick = async () => {
    const tokens = $('#tokens').value.split(/\s+/).filter(Boolean);
    if (!tokens.length) return;
    const title = prompt('崩溃记录标题', 'crash @ ' + new Date().toISOString());
    if (!title) return;
    const snapshotId = $('#snapSel').value ? Number($('#snapSel').value) : null;
    const c = await api('/api/crashes', {method:'POST', body:JSON.stringify({title, tokens, snapshotId})});
    alert('已保存崩溃记录 #' + c.id);
  };
};

function badge(level, text) {
  const cls = level==='ERROR'?'b-err': level==='WARNING'?'b-warn':'b-info';
  return `<span class="badge ${cls}">${esc(text)}</span>`;
}

function renderResolution(r) {
  const head = `<div class="card">
    <h2><span class="mono addr">${esc(r.inputToken)}</span>
      <span class="pill">seg ${r.segment}</span>
      <span class="pill">runtime ${esc(r.runtimeAddress)}</span>
      ${r.resolved ? badge('INFO','已定位') : badge('ERROR','未匹配')}
    </h2>`;
  if (!r.matches.length) {
    return head + `<p class="muted">任何模块/代次都未覆盖该地址。未匹配代次：[${r.unmatchedGenerations.join(', ')}]</p></div>`;
  }
  return head + r.matches.map(renderMatch).join('') + '</div>';
}

function renderMatch(m) {
  const w = m.winner;
  const winLine = w && w.line ? `${esc(w.line.file)}:${w.line.line}:${w.line.column}` : '<span class="muted">无行号</span>';
  const chain = m.inlineChain.map(f =>
    `<div class="tree"><span class="ind">${'  '.repeat(f.depth)}├─ depth ${f.depth}</span> ${esc(f.name)}` +
    (f.callFile ? ` <span class="muted">调用点 ${esc(f.callFile)}:${f.callLine ?? '?'}</span>` : '') +
    (f.declaredFile ? ` <span class="muted">声明 ${esc(f.declaredFile)}:${f.declaredLine ?? '?'}</span>` : '') +
    ` <span class="pill">die ${esc(f.dieOffset)}</span></div>`).join('');
  return `<div style="border-top:1px solid #24304a;padding:10px 0">
    <div class="row" style="gap:14px">
      <b>#${m.moduleId} ${esc(m.moduleName)}</b>
      <span class="pill">文件版本 v${m.debugFileVersionId}</span>
      <span class="pill">加载代次 gen ${m.loadGeneration}</span>
      <span class="pill">load bias <span class="addr">${esc(m.loadBias)}</span></span>
      <span class="pill">relative <span class="addr">${esc(m.relativeAddress)}</span></span>
      <span class="pill">${m.candidateCount} 个合法候选</span>
    </div>
    <p style="margin:8px 0 4px">落点：${winLine}
      ${w ? `<span class="pill">line table v${w.line?.tableVersion ?? '-'}</span>` : ''}
      ${w?.symbol ? `<span class="pill">符号 ${esc(w.symbol)}</span>` : ''}
      ${w ? `<span class="pill">CU ${esc(w.cuName ?? '')}</span>` : ''}
    </p>
    ${chain ? `<div style="margin:6px 0"><div class="muted" style="font-size:12px">内联调用链（叶→根）：</div>${chain}</div>` : ''}
    <details><summary class="muted" style="cursor:pointer">全部候选与排序依据</summary>
      <table><tr><th></th><th>范围</th><th>kind</th><th>宽度</th><th>深度</th><th>显式优先级</th><th>符号 / 行</th></tr>
      ${m.candidates.map(c=>`<tr>
        <td>${c.isWinner?badge('INFO','WIN'):''}</td>
        <td class="mono addr">${esc(c.rangeStart)}–${esc(c.rangeEnd)}</td>
        <td>${esc(c.kind)}</td><td class="mono">${esc(c.rangeWidth)}</td>
        <td>${c.inlineDepth}</td><td>${c.explicitPriority}</td>
        <td>${esc(c.symbol ?? '')} ${c.line?`<span class="muted">${esc(c.line.file)}:${c.line.line}</span>`:''}</td>
      </tr>`).join('')}</table>
    </details>
    ${m.reliability.length?`<div style="margin-top:6px">${m.reliability.map(x=>badge(x.severity,x.code)).join(' ')}</div>`:''}
  </div>`;
}

// ---------- Files / versions ----------
renderers.files = () => {
  $('#view').innerHTML = `
  <div class="card">
    <h2>导入新的调试文件（形成版本，不改旧崩溃记录）</h2>
    <div class="row">
      <input id="impName" placeholder="模块名，例如 libcrash.so" style="width:240px">
      <input id="impPath" placeholder="服务器本地可执行文件 / 分离调试文件路径" style="flex:1">
      <button class="act" id="impBtn">按路径导入</button>
    </div>
    <p class="muted" style="font-size:12px">同名文件重复导入自动递增 version_no；崩溃记录绑定导入时的文件 id，历史结论不会被新文件改写。</p>
  </div>
  <div class="card"><h2>已导入版本</h2>
    <table><tr><th>id</th><th>名称</th><th>版本</th><th>sha256</th><th>CU</th><th>范围</th><th>问题</th><th></th></tr>
      ${state.files.map(f=>`<tr>
        <td>${f.id}</td><td>${esc(f.name)}</td><td>v${f.versionNo}</td>
        <td class="mono muted" style="font-size:11px">${esc(f.sha256.slice(0,18))}…</td>
        <td>${f.cuCount}</td><td>${f.rangeCount}</td>
        <td>${f.issueCount?badge(f.issueCount?'WARNING':'INFO', f.issueCount+''):'0'}</td>
        <td><button class="ghost" data-open="${f.id}">打开</button></td>
      </tr>`).join('')}
    </table>
  </div>`;
  $('#impBtn').onclick = async () => {
    const name = $('#impName').value.trim(), path = $('#impPath').value.trim();
    if (!name || !path) return alert('名称与路径必填');
    await api('/api/files/import', {method:'POST', body:JSON.stringify({name, path})});
    await refresh();
  };
  document.querySelectorAll('[data-open]').forEach(b => b.onclick = () => {
    state.detailFile = Number(b.dataset.open);
    state.tab = 'detail';
    [...tabs.children].forEach(x => x.classList.toggle('active', x.dataset.tab==='detail'));
    render();
  });
};

// ---------- Detail ----------
renderers.detail = async () => {
  if (!state.detailFile) {
    $('#view').innerHTML = '<div class="card"><h2>请从“调试文件版本”打开一个文件</h2></div>';
    return;
  }
  const [file, cus, ranges, seqs] = await Promise.all([
    api('/api/files/'+state.detailFile),
    api('/api/files/'+state.detailFile+'/cus'),
    api('/api/files/'+state.detailFile+'/ranges'),
    api('/api/files/'+state.detailFile+'/sequences')
  ]);
  const total = file.sections.reduce((a,s)=>a+s.size,0) || 1;
  const colors = ['#5aa9ff','#41d18a','#f5b945','#c58cff','#ff8f6b','#6bd2ff','#9fe07a','#ff7ab6'];
  const map = file.sections.map((s,i)=>
    `<div title="${esc(s.name)} ${s.size}B @ ${esc(s.vaddr)}" style="width:${Math.max(2, s.size/total*100)}%;background:${colors[i%colors.length]}">${esc(s.name.replace('.debug_','').replace('.dwo',''))}</div>`
  ).join('');
  $('#view').innerHTML = `
  <div class="card">
    <h2>#${file.id} ${esc(file.name)} v${file.versionNo} — Section 地图</h2>
    <div class="section-map">${map}</div>
    <table style="margin-top:10px">
      <tr><th>section</th><th>vaddr</th><th>大小</th><th>原始字节摘要</th></tr>
      ${file.sections.map(s=>`<tr><td class="mono">${esc(s.name)}</td><td class="mono addr">${esc(s.vaddr)}</td>
        <td class="mono">${s.size}</td><td class="mono muted" style="font-size:11px">${esc(s.summary)}</td></tr>`).join('')}
    </table>
    ${file.issues.length?`<h2 style="margin-top:14px">解析问题（隔离结论）</h2>${file.issues.map(i=>`<div>${badge(i.severity,i.code)} <span class="muted">${esc(i.section)}:</span> ${esc(i.message)}</div>`).join('')}`:''}
  </div>
  <div class="grid2">
    <div class="card"><h2>Compilation Units</h2>
      <table><tr><th>offset</th><th>DWARF</th><th>kind</th><th>名称</th><th>范围/序列</th><th></th></tr>
      ${cus.map(c=>`<tr><td class="mono addr">${esc(c.offset)}</td><td>v${c.version}</td>
        <td>${esc(c.kind)}${c.dwoMissing?' '+badge('WARNING','dwo缺失'):''}</td>
        <td>${esc(c.name)}<div class="muted" style="font-size:11px">${esc(c.producer ?? '')}</div></td>
        <td>${c.rangeCount} / ${c.sequenceCount}</td></tr>`).join('')}
      </table>
    </div>
    <div class="card"><h2>地址范围（${ranges.length}，含零长度/重叠）</h2>
      <div style="max-height:340px;overflow:auto">
      <table><tr><th>start</th><th>end</th><th>kind</th><th>优先级</th><th>符号</th></tr>
      ${ranges.map(r=>`<tr style="${r.zeroLength?'opacity:.55':''}">
        <td class="mono addr">${esc(r.start)}</td><td class="mono addr">${esc(r.end)}</td>
        <td>${esc(r.kind)}</td><td>${r.explicitPriority}</td>
        <td>${esc(r.symbol ?? '')} ${r.zeroLength?badge('INFO','zero'):''}</td></tr>`).join('')}
      </table></div>
    </div>
  </div>
  <div class="card"><h2>Line program（多 sequence · 状态变化）</h2>
    ${seqs.map(sq=>`<details style="margin-bottom:8px" ${seqs.length===1?'open':''}>
      <summary class="mono">seq <span class="addr">${esc(sq.start)}</span>–<span class="addr">${esc(sq.end)}</span>
        seg ${sq.segment} · table v${sq.tableVersion} · ${sq.rows.length} 行</summary>
      <table><tr><th>#</th><th>address</th><th>file:line:col</th><th>stmt</th><th>end</th><th>isa</th><th>disc</th></tr>
      ${sq.rows.map(rw=>`<tr ${rw.endSequence?'style="opacity:.6"':''}><td>${rw.order}</td>
        <td class="mono addr">${esc(rw.address)}</td>
        <td>${esc(rw.file)}:${rw.line}:${rw.column}</td>
        <td>${rw.isStmt?'●':''}</td><td>${rw.endSequence?'END':''}</td><td>${rw.isa}</td><td>${rw.discriminator}</td></tr>`).join('')}
      </table></details>`).join('')}
  </div>`;
};

// ---------- Snapshots ----------
renderers.snapshots = () => {
  $('#view').innerHTML = `
  <div class="card"><h2>固定模块加载快照</h2>
    <div id="modRows"></div>
    <div class="row" style="margin-top:10px">
      <input id="snName" placeholder="快照名，例如 crash#42 加载快照" style="width:260px">
      <button class="ghost" id="addRow">+ 模块</button>
      <button class="act" id="createSn">创建并固定</button>
    </div>
  </div>
  <div class="card"><h2>已有快照（可含同一模块的多个加载代次）</h2>
    ${state.snapshots.map(s=>`<div style="margin-bottom:8px"><b>#${s.id} ${esc(s.name)}</b>
      ${s.fixed?badge('INFO','fixed'):''}
      <table>${s.modules.map(m=>`<tr><td>gen ${m.generation}</td><td>${esc(m.moduleName)}</td>
        <td class="muted">${esc(m.debugFileName)} v${m.versionNo}</td>
        <td class="mono addr">${esc(m.baseAddress)}</td></tr>`).join('')}</table></div>`).join('')}
  </div>`;
  let n = 0;
  const addRow = () => {
    const opts = state.files.map(f=>`<option value="${f.id}">${esc(f.name)} v${f.versionNo}</option>`).join('');
    $('#modRows').insertAdjacentHTML('beforeend',
      `<div class="row" style="margin-bottom:6px">
        <input class="mname" placeholder="模块名" style="width:200px">
        <select class="mfid" style="width:260px">${opts}</select>
        <input class="mbase" placeholder="加载基址 0x7f..." style="flex:1"></div>`);
  };
  addRow();
  $('#addRow').onclick = addRow;
  $('#createSn').onclick = async () => {
    const modules = [...document.querySelectorAll('#modRows .row')].map(row => ({
      moduleName: row.querySelector('.mname').value.trim() || 'module',
      debugFileId: Number(row.querySelector('.mfid').value),
      baseAddress: row.querySelector('.mbase').value.trim() || '0x0'
    }));
    await api('/api/snapshots', {method:'POST', body:JSON.stringify({name:$('#snName').value.trim()||'snapshot', fixed:true, modules})});
    await refresh();
  };
};

// ---------- Crashes ----------
renderers.crashes = async () => {
  const crashes = await api('/api/crashes');
  $('#view').innerHTML = `<div class="card"><h2>崩溃记录（冻结于导入时的文件版本与快照）</h2>
    ${crashes.length===0?'<p class="muted">暂无记录。去“罗盘查询”批量解析后保存。</p>':''}
    ${crashes.map(c=>`<details class="card" style="margin-bottom:10px">
      <summary><b>#${c.id} ${esc(c.title)}</b>
        <span class="pill">snapshot ${c.snapshotId ?? '-'}</span></summary>
      <pre class="muted">${esc(c.rawInput)}</pre>
      ${c.resolutions.map(renderResolution).join('')}
    </details>`).join('')}</div>`;
};

refresh().catch(e => $('#view').innerHTML = '<div class="card"><h2>加载失败</h2><pre>'+esc(e.message)+'</pre></div>');
