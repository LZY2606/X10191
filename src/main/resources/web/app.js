"use strict";
const $ = (s, el = document) => el.querySelector(s);
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(path + " -> " + r.status + " " + await r.text());
  return r.json();
};
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const hx = (v) => v == null ? "" : String(v);
function tag(kind, text) { return `<span class="tag ${kind}">${esc(text)}</span>`; }

const TABS = [
  ["import", "导入与版本", renderImport],
  ["sections", "Section 地图", renderSectionsWrap],
  ["ranges", "地址范围", renderRangesWrap],
  ["line", "Line Program", renderLineWrap],
  ["inline", "内联树", renderInlineWrap],
  ["query", "批量栈查询", renderQuery],
  ["crashes", "崩溃记录 / 快照", renderCrashesWrap],
  ["generations", "加载代次", renderGenerationsWrap],
];
let currentFileId = null;
let modulesCache = [];

function boot() {
  const nav = $("#tabs");
  nav.innerHTML = TABS.map(([id, name], i) =>
    `<button data-id="${id}" class="${i === 0 ? "active" : ""}">${name}</button>`).join("");
  nav.onclick = (e) => {
    const b = e.target.closest("button"); if (!b) return;
    nav.querySelectorAll("button").forEach(x => x.classList.remove("active"));
    b.classList.add("active");
    const tab = TABS.find(t => t[0] === b.dataset.id);
    tab[2]();
  };
  renderImport();
}

async function loadModules(preferId) {
  const data = await api("/api/modules");
  modulesCache = data.modules || [];
  const all = modulesCache.flatMap(m => m.versions.map(v => ({ ...v, moduleKey: m.moduleKey })))
    .sort((a, b) => b.id - a.id);
  if (preferId) currentFileId = preferId;
  if (!currentFileId && all.length) currentFileId = all[0].id;
  return { modules: modulesCache, all };
}

function fileOptions(all) {
  return all.map(v => `<option value="${v.id}" ${v.id === currentFileId ? "selected" : ""}>
    #${v.id} [${esc(v.moduleKey)}] ${esc(v.fileName)} — ${esc((v.summary || "").split(",").slice(0, 2).join(" "))}</option>`).join("");
}

async function renderImport() {
  const view = $("#view");
  view.innerHTML = `
  <div class="panel">
    <h2>导入调试文件（新版本不可变，旧崩溃记录不受影响）</h2>
    <div class="row">
      <label>模块 key <input id="f_module" value="main" size="10"></label>
      <label>文件 <input id="f_file" type="file"></label>
      <button class="act" id="f_go">导入并解析</button>
    </div>
    <div id="f_result" style="margin-top:12px"></div>
  </div>
  <div class="panel"><h2>已导入版本</h2><div id="f_versions"></div></div>`;
  $("#f_go").onclick = async () => {
    const file = $("#f_file").files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append("moduleKey", $("#f_module").value || "main");
    fd.append("fileName", file.name);
    fd.append("file", file);
    $("#f_result").innerHTML = `<span class="muted">解析中…</span>`;
    try {
      const res = await fetch("/api/import", { method: "POST", body: fd }).then(r => r.json());
      if (res.versionId == null) $("#f_result").innerHTML = `<pre class="json">${esc(JSON.stringify(res, null, 2))}</pre>`;
      else $("#f_result").innerHTML = importCard(res);
      currentFileId = res.versionId;
      renderImport();
    } catch (e) { $("#f_result").innerHTML = tag("err", e.message); }
  };
  const { all } = await loadModules();
  $("#f_versions").innerHTML = all.length ? versionsTable(all) : `<span class="muted">尚无导入</span>`;
}

function versionsTable(all) {
  return `<div class="scroll"><table><thead><tr>
    <th>#</th><th>模块</th><th>文件</th><th>导入时间</th><th>SHA-256</th><th>Build ID</th><th>摘要</th>
  </tr></thead><tbody>${all.map(v => `<tr>
    <td>${v.id}</td><td>${esc(v.moduleKey)}</td><td>${esc(v.fileName)}</td>
    <td class="small muted">${new Date(v.importedAt).toLocaleString()}</td>
    <td class="mono small">${esc(v.sha256.slice(0, 16))}…</td>
    <td class="mono small">${esc(v.buildId || "-")}</td>
    <td class="small">${esc(v.summary)}</td></tr>`).join("")}</tbody></table></div>`;
}

function importCard(r) {
  const d = r.diagnostics || [];
  const errs = d.filter(x => x.severity === "ERROR").length;
  const warns = d.filter(x => x.severity === "WARNING").length;
  return `<div class="cand primary"><b>#${r.versionId} ${esc(r.fileName)}</b>
    <div class="small muted">${esc(r.elf.class)} / ${esc(r.elf.type)} / machine ${r.elf.machine} /
      preferred base ${r.elf.preferredLoadBase} / relocs ${r.summary.relocationsApplied}</div>
    <div style="margin:6px 0">
      ${tag("info", "CU " + r.summary.cus)} ${tag("info", "split CU " + r.summary.splitCus)}
      ${tag("info", "函数 " + r.summary.functions)} ${tag("info", "sequence " + r.summary.sequences)}
      ${errs ? tag("err", "ERROR " + errs) : tag("ok", "无 ERROR")}
      ${warns ? tag("warn", "WARNING " + warns) : ""}
    </div>
    <div class="small mono muted">sha256 ${esc(r.digest.sha256)}</div>
    ${d.length ? `<div class="scroll" style="margin-top:8px"><table><thead><tr><th>级别</th><th>范围</th><th>CU</th><th>信息</th></tr></thead><tbody>
      ${d.map(x => `<tr><td>${tag(x.severity === "ERROR" ? "err" : "warn", x.severity)}</td>
        <td>${esc(x.scope)}</td><td class="small">${esc(x.cu || "")}</td><td class="small">${esc(x.message)}</td></tr>`).join("")}
    </tbody></table></div>` : ""}
  </div>`;
}

async function filePicker(all) {
  return `<div class="row" style="margin-bottom:12px">
    <label>调试文件版本 <select id="picker">${fileOptions(all)}</select></label>
    <span class="small muted">切换后各标签页只读展示该版本，导入新版本不会改变旧版本内容</span>
  </div>`;
}

async function renderSectionsWrap() { await genericRender(renderSections); }
async function renderRangesWrap() { await genericRender(renderRanges); }
async function renderLineWrap() { await genericRender(renderLine); }
async function renderInlineWrap() { await genericRender(renderInline); }

async function genericRender(fn) {
  const { all } = await loadModules();
  if (!all.length) { $("#view").innerHTML = `<div class="panel muted">请先在“导入与版本”导入一个 ELF 文件。</div>`; return; }
  await fn(all);
}

async function renderSections(all) {
  const view = $("#view");
  view.innerHTML = await filePicker(all) + `<div id="body"><span class="muted">加载中…</span></div>`;
  $("#picker").onchange = (e) => { currentFileId = +e.target.value; loadBody(); };
  async function loadBody() {
    const res = await api(`/api/file/${currentFileId}/sections`);
    const maxEnd = Math.max(1, ...res.sections.map(s => Number(BigInt(s.fileOffset) + BigInt(s.size))));
    $("#body").innerHTML = `
      <div class="panel"><h2>Section 地图</h2>
        <div class="small muted">色条按文件偏移比例展示；蓝色为调试相关 section。</div>
        <div style="margin:8px 0">${res.sections.map(s => {
          const left = Number(BigInt(s.fileOffset) * 10000n / BigInt(maxEnd)) / 100;
          const width = Math.max(0.3, Number(BigInt(s.size) * 10000n / BigInt(maxEnd)) / 100);
          return `<div class="bar" title="${esc(s.name)}"><span style="left:${left}%;width:${width}%;
            ${s.isDebug ? "" : "background:rgba(147,160,184,.25);border-color:#93a0b8"}"></span></div>`;
        }).join("")}</div>
        <div class="scroll"><table><thead><tr>
          <th>Section</th><th>类型</th><th>文件偏移</th><th>地址</th><th>大小</th><th>标志</th>
        </tr></thead><tbody>${res.sections.map(s => `<tr>
          <td class="mono">${esc(s.name)} ${s.isDebug ? tag("info", "debug") : ""}</td>
          <td>${s.type}</td><td class="mono">${s.fileOffset}</td>
          <td class="mono">${s.addr}</td><td class="mono">${s.size}</td>
          <td class="mono small">${s.flags}</td></tr>`).join("")}</tbody></table></div>
      </div>
      <div class="panel"><h2>Program headers</h2>
        <table><thead><tr><th>type</th><th>flags</th><th>offset</th><th>vaddr</th><th>filesz</th><th>memsz</th></tr></thead>
        <tbody>${res.programHeaders.map(p => `<tr class="mono small"><td>${p.type}</td><td>${p.flags}</td>
          <td>${p.offset}</td><td>${p.vaddr}</td><td>${p.filesz}</td><td>${p.memsz}</td></tr>`).join("")}</tbody></table>
      </div>`;
  }
  loadBody();
}

async function renderRanges(all) {
  const view = $("#view");
  view.innerHTML = await filePicker(all) + `<div id="body"><span class="muted">加载中…</span></div>`;
  $("#picker").onchange = (e) => { currentFileId = +e.target.value; loadBody(); };
  async function loadBody() {
    const res = await api(`/api/file/${currentFileId}/ranges`);
    $("#body").innerHTML = `
      <div class="panel"><h2>地址范围（保留零长度与重叠）</h2>
        <div>${tag("warn", "重叠 " + res.overlaps.length)}
          ${tag("info", "零长度 " + res.ranges.filter(r => r.zeroLength).length)}
          ${tag("info", "范围总数 " + res.ranges.length)}</div>
        ${res.overlaps.length ? `<div class="small" style="margin:8px 0">${res.overlaps.map(o =>
          `<div>${esc(o.a)} ⨉ ${esc(o.b)} @ ${o.start}..${o.end}</div>`).join("")}</div>` : ""}
        <div class="scroll"><table><thead><tr>
          <th>start</th><th>end</th><th>长度</th><th>函数 / 标签</th><th>CU</th><th>来源</th><th>深度</th><th>split</th>
        </tr></thead><tbody>${res.ranges.map(r => `<tr class="${r.zeroLength ? "" : ""}">
          <td class="mono">${r.start}${r.zeroLength ? " " + tag("warn", "zero") : ""}</td>
          <td class="mono">${r.end}</td><td class="mono">${r.length}</td>
          <td>${esc(r.function || r.tag)}<div class="small muted mono">${r.dieOffset}</div></td>
          <td class="small">${esc(r.cu)}</td><td class="small">${esc(r.source)}</td>
          <td>${r.depth}</td><td>${r.fromSplit ? tag("info", "dwo") : ""}</td>
        </tr>`).join("")}</tbody></table></div>
      </div>`;
  }
  loadBody();
}

async function renderLine(all) {
  const view = $("#view");
  view.innerHTML = await filePicker(all) + `<div id="body"><span class="muted">加载中…</span></div>`;
  $("#picker").onchange = (e) => { currentFileId = +e.target.value; loadBody(); };
  async function loadBody() {
    const res = await api(`/api/file/${currentFileId}/line`);
    $("#body").innerHTML = `
      <div class="panel"><h2>Line program 头与表版本</h2>
        <div class="scroll"><table><thead><tr>
          <th>偏移</th><th>版本</th><th>min insn</th><th>line base/range</th><th>opcode base</th>
          <th>addr/seg size</th><th>文件数</th>
        </tr></thead><tbody>${res.headers.map(h => `<tr class="mono small">
          <td>${h.offset}</td><td>${tag("info", "DWARF v" + h.version)}</td>
          <td>${h.minInstructionLength}</td><td>${h.lineBase}/${h.lineRange}</td>
          <td>${h.opcodeBase}</td><td>${h.addressSize}/${h.segmentSelectorSize}</td>
          <td>${h.files.length}</td></tr>`).join("")}</tbody></table></div>
      </div>
      <div class="panel"><h2>Line sequence（多 sequence 全部保留）</h2>
        <div class="scroll">${res.sequences.map(s => `
          <div class="cand"><b>${esc(s.cu)}</b> ${tag("info", s.version)}
            <span class="mono small muted">${s.start}..${s.end} seg-sel=${s.segmentSelectorSize}</span>
            <table style="margin-top:6px"><thead><tr><th>地址</th><th>seg</th><th>文件:行:列</th>
              <th>stmt</th><th>end_seq</th><th>disc</th></tr></thead><tbody>
            ${s.rows.map(r => `<tr class="mono small">
              <td>${r.address}</td><td>${r.sement === undefined ? r.segment : r.segment}</td>
              <td style="font-family:ui-monospace">${esc(r.file)}:${r.line}:${r.column}</td>
              <td>${r.isStmt ? "•" : ""}</td><td>${r.endSequence ? tag("warn", "end") : ""}</td>
              <td>${r.discriminator}</td></tr>`).join("")}
            </tbody></table></div>`).join("")}</div>
      </div>
      <div class="panel"><h2>状态机变化（special / standard / extended opcode）</h2>
        <div class="scroll"><table><thead><tr><th>op</th><th>address</th><th>file#</th><th>line</th>
          <th>column</th><th>stmt</th><th>end_seq</th></tr></thead><tbody>
        ${res.transitions.map(t => `<tr class="mono small"><td>${esc(t.op)}</td><td>${t.address}</td>
          <td>${t.fileIdx}</td><td>${t.line}</td><td>${t.column}</td>
          <td>${t.isStmt ? "•" : ""}</td><td>${t.endSequence ? "•" : ""}</td></tr>`).join("")}
        </tbody></table></div>
      </div>`;
  }
  loadBody();
}

async function renderInline(all) {
  const view = $("#view");
  view.innerHTML = await filePicker(all) + `<div id="body"><span class="muted">加载中…</span></div>`;
  $("#picker").onchange = (e) => { currentFileId = +e.target.value; loadBody(); };
  async function loadBody() {
    const res = await api(`/api/file/${currentFileId}/inline`);
    const byCu = {};
    for (const n of res.inlines) (byCu[n.cu] ||= []).push(n);
    $("#body").innerHTML = `<div class="panel"><h2>内联树</h2>
      ${Object.entries(byCu).map(([cu, ns]) => `<div class="cand"><b>${esc(cu)}</b>
        <table><thead><tr><th>depth</th><th>内联函数</th><th>call line</th>
          <th>外层函数</th><th>DIE</th></tr></thead><tbody>
        ${ns.sort((a,b)=>a.depth-b.depth).map(n => `<tr class="small">
          <td>${"　".repeat(Math.max(0,n.depth-1))}↳ ${n.depth}</td>
          <td class="mono">${esc(n.function)}</td><td>${n.callLine ?? ""}</td>
          <td class="small">${esc(n.parentFunction || "")}</td>
          <td class="mono small muted">${n.dieOffset}</td></tr>`).join("")}
        </tbody></table></div>`).join("") || `<span class="muted">无 inlined_subroutine</span>`}
    </div>`;
  }
  loadBody();
}

async function renderQuery() {
  const { all } = await loadModules();
  const view = $("#view");
  const moduleKeys = [...new Set(all.map(v => v.moduleKey))];
  view.innerHTML = `
  <div class="panel"><h2>批量粘贴栈地址</h2>
    <div class="row">
      <label>模块 <select id="q_module">${moduleKeys.map(k => `<option>${esc(k)}</option>`).join("")}</select></label>
      <label>固定版本 <select id="q_version"><option value="">（最新）</option>${fileOptions(all)}</select></label>
      <label>实际加载基址 <input id="q_base" value="0x555555554000" size="18"></label>
      <label>首选基址 <input id="q_pref" value="0x0" size="12"></label>
    </div>
    <div class="small muted" style="margin:6px 0">每行一个地址，可写 “0x401180” 或 “label: 0x401180”。load bias = 实际基址 − 首选基址。</div>
    <textarea id="q_addrs" placeholder="main+0x1180 0x555555555180&#10;frame2: 0x5555555552a0&#10;0x555555555050"></textarea>
    <div style="margin-top:8px"><button class="act" id="q_go">解析</button>
      <button class="act" id="q_save" style="background:#26314a;color:var(--fg)">存为崩溃记录（固定当前版本与快照）</button></div>
  </div>
  <div class="panel" id="q_out"></div>`;
  $("#q_go").onclick = () => runQuery(false);
  $("#q_save").onclick = () => runQuery(true);
}

function parseStack(text) {
  return text.split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(l => {
    const m = l.match(/^(?:(.*?)\s*[:\s])?\s*(0x[0-9a-fA-F]+|\d+)$/);
    if (m) return { label: (m[1] || "").trim() || null, address: m[2] };
    const anyAddr = l.match(/(0x[0-9a-fA-F]+)/);
    return { label: l, address: anyAddr ? anyAddr[1] : "0x0" };
  });
}

async function runQuery(save) {
  const moduleKey = $("#q_module").value;
  const versionId = $("#q_version").value ? +$("#q_version").value : null;
  const actualBase = $("#q_base").value || "0x0";
  const preferredBase = $("#q_pref").value || "0x0";
  const addrs = parseStack($("#q_addrs").value);
  if (save) {
    const title = prompt("崩溃记录标题", "crash-" + new Date().toISOString().slice(0, 19));
    if (!title) return;
    const body = { moduleKey, title, versionId, actualBase, preferredBase,
      addresses: addrs.map(a => ({ label: a.label, address: a.address })) };
    const r = await api("/api/crashes", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body) });
    alert("已保存崩溃记录 #" + r.id + "，版本与 load bias 已固定");
    return;
  }
  const body = { moduleKey, versionId, actualBase, preferredBase, addresses: addrs };
  const res = await api("/api/query", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body) });
  $("#q_out").innerHTML = res.results.map(resultCard).join("");
}

function resultCard(r) {
  const lines = r.lineCandidates || [];
  const funcs = r.functionCandidates || [];
  return `<div class="cand ${lines.length || funcs.length ? "primary" : ""}">
    <div class="row" style="justify-content:space-between">
      <b class="mono">${r.queryAddress}</b>
      <span class="small mono muted">relative ${r.relativeAddress} · bias ${r.loadBias}
        · base ${r.actualBase} − ${r.preferredBase}</span>
      <span>${r.trusted ? tag("ok", "结论可信") : tag("warn", "可信度受限")}
        ${r.tableVersionUsed ? tag("info", r.tableVersionUsed) : tag("warn", "无行表")}</span>
    </div>
    ${r.trustNotes.length ? `<ul class="small" style="margin:6px 0 0 18px">
      ${r.trustNotes.map(n => `<li class="muted">${esc(n)}</li>`).join("")}</ul>` : ""}
    <div class="grid2" style="margin-top:8px">
      <div><div class="small muted">行号候选（全部合法候选，按最邻近 sequence 行排序）</div>
        ${lines.length ? lines.map((c, i) => `<div class="cand ${i === 0 ? "primary" : ""}">
          <b>${esc(c.file)}:${c.line}:${c.column}</b>
          ${i === 0 ? tag("ok", "最佳") : ""}
          <div class="small muted mono">${esc(c.cu)} ${c.lineTableVersion}
            sequence ${c.sequenceStart}..${c.sequenceEnd}${c.isStmt ? " · stmt" : ""}${c.endSequenceRow ? " · end_sequence" : ""}</div>
        </div>`).join("") : `<div class="small muted">无行号候选</div>`}
      </div>
      <div><div class="small muted">函数 / 内联候选（最窄范围 → 内联深度 → 显式优先级）</div>
        ${funcs.length ? funcs.map((c, i) => `<div class="cand ${i === 0 ? "primary" : ""}">
          <b>${esc(c.function)}</b> ${i === 0 ? tag("ok", "最佳") : ""}
          ${c.fromSplitDwo ? tag("info", "dwo") : ""}
          <div class="small muted mono">${esc(c.tag)} @ ${esc(c.cu)} ${c.dieOffset}
            范围 ${c.matchedRange.start}..${c.matchedRange.end} (len ${c.matchedRange.length}${c.matchedRange.zeroLength ? ", zero" : ""})
            · priority ${c.explicitPriority}</div>
          <div class="frames">${c.inlineChain.map(f =>
            `<div class="frame">${"　".repeat(f.depth)}↳ #${f.depth} ${esc(f.function)}
              <span class="muted small">${f.line != null ? "line " + f.line : ""}
              ${f.abstractOrigin ? "origin " + f.abstractOrigin : ""}</span></div>`).join("")}</div>
        </div>`).join("") : `<div class="small muted">无函数候选</div>`}
      </div>
    </div>
  </div>`;
}

async function renderCrashesWrap() { await renderCrashes(); }

async function renderCrashes() {
  const data = await api("/api/crashes");
  const view = $("#view");
  view.innerHTML = `<div class="panel"><h2>崩溃记录（导入新调试文件不改变这里的固定版本与 load bias）</h2>
    <div id="crashList"></div><div id="crashDetail" style="margin-top:14px"></div></div>`;
  $("#crashList").innerHTML = data.crashes.length ? `<div class="scroll"><table><thead><tr>
    <th>#</th><th>标题</th><th>模块</th><th>版本</th><th>bias</th><th>地址数</th><th></th>
  </tr></thead><tbody>${data.crashes.map(c => `<tr>
    <td>${c.id}</td><td>${esc(c.title)}</td><td>${esc(c.moduleKey)}</td>
    <td>${c.versionId ?? tag("warn", "浮动(创建时无版本)")}</td>
    <td class="mono">${c.loadBias}</td><td>${c.addresses.length}</td>
    <td><button class="act" data-id="${c.id}">用固定快照重查</button></td></tr>`).join("")}
  </tbody></table></div>` : `<span class="muted">尚无崩溃记录。在“批量栈查询”里保存。</span>`;
  $("#crashList").onclick = async (e) => {
    const b = e.target.closest("button[data-id]"); if (!b) return;
    const res = await api(`/api/crashes/${b.dataset.id}/resolve`);
    $("#crashDetail").innerHTML =
      `<div class="small muted">崩溃 #${res.crashId} · 固定版本 ${res.fixedVersionId ?? "无"} · 固定 bias ${res.loadBias}</div>` +
      res.results.map(resultCard).join("");
  };
}

async function renderGenerationsWrap() {
  const { modules } = await loadModules();
  const view = $("#view");
  view.innerHTML = `<div class="panel"><h2>模块加载代次</h2>
    <div class="row"><label>模块 <select id="g_module">
      ${modules.map(m => `<option>${esc(m.moduleKey)}</option>`).join("")}
    </select></label><button class="act" id="g_go">刷新</button></div>
    <div id="g_out" style="margin-top:10px"></div></div>`;
  async function load() {
    const key = $("#g_module").value || "main";
    const res = await api(`/api/generations?moduleKey=${encodeURIComponent(key)}`);
    $("#g_out").innerHTML = res.generations.length ? `<table><thead><tr>
      <th>代次</th><th>版本</th><th>实际基址</th><th>首选基址</th><th>load bias</th><th>时间</th>
    </tr></thead><tbody>${res.generations.map(g => `<tr class="mono small">
      <td>${g.generation}</td><td>${g.versionId ?? "-"}</td>
      <td>${g.actualBase}</td><td>${g.preferredBase}</td><td>${g.loadBias}</td>
      <td class="muted">${new Date(g.recordedAt).toLocaleString()}</td></tr>`).join("")}
    </tbody></table>` : `<span class="muted">该模块暂无加载代次（保存崩溃记录时生成）。</span>`;
  }
  $("#g_go").onclick = load; load();
}

boot();
