"use strict";
const $ = (s, el=document) => el.querySelector(s);
const $$ = (s, el=document) => Array.from(el.querySelectorAll(s));

async function api(path, opts={}) {
  const res = await fetch(path, {
    headers: {"Content-Type": "application/json", ...(opts.headers||{})},
    ...opts
  });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`${res.status}: ${txt}`);
  }
  return res.json();
}

// ---- tabs ----
$$("nav button").forEach(b => b.addEventListener("click", () => {
  $$("nav button").forEach(x => x.classList.remove("active"));
  $$(".tab").forEach(x => x.classList.remove("active"));
  b.classList.add("active");
  $("#tab-" + b.dataset.tab).classList.add("active");
  if (b.dataset.tab === "detail") loadDetail();
  if (b.dataset.tab === "lines") loadLinesTab();
  if (b.dataset.tab === "files") loadFiles();
  if (b.dataset.tab === "snapshots") loadSnapshotsView();
}));

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
}
function vPill(v) { return `<span class="pill ${v >= 5 ? "v5" : "v4"}">DWARF${v}</span>`; }
function rangeText(r) {
  const zl = r.zeroLength ? ` <span class="pill warn">zero-length</span>` : "";
  return `<span class="mono addr">[${r.start} – ${r.end})</span>${zl}`;
}

// ---- query ----
$("#btn-query").addEventListener("click", runQuery);
$("#btn-demo").addEventListener("click", () => {
  $("#addresses").value = ["0x401020","0x401030","0x401040","0x401050","0x401090"].join("\n");
});

async function runQuery() {
  const addresses = $("#addresses").value.split(/\n+/).map(s => s.trim()).filter(Boolean);
  const snapshotId = $("#snapshot-select").value || null;
  const body = {addresses, snapshotId: snapshotId ? Number(snapshotId) : null};
  $("#query-results").innerHTML = "<div class='card'>解析中…</div>";
  try {
    const r = await api("/api/query", {method: "POST", body: JSON.stringify(body)});
    $("#query-results").innerHTML = r.results.map(renderQueryResult).join("");
  } catch (e) {
    $("#query-results").innerHTML = `<div class="card"><span class="pill bad">错误</span> ${esc(e.message)}</div>`;
  }
}

function renderQueryResult(q) {
  const bias = q.loadBias != null ? `load bias <b class="mono">${q.loadBias}</b>` : "无快照（按 vaddr）";
  const mod = q.moduleName ? `模块 <b>${esc(q.moduleName)}</b> @ <span class="mono">${q.moduleBase ?? ""}</span>` : "全部导入";
  const cand = q.candidates.map((c, i) => `
    <div class="cand ${i === 0 ? "best" : ""}">
      <div>
        <b>#${c.rank}</b> ${c.function ? esc(c.function) : "<i>（无函数 DIE）</i>"}
        ${vPill(c.dwarfVersion)}
        ${c.trusted ? '<span class="pill ok">可信</span>' : '<span class="pill bad">部分可信</span>'}
        <span class="pill ${c.explicitScore >= 3 ? "ok" : "warn"}">显式分 ${c.explicitScore}</span>
        内联深度 ${c.inlineDepth} · 范围宽度 <span class="mono">${c.rangeWidth}</span>
      </div>
      <div class="meta">
        ${rangeText(c.matchedRange)} · CU <b>${esc(c.cuName)}</b>
        @ <span class="mono">${c.cuOffset}</span> · 文件 <span class="mono">${esc(c.fileName)}</span>
        <span class="kv">${c.fileSha256.slice(0,16)}…</span>
      </div>
      ${c.line ? `<div class="meta">行表 ${vPill(c.tableVersion)} → <b class="mono">${esc(c.line.file)}:${c.line.line}:${c.line.column}</b>
        （sequence #${c.line.sequenceIndex} <span class="mono">[${c.line.sequenceStart}–${c.line.sequenceEnd})</span>
        stmt=${c.line.isStmt}）</div>` : '<div class="meta">无匹配行表记录</div>'}
      ${c.inlineChain && c.inlineChain.length ? `
        <details ${i === 0 ? "open" : ""}><summary>内联调用链（${c.inlineChain.length} 帧）</summary>
        <div class="chain">${c.inlineChain.slice().reverse().map(f => `
          <div>
            <span class="tag-inline">depth ${f.depth}</span>
            <b>${esc(f.function)}</b>
            <span class="meta mono">die ${f.dieOffset}</span>
            ${f.callFile ? `<div class="meta">调用点 ${esc(f.callFile)}${f.line != null ? ":"+f.line+(f.column!=null?":"+f.column:"") : ""}</div>` : ""}
          </div>`).join("")}
        </div></details>` : ""}
      ${c.notes.length ? `<div class="notes">⚠ ${c.notes.map(esc).join("；")}</div>` : ""}
    </div>`).join("") || "<div class='meta'>没有任何候选</div>";
  return `<div class="card result">
    <h3><span class="mono addr">${esc(q.raw)}</span></h3>
    <div class="meta">runtime <span class="mono">${q.runtimeAddress}</span> ·
      relative <span class="mono">${q.relativeAddress}</span> · ${bias} · ${mod}</div>
    <div class="summary">${esc(q.summary)}</div>
    ${q.warnings.length ? `<div class="notes">${q.warnings.map(esc).join("；")}</div>` : ""}
    ${cand}
  </div>`;
}

// ---- import / files ----
$("#btn-import").addEventListener("click", async () => {
  const f = $("#import-file").files[0];
  if (!f) { $("#import-status").textContent = "请选择文件"; return; }
  const fd = new FormData();
  fd.append("file", f, f.name);
  $("#import-status").textContent = "上传解析中…";
  try {
    const r = await fetch("/api/import", {method: "POST", body: fd}).then(x => x.json());
    if (r.error) { $("#import-status").innerHTML = `<span class="pill bad">${esc(r.error)}</span>`; return; }
    $("#import-status").innerHTML =
      `已导入 #${r.id} ${esc(r.versionLabel)} · ${r.deduped ? "去重命中已有版本" : "新版本"} · CU ${r.units} · scope ${r.scopes}` +
      (r.issues.length ? ` · <span class="pill warn">${r.issues.length} 个解析问题</span>` : "");
    loadFiles(); refreshSnapshotSelect();
  } catch (e) { $("#import-status").textContent = String(e); }
});

async function loadFiles() {
  const files = await api("/api/files");
  $("#files-table tbody").innerHTML = files.map(f => `
    <tr>
      <td>${f.id}</td>
      <td class="mono">${esc(f.path || "(upload)")}</td>
      <td class="mono">${f.sha256.slice(0,16)}…</td>
      <td>${f.units}</td><td>${f.scopes}</td>
      <td>${f.issues ? `<span class="pill ${f.issues ? "warn" : "ok"}">${f.issues}</span>` : 0}</td>
    </tr>`).join("");
  await populateFileSelects(files);
}

async function populateFileSelects(filesArg) {
  const files = filesArg || await api("/api/files");
  const opts = files.map(f => `<option value="${f.id}">#${f.id} ${esc((f.path||f.sha256).split("/").pop())}</option>`).join("");
  $("#detail-file").innerHTML = opts;
  $("#lines-file").innerHTML = opts;
  $("#detail-file").onchange = loadDetail;
  $("#lines-file").onchange = loadLinesTab;
}

// ---- section map / detail ----
async function loadDetail() {
  const id = $("#detail-file").value;
  if (!id) return;
  const d = await api(`/api/files/${id}`);
  const maxSize = Math.max(...d.sections.map(s => s.size), 1);
  const minAddr = Math.min(...d.sections.filter(s => BigNum(s.addr) > 0n).map(s => BigNum(s.addr)), 0n);
  const maxAddr = Math.max(...d.sections.map(s => BigNum(s.addr) + BigNum(s.size)), 1n);
  const span = maxAddr - minAddr || 1n;
  const sectionMap = d.sections.map(s => {
    const a = BigNum(s.addr);
    const pct = Number((a - (a > 0n ? minAddr : 0n)) * 100n / span);
    const w = Math.max(1, Number(BigNum(s.size) * 100n / span));
    const dwarf = s.name.startsWith(".debug") ? ' <span class="pill v5">debug</span>' : "";
    return `<div class="sect-row">
      <td class="mono">${esc(s.name)}${dwarf}</td>
      <div style="grid-column:2"><div class="sect-bar" style="margin-left:${Math.max(0,pct)}%;width:${w}%"></div></div>
      <td class="mono">${s.addr}</td>
      <td class="mono">${s.size} B</td>
    </div>`;
  }).join("");
  const units = d.units.map(u => `
    <details>
      <summary>${vPill(u.version)} <b>${esc(u.name || u.unitOffset)}</b>
        <span class="mono">${u.unitOffset}</span>
        ${u.isSkeleton ? '<span class="pill warn">skeleton</span>' : ""}
        ${u.isSplit ? '<span class="pill v4">split</span>' : ""}
        ${u.linked ? '<span class="pill ok">dwo 已链接</span>' : (u.isSkeleton ? '<span class="pill bad">缺 dwo</span>' : "")}
        · scope ${u.scopes}
      </summary>
      <div class="meta">stmt_list <span class="mono">${u.stmtList ?? "—"}</span>
        ${u.dwoId ? ` · dwo_id <span class="mono">${u.dwoId}</span>` : ""}
        ${u.issues.map(i => `<div class="notes">[${i.severity}] ${esc(i.location)}: ${esc(i.message)}</div>`).join("")}
      </div>
    </details>`).join("");
  const scopes = d.scopes.map(s => `
    <tr>
      <td class="mono">${s.dieOffset}</td>
      <td>0x${s.tag.toString(16)} ${s.tagInlineName(s.tag)}</td>
      <td>${esc(s.name ?? "?")}</td>
      <td>${s.inlineDepth}</td>
      <td>${s.ranges.map(r => `<div>${rangeText(r)}</div>`).join("")}</td>
      <td>${s.callLine ?? ""}${s.callColumn!=null && s.callLine!=null ? ":"+s.callColumn : ""}</td>
    </tr>`).join("");
  $("#detail-body").innerHTML = `
    <div class="kv">文件 <span class="mono">${esc(d.path ?? d.sha256)}</span> · SHA-256 <span class="mono">${d.sha256}</span>
      · ${d.size} 字节 · preferred base <span class="mono">${d.preferredBase ?? "—"}</span></div>
    ${d.issues.length ? `<div class="issues">解析问题：${d.issues.map(i=>`<div>[${i.severity}] ${esc(i.location)}: ${esc(i.message)}</div>`).join("")}</div>` : ""}
    <h3>Section 地图</h3>
    <div class="sect-map">
      <div class="sect-row" style="color:var(--muted)"><div>名称</div><div>地址分布</div><div>vaddr</div><div>大小</div></div>
      ${sectionMap}
    </div>
    <h3>Compilation Units</h3>
    ${units}
    <h3>地址范围（函数 / 内联 DIE）</h3>
    <table><thead><tr><th>DIE</th><th>tag</th><th>名称</th><th>内联深度</th><th>范围</th><th>调用点</th></tr></thead>
      <tbody>${scopes}</tbody></table>`;
}

function BigNum(h) {
  try { return BigInt(h); } catch { return 0n; }
}

// ---- line program ----
async function loadLinesTab() {
  const id = $("#lines-file").value;
  if (!id) return;
  const d = await api(`/api/files/${id}`);
  const stmts = d.units.map(u => u.stmtList).filter(Boolean);
  $("#lines-stmt").innerHTML = [...new Set(stmts)].map(s => `<option value="${s}">${s}</option>`).join("");
  $("#lines-stmt").onchange = () => showLines(id);
  if (stmts[0]) { $("#lines-stmt").value = stmts[0]; showLines(id, stmts[0]); }
}
async function showLines(id, stmtArg) {
  const stmt = stmtArg || $("#lines-stmt").value;
  const lp = await api(`/api/files/${id}/lines?stmtList=${encodeURIComponent(stmt)}`);
  const seqs = lp.sequences.map(s => `
    <span class="pill ${s.dwarfVersion >= 5 ? "v5" : "v4"}">seq#${s.index}
      <span class="mono">[${s.start}–${s.end})</span> rows ${s.rows}</span>`).join(" ");
  const rows = lp.transitions.map((t, i) => `
    <tr class="${t.endSequence ? "end-seq" : ""}">
      <td>${i}</td><td>${t.seq}</td><td class="mono addr">${t.address}</td>
      <td>${t.line}</td><td>${t.column}</td><td>${t.fileIndex}</td>
      <td>${t.isStmt ? "✓" : ""}</td><td>${t.endSequence ? "END" : ""}</td>
      <td class="mono">${esc(t.opcode)}</td>
    </tr>`).join("");
  const files = lp.files.map(f => `<div>[${f.index}] <b>${esc(f.name)}</b> <span class="meta">${esc(f.directory)}</span></div>`).join("");
  $("#lines-body").innerHTML = `
    <div class="kv">${vPill(lp.dwarfVersion)} · min_insn_len ${lp.minInsnLength}
      · line_base ${lp.lineBase} · line_range ${lp.lineRange} · opcode_base ${lp.opcodeBase}
      · default_is_stmt ${lp.defaultIsStmt}</div>
    <h3>文件表</h3>${files}
    <h3>Sequences</h3><div class="row">${seqs}</div>
    ${lp.issues.length ? `<div class="issues">${lp.issues.map(i=>esc(i.message)).join("<br>")}</div>`:""}
    <h3>状态变化轨迹</h3>
    <table><thead><tr><th>#</th><th>seq</th><th>address</th><th>line</th><th>col</th>
      <th>file</th><th>stmt</th><th></th><th>opcode</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ---- snapshots ----
$("#btn-snap").addEventListener("click", async () => {
  const files = await api("/api/files");
  if (!files.length) { alert("先导入调试文件"); return; }
  const label = $("#snap-label").value || ("snap-" + Date.now());
  const modules = files.map((f, i) => ({
    name: (f.path || `module${f.id}`).split("/").pop(),
    fileId: f.id,
    base: i === 0 ? "0x7f0000000000" : "0x7f1000000000",
    generation: 0
  }));
  await api("/api/snapshots", {method:"POST", body: JSON.stringify({label, modules})});
  loadSnapshotsView(); refreshSnapshotSelect();
});

async function loadSnapshotsView() {
  const snaps = await api("/api/snapshots");
  $("#snap-list").innerHTML = snaps.map(s => `
    <div class="cand">
      <b>#${s.id} ${esc(s.label)}</b> <span class="meta">${esc(s.createdAt)}</span>
      <table><thead><tr><th>模块</th><th>导入ID</th><th>base</th><th>generation</th></tr></thead>
      <tbody>${s.modules.map(m=>`<tr><td>${esc(m.name)}</td><td>${m.fileId}</td>
        <td class="mono">${m.base}</td><td>${m.generation}</td></tr>`).join("")}</tbody></table>
    </div>`).join("") || "<div class='meta'>尚无快照</div>";
}

async function refreshSnapshotSelect() {
  const snaps = await api("/api/snapshots");
  const cur = $("#snapshot-select").value;
  $("#snapshot-select").innerHTML = '<option value="">（无：按链接 vaddr 查全部导入）</option>' +
    snaps.map(s => `<option value="${s.id}">#${s.id} ${esc(s.label)}</option>`).join("");
  if (cur) $("#snapshot-select").value = cur;
}

// ---- init ----
Object.assign(window, {tagInlineName: (t) => ({
  [0x2e]: "DW_TAG_subprogram",
  [0x1d]: "DW_TAG_inlined_subroutine",
  [0x4e]: "DW_TAG_entry_point"
})[t] || ""});
loadFiles(); refreshSnapshotSelect();
