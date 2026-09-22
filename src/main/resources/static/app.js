// 行址罗盘 frontend
const $ = (id) => document.getElementById(id);
const hex = (n) => "0x" + BigInt(n).toString(16);

async function api(path, opts = {}) {
  const res = await fetch("/api" + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error((await res.json()).error || res.statusText);
  return res.json();
}

async function refreshVersions() {
  const list = await api("/versions");
  const sel = $("moduleVersion");
  sel.innerHTML = "";
  list.forEach((v) => {
    const o = document.createElement("option");
    o.value = v.id;
 o.textContent = "#" + v.id + " " + v.file_name + " [" + v.elf_class + " DWARF " + v.dwarf_versions + "]";
    sel.appendChild(o);
  });
  $("versionList").innerHTML = list.map((v) =>
    '<div class="card" onclick="loadVersion(' + v.id + ')">' +
      '<b>#' + v.id + ' ' + escapeHtml(v.file_name) + '</b><br>' +
      '<small>' + v.elf_class + ' ' + v.endian + ' build-id=' + (v.build_id || '-') +
      ' CU=' + v.cu_count + ' sections=' + v.section_count + (v.has_dwo ? ' split+dwo' : '') + '</small><br>' +
      '<small class="mono">sha256 ' + v.sha256.slice(0, 24) + '...</small></div>').join("");
}

async function uploadFile() {
  const f = $("elfFile").files[0];
  if (!f) return alert("先选择 ELF / 分离调试文件");
  const fd = new FormData();
  fd.append("file", f);
  const res = await fetch("/api/import", { method: "POST", body: fd }).then((r) => r.json());
  if (res.error) return alert(res.error);
  $("status").textContent = res.reused
    ? "已存在版本 #" + res.versionId + "（内容不可变，复用）"
    : "导入为新版本 #" + res.versionId;
  await refreshVersions();
  await loadVersion(res.versionId);
}

async function loadVersion(id) {
  const d = await api("/versions/" + id);
  $("detail").innerHTML = renderVersion(d);
  renderSectionMap(d);
  renderCus(d);
}

function renderVersion(d) {
  const warns = d.warnings.length
    ? '<div class="warn">' + d.warnings.map(escapeHtml).join("<br>") + '</div>' : "";
  return '<h3>版本 #' + d.versionId + ' ' + d.elfClass + '</h3>' +
    '<small class="mono">整体字节摘要 sha256: ' + d.rawSha256 + '</small>' + warns +
    '<div id="sectionMap"><h4>Section 地图</h4><div id="mapCanvas"></div></div>' +
    '<h4>编译单元 / 范围 / Line sequences</h4><div id="cuList"></div>';
}

function renderSectionMap(d) {
  const max = Math.max.apply(null, d.sections.map((s) => s.size).concat([1]));
  $("mapCanvas").innerHTML = d.sections.map((s) =>
    '<div class="maprow"><span class="mono mapname">' + s.name + '</span>' +
    '<span class="bar"><span class="fill" style="width:' + (s.size / max) * 100 + '%"></span></span>' +
    '<span class="mono">' + s.size + ' B</span>' +
    '<span class="mono small">' + (s.sha256 ? s.sha256.slice(0, 12) + "..." : "(无内容)") + '</span></div>').join("");
}

function renderCus(d) {
  $("cuList").innerHTML = d.cus.map((cu) => {
    const ranges = (cu.ranges.length ? cu.ranges : []).map((r) =>
      '<span class="tag mono">[' + hex(r.start) + ' - ' + hex(r.end) + '] ' +
      (r.end === r.start ? "零长度" : "宽 " + (r.end - r.start)) + '</span>').join(" ") || "<i>无 CU 范围</i>";
    const seqs = cu.sequences.map((s) =>
      '<details><summary class="mono">sequence ' + hex(s.start) + ' -> ' + hex(s.end) +
      '（' + s.rows.length + ' 行状态）</summary><table class="rows"><tr><th>地址</th><th>文件:行:列</th>' +
      '<th>stmt</th><th>结束</th></tr>' +
      s.rows.map((rw) => '<tr><td class="mono">' + hex(rw.address) + '</td><td>' +
        escapeHtml(rw.file || "?") + ':' + rw.line + ':' + rw.column + '</td><td>' +
        (rw.isStmt ? "yes" : "") + '</td><td>' + (rw.endSequence ? "END" : "") + '</td></tr>').join("") +
      '</table></details>').join("");
    const notes = cu.notes.length ? '<div class="warn small">' + cu.notes.map(escapeHtml).join("<br>") + '</div>' : "";
    return '<div class="card"><b>' + escapeHtml(cu.name || "?") + '</b> ' +
      '<span class="tag">DWARF' + cu.version + '</span>' +
      (cu.skeleton ? '<span class="tag split">skeleton</span>' : "") +
      (cu.split ? '<span class="tag split">split</span>' : "") +
      (cu.dwoName ? '<small> dwo=' + escapeHtml(cu.dwoName) + '</small>' : "") +
      '<div>' + ranges + '</div>' + seqs + notes + '</div>';
  }).join("");
}

async function createSession() {
  const title = $("sessionTitle").value;
  const r = await api("/sessions", { method: "POST", body: JSON.stringify({ title }) });
  $("sessionId").value = r.id;
  await refreshSessions();
}

async function refreshSessions() {
  const list = await api("/sessions");
  $("sessions").innerHTML = list.map((s) =>
    '<div class="card" onclick="$(\'sessionId\').value=' + s.id + '"><b>崩溃记录 #' + s.id +
    '</b> ' + escapeHtml(s.title) + '</div>').join("");
}

async function addModule() {
  const body = {
    sessionId: Number($("sessionId").value),
    versionId: Number($("moduleVersion").value),
    moduleName: $("moduleName").value || "main",
    loadBias: parseNum($("loadBias").value),
    generation: Number($("generation").value || 1),
    segment: Number($("segment").value || 0),
    buildId: null
  };
  await api("/sessions/" + body.sessionId + "/modules", { method: "POST", body: JSON.stringify(body) });
  $("status").textContent = "模块快照已固定 generation=" + body.generation + " bias=" + hex(body.loadBias);
}

async function batchResolve() {
  const sessionId = Number($("sessionId").value);
  const addresses = $("stackAddrs").value.split(/[\s,;]+/).filter(Boolean);
  const res = await api("/resolve/batch", {
    method: "POST", body: JSON.stringify({ sessionId, addresses })
  });
  $("results").innerHTML = renderResults(res.results);
}

function renderResults(views) {
  if (!views.length) return '<div class="warn">没有任何模块覆盖这些地址（检查 load bias / generation）。</div>';
  return views.map((v) => {
    const r = v.resolution;
    const p = r.primary;
    const chain = (p && p.inlineChain ? p.inlineChain : []).map((f, i) =>
      '<div class="chainframe">' + "\u3000".repeat(i) + '-> #' + f.depth + ' ' + escapeHtml(f.function) +
      (f.callLine ? ' <small>(调用点 ' + escapeHtml(f.callFile || "?") + ':' + f.callLine + ')</small>' : "") +
      '</div>').join("");
    return '<div class="card res"><b class="mono">' + hex(r.runtimeAddress) + '</b> @ ' +
      escapeHtml(v.moduleName) +
      ' <small>(generation ' + r.loadGeneration + ', bias ' + hex(r.loadBias) +
      ', 相对地址 ' + hex(r.fileRelativeAddress) + ')</small>' +
      '<div>-> ' + escapeHtml(p ? p.file : "?") + ':' + (p ? p.line : "?") + ':' +
      (p ? p.column : 0) + ' <b>' + escapeHtml(p ? p.function : "") + '</b></div>' +
      '<div class="small">CU=' + escapeHtml(p ? p.cu : "?") + ' 表版本 DWARF' +
      (p ? p.tableVersion : "?") + ' sequence ' + hex(p ? p.sequenceStart : 0) + '..' +
      hex(p ? p.sequenceEnd : 0) + ' 范围 ' + hex(p ? p.rangeStart : 0) + '..' +
      hex(p ? p.rangeEnd : 0) + ' (' + (p ? p.rangeWidth : 0) + ' 字节) ' +
      (p ? p.confidence : "") + '</div>' +
      (chain ? '<div class="inlinetree"><u>内联调用链</u>' + chain + '</div>' : "") +
      '<details><summary>' + r.candidates.length + ' 个候选</summary><table class="rows">' +
      r.candidates.map((c) => '<tr><td>#' + c.rank + '</td><td>' + escapeHtml(c.file || "?") + ':' +
        (c.line != null ? c.line : "?") + '</td><td>' + escapeHtml(c.function || "?") + '</td><td>宽 ' +
        c.rangeWidth + '</td><td>深度 ' + c.inlineDepth + '</td><td>DWARF' + c.tableVersion + '</td></tr>').join("") +
      '</table></details>' +
      (r.notes.length ? '<div class="warn small">' + r.notes.map(escapeHtml).join("<br>") + '</div>' : "") +
      '</div>';
  }).join("");
}

function parseNum(s) {
  s = s.trim();
  return s.startsWith("0x") ? parseInt(s, 16) : parseInt(s, 10);
}
function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

refreshVersions().catch(console.error);
refreshSessions().catch(console.error);
