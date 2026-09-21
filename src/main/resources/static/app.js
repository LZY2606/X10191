"use strict";
let currentVersion = null;
const $ = (id) => document.getElementById(id);
const hex = (n) => "0x" + (BigInt(n < 0 ? n >>> 0 : n)).toString(16);
const fmt = (n) => "0x" + BigInt(n).toString(16);
async function api(path, opts) {
  const res = await fetch("/api" + path, opts || {});
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function uploadFile() {
  const f = $("upFile").files[0];
  if (!f) return $("upMsg").textContent = "请先选择文件";
  const fd = new FormData();
  fd.append("file", f);
  fd.append("label", $("upLabel").value || f.name);
  fd.append("kind", "debug");
  const dwo = $("upDwo").files[0];
  if (dwo) fd.append("dwo", dwo);
  $("upMsg").textContent = "解析中…";
  try {
    const r = await fetch("/api/import", { method: "POST", body: fd }).then(x => x.json());
    if (r.versionId === undefined) throw new Error(JSON.stringify(r));
    $("upMsg").innerHTML = `<span class="good">已生成版本 #${r.versionId}，CU=${r.cuCount}，split=${r.splitStatus}</span>`
      + (r.issues.length ? `<br><span class="warn">${r.issues.join("<br>")}</span>` : "");
    await loadVersions(r.versionId);
  } catch (e) { $("upMsg").innerHTML = `<span class="bad">导入失败: ${e.message}</span>`; }
}

async function loadVersions(selectId) {
  const vs = await api("/versions");
  const el = $("versionList");
  if (!vs.length) { el.className = "vlist muted"; el.textContent = "尚未导入"; return; }
  el.className = "vlist";
  el.innerHTML = "";
  vs.forEach(v => {
    const d = document.createElement("div");
    if (v.id === selectId || (!currentVersion && vs[vs.length-1].id === v.id)) d.className = "active";
    d.innerHTML = `#${v.id} <b>${escapeHtml(v.label)}</b><br><span class="muted">${escapeHtml(v.fileName)} · CU ${v.cuCount} · ${v.splitStatus} · ${v.tableVersions.join(",")}</span>`;
    d.onclick = () => selectVersion(v.id);
    el.appendChild(d);
  });
  currentVersion = selectId || currentVersion || vs[vs.length-1].id;
  await selectVersion(currentVersion);
}

async function selectVersion(id) {
  currentVersion = id;
  [...$("versionList").children].forEach((c, i) =>
    c.classList.toggle("active", c.textContent.startsWith("#"+id)));
  ["overviewSec","sectionSec","cuSec","lineSec","querySec","crashSec"].forEach(x=>$(x).style.display="block");
  const [vs] = (await api("/versions")).filter(x=>x.id===id);
  $("overview").innerHTML = `
    <span class="pill">${vs.kind}</span><span class="pill">${vs.splitStatus}</span>
    <span class="pill">sections ${vs.sectionCount}</span><span class="pill">CU ${vs.cuCount}</span>
    <span class="pill">${vs.tableVersions.join(" / ")}</span>
    <div class="muted" style="margin-top:6px">${escapeHtml(vs.fileName)}</div>`;
  await Promise.all([loadSections(id), loadCus(id), loadRanges(id), loadSnapshots(id), loadCrashes(id)]);
  $("linePicker").textContent = "选择一个 CU";
  $("lineView").innerHTML = "";
}

async function loadSections(id) {
  const rows = await api(`/version/${id}/sections`);
  const total = rows.reduce((a,r)=>a+(r.size>0?1:0),0) || 1;
  const map = $("sectionMap"); map.innerHTML = "";
  rows.filter(r=>r.name).forEach(r => {
    const cls = r.allocated ? "alloc" : (r.name.includes("debug") ? "debug" : "zero");
    const w = Math.max(2, Math.min(100, Math.log10(r.size+10)/8*100));
    const b = document.createElement("div");
    b.className = "secbar " + cls;
    b.style.width = w + "%";
    b.title = `${r.name}\nsize=${r.size}\n${r.summary}\nsha=${r.sha256}`;
    b.innerHTML = `<span class="mono">${escapeHtml(r.name)}</span>&nbsp;<span class="muted">${fmt(r.size)}</span>`;
    map.appendChild(b);
  });
  const t = $("sectionTable");
  t.innerHTML = "<tr><th>section</th><th>addr</th><th>offset</th><th>size</th><th>flags</th><th>原始字节摘要</th><th>sha256</th></tr>";
  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${escapeHtml(r.name)||"<i>null</i>"}</td>
      <td class="mono">${fmt(r.addr)}</td><td class="mono">${fmt(r.offset)}</td>
      <td class="mono">${fmt(r.size)}</td><td class="mono">${fmt(r.flags)}</td>
      <td class="wrapcell muted">${escapeHtml(r.summary)}</td>
      <td class="mono muted">${r.sha256.slice(0,16)}</td>`;
    t.appendChild(tr);
  });
}

async function loadCus(id) {
  const cus = await api(`/version/${id}/cus`);
  const el = $("cuList"); el.innerHTML = "";
  cus.forEach(cu => {
    const d = document.createElement("div");
    d.style.padding = "6px 0";
    d.innerHTML = `<span class="clickable mono" id="cu-${cu.offset}">CU@${fmt(cu.offset)}</span>
      <b>${escapeHtml(cu.name||"?")}</b>
      <span class="pill">${cu.version}</span>${cu.split?'<span class="tag warn">split</span>':''}
      <span class="muted">seq ${cu.sequenceCount}, ranges ${cu.ranges.length}</span>
      ${cu.issues.length?`<div class="warn">${cu.issues.map(escapeHtml).join("；")}</div>`:""}`;
    d.querySelector(".clickable").onclick = ()=>loadLine(cu.offset);
    el.appendChild(d);
  });
}

async function loadRanges(id) {
  const rs = await api(`/version/${id}/ranges`);
  const t = $("rangeTable");
  t.innerHTML = "<tr><th>CU</th><th>函数</th><th>low</th><th>high</th><th>宽</th><th></th></tr>";
  rs.forEach(r => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono muted">${fmt(r.cuOffset)}</td>
      <td>${escapeHtml(r.function||"??")}</td>
      <td class="mono">${fmt(r.low)}</td><td class="mono">${fmt(r.high)}</td>
      <td class="mono">${fmt(r.high-r.low)}</td>
      <td>${r.zeroLength?'<span class="tag bad">零长度</span>':''}${r.inlined?'<span class="tag good">内联</span>':''}</td>`;
    t.appendChild(tr);
  });
}

async function loadLine(cuOffset) {
  $("linePicker").textContent = "加载中…";
  const v = await api(`/version/${currentVersion}/line/${cuOffset}`);
  $("linePicker").innerHTML = `CU@${fmt(cuOffset)} · DWARF v${v.version} · addr_size=${v.addressSize} · segment_selector=${v.segmentSelectorSize} · 文件 ${v.files.length}`;
  const el = $("lineView"); el.innerHTML = "";
  if (!v.sequences.length) { el.innerHTML = '<div class="muted">该 CU 无行程序（可能在缺失的 .dwo 中）</div>'; return; }
  v.sequences.forEach((s, idx) => {
    const box = document.createElement("div"); box.className = "seq-block";
    let rows = s.rows.map(r => `<tr>
      <td class="mono ${r.endSequence?'rowstate-end':''}">${fmt(r.address)}</td>
      <td>${escapeHtml(r.file)}</td><td>${r.line}</td><td>${r.column}</td>
      <td>${r.endSequence?'<span class="tag warn">end_sequence</span>':''}
          ${r.isStmt?'<span class="pill">stmt</span>':''}
          ${r.prologueEnd?'<span class="pill good">pe</span>':''}
          ${r.epilogueBegin?'<span class="pill warn">eb</span>':''}
          ${r.basicBlock?'<span class="pill">bb</span>':''}
          ${r.discriminator?`<span class="pill">disc=${r.discriminator}</span>`:''}</td></tr>`).join("");
    box.innerHTML = `<div class="seq-head mono">sequence #${idx}: ${fmt(s.start)} → ${fmt(s.end)}（${s.rows.length} 行）</div>
      <table><tr><th>address</th><th>file</th><th>line</th><th>col</th><th>状态</th></tr>${rows}</table>`;
    el.appendChild(box);
  });
}

async function createSnapshot() {
  const r = await fetch("/api/snapshot", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({
      versionId: currentVersion, moduleName: $("modName").value,
      preferredBase: parseInt($("prefBase").value), loadBase: parseInt($("loadBase").value),
      generation: parseInt($("gen").value)
    })
  }).then(x=>x.json());
  await loadSnapshots(currentVersion);
  alert("快照已固定 loadBias=" + fmt(r.loadBias));
}

async function loadSnapshots(vid) {
  const ss = await api(`/snapshots/${vid}`);
  $("snapList").innerHTML = ss.map(s=>
    `<div class="mono">gen ${s.generation} ${escapeHtml(s.moduleName)} bias=${fmt(s.loadBase-s.preferredBase)}</div>`).join("");
  const sel = $("snapSelect");
  const keep = sel.value;
  sel.innerHTML = '<option value="">无快照（按相对地址）</option>' +
    ss.map(s=>`<option value="${s.id}">gen${s.generation} ${escapeHtml(s.moduleName)} bias=${fmt(s.loadBase-s.preferredBase)}</option>`).join("");
  if (keep) sel.value = keep;
}

async function runQuery() {
  const body = { versionId: currentVersion, text: $("stackInput").value,
    snapshotId: $("snapSelect").value ? parseInt($("snapSelect").value) : null };
  const rs = await fetch("/api/query",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify(body)}).then(x=>x.json());
  renderResults(rs);
}

function renderResults(rs) {
  const el = $("queryResults"); el.innerHTML = "";
  rs.forEach(r => {
    const box = document.createElement("div"); box.className = "seq-block";
    const cand = r.candidates[0];
    let html = `<div class="seq-head mono">#${r.ordinal} ${escapeHtml(r.input)}
        → runtime ${fmt(r.runtimePc)} / 相对 ${fmt(r.relativePc)} / bias ${fmt(r.loadBias)}
        <span class="pill">${r.tableVersions.join(",")||"-"}</span>
        ${r.candidates.length>1?`<span class="tag warn">${r.candidates.length} 个合法候选</span>`:'<span class="tag good">唯一</span>'}</div>`;
    r.candidates.forEach((c,i) => {
      const l = c.line;
      html += `<div style="padding:6px 8px;border-bottom:1px solid var(--line)">
        <b>#${c.rank} ${l?escapeHtml(l.file)+":"+l.line+":"+l.column:"<span class='muted'>无行号</span>"}</b>
        <span class="muted">seq=${c.sequenceIndex}</span>
        <span class="pill">${escapeHtml(c.confidence)}</span>
        <div class="muted mono" style="font-size:11px">CU: ${escapeHtml(c.cuName||"?")} · ${c.tieKey}</div>
        <div class="chain">${c.inlineChain.map(f=>
          `<div class="frame mono">depth ${f.depth} ${escapeHtml(f.function)}
             <span class="muted">[${fmt(f.rangeLow)}..${fmt(f.rangeHigh)}]${f.callLine?(" call@"+f.callLine):""}</span></div>`).join("") || '<div class="muted">（无内联 DIE 覆盖）</div>'}</div>
        ${i===0?"":""}</div>`;
    });
    if (r.trusted.length) html += `<div class="good" style="padding:4px 8px">可信: ${r.trusted.map(escapeHtml).join("；")}</div>`;
    if (r.warnings.length) html += `<div class="warn" style="padding:4px 8px">注意: ${r.warnings.slice(0,6).map(escapeHtml).join("；")}</div>`;
    box.innerHTML = html;
    el.appendChild(box);
  });
}

async function saveCrash() {
  const label = prompt("崩溃记录标签", "crash-" + Date.now());
  if (!label) return;
  const r = await fetch("/api/crash",{method:"POST",headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ versionId:currentVersion, label,
      snapshotId: $("snapSelect").value?parseInt($("snapSelect").value):null,
      text: $("stackInput").value })}).then(x=>x.json());
  await loadCrashes(currentVersion);
  alert("已保存崩溃记录 #" + r.crashId + "，含 " + r.frames + " 帧，绑定版本 #" + currentVersion);
}

async function loadCrashes(vid) {
  const cs = await api(`/crashes/${vid}`);
  $("crashList").innerHTML = cs.length ? cs.map(c=>
    `<div class="mono">#${c.id} ${escapeHtml(c.label)} <span class="muted">snapshot=${c.snapshotId??"-"}</span></div>`).join("")
    : '<span class="muted">暂无</span>';
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

loadVersions();
