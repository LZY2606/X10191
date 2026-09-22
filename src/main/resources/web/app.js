"use strict";
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const hex = (n, pad = 0) => "0x" + (n >>> 0).toString(16).padStart(pad, "0");
const hex64 = (n) => "0x" + (BigInt.asUintN(64, BigInt(n))).toString(16);
const esc = (s) => (s ?? "").toString().replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]));

const state = { versionId: null, model: null, modules: [], snapshotModules: null };

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
  return r.json();
}

const TAG_NAMES = { 46: "DW_TAG_subprogram", 29: "DW_TAG_inlined_subroutine", 16649: "GNU_call_site", 11: "lexical_block" };

// ---------- versions ----------
async function loadVersions(selectId) {
  const vs = await api("/api/versions");
  const sel = $("#version-select");
  sel.innerHTML = vs.map((v) => `<option value="${v.id}">#${v.id} ${esc(v.label)} — ${esc(v.mainFileName)} (dwo:${v.dwo_count})</option>`).join("");
  if (vs.length && !state.versionId) { state.versionId = vs[vs.length - 1].id; sel.value = state.versionId; }
  if (state.versionId) sel.value = state.versionId;
  if (state.versionId) loadModel();
  return vs;
}
$("#version-select").addEventListener("change", (e) => { state.versionId = Number(e.target.value); state.model = null; loadModel(); });

$("#upload-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const dwoFiles = fd.getAll("dwo");
  fd.delete("dwo");
  // multipart "main" plus repeated dwo parts
  const main = e.target.querySelector('input[name=main]').files[0];
  const data = new FormData();
  data.set("label", fd.get("label") || "导入 " + new Date().toISOString());
  data.append("main", main);
  dwoFiles.forEach((f) => data.append("dwo", f));
  try {
    const row = await fetch("/api/versions", { method: "POST", body: data }).then((r) => { if (!r.ok) throw new Error(r.statusText); return r.json(); });
    state.versionId = row.id;
    await loadVersions();
  } catch (err) { alert("导入失败: " + err.message); }
});

// ---------- modules / snapshots ----------
$("#add-mod").addEventListener("click", () => {
  const name = $("#mod-name").value || "main";
  const rt = parseNum($("#mod-runtime").value);
  const fb = parseNum($("#mod-file").value);
  state.modules.push({ moduleName: name, runtimeBase: rt, fileBase: fb, note: null });
  renderModules();
});
function renderModules() {
  $("#mod-list").innerHTML = state.modules.map((m, i) =>
    `<li>${esc(m.moduleName)} rt=${m.runtimeBase == null ? "auto" : hex64(m.runtimeBase)} file=${m.fileBase == null ? "auto" : hex64(m.fileBase)}
      <button data-i="${i}">×</button></li>`).join("");
  $$("#mod-list button").forEach((b) => b.addEventListener("click", () => { state.modules.splice(Number(b.dataset.i), 1); renderModules(); }));
}
function parseNum(s) { if (!s || !s.trim()) return null; return Number(s.trim().replace(/^0x/, "0x")); }
$("#save-snap").addEventListener("click", async () => {
  if (!state.versionId) return alert("先选择版本");
  const r = await api("/api/snapshots", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ versionId: state.versionId, label: $("#snap-label").value || "快照", modules: state.modules }) });
  await loadSnapshots();
  $("#snapshot-select").value = r.id;
  state.snapshotModules = state.modules.map((m) => ({ ...m }));
});
async function loadSnapshots() {
  const ss = await api("/api/snapshots");
  const sel = $("#snapshot-select");
  sel.innerHTML = `<option value="">— 不使用快照（当前编辑的模块）—</option>` +
    ss.map((s) => `<option value="${s.id}">#${s.id} ${esc(s.label)} (v${s.versionId})</option>`).join("");
}
$("#snapshot-select").addEventListener("change", async (e) => {
  if (!e.target.value) { state.snapshotModules = null; return; }
  const ss = await api("/api/snapshots");
  const snap = ss.find((s) => s.id === Number(e.target.value));
  state.snapshotModules = JSON.parse(snap.moduleJson);
  state.versionId = snap.versionId; $("#version-select").value = snap.versionId; await loadModel();
});

// ---------- model rendering ----------
const SECTION_COLORS = ["#5b8def","#7fe0a5","#eccf75","#ed8aa0","#b58df1","#7fd1ff","#f5a36b","#9fefd8","#d0a0ff","#8f9bb8"];
async function loadModel() {
  if (!state.versionId) return;
  state.model = await api(`/api/versions/${state.versionId}/model`);
  renderSections(); renderRanges(); renderSequences(); renderCuTree();
}
function renderSections() {
  const secs = state.model.sections.filter((s) => s.size > 0);
  const max = Math.max(...secs.map((s) => Number(s.size)));
  $("#section-map").innerHTML = secs.map((s, i) => {
    const w = Math.max(2, Number(s.size) / max * 100);
    const c = SECTION_COLORS[i % SECTION_COLORS.length];
    return `<div class="seg" style="width:${w}%;background:${c}" title="${esc(s.name)} size=${Number(s.size)} sha=${esc(s.sha256)}">${esc(s.name.replace(".debug_","d_"))}</div>`;
  }).join("");
}
function renderRanges() {
  const rs = state.model.ranges;
  $("#ranges").innerHTML = `<table><thead><tr><th>start</th><th>end</th><th>宽</th><th>函数</th><th>CU</th><th>标记</th></tr></thead><tbody>` +
    rs.map((r) => `<tr class="${r.zeroLength ? "row-endseq" : ""}">
      <td class="mono">${hex64(r.start)}</td><td class="mono">${hex64(r.end)}</td>
      <td class="mono">${Number(r.end - r.start)}</td>
      <td>${esc(r.name || "?")}${r.inline ? ' <span class="pill">inline</span>' : ""}</td>
      <td>${esc(r.cuName || "")}</td>
      <td>${r.zeroLength ? '<span class="pill">zero-length</span>' : ""}</td></tr>`).join("") +
    `</tbody></table><p class="hint">共 ${rs.length} 段；重叠函数与零长度范围均保留。</p>`;
}
function renderSequences() {
  const seqs = state.model.sequences;
  $("#sequences").innerHTML = seqs.map((s, i) =>
    `<div class="card"><b>${s.id}</b>
      <span class="pill ${s.cuVersion >= 5 ? "dwarf5" : "dwarf4"}">DWARF${s.cuVersion}</span>
      <span class="mono">[${hex64(s.startAddress)}, ${hex64(s.endAddress)})</span>
      rows=${s.rowCount} files=${s.fileCount}
      <div>${s.files.map((f) => `<span class="pill">${esc(f || "?")}</span>`).join("")}</div>
      <button data-seq="${s.id}">查看状态变化</button></div>`).join("");
  $$("#sequences button").forEach((b) => b.addEventListener("click", () => loadRows(b.dataset.seq)));
}
async function loadRows(seqId) {
  const rows = await api(`/api/versions/${state.versionId}/sequences/${seqId}/rows`);
  $("#linerows").innerHTML = `<table><thead><tr><th>address</th><th>file:line:col</th><th>标志位</th></tr></thead><tbody>` +
    rows.map((r) => `<tr class="${r.endSeq ? "row-endseq" : ""} ${r.prologueEnd ? "row-prologue" : ""}">
      <td class="mono">${hex64(r.address)}</td>
      <td>${esc(r.file || "?")}:${r.line}:${r.column}</td>
      <td>${[r.isStmt ? "stmt":"", r.endSeq ? "END_SEQ":"", r.prologueEnd ? "prologue_end":"",
           r.epilogueBegin ? "epilogue_begin":"", r.basicBlock ? "basic_block":"", r.discriminator ? "disc="+r.discriminator:"",
           "op="+r.opIndex].filter(Boolean).join(" ")}</td></tr>`).join("") + "</tbody></table>";
}
function renderCuTree() {
  const m = state.model;
  $("#cu-and-tree").innerHTML = m.cus.map((cu) =>
    `<div class="card"><b>CU @ ${hex64(cu.offset)}</b>
      <span class="pill ${cu.version >= 5 ? "dwarf5" : "dwarf4"}">DWARF${cu.version}</span>
      ${cu.isSkeleton ? '<span class="pill">skeleton</span>' : ""}
      DIEs=${cu.dieCount}<br>${esc(cu.name || "?")} <span class="hint">${esc(cu.compDir || "")}</span>
      ${cu.warnings.length ? `<ul class="notes">${cu.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}
    </div>`).join("") +
    (m.warnings.length ? `<h2>解析信任度备注</h2><ul class="notes">${m.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : "");
}

// ---------- resolve ----------
$("#resolve-btn").addEventListener("click", async () => {
  const addresses = $("#addresses").value.split(/[\s,]+/).filter(Boolean);
  if (!addresses.length) return;
  const modules = state.snapshotModules || state.modules;
  const rs = await api("/api/resolve", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ versionId: state.versionId, addresses, modules }) });
  renderResults(rs);
});
function renderResults(rs) {
  $("#results").innerHTML = rs.map((r) => {
    const cand = r.functionCandidates[0];
    const loc = r.line ? `${esc(r.line.file || "?")}:${r.line.line}:${r.line.column}` : "<i>无行号</i>";
    const chain = cand ? cand.inlineChain.map((f, i) =>
      `<div class="chain">#${i} <b>${esc(f.name || "?")}</b> <span class="mono">[${hex64(f.start)},${hex64(f.end)})</span>` +
      (f.callLine ? ` <span class="hint">调用点 ${esc(f.callFile || "?")}:${f.callLine}:${f.callColumn}</span>` : "") + `</div>`).join("") : "<i>无函数候选</i>";
    const other = r.functionCandidates.length > 1
      ? `<details><summary class="hint">其它合法候选 ${r.functionCandidates.length - 1} 个（重叠 / 零长度）</summary>` +
        r.functionCandidates.slice(1).map((c) => `<div class="chain">${esc(c.name || "?")} <span class="mono">[${hex64(c.start)},${hex64(c.end)})</span> 宽=${Number(c.width)} 深度=${c.inlineDepth} 优先级=${c.explicitPriority}</div>`).join("") + `</details>` : "";
    return `<div class="card ${r.confidence.toLowerCase()}">
      <div><span class="addr">${esc(r.inputAddress)}</span>
        <span class="tag ${r.confidence.toLowerCase()}">${r.confidence}</span>
        ${loc} <span class="hint">(${esc(r.module)} #${r.loadGenerationIndex})</span></div>
      <div class="hint">runtime=${hex64(r.runtimeAddress)} relative=${hex64(r.relativeAddress)}
        load_bias=${hex64(r.loadBias)} CU=${esc(r.cuName || "?")}
        表版本=${r.tableVersion ?? "-"} 命中sequence数=${r.sequenceCount}</div>
      <div>${chain}</div>${other}
      ${r.notes.length ? `<ul class="notes">${r.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}
    </div>`;
  }).join("");
}

loadVersions().then(loadSnapshots);
