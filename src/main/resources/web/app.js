"use strict";
const $ = (id) => document.getElementById(id);
const hex = (n) => "0x" + (BigInt(n < 0 ? n >>> 0 : n)).toString(16);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let MODULES = [];
let CURRENT = {};

async function api(path, opts) {
  const res = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts));
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body) });

document.querySelectorAll("nav button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $(b.dataset.tab).classList.add("active");
    if (b.dataset.tab === "records") loadRecords();
    if (b.dataset.tab === "snapshot") loadSnapshots();
  });
});

function moduleOptions(selectedId) {
  return MODULES.map((m) =>
    `<option value="${m.id}" ${String(m.id) === String(selectedId) ? "selected" : ""}>${esc(m.key)} v${m.version}${m.superseded ? " (旧)" : ""}</option>`
  ).join("");
}

async function loadModules() {
  MODULES = await api("/api/modules");
  $("moduleList").innerHTML = MODULES.map((m) => `
    <div class="card">
      <h4>${esc(m.fileName)}
        <span class="pill ${m.superseded ? "old" : ""}">${m.superseded ? "已被新版本取代" : "当前版本"}</span></h4>
      <div class="muted mono">${esc(m.key)} · v${m.version} · ${m.cuCount} CU</div>
      <div class="muted mono">sha256: ${esc(m.sha256.slice(0, 24))}…</div>
      <div class="muted">导入于 ${new Date(m.importedAt).toLocaleString()}</div>
      <div class="row"><button data-view="${m.id}">查看解析</button></div>
    </div>`).join("");
  $("moduleList").querySelectorAll("button[data-view]").forEach((b) =>
    b.addEventListener("click", () => {
      selectTab("detail");
      $("detailModule").value = b.dataset.view;
      loadDetail();
    }));
  ["detailModule", "inlineModule", "qModule"].forEach((id) => {
    const first = MODULES[0]?.id;
    $(id).innerHTML = moduleOptions(CURRENT[id] || first);
  });
  if (CURRENT.detailModule) $("detailModule").value = CURRENT.detailModule;
  $("moduleWarnings").textContent = MODULES.flatMap((m) => m).length
    ? "" : "";
}

function selectTab(name) {
  document.querySelector(`nav button[data-tab="${name}"]`).click();
}

let pickedFile = null;
$("modPick").addEventListener("change", () => {
  pickedFile = $("modPick").files[0] || null;
  if (pickedFile && !$("modKey").value.trim()) $("modKey").value = pickedFile.name;
});
$("btnImport").addEventListener("click", async () => {
  try {
    let base64 = $("modBase64").value.trim();
    let fileName = pickedFile ? pickedFile.name : null;
    if (!base64 && pickedFile) {
      const buf = await pickedFile.arrayBuffer();
      base64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
    }
    if (!base64) { alert("请选择 ELF/调试文件，或粘贴 base64。"); return; }
    const m = await post("/api/modules/import", {
      key: $("modKey").value.trim() || fileName || "module",
      fileName: fileName || $("modKey").value.trim() || "module",
      base64,
    });
    CURRENT.detailModule = m.id;
    $("modBase64").value = ""; $("modKey").value = ""; $("modPick").value = "";
    pickedFile = null;
    await loadModules();
  } catch (e) { alert(e.message); }
});

async function loadDetail() {
  const id = $("detailModule").value;
  CURRENT.detailModule = id;
  if (!id) return;
  const d = await api(`/api/modules/${id}`);
  $("detailCu").innerHTML = d.cus.map((c, i) =>
    `<option value="${c.index}">#${c.index} ${esc(c.name || "(anon)")} · DWARF${c.version}</option>`).join("");
  renderDetail(d);
  $("detailCu").onchange = () => renderDetail(d);
  // populate inline tab selectors
  $("inlineCu").innerHTML = $("detailCu").innerHTML;
  $("inlineModule").value = id;
  $("inlineCu").onchange = () => renderInline(d);
  renderInline(d);
}

function renderDetail(d) {
  renderSectionMap(d);
  const ci = parseInt($("detailCu").value || "0", 10);
  const scopes = d.scopes[ci] || [];
  const rows = (d.lineRows[ci] || []);
  $("rangeTable").innerHTML = `<table><thead><tr>
    <th>scope</th><th>start</th><th>end</th><th>长度</th><th>depth/内联</th><th>调用点</th></tr></thead><tbody>
    ${scopes.flatMap((s) => s.ranges.map((rg) => `<tr>
      <td>${esc(s.name || s.linkageName || "(anon)")}${s.inline ? '<span class="badge">inlined</span>' : ""}</td>
      <td class="mono">${hex(rg.start)}</td><td class="mono">${hex(rg.end)}</td>
      <td class="mono">${rg.zeroLength ? '<span class="badge zero">零长度</span>' : rg.length}</td>
      <td>${s.depth}</td>
      <td class="mono">${esc(s.callFile || "")}:${s.callLine ?? ""}</td></tr>`)).join("")}
  </tbody></table>`;

  const seqs = d.sequences[ci] || [];
  $("sequenceList").innerHTML = seqs.map((sq) => {
    const sr = rows.filter((r) => r.sequenceIndex === sq.index);
    return `<div class="cand">
      <div><b>sequence #${sq.index}</b>
        <span class="badge seq">${hex(sq.start)} – ${hex(sq.end)}</span>
        <span class="small">${sq.rowCount} rows</span></div>
      <table><thead><tr><th>地址</th><th>文件</th><th>行:列</th><th>stmt</th><th>状态变化</th></tr></thead><tbody>
      ${sr.map((r) => `<tr>
        <td class="mono">${hex(r.address)}${r.endSequence ? ' <span class="badge zero">end_sequence</span>' : ""}</td>
        <td>${esc(r.file || "")}</td>
        <td class="mono">${r.line}:${r.column}</td>
        <td>${r.isStmt ? "✓" : ""}</td>
        <td class="small">${[r.basicBlock && "basic_block", r.prologueEnd && "prologue_end", r.epilogueBegin && "epilogue_begin", r.discriminator ? "disc=" + r.discriminator : ""].filter(Boolean).join(", ")}</td>
      </tr>`).join("")}
      </tbody></table></div>`;
  }).join("");
}

function renderSectionMap(d) {
  const digests = d.digests.filter((x) => x.present);
  const max = Math.max(1, ...digests.map((x) => Number(x.offset + x.size)));
  $("sectionMap").innerHTML = digests.map((s) => {
    const left = Number(s.offset) / max * 100;
    const width = Math.max(0.3, Number(s.size) / max * 100);
    return `<div class="secbar" title="offset ${hex(Number(s.offset))} size ${s.size} sha ${s.sha256.slice(0,16)}">
      <div class="fill" style="left:${left}%;width:${width}%"></div>
      <div class="lab">${esc(s.name)} <span class="small">@${hex(Number(s.offset))} · ${s.size}B</span></div></div>`;
  }).join("") + (d.warnings.length ? `<div class="warnbox">${d.warnings.map(esc).join("\n")}</div>` : "");
}

$("detailModule").addEventListener("change", loadDetail);
$("inlineModule").addEventListener("change", async () => {
  const id = $("inlineModule").value;
  const d = await api(`/api/modules/${id}`);
  $("inlineCu").innerHTML = d.cus.map((c, i) =>
    `<option value="${c.index}">#${c.index} ${esc(c.name || "(anon)")}</option>`).join("");
  $("inlineCu").onchange = () => renderInline(d);
  renderInline(d);
});

function renderInline(d) {
  const ci = parseInt($("inlineCu").value || "0", 10);
  const scopes = d.scopes[ci] || [];
  // Build a tree keyed on depth/offset ordering from the flat scope list.
  const roots = [];
  const stack = [];
  for (const s of scopes) {
    const node = { s, kids: [] };
    while (stack.length && stack[stack.length - 1].s.depth >= s.depth) stack.pop();
    if (stack.length) stack[stack.length - 1].kids.push(node);
    else roots.push(node);
    stack.push(node);
  }
  const draw = (nodes) => "<ul>" + nodes.map((n) => {
    const s = n.s;
    const rg = s.ranges[0];
    return `<li><b>${esc(s.name || s.linkageName || "(anonymous)")}</b>
      ${s.inline ? '<span class="badge">inlined</span>' : ""}
      <span class="small mono">${rg ? hex(rg.start) + "–" + hex(rg.end) : ""}</span>
      <span class="small">${esc(s.callFile || "")}:${s.callLine ?? ""}</span>
      ${draw(n.kids)}</li>`;
  }).join("") + "</ul>";
  $("inlineTree").innerHTML = draw(roots) || '<p class="muted">该 CU 无子程序范围。</p>';
}

// ---- single address query ----
$("btnQuery").addEventListener("click", async () => {
  try {
    const body = {
      moduleKey: MODULES.find((m) => String(m.id) === $("qModule").value)?.key,
      moduleVersion: null,
      relative: parseNum($("qRel").value),
      loadBias: parseNum($("qBias").value || "0"),
      generation: parseInt($("qGen").value || "1", 10),
    };
    const r = await post("/api/query/relative", body);
    renderQuery(r);
  } catch (e) { $("queryResult").innerHTML = `<p class="err">${esc(e.message)}</p>`; }
});

function parseNum(s) {
  s = s.trim();
  if (s.toLowerCase().startsWith("0x")) return Number("0x" + s.slice(2));
  return Number(s);
}

function renderQuery(r) {
  if (!r.resolved) {
    $("queryResult").innerHTML = `<div class="cand"><b>未命中</b>
      <div class="small">${(r.notes || []).map(esc).join("；")}</div>
      ${warningsBlock(r.warnings)}</div>`;
    return;
  }
  $("queryResult").innerHTML = `
    <div class="small">load bias <b class="mono">${hex(r.loadBias)}</b> · 代次 <b>${r.generation}</b> ·
      ${r.candidates.length} 个合法候选 · ${(r.notes || []).map(esc).join("；")}</div>` +
    r.candidates.map((c, i) => `<div class="cand ${i === 0 ? "primary" : ""}">
      <div><b>#${i + 1} ${esc(c.scopeName || "(无 DIE 范围，仅行表)")}</b>
        <span class="badge ${c.source === "line-only" ? "zero" : "seq"}">${c.source}</span>
        ${c.dwoMissing ? '<span class="badge zero">dwo 缺失</span>' : ""}</div>
      <div class="kv"><b>源码：</b>${esc(c.filePath || "?")}:${c.line ?? "?"}:${c.column ?? 0}</div>
      <div class="kv"><b>CU：</b>${esc(c.cuName || "?")} @ ${hex(c.cuOffset)} · ${esc(c.cuCompDir || "")}</div>
      <div class="kv"><b>模块：</b>${esc(c.moduleKey)} v${c.moduleVersion} (${esc(c.moduleFileName)})</div>
      <div class="kv"><b>相对地址：</b><span class="mono">${hex(c.relativeAddress)}</span>
        <b>运行时：</b><span class="mono">${hex(c.inputAddress)}</span></div>
      <div class="kv"><b>命中范围：</b><span class="mono">${hex(c.rangeStart)}–${hex(c.rangeEnd)}</span>
        宽度 ${c.rangeLength} · sequence #${c.sequenceIndex ?? "-"} · 内联深度 ${c.inlineDepth}</div>
      <div class="kv"><b>使用的表版本：</b>${esc(c.tableVersion)}</div>
      <div><b>内联调用链：</b>${chainHtml(c.inlineChain)}</div>
      ${warningsBlock(c.warnings)}
    </div>`).join("");
}

function chainHtml(chain) {
  if (!chain || !chain.length) return '<span class="small">（无）</span>';
  return '<div class="chain">' + chain.map((f, i) =>
    `<div>${i}. <b>${esc(f.name)}</b> <span class="small mono">@die ${hex(f.dieOffset)}</span>
      <span class="small">调用点 ${esc(f.callFile || "")}:${f.callLine ?? ""}</span></div>`).join("") + "</div>";
}
function warningsBlock(w) {
  if (!w || !w.length) return "";
  return `<div class="warnbox">${w.map(esc).join("\n")}</div>`;
}

// ---- snapshots ----
function addLoadRow(load) {
  const row = document.createElement("div");
  row.className = "row snap-row";
  row.innerHTML = `
    <select class="s-mod">${moduleOptions()}</select>
    <input class="s-bias mono" placeholder="load bias" value="${load?.loadBias != null ? hex(load.loadBias) : "0x0"}"/>
    <input class="s-gen" type="number" placeholder="代次" value="${load?.generation || 1}" style="width:70px"/>
    <input class="s-label" placeholder="标签（可选）" value="${esc(load?.label || "")}"/>
    <button class="s-del">删除</button>`;
  row.querySelector(".s-del").onclick = () => row.remove();
  if (load) row.querySelector(".s-mod").value = String(MODULES.find((m) => m.key === load.moduleKey && m.version === load.moduleVersion)?.id || MODULES[0]?.id);
  $("snapRows").appendChild(row);
}
$("btnAddLoad").onclick = () => addLoadRow();
$("btnSaveSnap").onclick = async () => {
  try {
    const loads = [...document.querySelectorAll(".snap-row")].map((r) => {
      const m = MODULES.find((x) => String(x.id) === r.querySelector(".s-mod").value);
      return { moduleKey: m.key, moduleVersion: m.version,
        loadBias: parseNum(r.querySelector(".s-bias").value || "0"),
        generation: parseInt(r.querySelector(".s-gen").value || "1", 10),
        label: r.querySelector(".s-label").value || null };
    });
    const snap = await post("/api/snapshots", { name: $("snapName").value || "snapshot", loads });
    $("snapRows").innerHTML = "";
    await loadSnapshots();
    alert("已保存快照 #" + snap.id);
  } catch (e) { alert(e.message); }
};
async function loadSnapshots() {
  const snaps = await api("/api/snapshots");
  $("snapshotList").innerHTML = snaps.map((s) => `
    <div class="cand"><b>#${s.id} ${esc(s.name)}</b> <span class="small">${new Date(s.createdAt).toLocaleString()}</span>
    <table><tbody>${s.loads.map((l) => `<tr><td>${esc(l.moduleKey)} v${l.moduleVersion}</td>
      <td class="mono">bias ${hex(l.loadBias)}</td><td>代次 ${l.generation}</td><td>${esc(l.label || "")}</td></tr>`).join("")}
    </tbody></table></div>`).join("");
  $("batchSnap").innerHTML = snaps.map((s) => `<option value="${s.id}">#${s.id} ${esc(s.name)}</option>`).join("");
}

// ---- batch ----
$("btnBatch").onclick = async () => {
  try {
    const r = await post("/api/batches", {
      snapshotId: parseInt($("batchSnap").value, 10),
      name: $("batchName").value || "batch",
      raw: $("batchRaw").value,
    });
    $("batchResult").innerHTML = r.results.map((x) => {
      if (x.error) return `<div class="cand"><span class="mono">${hex(x.inputAddress)}</span> <span class="err">${esc(x.error)}</span></div>`;
      const e = x.explanation;
      const top = e.candidates[0];
      return `<div class="cand ${e.resolved ? "primary" : ""}">
        <div><span class="mono">${hex(x.inputAddress)}</span> →
          模块 <b>${esc(x.moduleKey)} v${x.moduleVersion}</b>
          bias <span class="mono">${hex(x.loadBias)}</span> 代次 ${x.generation}
          相对 <span class="mono">${hex(x.relativeAddress)}</span></div>
        ${top ? `<div class="kv"><b>${esc(top.scopeName || "")}</b> · ${esc(top.filePath || "?")}:${top.line ?? "?"}
          · seq #${top.sequenceIndex ?? "-"} · 表 ${esc(top.tableVersion)} · 候选 ${e.candidates.length}</div>
          ${chainHtml(top.inlineChain)}` : '<span class="err">未命中</span>'}
        ${warningsBlock(e.warnings)}
      </div>`;
    }).join("");
  } catch (e) { $("batchResult").innerHTML = `<p class="err">${esc(e.message)}</p>`; }
};

// ---- records ----
async function loadRecords() {
  const batches = await api("/api/batches");
  $("recordList").innerHTML = batches.map((b) => `
    <div class="cand"><b>#${b.id} ${esc(b.name)}</b>
      <span class="small">快照 #${b.snapshotId} · ${new Date(b.createdAt).toLocaleString()}</span>
      <div class="mono small">${b.addresses.map(hex).map(esc).join("<br>")}</div>
      <div class="small">原始输入已固定保存，重新导入调试文件不改变本记录。</div></div>`).join("");
}

// boot
(async function init() {
  await loadModules();
  await loadSnapshots();
  addLoadRow();
  if (MODULES.length) loadDetail();
})();
