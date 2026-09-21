const $ = (id) => document.getElementById(id);
let versions = [], detail = null, crashes = [];
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error((await r.text()) || r.status);
  return r.json();
};
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const fmtLong = (s) => s ?? "-";

async function boot() {
  await refreshVersions();
  await refreshCrashes();
}
async function refreshVersions() {
  const j = await api("/api/versions");
  versions = j.versions;
  const sel = $("verSelect");
  sel.innerHTML = versions.map(v => `<option value="${v.id}">${esc(v.label)} #${v.id}${v.imported ? "" : "（空）"}</option>`).join("");
  if (versions.length) await loadVersion();
}
async function createVersion() {
  const label = $("newVerLabel").value.trim() || `version-${Date.now()}`;
  await api("/api/versions", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({label})});
  $("newVerLabel").value = "";
  await refreshVersions();
}
function curVersion() { return Number($("verSelect").value); }
async function uploadFile() {
  const f = $("fileInput").files[0];
  if (!f) { $("importMsg").textContent = "请先选择文件"; return; }
  const fd = new FormData();
  fd.append("role", $("roleSelect").value);
  fd.append("file", f);
  $("importMsg").textContent = "解析中…";
  try {
    const j = await api(`/api/versions/${curVersion()}/import`, {method:"POST", body: fd});
    $("importMsg").innerHTML = `<span class="ok">CU=${j.cuCount} size=${j.size}</span>`;
    await loadVersion(); await refreshVersions();
  } catch (e) { $("importMsg").innerHTML = `<span class="issue-error">${esc(e.message)}</span>`; }
}
async function loadVersion() {
  const id = curVersion(); if (!id) { detail = null; return; }
  detail = await api(`/api/versions/${id}`);
  renderDetail();
}
async function createCrash() {
  const label = $("crashLabel").value.trim() || `crash-${Date.now()}`;
  await api("/api/crashes", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({versionId: curVersion(), label})});
  $("crashLabel").value = "";
  await refreshCrashes();
}
async function refreshCrashes() {
  const j = await api("/api/crashes");
  crashes = j.crashes.filter(c => !curVersion() || c.versionId === curVersion());
  $("crashSelect").innerHTML = crashes.map(c => `<option value="${c.id}">${esc(c.label)} (v${c.versionId})</option>`).join("");
  await refreshLoads();
}
async function addLoad() {
  const cid = Number($("crashSelect").value);
  if (!cid) { alert("请先新建并选择崩溃记录"); return; }
  await api(`/api/crashes/${cid}/loads`, {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({moduleName: $("modName").value || "main",
      runtimeBase: $("rtBase").value.trim(), bias: $("exBias").value.trim() || null})});
  $("rtBase").value = ""; $("exBias").value = "";
  await refreshLoads();
}
async function refreshLoads() {
  const cid = Number($("crashSelect").value);
  const box = $("loads"); const gen = $("genSelect");
  if (!cid) { box.innerHTML = '<span class="muted">无崩溃</span>'; gen.innerHTML = '<option value="">所有加载代次</option>'; return; }
  const j = await api(`/api/crashes/${cid}/loads`);
  box.innerHTML = j.loads.length ? `<table><tr><th>代次</th><th>runtime</th><th>link</th><th>bias</th></tr>${
    j.loads.map(l=>`<tr><td>${l.generation}</td><td class="mono">${l.runtimeBase}</td><td class="mono">${l.linkBase}</td><td class="mono addr">${l.bias}</td></tr>`).join("")}</table>`
    : '<span class="muted">尚无加载快照</span>';
  gen.innerHTML = '<option value="">所有加载代次</option>' + j.loads.map(l=>`<option value="${l.generation}">代次 ${l.generation}</option>`).join("");
}

async function queryOne() {
  const addr = $("oneAddr").value.trim();
  if (!addr) return;
  const body = {addresses: addr, mode: $("mode").value, generation: $("genSelect").value || null,
    crashId: Number($("crashSelect").value) || null};
  const j = await api(`/api/versions/${curVersion()}/query-batch`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body)});
  renderBatch(j.results, false);
}
async function queryBatch() {
  const addresses = $("batchAddrs").value;
  if (!addresses.trim()) return;
  const body = {addresses, mode: $("mode").value, generation: $("genSelect").value || null,
    crashId: Number($("crashSelect").value) || null};
  const j = await api(`/api/versions/${curVersion()}/query-batch`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body)});
  renderBatch(j.results, true);
}
function renderBatch(results, multi) {
  const box = $("results");
  if (!results.length) { box.innerHTML = '<span class="muted">无结果</span>'; return; }
  box.innerHTML = results.map((r, idx) => {
    if (r.error) return `<div class="cand"><b>${esc(r.input)}</b> <span class="issue-error">${esc(r.error)}</span></div>`;
    return r.results.map(res => renderResult(res, r.input)).join("");
  }).join("");
}
function renderResult(r, input) {
  const cands = r.candidates.length ? r.candidates : [];
  const head = `<div class="cand">
    <div class="head"><div><b class="mono addr">${esc(input)}</b>
      <div class="muted">相对地址 <span class="mono">${r.relativeAddress}</span> ·
      load bias <span class="mono addr">${r.loadBias}</span>${r.generation!=null?` · 加载代次 <span class="badge">#${r.generation}</span>`:""} ·
      模块 ${esc(r.module||"-")}</div></div>
      <div>${cands.length?`<span class="tag ${cands[0].confidence}">${cands[0].confidence}</span>`:'<span class="tag line-only">未命中</span>'}</div></div>`;
  if (!cands.length) return head + '<div class="note">该相对地址未落入任何 line sequence / 范围。</div></div>';
  return head + cands.slice(0, 6).map(c => `
    <div style="border-top:1px solid var(--line);padding-top:8px;margin-top:8px">
      <div><b>${esc(c.file)}:${c.line}:${c.column}</b>
        <span class="tag ${c.confidence}">rank ${c.rank} · ${c.confidence}</span>
        <span class="muted">函数 ${esc(c.function||"-")}</span></div>
      <div class="kv" style="margin-top:6px">
        <div>CU</div><div class="mono">${esc(c.cuName||"-")} @ ${c.cuOffset} (DWARF${c.dwarfVersion})</div>
        <div>Line Sequence</div><div class="mono">#${c.sequenceIndex} ${c.sequenceStart} → ${c.sequenceEnd}（行地址 ${c.rowAddress}）</div>
        <div>使用表版本</div><div class="mono">.debug_line v${c.lineTableVersion}</div>
        <div>最窄范围</div><div class="mono">${c.enclosingRange?`${c.enclosingRange.low}–${c.enclosingRange.high} 长度 ${c.enclosingRange.length}`:"-"}</div>
        <div>内联深度</div><div>${c.inlineDepth} · dwo ${c.dwoResolved?"已解析":"缺失/不适用"}</div>
      </div>
      <div class="frames">${c.inlineChain.map((f,i)=>`
        <div class="frame">${"▸ ".repeat(1)}<b>${esc(f.name||f.tag)}</b>
          <span class="muted">[${f.tag} · ${f.source}]</span>
          ${f.callFile?`<div class="muted" style="margin-left:14px">调用点 ${esc(f.callFile)}:${f.callLine??"?"}:${f.callColumn??"?"}</div>`:""}
        </div>`).join("")}
      </div>
      <div>${c.trustNotes.map(n=>`<div class="note">⚠ ${esc(n)}</div>`).join("")}</div>
    </div>`).join("") + (r.candidates.length>6?'<div class="muted">…更多候选已保留并稳定排序</div>':'') + '</div>';
}

function tab(name) {
  for (const t of ["map","ranges","line","inline","issues"]) $(`tab-${t}`).hidden = (t !== name);
  document.querySelectorAll(".tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === name));
}
function bar(min, max, low, high, cls, label) {
  const span = max - min || 1;
  const left = ((low - min) / span) * 100;
  const width = Math.max(((high - low) / span) * 100, 0.4);
  return `<div class="bar"><div class="seg ${cls}" style="left:${left}%;width:${width}%" title="${label}">${label}</div></div>`;
}
function renderDetail() {
  if (!detail) return;
  // section map
  const secs = detail.sections;
  const maxSize = Math.max(1, ...secs.map(s=>parseInt(s.size)||0));
  $("tab-map").innerHTML = `<div class="muted" style="margin-bottom:6px">${detail.files.length} 个文件 · ${detail.cus.length} 个 CU；条带宽度按 section 字节数（对数感仅用于可视）</div>
    <div class="scroll"><table><tr><th>#</th><th>文件</th><th>section</th><th>地址</th><th>大小</th><th>解析</th></tr>
    ${secs.map(s=>`<tr><td>${s.index}</td><td>${esc(s.file)}</td><td class="mono">${esc(s.name)}</td>
      <td class="mono">${s.addr}</td><td class="mono">${s.size}</td>
      <td>${s.parsed?'<span class="ok">●</span>':""}</td></tr>`).join("")}</table></div>`;
  // ranges (flatten per CU + dies)
  const allRanges = [];
  for (const cu of detail.cus) {
    (cu.ranges||[]).forEach(r=>allRanges.push({cu:cu.name||cu.offset, label:`CU ${cu.name||cu.offset}`, ...r, zero:r.zeroLength}));
    JSON.parse(cu.dies).forEach(d=>(d.ranges||[]).forEach(r=>allRanges.push({cu:cu.name, label:`${d.tag} ${d.name||""}`.trim(), ...r, zero:r.zeroLength})));
  }
  const nums = allRanges.filter(r=>!r.zero).flatMap(r=>[parseBig(r.low), parseBig(r.high)]);
  const min = nums.length?Math.min(...nums):0n, max = nums.length?Math.max(...nums):1n;
  $("tab-ranges").innerHTML = allRanges.length ? allRanges.map(r =>
    bar(Number(min), Number(max>min?max:min+1n), Number(parseBig(r.low)), Number(parseBig(r.high>r.low?r.high:r.low+1n)),
        r.zero?"zero":"", `${r.label} ${r.low}..${r.high}${r.zero?" [零长度]":""}`)).join("")
    : '<span class="muted">无范围</span>';

  // line program state transitions
  const lineTabs = detail.cus.filter(c=>c.line).map(cu => {
    const lt = cu.line;
    const seqs = lt.sequences.map(seq => {
      const rows = seq.rows.map((r,i)=>`<tr${r.endSequence?' style="color:var(--warn)"':""}>
        <td class="mono">${r.address}</td><td>${r.line}</td><td>${r.column}</td>
        <td class="mono">${esc(r.path)}</td><td>${r.endSequence?"END_SEQ":""}</td>
        <td>${r.stmt?"stmt":""}</td><td>${r.discriminator||""}</td></tr>`).join("");
      return `<div style="margin-bottom:10px"><div class="muted">Sequence #${seq.index} ${seq.start} → ${seq.end}</div>
        <div class="scroll" style="max-height:180px"><table><tr><th>address</th><th>line</th><th>col</th><th>file</th><th></th><th></th><th>disc</th></tr>${rows}</table></div></div>`;
    }).join("");
    return `<div class="card" style="background:var(--panel2)"><h2>${esc(cu.name||cu.offset)} · .debug_line v${lt.version}</h2>${seqs}</div>`;
  }).join("");
  $("tab-line").innerHTML = lineTabs || '<span class="muted">无 line program</span>';

  // inline tree
  $("tab-inline").innerHTML = detail.cus.map(cu => {
    const dies = JSON.parse(cu.dies);
    const byParent = {};
    dies.forEach(d=>{ const p=d.parent??"root"; (byParent[p]??(byParent[p]=[])).push(d); });
    function node(d, depth) {
      const kids = (byParent[d.offset]||[]);
      const rng = (d.ranges||[]).map(r=>`${r.low}..${r.high}${r.zeroLength?"(0len)":""}`).join(" ");
      return `<div class="frame" style="margin-left:${depth*14}px">
        <span class="tag">${esc(d.tag)}</span> <b>${esc(d.name||"")}</b>
        <span class="muted mono">${rng}</span>
        ${d.callLine?`<span class="muted"> 调用 ${esc(d.callFile||"")}:${d.callLine}:${d.callColumn??""}</span>`:""}
        ${kids.map(k=>node(k,depth+1)).join("")}</div>`;
    }
    const roots = dies.filter(d=>!d.parent);
    const splitTag = cu.isSplit ? ", split" : "";
    const dwoTag = cu.dwoResolved ? ", dwo已合并" : (cu.isSplit ? ", 缺dwo" : "");
    return `<div class="card" style="background:var(--panel2)"><h2>${esc(cu.name||cu.offset)} (DWARF${cu.version}${splitTag}${dwoTag})</h2>
      ${roots.map(r=>node(r,0)).join("")}</div>`;
  }).join("");

  // issues
  const issues = [];
  (detail.issues||[]).forEach(i=>issues.push(i));
  detail.cus.forEach(cu=>JSON.parse(cu.issues||"[]").forEach(i=>issues.push(i)));
  $("tab-issues").innerHTML = issues.length ? `<div class="scroll"><table><tr><th>级别</th><th>范围</th><th>信息</th></tr>${
    issues.map(i=>`<tr><td class="issue-${i.severity}">${i.severity}</td><td class="mono">${esc(i.scope)}</td><td>${esc(i.message)}</td></tr>`).join("")}</table></div>`
    : '<span class="ok">无解析告警：所有 section 完整可信。</span>';
}
function parseBig(h) { return BigInt(String(h).startsWith("0x")?String(h):"0x"+String(h)); }

$("verSelect").addEventListener?.("change", refreshCrashes);
boot();
