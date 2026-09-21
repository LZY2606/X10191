"use strict";
const $ = (id) => document.getElementById(id);
const hex = (v) => "0x" + BigInt(v).toString(16);
const dec = (v) => (v === null || v === undefined) ? "" : String(v);

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
function post(path, body) {
  return api(path, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body)});
}
function el(tag, cls, html) {
  const e = document.createElement(tag); if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html; return e;
}
function esc(s) { return String(s ?? "").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c])); }

document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
  document.querySelectorAll("nav button").forEach(x => x.classList.remove("active"));
  document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
  b.classList.add("active");
  $("tab-" + b.dataset.tab).classList.add("active");
  if (b.dataset.tab === "sections") loadSections();
  if (b.dataset.tab === "ranges") loadRanges();
  if (b.dataset.tab === "lines") loadSequences();
  if (b.dataset.tab === "inline") loadInline();
  if (b.dataset.tab === "snapshots") { loadSnapshots(); loadCrashes(); }
});

async function refreshVersionSelectors() {
  const vs = await api("/api/versions");
  window.VERSIONS = vs;
  const opts = vs.map(v => `<option value="${v.id}">${esc(v.label)} (#${v.id}, ${esc(v.tableVersion)})</option>`).join("");
  for (const id of ["s-version","r-version","l-version","n-version","ss-version"])
    $(id).innerHTML = opts;
  renderVersionTable(vs);
}
function renderVersionTable(vs) {
  $("v-table").innerHTML = `<tr><th>ID</th><th>标签</th><th>优先级</th><th>DWARF</th><th>build-id</th>
    <th>SHA256</th><th>大小</th><th>split</th><th>导入时间</th></tr>` +
  vs.map(v => `<tr><td>${v.id}</td><td>${esc(v.label)}</td><td>${v.priority}</td>
    <td class="mono">${esc(v.tableVersion)}</td><td class="mono">${esc(v.buildId ?? "")}</td>
    <td class="mono small">${esc((v.sha256||"").slice(0,16))}…</td><td>${v.sizeBytes}</td>
    <td>${v.hasSplit ? '<span class="tag ok">有 dwo</span>' : '<span class="tag info">单文件</span>'}</td>
    <td class="small">${new Date(v.importedAt).toLocaleString()}</td></tr>`).join("");
}
async function doImport() {
  try {
    const r = await post("/api/import", {path: $("i-path").value.trim(),
      label: $("i-label").value.trim() || null, priority: Number($("i-prio").value || 100)});
    alert("已导入为版本 #" + r.versionId);
    await refreshVersionSelectors();
  } catch (e) { alert("导入失败: " + e.message); }
}

// ---------- address resolution ----------
function parseAddr(s) {
  let t = s.trim().replace(/_/g, ""); if (!t) return null;
  if (t.startsWith("0x") || t.startsWith("0X")) return BigInt(t);
  if (/^[0-9a-fA-F]{6,}$/.test(t)) return BigInt("0x" + t);
  return BigInt(t);
}
async function doResolve() {
  const addrs = $("q-addrs").value.split(/\s+/).filter(Boolean);
  const snapshotId = $("q-snapshot").value || null;
  const answers = await post("/api/resolve", {addresses: addrs.map(a => "0x"+parseAddr(a).toString(16)), snapshotId:
      snapshotId ? Number(snapshotId) : null});
  window.LAST_ANSWERS = answers;
  renderAnswers(answers);
}
function tagFor(c) {
  if (c.candidateKind.includes("内联")) return '<span class="tag ok">'+c.candidateKind+'</span>';
  if (c.candidateKind === "零长度符号") return '<span class="tag warn">零长度符号</span>';
  if (c.candidateKind === "仅行号") return '<span class="tag info">仅行号</span>';
  return '<span class="tag info">'+c.candidateKind+'</span>';
}
function renderAnswers(answers) {
  const box = $("q-results"); box.innerHTML = "";
  answers.forEach((a, idx) => {
    const p = el("div", "panel");
    const head = `<h2>#${idx+1} 查询地址 <span class="addr-chip">${hex(a.queryAddress)}</span>
      <span class="pill">${a.candidates.length} 个合法候选</span></h2>`;
    let body = "";
    if (a.moduleLabel) body += `<div class="small mut">模块 ${esc(a.moduleLabel)} · 代次 ${a.generation}
      · load bias <span class="addr-chip">${hex(a.loadBias)}</span>
      · 相对地址 <span class="addr-chip">${hex(a.resolvedRelative)}</span></div>`;
    if (a.notes.length) body += `<div class="small" style="color:var(--warn);margin-top:4px">${a.notes.map(esc).join("<br/>")}</div>`;
    if (!a.candidates.length) { body += `<p>没有匹配的源码位置。</p>`; }
    body += a.candidates.map((c, i) => `
      <details class="cand" ${i===0?"open":""}>
        <summary>${i===0?'<b>★ 首选解释</b>  ':''}${tagFor(c)}
          <span class="addr-chip">${esc(c.file)||"?"}:${c.line}${c.column?":"+c.column:""}</span>
          <span class="pill">DWARF${c.dwarfVersion}${c.segmented?" · 分段地址":""}</span>
          <span class="pill">${esc(c.versionLabel)}#${c.versionId}</span>
          <span class="pill">范围宽 ${c.rangeWidth}${c.rangeZeroLength?" · 零长度":""}</span></summary>
        <div class="body small">
          <div>CU: <span class="mono">${esc(c.cuName)}</span> @ ${hex(c.cuOffset)}</div>
          <div>line sequence #${c.sequenceId}: ${hex(c.seqStart)} → ${hex(c.seqEnd)}（相对地址 ${hex(c.relativeAddress)}）</div>
          ${c.inlineChain.length ? `<div class="chain">内联调用链（${c.inlineChain.length} 帧，最深在最下）:` +
            c.inlineChain.map(f => `<div class="f">└ <b>${esc(f.name)}</b>
              <span class="mut">${f.tag===29?"[inlined_subroutine]":f.tag===46?"[subprogram]":"[lexical_block]"}</span>
              ${f.callFile?`调用点 <span class="mono">${esc(f.callFile)}:${f.callLine}${f.callColumn?":"+f.callColumn:""}</span>`:""}
              ${f.declFile?`声明 <span class="mono">${esc(f.declFile)}:${f.declLine}</span>`:""}</div>`).join("") +
            `</div>` : `<div class="mut">无内联帧（顶层函数）。</div>`}
        </div>
      </details>`).join("");
    p.innerHTML = head + body;
    box.appendChild(p);
  });
}
async function freezeCrash() {
  const sid = $("q-snapshot").value;
  if (!sid) return alert("请先选择并固定一个加载快照。");
  const addrs = $("q-addrs").value.split(/\s+/).filter(Boolean).map(a => "0x"+parseAddr(a).toString(16));
  if (!addrs.length) return;
  const r = await post(`/api/snapshots/${sid}/crash`,
    {title: $("q-title").value.trim() || "崩溃 " + new Date().toLocaleString(), addresses: addrs});
  alert("已冻结崩溃记录 #" + r.crashId + "，之后导入新版本不会改变它。");
}

// ---------- section map ----------
async function loadSections() {
  const vid = $("s-version").value; if (!vid) return;
  const m = await api(`/api/versions/${vid}/sections`);
  $("sec-meta").innerHTML = `ELF${m.elfClass===2?64:32} · ${m.littleEndian?"小端":"大端"} ·
    build-id <span class="mono">${esc(m.buildId ?? "")}</span> ·
    表版本 <span class="mono">${esc(m.tableVersion)}</span> · ${m.sections.length} 个 section`;
  const dbg = m.sections.filter(s => s.debug);
  const map = $("sec-map"); map.innerHTML = "";
  const maxAddr = Math.max(1, ...m.sections.map(s => Number(BigInt(s.addr) & 0xffffffffn)));
  const bar = el("div","bar");
  m.sections.filter(s => Number(s.addr)>0).forEach(s => {
    const left = Number(BigInt(s.addr) & 0xffffffffn) / maxAddr * 100;
    const w = Math.max(0.15, Number(BigInt(s.size) & 0xffffffffn) / maxAddr * 100);
    const seg = el("i", s.debug ? "hot" : "");
    seg.style.left = left + "%"; seg.style.width = w + "%";
    seg.title = `${s.name} @ ${hex(s.addr)} size=${s.size}`;
    bar.appendChild(seg);
  });
  map.appendChild(bar);
  $("sec-table").innerHTML = `<tr><th>section</th><th>addr</th><th>offset</th><th>size</th>
    <th>flags</th><th>SHA256 摘要</th></tr>` +
  m.sections.map(s => `<tr><td class="mono ${s.debug?'':''}">${s.debug?'<b style="color:var(--accent)">'+esc(s.name)+'</b>':esc(s.name)}</td>
    <td class="mono">${hex(s.addr)}</td><td class="mono">${hex(s.offset)}</td>
    <td class="mono">${s.size}</td><td class="mono">0x${s.flags.toString(16)}</td>
    <td class="mono small">${esc((s.sha256??"").slice(0,18))}…</td></tr>`).join("");
}

// ---------- ranges / CUs ----------
async function loadRanges() {
  const vid = $("r-version").value; if (!vid) return;
  const [cus, rgs] = await Promise.all([api(`/api/versions/${vid}/cus`),
    api(`/api/versions/${vid}/ranges`)]);
  $("cu-table").innerHTML = `<tr><th>CU 偏移</th><th>名称</th><th>版本</th><th>DIE</th><th>dwo</th></tr>` +
    cus.map(c => `<tr><td class="mono">${hex(c.offset)}</td><td>${esc(c.name||"(无名字)")}
      <div class="small mut">${esc(c.compDir??"")}</div></td>
      <td><span class="tag info">DWARF${c.version}</span></td><td>${c.dies}</td>
      <td>${c.isSkeleton?'<span class="tag '+(c.dwoResolved?'ok':'err')+'">skeleton '+(c.dwoResolved?'已合并':'缺 dwo')+'</span>'
        : c.isDwo?'<span class="tag warn">split</span>':''} ${c.dwoName?'<div class="small mut">'+esc(c.dwoName)+'</div>':''}</td></tr>`).join("");
  $("rg-table").innerHTML = `<tr><th>start</th><th>end</th><th>宽</th><th>名称</th><th>来源</th></tr>` +
    rgs.map(r => `<tr><td class="mono">${hex(r.start)}</td><td class="mono">${hex(r.end)}</td>
      <td class="mono">${r.zeroLength?'<span class="tag warn">0</span>':r.width}</td>
      <td>${esc(r.name)} ${r.inline?'<span class="tag ok">内联</span>':''}</td>
      <td class="small mut">${r.source}</td></tr>`).join("");
}

// ---------- line state machine ----------
async function loadSequences() {
  const vid = $("l-version").value; if (!vid) return;
  const seqs = await api(`/api/versions/${vid}/sequences`);
  $("l-seq").innerHTML = seqs.map(s => `<option value="${s.id}">#${s.id} ${hex(s.start)}→${hex(s.end)}
    [${s.rows} 行 / ${s.events} 事件 DWARF${s.dwarfVersion}${s.segmented?" seg":""}]</option>`).join("");
  if (seqs.length) loadEvents();
}
async function loadEvents() {
  const vid = $("l-version").value, sid = Number($("l-seq").value);
  const d = await api(`/api/versions/${vid}/sequences/${sid}/events`);
  const s = d.sequence;
  $("l-info").innerHTML = `sequence #${s.id} · CU ${hex(s.cuOffset)} · ${hex(s.start)} → ${hex(s.end)}
    · DWARF${s.dwarfVersion}${s.segmented?" · <b style='color:var(--warn)'>分段地址</b>":""}
    · 目录 ${s.dirs.map(esc).join(" / ")}`;
  $("l-rows").innerHTML = `<tr><th>地址</th><th>文件</th><th>行:列</th><th>标志</th></tr>` +
    d.rows.map(r => `<tr ${r.endSequence?'style="color:var(--warn)"':''}><td class="mono">${hex(r.address)}</td>
      <td>${esc(r.file)}</td><td class="mono">${r.line}:${r.column}</td>
      <td class="small">${r.isStmt?"stmt ":""}${r.endSequence?"END_SEQ ":""}${r.prologueEnd?"prologue ":""}${r.discriminator?"disc="+r.discriminator:""}</td></tr>`).join("");
  $("l-events").innerHTML = `<tr><th>#</th><th>地址</th><th>状态(文件:行:列)</th><th>opcode</th></tr>` +
    d.events.map(e => `<tr><td>${e.pos}</td><td class="mono">${hex(e.address)}</td>
      <td class="small">${esc(e.file)}:${e.line}:${e.column}${e.isStmt?" [stmt]":""}</td>
      <td class="small"><b>${esc(e.kind)}</b> <span class="mut">${esc(e.detail)}</span></td></tr>`).join("");
}

// ---------- inline tree ----------
async function loadInline() {
  const vid = $("n-version").value; if (!vid) return;
  const d = await api(`/api/versions/${vid}/inline`);
  $("n-table").innerHTML = `<tr><th>DIE</th><th>CU</th><th>深度</th><th>名称</th><th>调用行</th><th>范围</th></tr>` +
    d.map(n => `<tr><td class="mono">${hex(n.dieOffset)}</td><td class="mono small">${hex(n.cuOffset)}</td>
      <td>${n.depth}</td><td>${n.tag===29?'<span class="tag ok">inline</span> ':'<span class="tag info">func</span> '}${esc(n.name)}</td>
      <td class="mono small">${n.callLine??""}</td>
      <td class="small">${n.ranges.map(r => hex(r.start)+(r.zeroLength?"(0长)":"…"+hex(r.end))).join("<br/>")}</td></tr>`).join("");
}

// ---------- snapshots / crashes ----------
async function loadSnapshots() {
  const ss = await api("/api/snapshots");
  window.SNAPSHOTS = ss;
  $("ss-pick").innerHTML = ss.map(s => `<option value="${s.id}">${esc(s.name)} (#${s.id})</option>`).join("");
  $("q-snapshot").innerHTML = `<option value="">（全部快照/最近代次）</option>` +
    ss.map(s => `<option value="${s.id}">${esc(s.name)} (#${s.id})</option>`).join("");
  if (ss.length) loadSnapshotLoads();
}
async function createSnapshot() {
  const name = $("ss-name").value.trim(); if (!name) return;
  const r = await post("/api/snapshots", {name});
  $("ss-name").value = "";
  await loadSnapshots();
  $("ss-pick").value = String(r.snapshotId);
  loadSnapshotLoads();
}
async function addLoad() {
  const sid = Number($("ss-pick").value);
  const versionId = Number($("ss-version").value);
  const base = parseAddr($("ss-base").value.trim() || "0x0");
  const label = $("ss-label").value.trim() || undefined;
  await post(`/api/snapshots/${sid}/loads`, {versionId,
    baseAddress: "0x"+base.toString(16), generation: Number($("ss-gen").value), label});
  loadSnapshotLoads();
}
async function loadSnapshotLoads() {
  const sid = $("ss-pick").value; if (!sid) return;
  const loads = await api(`/api/snapshots/${sid}/loads`);
  $("ss-loads").innerHTML = `<tr><th>模块</th><th>版本</th><th>代次</th><th>基址</th><th>load bias</th><th>登记时间</th></tr>` +
    loads.map(l => `<tr><td>${esc(l.label)}</td><td>#${l.versionId}</td><td>${l.generation}</td>
      <td class="mono">${hex(l.baseAddress)}</td><td class="mono">${hex(l.bias)}</td><td class="small">${new Date(l.loadedAt).toLocaleString()}</td></tr>`).join("");
}
async function loadCrashes() {
  const cs = await api("/api/crashes");
  $("cr-table").innerHTML = `<tr><th>#</th><th>快照</th><th>标题</th><th>创建时间</th></tr>` +
    cs.map(c => `<tr><td>${c.id}</td><td>#${c.snapshotId}</td><td>${esc(c.title)}</td>
      <td class="small">${new Date(c.createdAt).toLocaleString()}</td></tr>`).join("");
}

refreshVersionSelectors().then(loadSnapshots).catch(e => {
  document.body.insertAdjacentHTML("afterbegin",
    `<div style="background:#3a1717;padding:10px">初始化失败: ${esc(e.message)}</div>`);
});
