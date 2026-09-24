package compass

fun indexHtml(): String = """
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>行址罗盘</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2e;--panel2:#18233d;--line:#2b3a5f;--text:#e7eefc;--muted:#9fb0d0;--accent:#62d2ff;--good:#7ee0a5;--warn:#ffd166;--bad:#ff7b8a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top left,#172444,#0b1020 45%);font:14px/1.55 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;color:var(--text)}
header{padding:28px 34px 16px;border-bottom:1px solid var(--line)}h1{margin:0;font-size:30px;letter-spacing:.18em}.sub{color:var(--muted);margin-top:6px}
main{display:grid;grid-template-columns:360px 1fr;gap:18px;padding:20px 28px}.card{background:rgba(18,26,46,.92);border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:0 10px 30px #0004;margin-bottom:16px}
h2{font-size:16px;margin:0 0 12px;color:var(--accent)}label{display:block;color:var(--muted);font-size:12px;margin:8px 0 4px}input,textarea,select,button{width:100%;background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:9px;padding:9px 10px;font:inherit}textarea{min-height:130px;resize:vertical}button{cursor:pointer;background:linear-gradient(135deg,#178fb5,#2757a8);border:0;font-weight:700;margin-top:10px}button.secondary{background:#263555}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{border-bottom:1px solid var(--line);padding:7px 6px;text-align:left;vertical-align:top}th{color:var(--muted);position:sticky;top:0;background:var(--panel)}.scroll{max-height:340px;overflow:auto}.tag{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:1px 8px;color:var(--muted);font-size:11px}.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.tabs{display:flex;gap:8px;margin-bottom:12px}.tabs button{width:auto;margin:0}.result{border-left:3px solid var(--accent);padding:10px 12px;background:#0f172b;border-radius:8px;margin:8px 0}.chain{margin-left:12px;border-left:1px dashed var(--line);padding-left:10px;color:var(--muted)}
</style>
</head>
<body>
<header><h1>行址罗盘</h1><div class="sub">本地解析 ELF / DWARF 4 / DWARF 5：section 地图、line program、内联树、load bias 与稳定候选解释</div></header>
<main>
<section>
<div class="card"><h2>导入调试文件版本</h2><input id="file" type="file" accept=".elf,.o,.so,.dwo,*/*"><button onclick="uploadFile()">导入并形成不可变版本</button><div id="importResult" class="mono"></div></div>
<div class="card"><h2>固定模块加载快照</h2><label>版本</label><select id="versionSelect"></select><div class="grid2"><div><label>运行时模块基址</label><input id="moduleBase" value="0x7f000000"></div><div><label>相对地址基址</label><input id="relativeBase" value="0"></div></div><label>快照名</label><input id="snapshotLabel" value="crash-generation-1"><label>segment selector（可空）</label><input id="segment" placeholder="0"><button onclick="createSnapshot()">固定快照</button><div id="snapshotResult"></div></div>
<div class="card"><h2>批量粘贴栈地址</h2><textarea id="addresses" placeholder="0x1040\n0x1048&#10;4168"></textarea><button onclick="batchQuery()">批量查询</button><button class="secondary" onclick="loadAll()">刷新数据</button></div>
</section>
<section>
<div class="card"><h2>地址解释</h2><div id="queryResults">选择快照并粘贴地址，结果会列出 load bias、CU、sequence、内联调用链和 DWARF/line table 版本。</div></div>
<div class="tabs"><button onclick="show('sections')">Section 地图</button><button onclick="show('ranges')">地址范围</button><button onclick="show('lines')">Line Program 状态</button><button onclick="show('trust')">可信度 / 损坏隔离</button></div>
<div id="sections" class="panel card"><h2>Section 地图</h2><div class="scroll"><table><thead><tr><th>#</th><th>名称</th><th>地址</th><th>偏移</th><th>大小</th><th>SHA-256 摘要</th></tr></thead><tbody id="sectionsBody"></tbody></table></div></div>
<div id="ranges" class="panel card" hidden><h2>地址范围与内联树</h2><div class="scroll"><table><thead><tr><th>CU</th><th>函数 / DIE</th><th>范围</th><th>Segment</th><th>来源</th><th>DWARF</th></tr></thead><tbody id="rangesBody"></tbody></table></div></div>
<div id="lines" class="panel card" hidden><h2>Line Program 状态变化</h2><div class="scroll"><table><thead><tr><th>CU</th><th>Seq</th><th>地址</th><th>文件:行:列</th><th>Stmt</th><th>End</th><th>Disc</th></tr></thead><tbody id="linesBody"></tbody></table></div></div>
<div id="trust" class="panel card" hidden><h2>解析告警</h2><div class="scroll"><table><thead><tr><th>阶段</th><th>级别</th><th>偏移</th><th>信息</th></tr></thead><tbody id="warningsBody"></tbody></table></div></div>
</section>
</main>
<script>
let versions=[];async function api(url,options){const r=await fetch(url,options);if(!r.ok)throw new Error(await r.text());return r.json()}
function hex(v){return '0x'+BigInt(v).toString(16)}function esc(s){return String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function loadAll(){versions=await api('/api/versions');versionSelect.innerHTML=versions.map(v=>`<option value="${v.id}">#${v.id} ${esc(v.fileName)} ${v.cuCount} CU</option>`).join('');await refreshPanels()}
document.getElementById('versionSelect').addEventListener('change',refreshPanels);
async function refreshPanels(){const id=versionSelect.value;if(!id)return;const [sections,ranges,lines,warnings]=await Promise.all(['sections','ranges','lines','warnings'].map(x=>api(`/api/versions/${id}/${x}`)));sectionsBody.innerHTML=sections.map(s=>`<tr><td>${s.ordinal}</td><td class="mono">${esc(s.name)||'<span class=warn>NULL</span>'}</td><td class="mono">${hex(s.address)}</td><td class="mono">${hex(s.offset)}</td><td class="mono">${hex(s.size)}</td><td class="mono">${esc(s.sha256.slice(0,20))}…</td></tr>`).join('');rangesBody.innerHTML=ranges.map(r=>`<tr><td>${r.cu}<br><span class=tag>${r.dwarf} ${esc(r.splitStatus)}</span></td><td>${esc(r.function||r.tag)}<br><span class=tag>${esc(r.tag)}</span></td><td class="mono">${hex(r.start)}–${hex(r.end)}</td><td>${r.segment}</td><td>${esc(r.source)}</td><td>${r.dwarf}</td></tr>`).join('');linesBody.innerHTML=lines.map(r=>`<tr><td>${r.cu}/${r.dwarf}</td><td>${r.sequence}</td><td class="mono">${hex(r.address)}</td><td>${esc(r.file)}:${r.line}:${r.column}</td><td>${r.stmt?'●':''}</td><td>${r.endSequence?'■':''}</td><td>${r.discriminator}</td></tr>`).join('');warningsBody.innerHTML=warnings.map(w=>`<tr><td>${esc(w.stage)}</td><td class="${w.severity==='error'?'bad':'warn'}">${esc(w.severity)}</td><td class="mono">${esc(w.offset)}</td><td>${esc(w.message)}</td></tr>`).join('')}
async function uploadFile(){const f=file.files[0];const fd=new FormData();fd.append('file',f);const r=await fetch('/api/import',{method:'POST',body:fd});const j=await r.json();importResult.innerHTML=r.ok?`version #${j.versionId}; warnings=${j.warnings.length}`:await r.text();await loadAll()}
async function createSnapshot(){const body=JSON.stringify({label:snapshotLabel.value,versionId:+versionSelect.value,moduleBase:moduleBase.value,relativeBase:relativeBase.value,segment:segment.value?+segment.value:null});const j=await api('/api/snapshots',{method:'POST',headers:{'Content-Type':'application/json'},body});snapshotResult.innerHTML=`snapshot #${j.snapshotId}<br>load bias = <span class=mono>${hex(j.loadBias)}</span>`}
function show(id){document.querySelectorAll('.panel').forEach(x=>x.hidden=x.id!==id)}
function renderCandidate(c){return `<div class=result><b>${esc(c.file||'?')}:${c.line}:${c.column}</b> <span class=tag>DWARF ${c.cuVersion}</span> <span class=tag>CU #${c.cuOrdinal}</span> <span class=tag>seq #${c.sequenceOrdinal}</span><p>relative <span class=mono>${hex(c.relativeAddress)}</span> + bias <span class=mono>${hex(c.loadBias)}</span> = runtime <span class=mono>${hex(c.runtimeAddress)}</span>；范围宽度 ${c.rangeWidth}，内联深度 ${c.inlineDepth}，可信度 <b class="${c.confidence==='high'?'good':'warn'}">${c.confidence}</b></p><div class=chain>${c.inlineChain.map(f=>`<div>#${f.depth} ${esc(f.name)} <span class=tag>${esc(f.tag)}</span> ${f.callFile?`called from ${esc(f.callFile)}:${f.callLine}`:''} <span class=mono>[${hex(f.start)},${hex(f.end)})</span></div>`).join('')}</div><div class=tag>${c.trust.map(esc).join('<br>')}</div></div>`}
async function batchQuery(){const snapshots=await api('/api/snapshots');const s=snapshots[snapshots.length-1];if(!s)return alert('请先创建快照');const j=await api('/api/batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({snapshotId:s.id,text:addresses.value})});queryResults.innerHTML=j.results.map(x=>`<h2>${esc(x.input)} ${x.candidates.length?'':'<span class=bad>无候选</span>'}</h2>${x.candidates.map(renderCandidate).join('')||esc(x.message||'')}`).join('')}
loadAll().catch(e=>queryResults.textContent=e);
</script>
</body></html>
"""
