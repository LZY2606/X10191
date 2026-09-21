const $ = s => document.querySelector(s);
const state = { versionId: null, snapshotId: null, tab: 'sections' };
function toast(m){ const t=$('#toast'); t.textContent=m; t.style.display='block'; setTimeout(()=>t.style.display='none',2600); }
async function api(path, opts={}){
  const r = await fetch(path, opts);
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}
function esc(s){ return String(s??'').replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function hex(v){ return v==null?'-':String(v); }
function confidenceTag(c){
  const map={high:['ok','高'],ambiguous:['warn','多候选'],partial:['warn','部分'],none:['err','无']};
  const [cls,txt]=map[c]||['err',c];
  return `<span class="tag ${cls}">${txt}</span>`;
}
async function loadVersions(){
  const vs = await api('/api/versions');
  $('#versionList').innerHTML = vs.length ? `<table><tbody>${vs.map(v=>`
    <tr style="cursor:pointer" data-id="${v.id}" class="${state.versionId===v.id?'':''}">
      <td>
        <div><b>#${v.id}</b> ${esc(v.label)} <span class="tag acc">DWARF ${esc(v.dwarfVersions||'?')}</span></div>
        <div class="muted mono">${esc(v.fileName)}</div>
        <div class="muted mono">${esc(v.sha256.slice(0,16))}… ${esc(v.createdAt)}</div>
      </td>
    </tr>`).join('')}</tbody></table>` : '<div class="muted">尚未导入任何调试文件</div>';
  [...document.querySelectorAll('#versionList tr')].forEach(tr=>tr.onclick=()=>{
    state.versionId = Number(tr.dataset.id); loadSnapshots(); renderTab();
  });
  if(!state.versionId && vs.length){ state.versionId=vs[0].id; loadSnapshots(); renderTab(); }
}
async function loadSnapshots(){
  const all = await api('/api/snapshots');
  $('#snapList').innerHTML = all.length ? all.map(s=>
    `<div class="mono">#${s.id} v${s.versionId} gen${s.generation} bias=${s.loadBias} ${esc(s.note)}</div>`
  ).join('') : '<div class="muted">无快照</div>';
  $('#snapSel').innerHTML = all.map(s=>
    `<option value="${s.id}" ${state.snapshotId===s.id?'selected':''}>#${s.id} v${s.versionId} gen${s.generation} bias ${s.loadBias}</option>`
  ).join('');
  if(all.length && !state.snapshotId){ state.snapshotId=all[all.length-1].id; $('#snapSel').value=state.snapshotId; }
}
$('#importBtn').onclick = async ()=>{
  const f=$('#file').files[0]; if(!f) return toast('选择文件');
  const fd=new FormData(); fd.append('label',$('#label').value||'imported'); fd.append('file',f);
  try{
    const r=await fetch('/api/versions/import',{method:'POST',body:fd}).then(r=>r.ok?r.json():r.text().then(t=>{throw Error(t)}));
    toast(`已保存为版本 ${r.id}（旧崩溃记录不变）`); state.versionId=r.id; await loadVersions(); await loadSnapshots(); renderTab();
  }catch(e){ toast('导入失败: '+e.message); }
};
$('#snapBtn').onclick = async ()=>{
  if(!state.versionId) return toast('先选择版本');
  await api('/api/snapshots',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({versionId:state.versionId,loadBias:$('#bias').value,moduleBase:$('#modbase').value||null,note:$('#note').value})});
  await loadSnapshots(); toast('模块加载已固定');
};
$('#snapSel').onchange = e=> state.snapshotId=Number(e.target.value);
$('#singleBtn').onclick = async ()=>{
  if(!state.versionId) return toast('先选择版本');
  const e=await api('/api/resolve',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({versionId:state.versionId,address:$('#singleAddr').value,loadBias:$('#singleBias').value})});
  $('#results').innerHTML = resultBlock(e);
};
$('#batchBtn').onclick = async ()=>{
  const id=Number($('#snapSel').value); if(!id) return toast('先固定快照');
  const r=await api('/api/batch',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({snapshotId:id,addresses:$('#batch').value,persist:true})});
  $('#results').innerHTML = (r.batchId?`<div class="muted">批次 #${r.batchId} 已固定（快照不可变）</div>`:'') +
    r.results.map(resultBlock).join('');
};
function resultBlock(e){
  return `<div class="panel" style="margin-top:10px">
    <div class="row" style="align-items:baseline">
      <div class="mono big" style="flex:2">运行时 ${e.runtimeAddress} → 相对 ${e.relativeAddress}</div>
      ${confidenceTag(e.confidence)}
      <span class="tag ${e.trustworthy?'ok':'err'}">${e.trustworthy?'结论可信':'无法定位'}</span>
    </div>
    <div class="muted mono">load_bias=${e.loadBias} ${e.snapshotId?('快照#'+e.snapshotId+' 代次 '+e.generation):''} 模块 ${esc(e.module??'-')}</div>
    <div class="cards" style="margin-top:10px">
      ${e.candidates.map(c=>`<div class="card">
        <div><b>#${c.rank}</b> ${esc(c.symbol??'(无名)')} <span class="tag acc">${esc(c.source)}</span>
          ${c.exact?'<span class="tag ok">精确行</span>':''}</div>
        <div class="mono">${esc(c.filePath??'?')}:${c.line??'?'}:${c.column??'?'}</div>
        <div class="muted mono">CU ${esc(c.cuName??'?')} · seq ${c.sequenceIndex??'-'} · 表版本 DWARF line v${c.tableVersion??'?'}</div>
        <div class="muted mono">范围 ${c.matchedRangeStart}–${c.matchedRangeEnd} (长度 ${c.rangeLength}) 深度 ${c.inlineDepth} 优先级 ${c.priority}</div>
        ${c.inlineChain.length?`<div class="tree">${c.inlineChain.map(f=>
          `<div class="node">${esc(f.name??'(inline)')} <span class="tag">${esc(f.tag)}</span>`+
          (f.callLine?`<span class="muted mono"> 调用点 ${esc(f.file??'')}:${f.callLine}:${f.callColumn??'?'}</span>`:'')+
          (f.abstractOriginResolved?'':' <span class="tag warn">origin 未解析</span>')+`</div>`).join('')}</div>`:''}
        ${c.warnings.map(w=>`<div class="small" style="color:var(--warn)">⚠ ${esc(w)}</div>`).join('')}
      </div>`).join('') || '<div class="muted">没有候选落在任何范围或 sequence 内</div>'}
    </div>
    ${e.warnings.length?`<details style="margin-top:8px"><summary class="muted">解析告警 (${e.warnings.length})</summary>${e.warnings.map(w=>`<div class="small" style="color:var(--warn)">⚠ ${esc(w)}</div>`).join('')}</details>`:''}
  </div>`;
}
document.querySelectorAll('#tabs button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('#tabs button').forEach(x=>x.classList.remove('active'));
  b.classList.add('active'); state.tab=b.dataset.tab; renderTab();
});
async function renderTab(){
  if(!state.versionId){ $('#tabBody').innerHTML='<div class="muted">导入并选择一个版本</div>'; return; }
  const id=state.versionId;
  if(state.tab==='sections') return renderSections(id);
  if(state.tab==='ranges') return renderRanges(id);
  if(state.tab==='sequences') return renderSequences(id);
  if(state.tab==='inlines') return renderInlines(id);
  if(state.tab==='cus') return renderCus(id);
}
async function renderSections(id){
  const ss=await api(`/api/versions/${id}/sections`);
  const max=Math.max(1,...ss.map(s=>s.size));
  $('#tabBody').innerHTML=`<div class="muted" style="margin-bottom:8px">共 ${ss.length} 个 debug section；条纹表示缺失/异常，悬浮查看原始字节 SHA-256。</div>`+
    ss.map(s=>{
      const pct=Math.max(2,Math.round(s.size/max*100));
      const miss=!!s.error;
      return `<div title="${esc(s.sha256??'')}">
        <div class="row mono small" style="margin:0"><span style="flex:2">${esc(s.name)}</span>
          <span>${s.size} B</span><span>@${esc(s.addr)}</span>
          <span>${s.allocated?'<span class="tag acc">ALLOC</span>':''}</span>
          ${miss?'<span class="tag err">'+esc(s.error)+'</span>':''}</div>
        <div class="sectionbar ${miss?'miss':''}" style="width:${pct}%"></div>
      </div>`;
    }).join('');
}
async function renderRanges(id){
  const rs=await api(`/api/versions/${id}/ranges`);
  $('#tabBody').innerHTML=`<div class="muted" style="margin-bottom:8px">保留重叠与零长度范围；半开区间 [start,end)。</div>
  <table><thead><tr><th>CU</th><th>符号 / DIE</th><th>tag</th><th>深度</th><th>范围</th></tr></thead><tbody>`+
  rs.map(r=>`<tr><td class="mono small">${esc(r.cu)}</td><td>${esc(r.name??'?')} <span class="muted">@${esc(r.dieOffset)}</span></td>
    <td><span class="tag">${esc(r.tag)}</span></td><td>${r.depth}</td>
    <td>${r.ranges.map(g=>`<div class="mono small">${g.start} → ${g.end} <span class="muted">(len ${g.length}${g.length==='0x0'?' ⌀零长':''})</span></div>`).join('')}</td></tr>`).join('')+
  `</tbody></table>`;
}
async function renderSequences(id){
  const ss=await api(`/api/versions/${id}/sequences`);
  $('#tabBody').innerHTML = ss.length ? ss.map(s=>`
    <div class="panel" style="margin-bottom:10px">
      <div class="row mono"><b>${esc(s.cu)}</b>
        <span class="tag acc">line v${s.tableVersion} / CU v${s.cuVersion}</span>
        <span class="tag">sequence #${s.sequence}</span>
        <span class="muted">${s.start} → ${s.end}</span></div>
      <div class="flex">
        <div><div class="muted small">行（state 落盘）</div>
        <table><thead><tr><th>地址</th><th>文件</th><th>行:列</th></tr></thead><tbody>
        ${s.rows.filter(r=>!r.endSequence).map(r=>`<tr><td class="mono">${r.address}</td><td class="small">${esc(r.file)}</td><td class="mono">${r.line}:${r.column}</td></tr>`).join('')}
        <tr><td class="mono">${s.rows[s.rows.length-1].address}</td><td colspan="2" class="tag warn">end_sequence（独占终止地址）</td></tr>
        </tbody></table></div>
        <div><div class="muted small">状态机变化（含未落盘 opcode）</div><pre>${s.trace.map(t=>
          `${t.emitted?'▶':' '} ${t.address.padEnd(10)} f${String(t.file).padStart(2)} ${String(t.line).padStart(4)}:${String(t.column).padEnd(3)} ${t.opcode}${t.endSequence?' END_SEQ':''}`
        ).join('\n')}</pre></div>
      </div>
    </div>`).join('') : '<div class="muted">没有 line sequence</div>';
}
async function renderInlines(id){
  const xs=await api(`/api/versions/${id}/inlines`);
  const byCu={}; xs.forEach(x=>(byCu[x.cu]=byCu[x.cu]||[]).push(x));
  $('#tabBody').innerHTML=Object.entries(byCu).map(([cu,nodes])=>{
    const roots=nodes.filter(n=>n.depth===0);
    function kids(n){return nodes.filter(m=>m.depth===n.depth+1 && samePath(m,n));}
    function samePath(m,n){ return m.path && n.path && m.path.length>n.path.length; }
    function node(n,indent){
      const ks=nodesInside(n,nodes);
      return `<div class="node" style="margin-left:${indent*14}px">
        <b>${esc(n.name??'(anonymous)')}</b> <span class="tag ${n.tag==='inlined_subroutine'?'acc':''}">${esc(n.tag)}</span>
        ${n.callLine?`<span class="muted mono">调用点 :${n.callLine}:${n.callColumn??'?'}</span>`:''}
        ${n.ranges.map(r=>`<span class="muted mono small"> ${r.start}–${r.end}</span>`).join('')}
        ${ks.map(k=>node(k,indent+1)).join('')}</div>`;
    }
    function nodesInside(n,all){
      // path arrays list ancestor names; rebuild by matching prefix + depth
      return all.filter(m=>m.depth===n.depth+1 && m.path && n.name && m.path[m.path.length-1]===n.name
        || (m.depth===n.depth+1 && false));
    }
    return `<div class="panel" style="margin-bottom:10px"><h2>${esc(cu)}</h2><div class="tree">`+
      roots.map(r=>flatTree(r,nodes,0)).join('')+`</div></div>`;
  }).join('') || '<div class="muted">没有函数/内联 DIE</div>';
}
function flatTree(n, all, depth){
  const kids=all.filter(m=>m.depth===n.depth+1 && m.path && n.name && m.path[m.path.length-1]===n.name);
  return `<div class="node" style="margin-left:${depth*14}px"><b>${esc(n.name??'?')}</b>
    <span class="tag ${n.tag==='inlined_subroutine'?'acc':''}">${esc(n.tag)}</span>
    ${n.callLine?`<span class="muted mono">:${n.callLine}:${n.callColumn??'?'}</span>`:''}
    ${n.ranges.map(r=>`<span class="muted mono small">${r.start}–${r.end}</span>`).join('')}</div>`+
    kids.map(k=>flatTree(k,all,depth+1)).join('');
}
async function renderCus(id){
  const cus=await api(`/api/versions/${id}/cus`);
  $('#tabBody').innerHTML=`<table><thead><tr><th>#</th><th>版本</th><th>名称</th><th>split</th><th>范围</th><th>stmt_list</th></tr></thead><tbody>`+
  cus.map(c=>`<tr><td>${c.index}${c.isDwo?' <span class="tag acc">dwo</span>':''}</td>
    <td>DWARF${c.version}</td><td class="small">${esc(c.name??'?')}<div class="muted">${esc(c.compDir??'')}</div></td>
    <td>${c.split==='none'?'<span class="tag">none</span>':c.split.startsWith('missing')?'<span class="tag err">'+esc(c.split)+'</span>':'<span class="tag ok">'+esc(c.split)+'</span>'}</td>
    <td>${c.ranges.map(r=>`<div class="mono small">${r.start}–${r.end}</div>`).join('')}</td>
    <td class="mono small">${esc(c.stmtList??'-')}</td></tr>`).join('')+`</tbody></table>`;
}
fetch('/api/health').then(r=>r.json()).then(h=>$('#health').textContent=h.name+' · '+h.status).catch(()=>$('#health').textContent='后端未连接');
loadVersions();
