<?php
declare(strict_types=1);

/* Keep the existing Analyzer backend and visual design; add lazy request history. */
ob_start();
require __DIR__ . '/antibot-analyzer.php';
$html = ob_get_clean();

$extra = <<<'HTML'
<style>
.history-btn{background:#182235;color:#cbd5e1;border:0;border-radius:7px;padding:7px 9px;font-size:11px;cursor:pointer;margin-left:6px}.history-btn:hover{background:#24334d}.history-panel{display:none;margin-top:14px;border-top:1px solid #243044;padding-top:12px}.history-panel.open{display:block}.history-head{display:flex;justify-content:space-between;gap:10px;font-size:12px;margin-bottom:8px}.history-head span{color:#94a3b8;font-size:11px}.history-list{max-height:430px;overflow:auto;background:#080d16;border:1px solid #243044;border-radius:10px}.history-event{display:grid;grid-template-columns:145px 72px 1fr;gap:8px;padding:8px 10px;border-bottom:1px solid #172033;font-size:11px}.history-event:last-child{border-bottom:0}.history-event time{color:#94a3b8;font-family:monospace}.history-kind{font-size:9px;font-weight:800;color:#93c5fd}.history-kind.request{color:#6ee7b7}.history-kind.captcha{color:#fde68a}.history-kind.block{color:#fca5a5}.history-event code{white-space:pre-wrap;overflow-wrap:anywhere;color:#e2e8f0}.history-event small{grid-column:3;color:#64748b;font-family:monospace}.history-urls{margin-top:10px;font-size:11px;color:#cbd5e1}.history-url{display:block;width:100%;text-align:left;margin-top:4px;background:#111a2a;color:#93c5fd;border:0;border-radius:6px;padding:5px 7px;cursor:pointer;font:11px monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.history-loading{padding:12px;color:#94a3b8;font-size:11px}.history-error{padding:12px;color:#fca5a5;font-size:11px}@media(max-width:700px){.history-event{grid-template-columns:1fr}.history-event small{grid-column:auto}}
</style>
<script>
(function(){
const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const label=k=>k==='request'?'REQUEST':k.toUpperCase();
const copy=async v=>{try{await navigator.clipboard.writeText(v)}catch(_){const t=document.createElement('textarea');t.value=v;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()}};

function makeHistory(value,type,anchor){
 if(!value||anchor.dataset.historyAttached==='1')return;
 anchor.dataset.historyAttached='1';
 const btn=document.createElement('button');btn.type='button';btn.className='history-btn';btn.textContent='История';
 anchor.insertAdjacentElement('afterend',btn);
 const panel=document.createElement('div');panel.className='history-panel';panel.innerHTML='<div class="history-loading">Нажмите «История», чтобы загрузить события…</div>';
 const host=anchor.closest('.card,.item,.row,.panel,section,article,li,td')||anchor.parentElement;
 if(host)host.appendChild(panel);
 let loaded=false;
 btn.addEventListener('click',async()=>{
   panel.classList.toggle('open');btn.textContent=panel.classList.contains('open')?'Скрыть':'История';
   if(loaded||!panel.classList.contains('open'))return;
   panel.innerHTML='<div class="history-loading">Загрузка истории…</div>';
   try{
     const r=await fetch('request-history.php?type='+encodeURIComponent(type)+'&value='+encodeURIComponent(value),{credentials:'same-origin',cache:'no-store'});
     const d=await r.json();if(!d.ok)throw new Error(d.error||'Ошибка');loaded=true;
     let html='<div class="history-head"><b>История обращений</b><span>'+d.events.length+' событий · '+d.sessions+' сессий · '+d.ips.length+' IP'+(d.truncated?' · показаны последние':'')+'</span></div><div class="history-list">';
     if(!d.events.length)html+='<div class="history-loading">Событий не найдено.</div>';
     d.events.forEach(e=>html+='<div class="history-event"><time>'+esc(e.time)+'</time><span class="history-kind '+esc(e.kind)+'">'+esc(label(e.kind))+'</span><code>'+esc(e.message)+'</code><small>'+esc(e.ip)+' · '+esc(e.ray)+'</small></div>');
     html+='</div><div class="history-urls"><b>Уникальные URL:</b>';
     if(!d.urls.length)html+=' нет'; else d.urls.slice(0,100).forEach(u=>html+='<button type="button" class="history-url" data-history-copy="'+esc(u)+'">'+esc(u)+'</button>');
     if(d.urls.length>100)html+=' <span>+'+(d.urls.length-100)+' ещё</span>';html+='</div>';panel.innerHTML=html;
   }catch(e){panel.innerHTML='<div class="history-error">Не удалось загрузить историю: '+esc(e.message)+'</div>'}
 });
}

function initHistory(){
 // First support the structured card markup if a future version provides it.
 document.querySelectorAll('.entity-card').forEach(card=>{
   const valueEl=card.querySelector('.entity-value'),typeEl=card.querySelector('.entity-type');
   if(valueEl&&typeEl)makeHistory(valueEl.textContent.trim(),/Fingerprint/i.test(typeEl.textContent)?'fingerprint':'ip',valueEl);
 });
 // Current Analyzer has no .entity-card markup. Find visible leaf elements whose text is exactly an IP or fingerprint.
 const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_ELEMENT);
 const nodes=[];
 while(walker.nextNode())nodes.push(walker.currentNode);
 nodes.forEach(el=>{
   if(el.tagName==='SCRIPT'||el.tagName==='STYLE'||el.tagName==='BUTTON'||el.dataset.historyAttached==='1')return;
   const text=(el.textContent||'').trim();
   if(text.length>0&&text.length<=128&&el.children.length===0){
     if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text))makeHistory(text,'ip',el);
     else if(/^[a-f0-9]{32,128}$/i.test(text))makeHistory(text,'fingerprint',el);
   }
 });
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initHistory);else initHistory();
document.addEventListener('click',e=>{const b=e.target.closest('[data-history-copy]');if(!b)return;const v=b.getAttribute('data-history-copy')||'';copy(v);const old=b.textContent;b.textContent='✓ Скопировано';setTimeout(()=>b.textContent=old,900)});
})();
</script>
HTML;

$html = str_replace('</head>', $extra . '</head>', $html);
echo $html;
