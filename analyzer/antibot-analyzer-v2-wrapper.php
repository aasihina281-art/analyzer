<?php
declare(strict_types=1);

/* Keep the existing Analyzer backend and visual design; add request history and analytical risk signals. */
ob_start();
require __DIR__ . '/antibot-analyzer.php';
$html = ob_get_clean();

$extra = <<<'HTML'
<style>
.history-btn{background:#182235;color:#cbd5e1;border:0;border-radius:7px;padding:7px 9px;font-size:11px;cursor:pointer;margin-left:6px}.history-btn:hover{background:#24334d}.history-panel{display:none;margin-top:14px;border-top:1px solid #243044;padding-top:12px}.history-panel.open{display:block}.history-head{display:flex;justify-content:space-between;gap:10px;font-size:12px;margin-bottom:8px}.history-head span{color:#94a3b8;font-size:11px}.history-list{max-height:430px;overflow:auto;background:#080d16;border:1px solid #243044;border-radius:10px}.history-event{display:grid;grid-template-columns:145px 72px 1fr;gap:8px;padding:8px 10px;border-bottom:1px solid #172033;font-size:11px}.history-event:last-child{border-bottom:0}.history-event time{color:#94a3b8;font-family:monospace}.history-kind{font-size:9px;font-weight:800;color:#93c5fd}.history-kind.request{color:#6ee7b7}.history-kind.captcha{color:#fde68a}.history-kind.block{color:#fca5a5}.history-event code{white-space:pre-wrap;overflow-wrap:anywhere;color:#e2e8f0}.history-event small{grid-column:3;color:#64748b;font-family:monospace}.history-urls{margin-top:10px;font-size:11px;color:#cbd5e1}.history-url{display:block;width:100%;text-align:left;margin-top:4px;background:#111a2a;color:#93c5fd;border:0;border-radius:6px;padding:5px 7px;cursor:pointer;font:11px monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.history-loading{padding:12px;color:#94a3b8;font-size:11px}.history-error{padding:12px;color:#fca5a5;font-size:11px}
.risk-summary{background:#101827;border:1px solid #243044;border-radius:16px;padding:16px;margin:18px 0}.risk-summary-head{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:12px}.risk-summary-title{font-size:16px;font-weight:700}.risk-summary-note{font-size:11px;color:#94a3b8}.risk-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.risk-item{background:#0b1220;border:1px solid #243044;border-radius:10px;padding:10px}.risk-item-top{display:flex;justify-content:space-between;gap:8px;align-items:center}.risk-score{font-weight:800;font-size:16px}.risk-score.high{color:#f87171}.risk-score.medium{color:#fbbf24}.risk-score.low{color:#6ee7b7}.risk-level{font-size:9px;font-weight:800}.risk-value{font:11px monospace;margin:7px 0;word-break:break-all;color:#e2e8f0}.risk-meta{font-size:10px;color:#94a3b8;line-height:1.55}.risk-reasons{margin:7px 0 0;padding-left:15px;color:#cbd5e1;font-size:10px}.risk-legend{margin-top:10px;font-size:10px;color:#64748b}.risk-badge{display:inline-block;margin-top:8px;border-radius:999px;padding:4px 7px;font-size:9px;font-weight:800}.risk-badge.high{background:#3a1418;color:#fca5a5}.risk-badge.medium{background:#382f08;color:#fde68a}.risk-badge.low{background:#0d3328;color:#6ee7b7}@media(max-width:700px){.history-event{grid-template-columns:1fr}.history-event small{grid-column:auto}.risk-grid{grid-template-columns:1fr}}
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
 const host=anchor.closest('.entity-card')||anchor.parentElement;
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
function renderRisk(items){
 const old=document.querySelector('.risk-summary');if(old)old.remove();
 const panel=document.createElement('section');panel.className='risk-summary';
 let html='<div class="risk-summary-head"><div><div class="risk-summary-title">Подозрительные Fingerprint</div><div class="risk-summary-note">Аналитический score 0–100. Ничего автоматически не блокирует.</div></div><div class="risk-summary-note">'+items.length+' наиболее подозрительных</div></div>';
 if(!items.length)html+='<div class="risk-summary-note">Недостаточно данных для расчёта.</div>';
 else{html+='<div class="risk-grid">';items.slice(0,12).forEach(x=>{html+='<div class="risk-item"><div class="risk-item-top"><span class="risk-score '+x.level.toLowerCase()+'">'+x.score+'/100</span><span class="risk-level">'+esc(x.level)+'</span></div><div class="risk-value">'+esc(x.value)+'</div><div class="risk-meta">'+x.ipCount+' IP · '+x.sessions+' сессий · '+x.requests+' запросов<br>'+x.captchaShown+' CAPTCHA · '+x.captchaPassed+' passed · '+x.blocked+' блокировок · '+x.urlCount+' URL</div><ul class="risk-reasons">'+x.reasons.slice(0,4).map(r=>'<li>'+esc(r)+'</li>').join('')+'</ul></div>'});html+='</div>';}
 html+='<div class="risk-legend">LOW &lt; 40 · MEDIUM 40–69 · HIGH 70+. Это сигнал для расследования, а не доказательство вредоносности.</div>';panel.innerHTML=html;
 const grid=document.querySelector('.grid');if(grid)grid.insertAdjacentElement('afterend',panel);
}
async function initRisk(){try{const r=await fetch('risk-summary.php',{credentials:'same-origin',cache:'no-store'});const d=await r.json();if(d.ok)renderRisk(d.items||[])}catch(_){}}
function initHistory(){document.querySelectorAll('.entity-card').forEach(card=>{const valueEl=card.querySelector('.entity-value'),typeEl=card.querySelector('.entity-type');if(valueEl&&typeEl)makeHistory(valueEl.textContent.trim(),/Fingerprint/i.test(typeEl.textContent)?'fingerprint':'ip',valueEl)})}
function init(){initHistory();initRisk()}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
document.addEventListener('click',e=>{const b=e.target.closest('[data-history-copy]');if(!b)return;const v=b.getAttribute('data-history-copy')||'';copy(v);const old=b.textContent;b.textContent='✓ Скопировано';setTimeout(()=>b.textContent=old,900)});
})();
</script>
HTML;

$html = str_replace('</head>', $extra . '</head>', $html);
echo $html;
