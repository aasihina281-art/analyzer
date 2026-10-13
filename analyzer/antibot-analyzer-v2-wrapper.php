<?php
declare(strict_types=1);

/* Keep the existing Analyzer backend and visual design; add request history and analytical risk signals. */
ob_start();
require __DIR__ . '/antibot-analyzer.php';
$html = ob_get_clean();

// Read the native log directly so charts include every request/IP, regardless of analyzer filters or cards.
$trafficLog = dirname(__DIR__) . '/antibot/logs/antibot.log';
if (!is_readable($trafficLog)) $trafficLog = dirname(__DIR__) . '/antibot/antibot.log';
$trafficTotalRequests = 0;
$trafficIpTotals = [];
$trafficFirst = null;
$trafficLast = null;
if (is_readable($trafficLog) && ($trafficHandle = fopen($trafficLog, 'rb')) !== false) {
    while (($line = fgets($trafficHandle)) !== false) {
        if (!preg_match('/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s*(.*)$/u', rtrim($line, "\r\n"), $m)) continue;
        $message = trim($m[4]);
        // Count actual logged HTTP requests, not FP/CAPTCHA metadata lines.
        if ($message === '' || !($message[0] === '/' || preg_match('/^https?:\/\//i', $message))) continue;
        $ts = strtotime($m[1]);
        if ($ts === false) continue;
        $ip = $m[3];
        $trafficTotalRequests++;
        if (!isset($trafficIpTotals[$ip])) $trafficIpTotals[$ip] = ['ip'=>$ip, 'requests'=>0, 'first'=>$m[1], 'last'=>$m[1]];
        $trafficIpTotals[$ip]['requests']++;
        if ($m[1] < $trafficIpTotals[$ip]['first']) $trafficIpTotals[$ip]['first'] = $m[1];
        if ($m[1] > $trafficIpTotals[$ip]['last']) $trafficIpTotals[$ip]['last'] = $m[1];
        $trafficFirst = $trafficFirst === null ? $ts : min($trafficFirst, $ts);
        $trafficLast = $trafficLast === null ? $ts : max($trafficLast, $ts);
    }
    fclose($trafficHandle);
}
$trafficBucketFormat = ($trafficFirst !== null && $trafficLast - $trafficFirst <= 172800) ? 'Y-m-d H:00' : 'Y-m-d';
$trafficTopIps = array_values($trafficIpTotals);
usort($trafficTopIps, static fn($a, $b) => ($b['requests'] <=> $a['requests']) ?: strcmp($a['ip'], $b['ip']));
$trafficTopIps = array_slice($trafficTopIps, 0, 40);
$trafficTopSet = array_fill_keys(array_column($trafficTopIps, 'ip'), true);
$trafficBuckets = [];
if (is_readable($trafficLog) && ($trafficHandle = fopen($trafficLog, 'rb')) !== false) {
    while (($line = fgets($trafficHandle)) !== false) {
        if (!preg_match('/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s*(.*)$/u', rtrim($line, "\r\n"), $m)) continue;
        $message = trim($m[4]);
        if ($message === '' || !($message[0] === '/' || preg_match('/^https?:\/\//i', $message))) continue;
        $ts = strtotime($m[1]);
        if ($ts === false) continue;
        $bucket = date($trafficBucketFormat, $ts);
        if (!isset($trafficBuckets[$bucket])) $trafficBuckets[$bucket] = ['label'=>$bucket, 'counts'=>[], 'other'=>0, 'total'=>0];
        $trafficBuckets[$bucket]['total']++;
        if (isset($trafficTopSet[$m[3]])) {
            $trafficBuckets[$bucket]['counts'][$m[3]] = ($trafficBuckets[$bucket]['counts'][$m[3]] ?? 0) + 1;
        } else {
            $trafficBuckets[$bucket]['other']++;
        }
    }
    fclose($trafficHandle);
}
ksort($trafficBuckets, SORT_STRING);
$trafficData = [
    'buckets'=>array_values($trafficBuckets),
    'topIps'=>$trafficTopIps,
    'totalRequests'=>$trafficTotalRequests,
    'uniqueIps'=>count($trafficIpTotals),
    'bucketMode'=>$trafficBucketFormat === 'Y-m-d H:00' ? 'hour' : 'day',
    'logAvailable'=>is_readable($trafficLog),
];
$trafficDataJson = json_encode($trafficData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

$extra = <<<'HTML'
<style>
.history-btn{background:#182235;color:#cbd5e1;border:0;border-radius:7px;padding:7px 9px;font-size:11px;cursor:pointer;margin-left:6px}.history-btn:hover{background:#24334d}.history-panel{display:none;margin-top:14px;border-top:1px solid #243044;padding-top:12px}.history-panel.open{display:block}.history-head{display:flex;justify-content:space-between;gap:10px;font-size:12px;margin-bottom:8px}.history-head span{color:#94a3b8;font-size:11px}.history-list{max-height:430px;overflow:auto;background:#080d16;border:1px solid #243044;border-radius:10px}.history-event{display:grid;grid-template-columns:145px 72px 1fr;gap:8px;padding:8px 10px;border-bottom:1px solid #172033;font-size:11px}.history-event:last-child{border-bottom:0}.history-event time{color:#94a3b8;font-family:monospace}.history-kind{font-size:9px;font-weight:800;color:#93c5fd}.history-kind.request{color:#6ee7b7}.history-kind.captcha{color:#fde68a}.history-kind.block{color:#fca5a5}.history-event code{white-space:pre-wrap;overflow-wrap:anywhere;color:#e2e8f0}.history-event small{grid-column:3;color:#64748b;font-family:monospace}.history-urls{margin-top:10px;font-size:11px;color:#cbd5e1}.history-url{display:block;width:100%;text-align:left;margin-top:4px;background:#111a2a;color:#93c5fd;border:0;border-radius:6px;padding:5px 7px;cursor:pointer;font:11px monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.history-loading{padding:12px;color:#94a3b8;font-size:11px}.history-error{padding:12px;color:#fca5a5;font-size:11px}
.global-visits{background:#101827;border:1px solid #243044;border-radius:16px;padding:16px;margin:18px 0}.global-visits-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:12px}.global-visits-title{font-size:16px;font-weight:700}.global-visits-note{font-size:11px;color:#94a3b8;line-height:1.5}.global-visits-controls{display:flex;gap:7px;flex-wrap:wrap;margin:12px 0}.traffic-mode{background:#111a2a;color:#cbd5e1;border:1px solid #334155;border-radius:7px;padding:8px 10px;font-size:11px;cursor:pointer}.traffic-mode.active{background:#1d4ed8;border-color:#60a5fa;color:white}.global-visits-legend{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0;color:#cbd5e1;font-size:11px}.global-visits-legend span{display:inline-flex;align-items:center;gap:5px}.global-visits-legend i{display:inline-block;width:9px;height:9px;border-radius:3px}.global-visits-plot{width:100%;overflow:auto}.global-visits-svg{display:block;width:100%;min-width:620px;height:auto}.global-visits-stats{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.global-visits-stat{flex:1;min-width:100px;border-radius:9px;padding:9px;background:#0b1220;border:1px solid #243044}.global-visits-stat b{display:block;font-size:18px}.global-visits-stat span{font-size:10px;color:#94a3b8}.global-visits-empty{padding:18px;color:#94a3b8;font-size:12px}.traffic-table{width:100%;border-collapse:collapse;font-size:11px;color:#cbd5e1}.traffic-table th,.traffic-table td{padding:8px;border-bottom:1px solid #263449;text-align:left}.traffic-table th{color:#94a3b8;font-weight:600}.traffic-table code{overflow-wrap:anywhere}.traffic-history-btn{background:#182235;color:#93c5fd;border:1px solid #334155;border-radius:6px;padding:5px 8px;cursor:pointer}.traffic-history{margin-top:12px;border:1px solid #263449;border-radius:9px;max-height:320px;overflow:auto}.traffic-cell{min-width:18px;height:19px;border-radius:3px}.traffic-heatmap{border-collapse:separate;border-spacing:3px;font-size:10px;color:#cbd5e1}.traffic-heatmap th{font-weight:500;white-space:nowrap}.traffic-heatmap td{padding:0;text-align:center}.traffic-heatmap-wrap{overflow:auto}

.interval-chart{margin-top:14px;padding:12px;background:#0b1220;border:1px solid #243044;border-radius:10px}.interval-chart-head{display:flex;justify-content:space-between;gap:10px;margin-bottom:8px;font-size:12px}.interval-chart-head span{color:#94a3b8;font-size:10px}.interval-url-select{max-width:100%;width:100%;background:#111a2a;color:#e2e8f0;border:1px solid #334155;border-radius:7px;padding:8px;font-size:11px}.interval-stats{margin:9px 0;color:#cbd5e1;font-size:11px;line-height:1.6}.interval-plot{width:100%;overflow-x:auto}.interval-svg{display:block;width:100%;min-width:460px;height:auto}.interval-svg text{font-family:Arial,sans-serif}
</style>
<script>
(function(){
const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const label=k=>k==='request'?'REQUEST':k.toUpperCase();
const copy=async v=>{try{await navigator.clipboard.writeText(v)}catch(_){const t=document.createElement('textarea');t.value=v;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()}};
function drawIntervals(panel,events,url){
 const stats=panel.querySelector('.interval-stats'),plot=panel.querySelector('.interval-plot');
 if(!url){stats.textContent='Выберите URL, чтобы построить график.';plot.innerHTML='';return}
 const rows=events.filter(e=>e.kind==='request'&&e.message===url).sort((a,b)=>a.time.localeCompare(b.time));
 const gaps=[];
 for(let i=1;i<rows.length;i++){
   const delta=(Date.parse(rows[i].time.replace(' ','T')+'Z')-Date.parse(rows[i-1].time.replace(' ','T')+'Z'))/1000;
   if(Number.isFinite(delta)&&delta>=0)gaps.push({seconds:delta,time:rows[i].time,ip:rows[i].ip});
 }
 if(!gaps.length){stats.textContent='Недостаточно запросов к этому URL для расчёта интервалов (нужно минимум два).';plot.innerHTML='';return}
 const sorted=gaps.map(x=>x.seconds).sort((a,b)=>a-b),median=sorted.length%2?sorted[(sorted.length-1)/2]:(sorted[sorted.length/2-1]+sorted[sorted.length/2])/2;
 const avg=gaps.reduce((a,x)=>a+x.seconds,0)/gaps.length,min=sorted[0],max=sorted[sorted.length-1];
 stats.textContent='Запросов: '+rows.length+' · Интервалов: '+gaps.length+' · Медиана: '+median.toFixed(2)+' с · Средний: '+avg.toFixed(2)+' с · Мин.: '+min.toFixed(2)+' с · Макс.: '+max.toFixed(2)+' с';
 const W=760,H=210,L=48,R=14,T=14,B=32,iw=W-L-R,ih=H-T-B,peak=Math.max(1,...gaps.map(x=>x.seconds));
 const pts=gaps.map((g,i)=>({x:L+(gaps.length===1?iw/2:i*iw/(gaps.length-1)),y:T+ih-(g.seconds/peak)*ih,g}));
 const path=pts.map((p,i)=>(i?'L':'M')+p.x.toFixed(1)+' '+p.y.toFixed(1)).join(' ');
 const ticks=[0,peak/2,peak];
 let svg='<svg viewBox=\"0 0 '+W+' '+H+'\" role=\"img\" aria-label=\"Интервалы между запросами в секундах\" class=\"interval-svg\">'+ticks.map(v=>{const y=T+ih-(v/peak)*ih;return '<line x1=\"'+L+'\" y1=\"'+y+'\" x2=\"'+(W-R)+'\" y2=\"'+y+'\" stroke=\"#263449\"/><text x=\"'+(L-8)+'\" y=\"'+(y+4)+'\" text-anchor=\"end\" fill=\"#94a3b8\" font-size=\"10\">'+v.toFixed(1)+'с</text>'}).join('')+'<path d=\"'+path+'\" fill=\"none\" stroke=\"#60a5fa\" stroke-width=\"2\"/>'+pts.map(p=>'<circle cx=\"'+p.x+'\" cy=\"'+p.y+'\" r=\"3\" fill=\"#6ee7b7\"><title>'+esc(p.g.time)+' · '+p.g.seconds.toFixed(2)+' с · '+esc(p.g.ip)+'</title></circle>').join('')+'<text x=\"'+(W/2)+'\" y=\"'+(H-6)+'\" text-anchor=\"middle\" fill=\"#94a3b8\" font-size=\"10\">Последовательные запросы ('+gaps.length+' интервалов)</text></svg>';
 plot.innerHTML=svg;
}
function makeHistory(value,type,anchor){
 if(!value||anchor.dataset.historyAttached==='1')return;
 anchor.dataset.historyAttached='1';
 const btn=document.createElement('button');btn.type='button';btn.className='history-btn';btn.textContent='История';
 const actions=anchor.closest('.entity-card')?.querySelector('.entity-actions');
 if(actions) actions.appendChild(btn); else anchor.insertAdjacentElement('afterend',btn);
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
     html+='</div><section class="interval-chart"><div class="interval-chart-head"><b>Интервал между запросами</b><span>Для выбранного URL</span></div><select class="interval-url-select" aria-label="URL для графика"><option value="">Выберите URL</option>'+d.urls.map((u,i)=>'<option value="'+i+'">'+esc(u)+'</option>').join('')+'</select><div class="interval-stats">Выберите URL, чтобы построить график.</div><div class="interval-plot"></div></section><div class="history-urls"><b>Уникальные URL:</b>'
     if(!d.urls.length)html+=' нет'; else d.urls.slice(0,100).forEach(u=>html+='<button type="button" class="history-url" data-history-copy="'+esc(u)+'">'+esc(u)+'</button>');
     if(d.urls.length>100)html+=' <span>+'+(d.urls.length-100)+' ещё</span>';html+='</div>';panel.innerHTML=html;
     const sel=panel.querySelector('.interval-url-select');
     sel?.addEventListener('change',()=>drawIntervals(panel,d.events,d.urls[Number(sel.value)]||''));

   }catch(e){panel.innerHTML='<div class="history-error">Не удалось загрузить историю: '+esc(e.message)+'</div>'}
 });
}
function renderGlobalVisits(data){
 const old=document.querySelector('.global-visits');if(old)old.remove();
 const panel=document.createElement('section');panel.className='global-visits';
 const colors=['#38bdf8','#f472b6','#a78bfa','#fbbf24','#34d399','#fb7185','#60a5fa','#c084fc','#2dd4bf'];
 let mode='timeline';
 const fmt=n=>(Number(n)||0).toLocaleString('ru-RU');
 const buckets=Array.isArray(data?.buckets)?data.buckets:[];
 const topIps=Array.isArray(data?.topIps)?data.topIps:[];
 const sumOthers=buckets.reduce((n,b)=>n+(Number(b.other)||0),0);
 const header='<div class="global-visits-head"><div><div class="global-visits-title">📈 Активность всех IP-адресов</div><div class="global-visits-note">Графики построены по каждому HTTP-запросу из antibot.log, независимо от фильтров, CAPTCHA и наличия карточки посетителя. Для читаемости линии показывают 8 самых активных IP, остальные адреса объединены в «Другие IP»; все запросы учитываются в суммах.</div></div><div class="global-visits-note">'+fmt(data?.uniqueIps)+' IP<br>'+fmt(data?.totalRequests)+' запросов</div></div>';
 panel.innerHTML=header+'<div class="global-visits-controls"><button type="button" class="traffic-mode active" data-mode="timeline">Временная шкала</button><button type="button" class="traffic-mode" data-mode="top">Топ IP</button><button type="button" class="traffic-mode" data-mode="heatmap">Тепловая карта</button></div><div class="global-visits-note traffic-period"></div><div class="global-visits-plot"></div><div class="global-visits-stats"></div><div class="traffic-history" hidden></div>';
 const plot=panel.querySelector('.global-visits-plot'), stats=panel.querySelector('.global-visits-stats'), period=panel.querySelector('.traffic-period'), history=panel.querySelector('.traffic-history');
 const showHistory=async ip=>{
  history.hidden=false;history.innerHTML='<div class="global-visits-empty">Загружаю историю IP '+esc(ip)+'…</div>';
  try{const r=await fetch('request-history.php?type=ip&value='+encodeURIComponent(ip),{credentials:'same-origin',cache:'no-store'});const d=await r.json();if(!d.ok)throw new Error(d.error||'Ошибка');
   history.innerHTML='<div style="padding:10px;font-size:11px;color:#cbd5e1"><b>История IP '+esc(ip)+'</b> · '+d.events.length+' событий'+(d.truncated?' · показаны последние':'')+'</div>'+(d.events.length?d.events.map(e=>'<div class="history-event"><time>'+esc(e.time)+'</time><span class="history-kind '+esc(e.kind)+'">'+esc(label(e.kind))+'</span><code>'+esc(e.message)+'</code><small>'+esc(e.ip)+' · '+esc(e.ray)+'</small></div>').join(''):'<div class="global-visits-empty">Записей не найдено.</div>');
  }catch(e){history.innerHTML='<div class="global-visits-empty">Не удалось загрузить историю: '+esc(e.message)+'</div>'}
 };
 function svgBase(W,H,L,R,T,B,max){const iw=W-L-R,ih=H-T-B;let s='<svg viewBox="0 0 '+W+' '+H+'" class="global-visits-svg" role="img">';const step=Math.max(1,Math.ceil(max/4));for(let v=0;v<=max;v+=step){const y=T+ih-(v/max)*ih;s+='<line x1="'+L+'" y1="'+y+'" x2="'+(W-R)+'" y2="'+y+'" stroke="#263449"/><text x="'+(L-8)+'" y="'+(y+4)+'" text-anchor="end" fill="#94a3b8" font-size="10">'+v+'</text>';}return {s,iw,ih};}
 function render(){
  panel.querySelector('.global-visits-legend')?.remove();
  panel.querySelectorAll('.traffic-mode').forEach(b=>b.classList.toggle('active',b.dataset.mode===mode));
  history.hidden=true;history.innerHTML='';
  if(!data?.logAvailable){plot.innerHTML='<div class="global-visits-empty">Не удалось прочитать antibot.log. Проверь путь и права доступа.</div>';stats.innerHTML='';return}
  if(!buckets.length||!topIps.length){plot.innerHTML='<div class="global-visits-empty">В журнале не найдено HTTP-запросов.</div>';stats.innerHTML='';return}
  period.textContent='Интервал группировки: '+(data.bucketMode==='hour'?'по часам':'по дням')+'. В анализе '+fmt(data.totalRequests)+' запросов от '+fmt(data.uniqueIps)+' IP-адресов.';
  const displayed=topIps.slice(0,8),displayedSet=new Set(displayed.map(x=>x.ip));
  const totals=topIps.reduce((n,x)=>n+x.requests,0);
  if(mode==='timeline'){
   const W=980,H=330,L=58,R=18,T=18,B=52,max=Math.max(1,...buckets.flatMap(b=>[...displayed.map(x=>Number(b.counts?.[x.ip])||0),Number(b.other)||0]));let {s,iw,ih}=svgBase(W,H,L,R,T,B,max);
   const series=displayed.map((ip,i)=>({key:ip.ip,label:ip.ip,color:colors[i%colors.length],value:b=>Number(b.counts?.[ip.ip])||0}));series.push({key:'__other',label:'Другие IP',color:'#94a3b8',value:b=>Number(b.other)||0});
   series.forEach(ser=>{const pts=buckets.map((b,i)=>({x:L+(buckets.length===1?iw/2:i*iw/(buckets.length-1)),y:T+ih-(ser.value(b)/max)*ih,v:ser.value(b),label:b.label}));s+='<path d="'+pts.map((p,i)=>(i?'L':'M')+p.x.toFixed(1)+' '+p.y.toFixed(1)).join(' ')+'" fill="none" stroke="'+ser.color+'" stroke-width="2.2"/>'+pts.map(p=>'<circle cx="'+p.x+'" cy="'+p.y+'" r="3" fill="'+ser.color+'"><title>'+esc(p.label)+' · '+esc(ser.label)+': '+p.v+' запросов</title></circle>').join('');});
   const step=Math.max(1,Math.ceil(buckets.length/9));buckets.forEach((b,i)=>{if(i%step!==0&&i!==buckets.length-1)return;const x=L+(buckets.length===1?iw/2:i*iw/(buckets.length-1));s+='<text transform="translate('+x+' '+(H-22)+') rotate(-30)" text-anchor="end" fill="#94a3b8" font-size="9">'+esc(b.label)+'</text>';});s+='</svg>';plot.innerHTML=s;
   panel.querySelector('.global-visits-legend')?.remove();const legend=document.createElement('div');legend.className='global-visits-legend';legend.innerHTML=series.map(x=>'<span><i style="background:'+x.color+'"></i>'+esc(x.label)+'</span>').join('');period.insertAdjacentElement('afterend',legend);
  } else if(mode==='top'){
   const rows=topIps.slice(0,20);const max=Math.max(1,...rows.map(x=>x.requests));let html='<table class="traffic-table"><thead><tr><th>IP-адрес</th><th>Запросы</th><th>Доля</th><th>Последняя активность</th><th></th></tr></thead><tbody>';
   rows.forEach((x,i)=>{const pct=(x.requests/Math.max(1,data.totalRequests)*100);html+='<tr><td><code>'+esc(x.ip)+'</code></td><td>'+fmt(x.requests)+'</td><td><div style="background:#1e293b;height:7px;border-radius:5px;min-width:60px"><div style="width:'+Math.min(100,x.requests/max*100)+'%;height:7px;border-radius:5px;background:'+colors[i%colors.length]+'"></div></div><span>'+pct.toFixed(1)+'%</span></td><td>'+esc(x.last)+'</td><td><button type="button" class="traffic-history-btn" data-ip-history="'+esc(x.ip)+'">История</button></td></tr>';});html+='</tbody></table><div class="global-visits-note" style="margin-top:8px">Показаны 20 самых активных IP из '+fmt(data.uniqueIps)+'. Адреса ниже топ-40 учтены в группе «Другие IP» временной шкалы.</div>';plot.innerHTML=html;
  } else {
   const rows=topIps.slice(0,20),cols=buckets.slice(-24),max=Math.max(1,...cols.flatMap(b=>rows.map(x=>Number(b.counts?.[x.ip])||0)));
   let html='<div class="traffic-heatmap-wrap"><table class="traffic-heatmap"><thead><tr><th>IP / время</th>'+cols.map(b=>'<th title="'+esc(b.label)+'">'+esc(data.bucketMode==='hour'?b.label.slice(-5):b.label.slice(5))+'</th>').join('')+'</tr></thead><tbody>';
   rows.forEach(x=>{html+='<tr><th><button type="button" class="traffic-history-btn" data-ip-history="'+esc(x.ip)+'">'+esc(x.ip)+'</button></th>'+cols.map(b=>{const v=Number(b.counts?.[x.ip])||0,alpha=v?Math.min(.95,.12+v/max*.83):.04;return '<td><div class="traffic-cell" title="'+esc(x.ip)+' · '+esc(b.label)+' · '+v+' запросов" style="background:rgba(56,189,248,'+alpha+')"></div></td>';}).join('')+'</tr>';});html+='</tbody></table></div><div class="global-visits-note" style="margin-top:8px">Показаны 20 самых активных IP и до 24 последних интервалов. Чем ярче ячейка, тем больше запросов.</div>';plot.innerHTML=html;
  }
  const topShown=topIps.slice(0,8).reduce((n,x)=>n+x.requests,0);stats.innerHTML='<div class="global-visits-stat"><b>'+fmt(data.totalRequests)+'</b><span>Все запросы из лога</span></div><div class="global-visits-stat"><b>'+fmt(data.uniqueIps)+'</b><span>Уникальных IP</span></div><div class="global-visits-stat"><b>'+fmt(topShown)+'</b><span>Запросы топ-8 IP</span></div><div class="global-visits-stat"><b>'+fmt(sumOthers)+'</b><span>Запросы прочих IP по времени</span></div>';
 }
 panel.querySelectorAll('.traffic-mode').forEach(b=>b.addEventListener('click',()=>{mode=b.dataset.mode;render()}));
 panel.addEventListener('click',e=>{const b=e.target.closest('[data-ip-history]');if(b)showHistory(b.getAttribute('data-ip-history'));});
 const grid=document.querySelector('.grid');if(grid)grid.insertAdjacentElement('afterend',panel);render();
}
const trafficData=__TRAFFIC_DATA__;
function initGlobalVisits(){renderGlobalVisits(trafficData)}
function initHistory(){document.querySelectorAll('.entity-card').forEach(card=>{const valueEl=card.querySelector('.entity-value'),typeEl=card.querySelector('.entity-type');if(valueEl&&typeEl)makeHistory(valueEl.textContent.trim(),/Fingerprint/i.test(typeEl.textContent)?'fingerprint':'ip',valueEl)})}
function init(){initGlobalVisits();initHistory()}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
document.addEventListener('click',e=>{const b=e.target.closest('[data-history-copy]');if(!b)return;const v=b.getAttribute('data-history-copy')||'';copy(v);const old=b.textContent;b.textContent='✓ Скопировано';setTimeout(()=>b.textContent=old,900)});
})();
</script>
HTML;

$extra = str_replace('__TRAFFIC_DATA__', $trafficDataJson ?: '{"buckets":[],"topIps":[],"totalRequests":0,"uniqueIps":0,"bucketMode":"day","logAvailable":false}', $extra);
$html = str_replace('</head>', $extra . '</head>', $html);
echo $html;
