<?php
declare(strict_types=1);

require_once __DIR__ . '/auth.php';
analyzerRequireLogin();
header('Content-Type: application/json; charset=utf-8');

$root = dirname(__DIR__) . '/antibot';
$log = is_readable($root . '/logs/antibot.log') ? $root . '/logs/antibot.log' : $root . '/antibot.log';
if (!is_readable($log)) {
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>'Лог AntiBot не найден или недоступен для чтения'], JSON_UNESCAPED_UNICODE);
    exit;
}

/*
 * This is an ANALYTICAL score, not a verdict and never triggers blocking.
 * It deliberately rewards multiple independent signals rather than IP alone.
 */
$fp = [];
$fh = fopen($log, 'rb');
if ($fh === false) {
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>'Не удалось открыть лог'], JSON_UNESCAPED_UNICODE);
    exit;
}

$sessions = [];
while (($line = fgets($fh)) !== false) {
    $line = rtrim($line, "\r\n");
    if (!preg_match('/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s*(.*)$/u', $line, $m)) continue;
    $time=$m[1]; $ray=$m[2]; $ip=$m[3]; $msg=trim($m[4]);
    if (!isset($sessions[$ray])) $sessions[$ray]=['ip'=>$ip,'first'=>$time,'last'=>$time,'fp'=>[],'requests'=>0,'captchaShown'=>0,'captchaPassed'=>0,'blocked'=>0,'urls'=>[],'robot'=>false,'whitelist'=>false];
    $s=&$sessions[$ray];
    $s['last']=$time;
    if ($msg!=='' && ($msg[0]==='/' || preg_match('/^https?:\/\//i',$msg))) { $s['requests']++; if($msg[0]==='/')$s['urls'][$msg]=true; }
    if (preg_match('/\bFP:\s*([a-f0-9]{16,128})\b/i',$msg,$fm)) $s['fp'][strtolower($fm[1])]=true;
    if (stripos($msg,'Show captcha')!==false) $s['captchaShown']++;
    if (stripos($msg,'Successfully passed the captcha')!==false) $s['captchaPassed']++;
    if (stripos($msg,'blocked')!==false || stripos($msg,'blocking page')!==false || stripos($msg,'Added to list')!==false) $s['blocked']++;
    if (stripos($msg,'Indexing robot')!==false || stripos($msg,'Found in list:')!==false) $s['robot']=true;
    if (stripos($msg,'whitelist')!==false || stripos($msg,'white list')!==false) $s['whitelist']=true;
    unset($s);
}
fclose($fh);

foreach($sessions as $s){
    if($s['robot']||$s['whitelist']||empty($s['fp'])) continue;
    foreach(array_keys($s['fp']) as $f){
        if(!isset($fp[$f])) $fp[$f]=['value'=>$f,'ips'=>[],'sessions'=>0,'requests'=>0,'captchaShown'=>0,'captchaPassed'=>0,'blocked'=>0,'urls'=>[],'first'=>$s['first'],'last'=>$s['last']];
        $e=&$fp[$f]; $e['ips'][$s['ip']]=true; $e['sessions']++; $e['requests']+=$s['requests']; $e['captchaShown']+=$s['captchaShown']; $e['captchaPassed']+=$s['captchaPassed']; $e['blocked']+=min(1,$s['blocked']);
        foreach(array_keys($s['urls']) as $u)$e['urls'][$u]=true;
        if($s['first']<$e['first'])$e['first']=$s['first']; if($s['last']>$e['last'])$e['last']=$s['last'];
        unset($e);
    }
}

$out=[];
foreach($fp as $e){
    $ipCount=count($e['ips']); $urlCount=count($e['urls']);
    $score=0; $reasons=[];
    if($ipCount>=20){$score+=35;$reasons[]='20+ IP на один fingerprint';}
    elseif($ipCount>=10){$score+=25;$reasons[]='10+ IP на один fingerprint';}
    elseif($ipCount>=5){$score+=15;$reasons[]='5+ IP на один fingerprint';}
    if($e['sessions']>=20){$score+=15;$reasons[]='20+ сессий';} elseif($e['sessions']>=5){$score+=10;$reasons[]='5+ сессий';}
    if($e['requests']>=100){$score+=15;$reasons[]='100+ запросов';} elseif($e['requests']>=20){$score+=10;$reasons[]='20+ запросов';}
    if($e['captchaShown']>=5){$score+=10;$reasons[]='много показов CAPTCHA';} elseif($e['captchaShown']>=3){$score+=6;$reasons[]='повторные CAPTCHA';}
    if($e['captchaPassed']>=5){$score+=15;$reasons[]='много успешных CAPTCHA';} elseif($e['captchaPassed']>=3){$score+=10;$reasons[]='повторные успешные CAPTCHA';}
    if($e['blocked']>=3){$score+=15;$reasons[]='3+ блокировки';} elseif($e['blocked']>=1){$score+=8;$reasons[]='есть блокировки';}
    if($urlCount>=10){$score+=5;$reasons[]='10+ уникальных URL';}
    $score=min(100,$score);
    $level=$score>=70?'HIGH':($score>=40?'MEDIUM':'LOW');
    $out[]=['value'=>$e['value'],'score'=>$score,'level'=>$level,'ipCount'=>$ipCount,'sessions'=>$e['sessions'],'requests'=>$e['requests'],'captchaShown'=>$e['captchaShown'],'captchaPassed'=>$e['captchaPassed'],'blocked'=>$e['blocked'],'urlCount'=>$urlCount,'reasons'=>$reasons];
}

usort($out,static fn($a,$b)=>($b['score']<=>$a['score']) ?: ($b['ipCount']<=>$a['ipCount']) ?: ($b['sessions']<=>$a['sessions']));
$out=array_slice($out,0,50);

echo json_encode(['ok'=>true,'items'=>$out,'generatedAt'=>date('Y-m-d H:i:s')],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
