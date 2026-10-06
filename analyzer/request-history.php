<?php
declare(strict_types=1);
require_once __DIR__ . '/auth.php';
analyzerRequireLogin();
header('Content-Type: application/json; charset=utf-8');
$root=dirname(__DIR__).'/antibot';
$log=is_readable($root.'/logs/antibot.log')?$root.'/logs/antibot.log':$root.'/antibot.log';
$type=(string)($_GET['type']??''); $value=trim((string)($_GET['value']??''));
if(!in_array($type,['ip','fingerprint'],true)||$value===''){http_response_code(400);echo json_encode(['ok'=>false,'error'=>'Некорректные параметры'],JSON_UNESCAPED_UNICODE);exit;}
$events=[];$ips=[];$urls=[];$sessions=[];$fh=fopen($log,'rb');
while(($line=fgets($fh))!==false){
 if(!preg_match('/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s*(.*)$/u',rtrim($line,"\r\n"),$m))continue;
 $msg=trim($m[4]); $match=$type==='ip' ? $m[3]===$value : (bool)preg_match('/\bFP:\s*'.preg_quote($value,'/').'\b/i',$msg);
 if(!$match)continue;
 $kind='event'; if($msg!==''&&$msg[0]==='/'){$kind='request';$urls[$msg]=1;} elseif(str_starts_with($msg,'REF:'))$kind='referrer'; elseif(str_starts_with($msg,'PTR:'))$kind='ptr'; elseif(str_starts_with($msg,'UA:'))$kind='ua'; elseif(stripos($msg,'captcha')!==false)$kind='captcha'; elseif(stripos($msg,'blocked')!==false||stripos($msg,'blocking page')!==false)$kind='block';
 $sessions[$m[2]]=1;$ips[$m[3]]=1;$events[]=['time'=>$m[1],'ray'=>$m[2],'ip'=>$m[3],'kind'=>$kind,'message'=>$msg];
 if(count($events)>=250)break;
}
fclose($fh);usort($events,fn($a,$b)=>strcmp($a['time'],$b['time']));
echo json_encode(['ok'=>true,'events'=>$events,'sessions'=>count($sessions),'ips'=>array_keys($ips),'urls'=>array_keys($urls)],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
