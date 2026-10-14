#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Независимый ручной эталон по antibot.log (ШАГ 1).

Формат строки: YYYY-MM-DD HH:MM:SS RAYID IP MESSAGE
visitor_id = поле RAYID (3-й токен после времени — идентификатор визитера в логе).

Эталонные правила (по ТЗ):
 - request: message начинается с "/"
 - captcha_shown: строки "Show captcha*" (включая "for REFERRER/DIRECT"),
   ДЕДУПЛИЦИРУЮТСЯ до 1 события на запрос (visitor_id+секунда)
 - captcha_passed: "Successfully passed the captcha" (каждая строка)
 - blocks: "Display the blocking page" (каждая строка = событие)
 - events: всё, что не попало в категории выше (служебные строки)
"""
import re, sys, json
from collections import defaultdict, Counter
from datetime import datetime

LOG = sys.argv[1] if len(sys.argv) > 1 else '/workspace/antibot.log'

LINE_RE = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ([0-9a-f]+) (\S+) (.*)$')

def ts(s): return datetime.strptime(s, '%Y-%m-%d %H:%M:%S')

total_lines = 0
requests = 0
show_captcha_raw = 0     # все строки Show captcha*
show_captcha_dedup = 0   # после дедупликации (visitor+секунда)
passed = 0
blocks = 0
events_other = 0         # всё остальное (не REQ и не captcha/block строки)

visitors = defaultdict(lambda: {
    'requests': 0, 'urls': Counter(), 'times': [], 'req_times': [],
    'events': Counter(), 'fps': set(), 'ips': set(), 'ua': set(),
    'shown_raw': 0, 'shown_keys': set(), 'passed': 0, 'blocks': 0,
})
all_ips, all_fps = set(), set()

CAPTCHA_KIND = re.compile(r'^Show captcha\b')

with open(LOG, encoding='utf-8-sig') as f:
    for line in f:
        line = line.rstrip('\r\n')
        if not line.strip():
            continue
        total_lines += 1
        m = LINE_RE.match(line)
        if not m:
            print('UNPARSED:', line[:120]); continue
        t, vid, ip, msg = m.groups()
        v = visitors[vid]
        v['times'].append(t)
        v['ips'].add(ip)
        all_ips.add(ip)

        if msg.startswith('/'):
            requests += 1
            v['requests'] += 1
            url = msg.split('?', 1)[0]          # query отрезан
            v['urls'][url] += 1
            v['req_times'].append(t)
            v['events']['REQ'] += 1
        elif CAPTCHA_KIND.match(msg):
            show_captcha_raw += 1
            v['shown_raw'] += 1
            v['events']['Show captcha'] += 1
            v['shown_keys'].add((t,))           # дедуп: visitor+секунда
        elif msg.startswith('Successfully passed the captcha'):
            passed += 1
            v['passed'] += 1
            v['events']['Successfully passed'] += 1
        elif msg.startswith('Display the blocking page'):
            blocks += 1
            v['blocks'] += 1
            v['events']['BLOCK'] += 1
        else:
            events_other += 1
            key = msg.split(':', 1)[0].split(' ', 1)[0]
            if msg.startswith('FP:'):
                fp = msg.split(':', 1)[1].strip().lower()
                v['fps'].add(fp); all_fps.add(fp)
                v['events']['FP'] += 1
            elif msg.startswith('FPS:'):
                v['events']['FPS'] += 1
            elif msg.startswith('REF:'):
                v['events']['REF'] += 1
            elif msg.startswith('PTR:'):
                v['events']['PTR'] += 1
            elif msg.startswith('UA:'):
                ua = msg[3:].strip()
                if ua: v['ua'].add(ua)
                v['events']['UA'] += 1
            elif msg.startswith('Tag set'):
                v['events']['Tag set'] += 1
            elif msg.startswith('Displaying'):
                v['events']['Displaying'] += 1
            elif msg.startswith('Indexing robot'):
                v['events']['Indexing robot'] += 1
            elif msg.startswith('Empty User-Agent'):
                v['events']['Empty UA'] += 1
            elif msg.startswith('Error'):
                v['events']['Error'] += 1
            elif msg.startswith('Added to list'):
                v['events']['Added to list'] += 1
            elif msg.startswith('Found in list'):
                v['events']['Found in list'] += 1
            else:
                v['events'][key] += 1

# дедуп показов капчи: одна секунда одного visitor = 1 событие
for v in visitors.values():
    show_captcha_dedup += len(v['shown_keys'])

def avg_interval(times):
    rt = sorted(set(times))
    if len(rt) < 2: return None
    d = [ (ts(b)-ts(a)).total_seconds() for a,b in zip(rt, rt[1:]) ]
    return round(sum(d)/len(d), 2)

top20 = sorted(visitors.items(), key=lambda kv: -kv[1]['requests'])[:20]
out = {
    'total_lines': total_lines,
    'total_requests': requests,
    'total_visitors': len(visitors),
    'total_ips': len(all_ips),
    'total_fingerprints': len(all_fps),
    'total_captcha_shown_raw': show_captcha_raw,
    'total_captcha_shown_dedup': show_captcha_dedup,
    'total_captcha_passed': passed,
    'total_blocks': blocks,
    'total_events_other': events_other,
    'check_sum': requests + show_captcha_raw + passed + blocks + events_other,
    'top20': [
        {
            'visitor_id': vid,
            'requests': v['requests'],
            'urls': dict(v['urls']),
            'first_seen': min(v['times']),
            'last_seen': max(v['times']),
            'avg_interval_seconds': avg_interval(v['req_times']),
            'events': dict(v['events']),
            'fingerprints': sorted(v['fps']),
            'ips': sorted(v['ips']),
            'captcha_shown_dedup': len(v['shown_keys']),
            'captcha_passed': v['passed'],
            'blocks': v['blocks'],
        } for vid, v in top20
    ],
}
json.dump(out, open('/workspace/reference.json', 'w'), ensure_ascii=False, indent=1)
print(json.dumps({k: out[k] for k in out if k != 'top20'}, indent=1))
print('--- TOP-20 visitors ---')
for e in out['top20']:
    print(f"{e['visitor_id']} ip={','.join(e['ips'])} req={e['requests']} "
          f"urls={len(e['urls'])} avg_int={e['avg_interval_seconds']} "
          f"fp={len(e['fingerprints'])} shown={e['captcha_shown_dedup']} pass={e['captcha_passed']} block={e['blocks']}")
