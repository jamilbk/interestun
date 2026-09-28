import subprocess,time,json,pathlib,threading,datetime,sys,os
label=sys.argv[1];duration=int(sys.argv[2]) if len(sys.argv)>2 else 10
modes=sys.argv[3:] or ['send','receive','duplex']
binary='/Users/jamil/tmp/interestun/target/release/interestun'
pid=subprocess.check_output(['pgrep','-f','^'+binary+' utun14 --cipher aes256-gcm$'],text=True).strip();assert pid.isdigit()
state=pathlib.Path('/var/folders/c3/8864l50s27z2v0d2q5t6lm900000gn/T/interestun-windows-pmmazehv/state.json')
log=pathlib.Path(json.loads(state.read_text())['log'])
out=pathlib.Path('/tmp/interestun-optimization')/label;out.mkdir(parents=True,exist_ok=False)
def cpu():
 fields=subprocess.check_output(['ps','-p',pid,'-o','time=,rss='],text=True).split();secs=0
 for v in fields[0].split(':'):secs=secs*60+float(v)
 return {'time':time.monotonic(),'cpu':secs,'rss_kib':int(fields[1])}
summary={'label':label,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'pid':pid,'duration':duration,'log':str(log),'runs':[]}
for mode in modes:
 flags={'send':[],'receive':['-R'],'duplex':['--bidir'],'send4':['-P','4'],'receive4':['-R','-P','4'],'send8':['-P','8'],'receive8':['-R','-P','8'],'send-window':['-w','2M'],'receive-window':['-R','-w','2M'],'send-zero':['-Z','-l','1M'],'send-paced5':['-b','5G','--pacing-timer','100'],'send-paced6':['-b','6G','--pacing-timer','100'],'send-paced8':['-b','8G','--pacing-timer','100']}[mode]
 (out/(mode+'-interface-before.txt')).write_text(subprocess.check_output(['netstat','-ibnI','utun14'],text=True))
 offset=log.stat().st_size;samples=[cpu()];stop=threading.Event()
 def sample():
  while not stop.wait(.5):samples.append(cpu())
 thread=threading.Thread(target=sample);thread.start()
 args=['iperf3','-c','10.20.0.1','-t',str(duration),'-O','1','-J','--connect-timeout','5000',*flags]
 try:p=subprocess.run(args,capture_output=True,text=True,timeout=duration+20)
 finally:stop.set();thread.join();samples.append(cpu())
 (out/(mode+'.json')).write_text(p.stdout)
 (out/(mode+'-interface-after.txt')).write_text(subprocess.check_output(['netstat','-ibnI','utun14'],text=True))
 with log.open() as f:f.seek(offset);(out/(mode+'.log')).write_text(f.read())
 data=json.loads(p.stdout);end=data.get('end',{});steady=[s for s in samples if 2<=s['time']-samples[0]['time']<=duration]
 a,b=steady[0],steady[-1]
 row={'mode':mode,'gbps':end.get('sum_received',{}).get('bits_per_second',0)/1e9,'reverse_gbps':end.get('sum_received_bidir_reverse',{}).get('bits_per_second',0)/1e9,'cpu_cores':(b['cpu']-a['cpu'])/(b['time']-a['time']),'rss_mib':max(s['rss_kib'] for s in samples)/1024,'retransmits':end.get('sum_sent',{}).get('retransmits'),'error':data.get('error'),'command':args,'samples':samples}
 summary['runs'].append(row);(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 print(json.dumps({k:v for k,v in row.items() if k not in ('samples','command')}),flush=True)
 if p.returncode:raise RuntimeError(data.get('error',p.stderr))
print('RESULTS',out,flush=True)
