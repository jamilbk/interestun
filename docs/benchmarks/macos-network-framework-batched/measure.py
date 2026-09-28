import subprocess,time,json,pathlib,threading,datetime
binary='/Users/jamil/tmp/interestun/target/release/interestun'
pid=subprocess.run(['pgrep','-f','^'+binary+' utun14 --cipher aes256-gcm$'],capture_output=True,text=True,check=True).stdout.strip()
assert pid.isdigit(),pid
out=pathlib.Path('/tmp/interestun-cpu-30s-'+str(time.time_ns()));out.mkdir()
def process_cpu():
 p=subprocess.run(['ps','-p',pid,'-o','time=,rss='],capture_output=True,text=True,check=True)
 fields=p.stdout.split();seconds=0
 for value in fields[0].split(':'):seconds=seconds*60+float(value)
 return {'monotonic':time.monotonic(),'cpu_seconds':seconds,'rss_kib':int(fields[1])}
summary={'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'daemon_pid':int(pid),'logical_cpus':int(subprocess.run(['sysctl','-n','hw.logicalcpu'],capture_output=True,text=True,check=True).stdout),'backend':'Network.framework','features':'io-profile','runs':[]}
for label,flags in [('mac-to-windows',[]),('windows-to-mac',['-R'])]:
 samples=[process_cpu()];stop=threading.Event()
 def sample():
  while not stop.wait(1):samples.append(process_cpu())
 thread=threading.Thread(target=sample);thread.start()
 try:
  p=subprocess.run(['iperf3','-c','10.20.0.1','-t','30','-O','1','-J','--connect-timeout','5000',*flags],capture_output=True,text=True,timeout=50)
 finally:
  stop.set();thread.join();samples.append(process_cpu())
 (out/(label+'.json')).write_text(p.stdout)
 d=json.loads(p.stdout);e=d.get('end',{});r=e.get('sum_received',{})
 # Exclude initial connection/warmup and the end-of-test control exchange.
 # CPU deltas use steady 1-second process snapshots within the traffic window.
 steady=[s for s in samples if 2 <= s['monotonic']-samples[0]['monotonic'] <= 30]
 first,last=steady[0],steady[-1]
 cores=(last['cpu_seconds']-first['cpu_seconds'])/(last['monotonic']-first['monotonic'])
 intervals=[(b['cpu_seconds']-a['cpu_seconds'])/(b['monotonic']-a['monotonic']) for a,b in zip(steady,steady[1:])]
 row={'direction':label,'exit':p.returncode,'error':d.get('error'),'receiver_gbps':r.get('bits_per_second',0)/1e9,'receiver_seconds':r.get('seconds'),'mac_daemon_cpu_percent':cores*100,'mac_daemon_cpu_cores':cores,'mac_daemon_cpu_sample_seconds':last['monotonic']-first['monotonic'],'mac_daemon_one_second_peak_percent':max(intervals)*100,'mac_daemon_peak_sampled_rss_mib':max(s['rss_kib'] for s in samples)/1024,'iperf_cpu_percent':e.get('cpu_utilization_percent'),'samples':samples}
 summary['runs'].append(row)
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 print(json.dumps({k:v for k,v in row.items() if k!='samples'}),flush=True)
 if p.returncode:raise RuntimeError(d.get('error',p.stderr))
print('RESULTS',str(out),flush=True)
