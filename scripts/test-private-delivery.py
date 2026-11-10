#!/usr/bin/env python3
# Modified by Tekmyster Industries, LLC — remains GPL-3.0
# SPDX-License-Identifier: GPL-3.0-or-later
"""Finite private packaging tests. Requires prebuilt packages and benign DNS seed.
Never registers services or operates on any root other than a newly created UUID.
"""
import argparse, concurrent.futures, importlib.util, json, os
from pathlib import Path
import secrets, shutil, signal, socket, struct, subprocess, sys, time, uuid, zipfile
import urllib.request, urllib.parse

def module(path):
    spec=importlib.util.spec_from_file_location('delivery',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def wait(predicate,seconds=20):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        if predicate():return
        time.sleep(.05)
    raise TimeoutError('Fixture boundary not reached')
def checkpoint(tool,root,release,generation,phase):
    m=module(tool);original=m.atomic
    def atomic(path,value):
        original(path,value)
        if path.name==('transition.json' if phase=='prepared' else 'current.json'):
            (root/'checkpoint').write_text(phase)
            while True:time.sleep(.1)
    m.atomic=atomic;m.activate(root,release,generation,True)
def main():
    p=argparse.ArgumentParser();p.add_argument('--tool',type=Path,required=True);p.add_argument('--old',type=Path,required=True);p.add_argument('--new',type=Path,required=True);p.add_argument('--seed',type=Path,required=True);p.add_argument('--dns-port',type=int,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--checkpoint',nargs=4)
    a=p.parse_args()
    for name in ('tool','old','new','seed','output'):setattr(a,name,getattr(a,name).resolve())
    if a.checkpoint:checkpoint(a.tool,Path(a.checkpoint[0]),a.checkpoint[1],int(a.checkpoint[2]),a.checkpoint[3]);return
    a.output.mkdir(parents=True,exist_ok=False);m=module(a.tool);events=[];count=0
    def check(ok,label):
        nonlocal count
        if not ok:raise AssertionError(label)
        count+=1;events.append({'check':label,'ok':True})
    def reject(action,label):
        try:action()
        except (ValueError,OSError,KeyError,zipfile.BadZipFile,subprocess.CalledProcessError):check(True,label);return
        raise AssertionError('Expected rejection: '+label)
    root=a.output/('install-'+uuid.uuid4().hex);m.init(root)
    reject(lambda:m.init(root),'fresh install refuses existing root')
    reject(lambda:m.stage(root,a.old),'unsigned production stage refused before mutation')
    old=m.stage(root,a.old,allow_unsigned=True);m.activate(root,old['release'],0,True)
    check(m.state(root)['generation']==1,'cold activation')
    shutil.copyfile(a.seed,root/'data/dns.config')
    # Deliberately outside every native-manager filename. Native authority is never invoked.
    boundary=root/'data/packaging-boundary-inert';boundary.mkdir()
    for name in ['leases','grants','owner-journal','epochs','fences','quorum','membership','reservations','identity','syslog-spool','backup-artifact']:
        (boundary/(name+'.txt')).write_text('INERT packaging preservation sentinel '+name+' v7\n')
    protected=m.files(boundary)
    credential=a.output/'fixture-credential.txt';credential.write_text(secrets.token_urlsafe(32))
    password=credential.read_text();web=socket.socket();web.bind(('127.0.0.1',0));port=web.getsockname()[1];web.close()
    base='http://127.0.0.1:'+str(port);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    processes=[];launcher=None;log=None;pid=None
    def api(path,fields=None,token=None):
        request=urllib.request.Request(base+path,data=urllib.parse.urlencode(fields or {}).encode(),headers={'Authorization':'Bearer '+token} if token else {})
        with opener.open(request,timeout=5) as response:value=json.load(response)
        if value.get('status')!='ok':raise RuntimeError('Native API rejected '+path+': '+value.get('errorMessage',''))
        return value
    def login():return api('/api/user/login',{'user':'admin','pass':password})['token']
    def start(label):
        nonlocal launcher,log,pid
        env=os.environ.copy();env.update(DNS_SERVER_ADMIN_PASSWORD_FILE=str(credential),DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES='127.0.0.1',DNS_SERVER_WEB_SERVICE_HTTP_PORT=str(port),DNS_SERVER_LOG_FOLDER_PATH=str(root/'data/logs'))
        log=(a.output/(label+'.log')).open('wb')
        launcher=subprocess.Popen([sys.executable,str(a.tool),'run',str(root),'--allow-unsigned-development'],env=env,stdout=log,stderr=subprocess.STDOUT)
        token=None
        def ready():
            nonlocal token
            if launcher.poll() is not None:raise RuntimeError('Owned launcher exited; inspect '+label+'.log')
            try:token=login();return True
            except (OSError,RuntimeError):return False
        wait(ready);pid=m.read(root/'process.json')['pid'];processes.append({'label':label,'launcherPid':launcher.pid,'nativePid':pid,'startedUtc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'release':m.state(root)['release'],'dnsPort':a.dns_port,'webPort':port})
        original=token;fresh=login();settings=api('/api/settings/get',token=fresh)['response']
        if label!='cold':check(settings['defaultRecordTtl']==601,label+' retained setting read before any modification')
        api('/api/settings/set',{'defaultRecordTtl':'601'},fresh)
        check(api('/api/settings/get',token=fresh)['response']['defaultRecordTtl']==601,label+' fresh admin read/modify and setting readback')
        api('/api/settings/get',token=original);api('/api/user/logout',token=fresh);api('/api/user/logout',token=original)
        return settings
    def stop():
        nonlocal launcher,log,pid
        if launcher is not None:
            if launcher.poll() is None:
                if pid is None and (root/'process.json').exists():pid=m.read(root/'process.json').get('pid')
                if pid is not None:os.kill(pid,signal.SIGTERM)
            launcher.wait(timeout=25);log.close()
            check(not (root/'process.json').exists(),'owned native exit observed and marker released')
            if processes:processes[-1]['exitCode']=launcher.returncode
            launcher=None
    def dns(tcp=False):
        identifier=secrets.randbits(16);name='answer.packaging.fixture.test'
        question=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
        packet=struct.pack('!HHHHHH',identifier,0x100,1,0,0,0)+question;started=time.perf_counter()
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            if tcp:
                s.connect(('127.0.0.1',a.dns_port));s.sendall(struct.pack('!H',len(packet))+packet)
                def exact(n):
                    b=b''
                    while len(b)<n:
                        part=s.recv(n-len(b))
                        if not part:raise OSError('Short DNS stream')
                        b+=part
                    return b
                result=exact(struct.unpack('!H',exact(2))[0])
            else:s.sendto(packet,('127.0.0.1',a.dns_port));result,source=s.recvfrom(4096)
        ident,flags,_,answers,_,_=struct.unpack('!HHHHHH',result[:12])
        if ident!=identifier or flags&15 or not flags&0x400 or answers<1 or b'\xc0\x00\x02\x2a' not in result:
            events.append({'dnsFailure':True,'nativePid':pid,'flags':flags,'rcode':flags&15,'aa':bool(flags&0x400),'answers':answers,'responseHex':result.hex(),'expected':'192.0.2.42','queryBytes':len(packet),'elapsedMs':(time.perf_counter()-started)*1000})
            raise AssertionError('Expected authoritative NoError A 192.0.2.42')
        return (time.perf_counter()-started)*1000,len(packet),len(result)
    def sample(label):
        for tcp in (False,True):
            elapsed,size,response=dns(tcp);events.append({'dns':label,'nativePid':pid,'source':'127.0.0.1','target':'127.0.0.1:'+str(a.dns_port),'transport':'TCP' if tcp else 'UDP','rcode':'NoError','aa':True,'address':'192.0.2.42','elapsedMs':elapsed,'queryBytes':size,'responseBytes':response,'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())})
    try:
        first=start('cold');token=login()
        api('/api/zones/create',{'zone':'packaging.fixture.test','type':'Primary'},token)
        api('/api/zones/records/add',{'domain':'answer.packaging.fixture.test','zone':'packaging.fixture.test','type':'A','ipAddress':'192.0.2.42'},token)
        api('/api/user/logout',token=token);sample('before-stage')
        wait(lambda:(root/'data/zones/packaging.fixture.test.zone').exists())
        check(b'\xc0\x00\x02\x2a' in (root/'data/zones/packaging.fixture.test.zone').read_bytes(),'fixture record durably saved before abrupt native stop')
        new=m.stage(root,a.new,allow_unsigned=True);sample('during-stage-old-process')
        reject(lambda:m.activate(root,new['release'],1,True),'active owned process blocks cutover');sample('after-refused-live-cutover')
        with m.lock(root):reject(lambda:m.stage(root,a.new,allow_unsigned=True),'concurrent staging is refused')
        # Finite local correctness load, never recursive/external DNS.
        for _ in range(10):dns()
        before=time.perf_counter();latencies=[];errors=0
        def query(_):
            try:return dns()[0]
            except (OSError,AssertionError):return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for value in pool.map(query,range(200)):
                if value is None:errors+=1
                else:latencies.append(value)
        duration=time.perf_counter()-before;latencies.sort()
        load={'offered':200,'completedCorrect':len(latencies),'errors':errors,'concurrency':4,'warmup':10,'seconds':duration,'correctQps':len(latencies)/duration,'p50ms':latencies[len(latencies)//2],'p95ms':latencies[int(len(latencies)*.95)],'nativePid':pid,'query':'authoritative A answer.packaging.fixture.test','resourceCap':'4 threads, 200 DNS requests, 2-second socket timeout; shared-host WSL/Windows fixture only'}
        check(errors==0,'bounded 200-packet authoritative DNS load')
        # Thirty bounded authenticated management reads under separate admission.
        t=login();before=time.perf_counter()
        for _ in range(30):check(api('/api/settings/get',token=t)['response']['defaultRecordTtl']==601,'bounded native management read')
        load['management']={'offered':30,'completed':30,'errors':0,'concurrency':1,'seconds':time.perf_counter()-before};api('/api/user/logout',token=t)
        stop();data_before=m.files(root/'data');(a.output/'data-preimage.json').write_bytes(m.encode([{'path':n,'sha256':m.digest(b),'length':len(b)} for n,b in data_before.items()]))
        reject(lambda:m.activate(root,new['release'],0,True),'stale generation refused')
        reject(lambda:m.activate(root,new['release'],1),'unsigned activation refused')
        # A filesystem obstruction is an ordinary command failure with retained journal.
        (root/'previous.json').unlink();(root/'previous.json').mkdir()
        reject(lambda:m.activate(root,new['release'],1,True),'write obstruction retains prepared transaction')
        (root/'previous.json').rmdir();check(m.reconcile(root)['result']=='not-applied','obstructed cutover reconciles without data restore')
        def crash(phase):
            args=[sys.executable,str(Path(__file__).resolve()),'--tool',str(a.tool),'--old',str(a.old),'--new',str(a.new),'--seed',str(a.seed),'--dns-port',str(a.dns_port),'--output',str(a.output),'--checkpoint',str(root),new['release'],'1',phase]
            child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:wait(lambda:(root/'checkpoint').exists());child.kill();out,err=child.communicate(timeout=10)
            finally:
                if child.poll() is None:child.kill();child.wait()
            events.append({'checkpoint':phase,'pid':child.pid,'exit':child.returncode,'stderr':err.decode(errors='replace')});(root/'checkpoint').unlink()
        crash('prepared');check(m.reconcile(root)['result']=='not-applied','OS-process termination before pointer switch aborts safely')
        check(m.state(root)['release']==old['release'],'old package remains active before cutover')
        crash('committed');check(m.reconcile(root)['result']=='committed','lost response discovers committed cutover')
        check(m.reconcile(root)['result']=='no-transition','repeated discovery has no second apply')
        check(m.files(root/'data')==data_before,'all data bytes unchanged across interrupted staging/cutover')
        upgraded=start('upgraded');sample('new-process-after-upgrade')
        check(upgraded['dnsServerDomain']==first['dnsServerDomain'] and upgraded['dnsServerLocalEndPoints']==first['dnsServerLocalEndPoints'],'native identity/listeners preserved')
        check(m.files(boundary)==protected,'inert authority boundary survives new native process')
        stop();m.activate(root,old['release'],2,True,True);start('rolled-back');sample('previous-compatible-package-after-rollback');stop()
        check(m.files(boundary)==protected,'inert lease/grant/epoch/fence/quorum data preserved through rollback')
        reject(lambda:m.activate(root,old['release'],3,True),'same release does not reapply')
        # Package policy negatives use new benign mutated archives only.
        original=a.old.read_bytes()
        import io
        with zipfile.ZipFile(io.BytesIO(original)) as z:entries={n:z.read(n) for n in z.namelist()}
        for label,name,value in [('tamper','DnsServerCore.dll',b'bad'),('traversal','../outside',b'x'),('absolute','/outside',b'x'),('windows-path','C:/outside',b'x'),('case-alias','dnsservercore.dll',b'x'),('unlisted','extra.txt',b'x'),('config','dns.config',b'inert')]:
            bad=dict(entries);bad[name]=value;path=a.output/(label+'.zip')
            with zipfile.ZipFile(path,'w') as z:
                for n,b in bad.items():z.writestr(n,b)
            reject(lambda:m.stage(root,path,allow_unsigned=True),label+' rejected before active/data mutation')
        bad=dict(entries);bad.pop('DnsServerCore.dll');path=a.output/'missing.zip'
        with zipfile.ZipFile(path,'w') as z:
            for n,b in bad.items():z.writestr(n,b)
        reject(lambda:m.stage(root,path,allow_unsigned=True),'missing file refused')
        # Explicit unsupported compatibility/version and duplicate/link contracts.
        for label,change in [('unsupported-engine',lambda v:v['compatibility'].update(engine='999.0.0')),('unsupported-version',lambda v:v.update(version='garbage'))]:
            bad=dict(entries);contract=json.loads(bad['delivery.json']);change(contract);bad['delivery.json']=m.encode(contract);path=a.output/(label+'.zip')
            with zipfile.ZipFile(path,'w') as z:
                for n,b in bad.items():z.writestr(n,b)
            reject(lambda:m.stage(root,path,allow_unsigned=True),label+' refused')
        path=a.output/'duplicate.zip'
        with zipfile.ZipFile(path,'w') as z:
            for n,b in entries.items():z.writestr(n,b)
            import warnings
            with warnings.catch_warnings():warnings.simplefilter('ignore');z.writestr('DnsServerCore.dll',b'x')
        reject(lambda:m.stage(root,path,allow_unsigned=True),'duplicate ZIP path refused')
        path=a.output/'link.zip'
        with zipfile.ZipFile(path,'w') as z:
            for n,b in entries.items():z.writestr(n,b)
            info=zipfile.ZipInfo('link');info.external_attr=0o120777<<16;z.writestr(info,'../data')
        reject(lambda:m.stage(root,path,allow_unsigned=True),'ZIP symlink refused')
        staged=root/'releases'/new['release']/'DnsServerCore.dll';b=staged.read_bytes();staged.write_bytes(b'corrupt')
        reject(lambda:m.activate(root,new['release'],3,True),'staged payload tamper refused');staged.write_bytes(b)
        check(m.state(root)['release']==old['release'] and m.files(boundary)==protected,'negative cases preserve active selection and inert authority')
        result={'passed':count,'platform':sys.platform,'root':str(root),'old':old,'new':new,'processes':processes,'events':events,'load':load,'limitations':['Unsigned development only; real CMS signing/trust untested','Alpha package versions differ in manifest only; engine is unchanged accepted source; no historical schema upgrade qualification','Binary rollback retains current data; no stale authority restore','Native target interrupted during stop/start; samples do not prove continuous availability','Inert authority sentinels are outside native authority filenames; no DHCP traffic/authority manager invoked','No service-manager, power-loss, production or full disaster-recovery claim','No source-specific management restrictions changed; target-observed source not inspected']}
        (a.output/'RESULT.json').write_bytes(m.encode(result));print(json.dumps({'passed':count,'result':str(a.output/'RESULT.json'),'load':load}))
    finally:
        if launcher is not None:stop()
        (a.output/'EVENTS.json').write_bytes(m.encode(events))
if __name__=='__main__':main()
