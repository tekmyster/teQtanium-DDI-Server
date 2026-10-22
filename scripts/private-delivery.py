#!/usr/bin/env python3
# Modified by Tekmyster Industries, LLC — remains GPL-3.0
# SPDX-License-Identifier: GPL-3.0-or-later
"""Private portable releases. No service installation, trust-store or data mutation.

Unsigned development requires an explicit flag on each read/activation. Hashes are
integrity checks, never a signature. Production use requires independent approval.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import uuid
import zipfile

SCHEMA=1
COMPAT={'engine':'15.6.1','framework':'net10.0','dataEpoch':1,
        'authority':'preserve-in-place-no-import','recoveryAutomation':'Disabled',
        'protection':'Monitor','dns':'Monitor','dhcp':'Observe'}
MAX_SIZE=1024**3
def fail(message): raise ValueError(message)
def digest(data): return hashlib.sha256(data).hexdigest()
def encode(value): return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def read(path): return json.loads(path.read_bytes())
def safe_path(name):
    if not isinstance(name,str) or not name or '\\' in name or ':' in name or any(ord(c)<32 for c in name): fail('Unsafe package path')
    p=PurePosixPath(name)
    if len(name)>220 or len(p.parts)>16:fail('Package path exceeds supported length/depth')
    if p.is_absolute() or p.as_posix()!=name or any(x in ('','.','..') or x.endswith(('.', ' ')) for x in p.parts): fail('Unsafe package path')
    if any(re.fullmatch(r'(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?',x,re.I) for x in p.parts): fail('Reserved path')
    return p
def no_links(path):
    for p in [path,*path.parents]:
        if p.exists() and (p.is_symlink() or getattr(p.lstat(),'st_file_attributes',0)&0x400): fail('Symlink/reparse paths are not supported')
        if p.is_file() and p.stat().st_nlink>1:fail('Hardlinked files are not supported')
def entry_info(path):
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:fail('Symlink/reparse paths are not supported')
    if stat.S_ISREG(info.st_mode) and info.st_nlink>1:fail('Hardlinked files are not supported')
    return info
def files(folder):
    no_links(folder)
    result={}
    for p in sorted(folder.rglob('*')):
        info=entry_info(p)
        if stat.S_ISREG(info.st_mode):
            name=p.relative_to(folder).as_posix();safe_path(name)
            if name.casefold() in {n.casefold() for n in result}: fail('Case-colliding file')
            result[name]=p.read_bytes()
    return result
def payload_policy(names):
    # Packages contain code/assets, never a live config/authority snapshot.
    forbidden={'data','config','logs','scopes','leases','backups','captures','inventory','evidence','.git','node_modules'}
    for name in names:
        p=safe_path(name)
        if any(x.casefold() in forbidden for x in p.parts) or p.suffix.lower() in {'.key','.pfx','.p12','.pcap','.kdbx','.config'} and p.name not in {'DnsServerApp.dll.config'}:
            fail('Configuration, authority, credentials or operational data in payload')
        if p.name.lower() in {'auth.json','security.json','syslog.json','ipam.json','credentials.json','lab-connection.json'}: fail('Deployment data in payload')
def create(payload,archive,version,source,runtime='portable-net10.0'):
    if not re.fullmatch(r'0\.[0-9]+\.[0-9]+-alpha\.[0-9]+',version): fail('Use a teQtanium alpha version')
    data=files(payload);payload_policy(data)
    if 'delivery.json' in data: fail('Reserved manifest name')
    required={'DnsServerApp.dll','DnsServerCore.dll','DnsServerApp.runtimeconfig.json','DnsServerApp.deps.json','www/index.html','LICENSE','THIRD-PARTY-NOTICES.md'}
    if not required<=data.keys(): fail('Incomplete application payload')
    if runtime not in ('portable-net10.0','linux-x64','win-x64'):fail('Unsupported runtime')
    if runtime!='portable-net10.0' and ('DnsServerApp'+('.exe' if runtime=='win-x64' else '')) not in data:fail('Missing native app host')
    provenance=read(source)
    for key in ('sourceCommit','rawSourceManifestSha256','canonicalSourceManifestSha256','dependencyManifestSha256','packageGraphSha256'):
        if not re.fullmatch('[a-f0-9]{40}' if key=='sourceCommit' else '[a-f0-9]{64}',provenance.get(key,'')): fail('Incomplete immutable provenance')
    manifest={'schema':SCHEMA,'distribution':'private','signature':'external-detached-CMS-required',
              'version':version,'runtime':runtime,'compatibility':COMPAT,'provenance':provenance,
              'files':[{'path':n,'length':len(b),'sha256':digest(b)} for n,b in sorted(data.items())]}
    data['delivery.json']=encode(manifest)
    no_links(archive.parent)
    with archive.open('xb') as stream:
        with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
            for name,b in sorted(data.items()):
                info=zipfile.ZipInfo(name,(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16
                z.writestr(info,b)
        stream.flush();os.fsync(stream.fileno())
    return {'archiveSha256':digest(archive.read_bytes()),'version':version,'signed':False,'files':len(data)}
def verify(archive,signature=None,thumbprint=None,allow_unsigned=False):
    no_links(archive)
    if archive.stat().st_size>MAX_SIZE: fail('Archive exceeds limit')
    content=archive.read_bytes()
    if signature is not None:
        if not thumbprint: fail('Pinned signer thumbprint required')
        subprocess.run(['pwsh','-NoProfile','-File',str(Path(__file__).with_name('private-delivery-signature.ps1')),
                        '-Mode','Verify','-Archive',str(archive),'-Signature',str(signature),'-Thumbprint',thumbprint],check=True,stdout=subprocess.PIPE)
        signed=True
    elif allow_unsigned: signed=False
    else: fail('Trusted signature required; unsigned development needs explicit opt-in')
    # Hold exact verified bytes through parse/extract; no signature/parse TOCTOU.
    if signed:
        # Signing helper reads the file. Check it did not change during verification.
        if digest(content)!=digest(archive.read_bytes()): fail('Archive changed during signature verification')
    return parse(content,signed)
def parse(content,signed=False):
    import io
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        entries=z.infolist();seen=set();total=0
        if len(entries)>6000: fail('Too many entries')
        for e in entries:
            safe_path(e.filename);key=e.filename.casefold()
            if key in seen or e.is_dir() or stat.S_IFMT(e.external_attr>>16) not in (0,stat.S_IFREG): fail('Duplicate or non-file entry')
            seen.add(key);total+=e.file_size
            if e.file_size>256*1024**2 or total>MAX_SIZE: fail('Expanded archive exceeds limit')
        manifest=json.loads(z.read('delivery.json'))
        if manifest.get('schema')!=SCHEMA or manifest.get('distribution')!='private' or manifest.get('runtime') not in ('portable-net10.0','linux-x64','win-x64'): fail('Unsupported package contract')
        if manifest.get('compatibility')!=COMPAT: fail('Incompatible component/data contract')
        if not re.fullmatch(r'0\.[0-9]+\.[0-9]+-alpha\.[0-9]+',manifest.get('version','')): fail('Invalid version')
        records=manifest['files'];names=[r['path'] for r in records];payload_policy(names)
        if len(set(n.casefold() for n in names))!=len(names) or {e.filename for e in entries}!=set(names)|{'delivery.json'}: fail('Manifest coverage mismatch')
        result={}
        for r in records:
            b=z.read(r['path'])
            if len(b)!=r['length'] or digest(b)!=r['sha256']: fail('File digest mismatch')
            result[r['path']]=b
        result['delivery.json']=z.read('delivery.json')
    return manifest,result,digest(content),signed
def atomic(path,value):
    no_links(path)
    tmp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.pending')
    with tmp.open('xb') as f: f.write(encode(value));f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)
@contextlib.contextmanager
def lock(root,name='transaction.lock'):
    p=root/name;no_links(p)
    with p.open('a+b') as f:
        if not p.stat().st_size: f.write(b'0');f.flush()
        f.seek(0)
        if os.name=='nt':
            import msvcrt
            try: msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
            except OSError: fail('Installation busy')
        else:
            import fcntl
            try: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError: fail('Installation busy')
        try: yield
        finally:
            if os.name=='nt': f.seek(0);msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)
            else: fcntl.flock(f,fcntl.LOCK_UN)
def owned(root):
    no_links(root)
    if not root.is_absolute() or not (root/'.teqtanium-owned').is_file(): fail('Use an initialized absolute owned root')
    if read(root/'.teqtanium-owned')!={'schema':1,'scope':'private-portable'}: fail('Invalid owned root marker')
    for p in root.rglob('*'):entry_info(p)
def init(root):
    no_links(root)
    if not root.is_absolute() or root.exists(): fail('Initialize a new absolute disposable root')
    root.mkdir(parents=True)
    (root/'releases').mkdir();(root/'data').mkdir()
    atomic(root/'.teqtanium-owned',{'schema':1,'scope':'private-portable'})
    atomic(root/'current.json',{'generation':0,'release':None,'version':None})
def stage(root,archive,**kwargs):
    owned(root)
    # Snapshot once into a new owned file so signature verification and extraction
    # read the same local immutable input, never a caller-controlled changing path.
    with lock(root):
        import shutil
        if shutil.disk_usage(root).free < archive.stat().st_size*4+32*1024**2:fail('Insufficient staging free space')
        snapshot=root/('input-'+uuid.uuid4().hex+'.zip')
        with archive.open('rb') as src,snapshot.open('xb') as dst: shutil.copyfileobj(src,dst);dst.flush();os.fsync(dst.fileno())
        try: m,data,key,signed=verify(snapshot,**kwargs)
        except BaseException:
            snapshot.unlink();raise
        stored=root/(key+'.zip')
        if stored.exists():
            if digest(stored.read_bytes())!=key:fail('Stored package changed')
            snapshot.unlink()
        else:snapshot.rename(stored)
        if signed:
            signature=root/(key+'.p7s');b=kwargs['signature'].read_bytes()
            if signature.exists() and signature.read_bytes()!=b:fail('Stored signature differs')
            if not signature.exists():
                with signature.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
        destination=root/'releases'/key
        if destination.exists():
            if files(destination)!=data: fail('Staged release changed')
        else:
            work=root/'releases'/('.pending-'+uuid.uuid4().hex);work.mkdir()
            for n,b in data.items():
                p=work/n;p.parent.mkdir(parents=True,exist_ok=True)
                with p.open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
                if m['runtime']=='linux-x64' and n=='DnsServerApp':p.chmod(0o755)
            work.rename(destination)
        atomic(root/(key+'.verification.json'),{'sha256':key,'signed':signed,'thumbprint':kwargs.get('thumbprint'),'version':m['version']})
        return {'release':key,'version':m['version'],'signed':signed}
def state(root): return read(root/'current.json')
def number(version):return tuple(map(int,re.findall(r'\d+',version)))
def ensure_stopped(root):
    if (root/'process.json').exists():
        pid=read(root/'process.json')['pid']
        # A stale record must be investigated; never terminate an unproven process.
        fail('Owned process record exists; verify exit before removing its record: '+str(pid))
def validate_release(root,key,allow_unsigned):
    if not re.fullmatch('[a-f0-9]{64}',key):fail('Invalid release identity')
    receipt=read(root/(key+'.verification.json'))
    if receipt['sha256']!=key or not receipt['signed'] and not allow_unsigned: fail('Unsigned activation denied')
    archive=root/(key+'.zip')
    m,expected,actual,signed=verify(archive,signature=root/(key+'.p7s') if receipt['signed'] else None,
                                  thumbprint=receipt.get('thumbprint'),allow_unsigned=allow_unsigned)
    if actual!=key:fail('Stored archive identity changed')
    mapping=files(root/'releases'/key)
    if mapping!=expected:fail('Staged release differs from verified package')
    if m['compatibility']!=COMPAT:fail('Incompatible release')
    records=m['files']
    if set(mapping)!={r['path'] for r in records}|{'delivery.json'}:fail('Staged coverage changed')
    for r in records:
        b=mapping[r['path']]
        if digest(b)!=r['sha256'] or len(b)!=r['length']:fail('Staged file changed')
    return m
def activate(root,key,expected,allow_unsigned=False,rollback=False):
    owned(root)
    with lock(root),lock(root,'run.lock'):
        ensure_stopped(root)
        if (root/'transition.json').exists():fail('Interrupted transition requires reconcile')
        old=state(root)
        if old['generation']!=expected:fail('Concurrent state change')
        m=validate_release(root,key,allow_unsigned)
        if old['release']==key:fail('Release already active')
        if old['version'] and number(m['version'])<=number(old['version']) and not rollback:fail('Upgrade version must increase')
        if rollback:
            history=root/'previous.json'
            if not history.exists() or read(history)['release']!=key:fail('Rollback restricted to immediate prior release')
        new={'generation':expected+1,'release':key,'version':m['version']}
        atomic(root/'transition.json',{'before':old,'after':new,'kind':'rollback' if rollback else 'activate'})
        # No config/lease/authority snapshot is written or restored.
        atomic(root/'previous.json',old);atomic(root/'current.json',new)
        (root/'transition.json').unlink()
        return new
def reconcile(root):
    owned(root)
    with lock(root),lock(root,'run.lock'):
        ensure_stopped(root);journal=root/'transition.json'
        if not journal.exists():return {'result':'no-transition','current':state(root)}
        j=read(journal);current=state(root)
        if current not in (j['before'],j['after']):fail('Unknown transition state; retain all evidence')
        # Never start a service or restore data on restart.
        if current==j['after']:atomic(root/'previous.json',j['before'])
        journal.rename(root/('transition-reconciled-'+uuid.uuid4().hex+'.json'))
        return {'result':'committed' if current==j['after'] else 'not-applied','current':current}
def run(root,allow_unsigned=False):
    owned(root)
    with lock(root,'run.lock'):
        ensure_stopped(root)
        if (root/'transition.json').exists():fail('Reconcile interrupted transition first')
        current=state(root);manifest=validate_release(root,current['release'],allow_unsigned)
        payload=root/'releases'/current['release']
        runtime=manifest['runtime']
        if runtime=='linux-x64' and (sys.platform!='linux' or os.uname().machine!='x86_64'):fail('Package requires native Linux x64')
        if runtime=='win-x64' and os.name!='nt':fail('Package requires native Windows x64')
        command=['dotnet',str(payload/'DnsServerApp.dll')] if runtime=='portable-net10.0' else [str(payload/('DnsServerApp.exe' if runtime=='win-x64' else 'DnsServerApp'))]
        # Reserve the process marker before creation. A launcher crash between
        # spawn and PID persistence still fails closed on subsequent activation.
        atomic(root/'process.json',{'pid':None,'release':current['release'],'state':'starting'})
        try:child=subprocess.Popen(command+['--portable-app','--stop-if-bind-fails',str(root/'data')],cwd=payload)
        except BaseException:
            (root/'process.json').unlink();raise
        atomic(root/'process.json',{'pid':child.pid,'release':current['release'],'state':'running'})
        try:return child.wait()
        except KeyboardInterrupt:
            child.wait(timeout=30);return child.returncode
        finally:
            if child.poll() is not None:(root/'process.json').unlink()
def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    c=sub.add_parser('create');c.add_argument('payload',type=Path);c.add_argument('archive',type=Path);c.add_argument('--version',required=True);c.add_argument('--provenance',type=Path,required=True);c.add_argument('--runtime',default='portable-net10.0')
    for command in ('verify','stage'):
        c=sub.add_parser(command)
        if command=='stage':c.add_argument('root',type=Path)
        c.add_argument('archive',type=Path);c.add_argument('--signature',type=Path);c.add_argument('--thumbprint');c.add_argument('--allow-unsigned-development',action='store_true')
    c=sub.add_parser('init');c.add_argument('root',type=Path)
    for command in ('activate','rollback'):
        c=sub.add_parser(command);c.add_argument('root',type=Path);c.add_argument('release');c.add_argument('--expected-generation',required=True,type=int);c.add_argument('--allow-unsigned-development',action='store_true')
    for command in ('reconcile','run'):
        c=sub.add_parser(command);c.add_argument('root',type=Path)
        if command=='run':c.add_argument('--allow-unsigned-development',action='store_true')
    a=p.parse_args();cmd=a.command
    if cmd=='create':result=create(a.payload,a.archive,a.version,a.provenance,a.runtime)
    elif cmd=='init':init(a.root);result={'initialized':str(a.root)}
    elif cmd in ('verify','stage'):
        opts={'signature':a.signature,'thumbprint':a.thumbprint,'allow_unsigned':a.allow_unsigned_development}
        if cmd=='stage':result=stage(a.root,a.archive,**opts)
        else:
            m,_,key,signed=verify(a.archive,**opts);result={'sha256':key,'version':m['version'],'signed':signed}
    elif cmd in ('activate','rollback'):result=activate(a.root,a.release,a.expected_generation,a.allow_unsigned_development,cmd=='rollback')
    elif cmd=='reconcile':result=reconcile(a.root)
    else:sys.exit(run(a.root,a.allow_unsigned_development))
    print(json.dumps(result))
if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,zipfile.BadZipFile,subprocess.CalledProcessError) as error:
        print('Delivery rejected: '+str(error),file=sys.stderr);sys.exit(1)
