# SPDX-License-Identifier: GPL-3.0-only
"""Benign synthetic publication-candidate tests. No services, secrets or publication."""
import argparse, datetime, hashlib, json, shutil, subprocess, concurrent.futures, os
from pathlib import Path

def command(args,cwd=None):
    return subprocess.run(args,cwd=cwd,capture_output=True,text=True,encoding='utf-8',errors='replace')
def git(root,*args):
    p=command(['git','-C',str(root),*args])
    if p.returncode: raise RuntimeError(p.stdout+p.stderr)
    return p.stdout.strip()
def write(root,name,data):
    path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(data if isinstance(data,bytes) else data.encode('utf-8'))
def snapshot(root):
    return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file() and '.git' not in p.relative_to(root).parts}
def manifest(root,classification=None,origin=None):
    base=git(root,'rev-parse','HEAD');entries=[]
    for path in sorted(root.rglob('*')):
        if not path.is_file() or '.git' in path.relative_to(root).parts or path.name=='PUBLIC-SOURCE-PROVENANCE.json': continue
        name=path.relative_to(root).as_posix()
        kind='InheritedFontAsset' if name.startswith('DnsServerCore/www/fonts/') and path.suffix.lower() in ('.otf','.ttf','.woff','.woff2','.eot') else 'PublicBrandingAsset' if path.suffix.lower() in ('.png','.jpg','.jpeg','.ico','.gif','.bmp') else 'GPL-covered'
        entries.append(dict(path=name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),classification=classification or kind,origin=origin or 'accepted-base:'+base+':'+name))
    data=dict(schemaVersion=1,baseCommit=base,files=entries)
    write(root,'PUBLIC-SOURCE-PROVENANCE.json',json.dumps(data,indent=2)+'\n')
    return data
def main():
    a=argparse.ArgumentParser();a.add_argument('--output',required=True);a.add_argument('--ci-checkout-regression',action='store_true');args=a.parse_args()
    if args.ci_checkout_regression: return ci_checkout_regression(args.output)
    out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=False)
    source=Path(__file__).resolve().parents[1];baseline=out/'baseline';baseline.mkdir()
    frozen_tools={n:hashlib.sha256((source/n).read_bytes()).hexdigest() for n in ('scripts/check-public-license.ps1','scripts/check_public_source.py','scripts/test-public-source-guard.py')}
    for name in ('PUBLICATION-HOLD.txt','PRIVATE-FILES.txt','Tectanium.WindowsService/Program.cs','Tectanium.WindowsService/Tectanium.WindowsService.csproj','docs/branding/teqtanium-original.png','DnsServerCore/www/img/loader.gif','DnsServerWindowsSetup/logo.bmp','DnsServerCore/www/fonts/FontAwesome.otf','DnsServerCore/www/fonts/fontawesome-webfont.eot','DnsServerCore/www/fonts/fontawesome-webfont.ttf','DnsServerCore/www/fonts/fontawesome-webfont.woff','DnsServerCore/www/fonts/fontawesome-webfont.woff2'):
        write(baseline,name,(source/name).read_bytes())
    write(baseline,'sample.cs','// SPDX-License-Identifier: GPL-3.0-only\n// GNU General Public License; synthetic eligible source\nclass Sample {}\n')
    git(baseline,'init');git(baseline,'config','user.name','Guard Fixture');git(baseline,'config','user.email','fixture@invalid');git(baseline,'config','core.autocrlf','false');git(baseline,'add','.');git(baseline,'commit','-m','Synthetic eligible baseline with exact historical GPL exceptions')
    receipts=[];pending=[];executor=concurrent.futures.ThreadPoolExecutor(max_workers=4)
    def case(name,mutate=lambda r:None,expected=1,reason=None,scope='CommunitySource',post=None):
        root=out/name;shutil.copytree(baseline,root);mutate(root)
        # Fixtures deliberately make path/content attacks look fully inventoried/provenanced.
        git(root,'add','-A');git(root,'commit','--allow-empty','-m','Synthetic case input')
        manifest(root)
        if post: post(root)
        git(root,'add','-A')
        before=snapshot(root)
        cmd=['pwsh','-NoProfile','-NonInteractive','-File',str(source/'scripts/check-public-license.ps1'),'-RepositoryRoot',str(root)]
        if scope is not None: cmd+=['-PublicationScope',scope]
        def execute():
            p=command(cmd);after=snapshot(root);text=p.stdout+p.stderr
            passed=(p.returncode==0 if expected==0 else p.returncode!=0) and before==after and (reason is None or reason in text)
            print(name,'PASS' if passed else 'FAIL',p.returncode,flush=True)
            return dict(case=name,command=cmd,expectedExit=expected,actualExit=p.returncode,expectedMessage=reason,stdout=p.stdout,stderr=p.stderr,unchanged=before==after,files=before,pass_=passed)
        pending.append(executor.submit(execute))
    case('eligible-gpl-historical-exceptions-assets',expected=0,reason='exact staged files')
    case('private-inventory-excluded-from-candidate',lambda r:write(r,'PRIVATE-FILES.txt','Apps/teQtanium.Private/absent.cs\n'),expected=0)
    case('literal-key-format-placeholder',lambda r:write(r,'DnsServerCore/www/index.html',(source/'DnsServerCore/www/index.html').read_bytes()),expected=0)
    case('inline-key-header-elsewhere',lambda r:write(r,'placeholder.html','<textarea placeholder="-----BEGIN '+'PRIVATE KEY-----"></textarea>\n'),reason='Private key material')
    case('renamed-original-key-template',lambda r:write(r,'renamed.html',(source/'DnsServerCore/www/index.html').read_bytes()),reason='Private key material')
    case('changed-key-placeholder-body',lambda r:write(r,'DnsServerCore/www/index.html',(source/'DnsServerCore/www/index.html').read_bytes().replace(b'MII...',b'MIISYNTHETICNOTAKEY')),reason='Private key material')
    case('historical-jpeg-in-png-name',lambda r:write(r,'docs/screenshots/about.png',(source/'docs/screenshots/about.png').read_bytes()),expected=0)
    for name,path,data,reason in [
        ('private-notice','renamed.cs','// Copyright (c) 2026 Tekmyster Industries, LLC. All Rights Reserved.\n','Private notice'),
        ('private-notice-late','moved.cs','\n'*2100+'// Proprietary and Confidential\n','Private notice'),
        ('reserved-no-header','Apps/teQtanium.New/new.cs','// GPL-3.0-only\n','Reserved private path'),
        ('case-private-path','apps/TEQTANIUM.New/new.cs','// GPL-3.0-only\n','Reserved private path'),
        ('historical-project-new-file','Tectanium.WindowsService/new.cs','// GPL-3.0-only\n','Reserved private path'),
        ('historical-exception-private-header','Tectanium.WindowsService/Program.cs','// Proprietary and Confidential\n','Private notice'),
        ('uppercase-dll','Payload.DLL','synthetic','Binary/archive'),
        ('uppercase-exe','Payload.EXE','synthetic','Binary/archive'),
        ('extensionless-apphost','apphost',b'MZsynthetic','Disguised'),
        ('linux-apphost','apphost-linux',b'\x7fELFsynthetic','Disguised'),
        ('renamed-zip','notes.txt',b'PK\x03\x04synthetic','Disguised'),
        ('opaque-source','opaque.cs',b'\x00\x81synthetic','Opaque'),
        ('archive','payload.ZIP','synthetic','Binary/archive'),
        ('capture','probe.PCAPNG','synthetic','Binary/archive'),
        ('evidence','evidence/result.json','{}','Operational/private'),
        ('inventory','inventory/nodes.json','{}','Operational/private'),
        ('synthetic-secret','secrets/token.txt','not-a-real-secret','Operational/private'),
        ('synthetic-env','.env','fixture=true','Operational/private'),
        ('private-dhcpq','tools/DHCP-Q/main.cs','synthetic','Operational/private'),
        ('key-material','notes.txt','-----BEGIN '+'PRIVATE KEY-----\nsynthetic','Private key'),
        ('font-disguised-executable','DnsServerCore/www/fonts/FontAwesome.otf',b'MZsynthetic','Disguised'),
        ('font-private-notice','DnsServerCore/www/fonts/FontAwesome.otf','// Proprietary and Confidential\n','Invalid inherited font asset'),
        ('new-font-name','DnsServerCore/www/fonts/new.woff',b'wOFFsynthetic','Only exact inherited font'),
        ('gif-disguised-exe','docs/image.gif',b'MZsynthetic','Disguised'),
        ('bmp-disguised-exe','docs/image.bmp',b'MZsynthetic','Disguised'),
    ]: case(name,lambda r,p=path,d=data:write(r,p,d),reason=reason)
    case('inventory-normalized-present',lambda r:(write(r,'private/sample.cs','synthetic'),write(r,'PRIVATE-FILES.txt','PRIVATE\\sample.cs\n')),reason='Inventoried private file')
    case('inventoried-original-font',lambda r:write(r,'PRIVATE-FILES.txt','DnsServerCore/www/fonts/FontAwesome.otf\n'),reason='Inventoried private file')
    case('font-under-private-path',lambda r:write(r,'docs/enterprise/FontAwesome.otf',(source/'DnsServerCore/www/fonts/FontAwesome.otf').read_bytes()),reason='Reserved private path')
    def alter_font(root):
        p=root/'DnsServerCore/www/fonts/FontAwesome.otf';data=p.read_bytes();p.write_bytes(data[:-1]+bytes([data[-1]^1]))
    case('altered-original-font-hash',post=alter_font,reason='Provenance hash differs')
    case('inventory-duplicate',lambda r:write(r,'PRIVATE-FILES.txt','absent\\file.cs\nABSENT/file.cs\n'),reason='Duplicate normalized private inventory')
    for label,value in [('parent','../outside.cs'),('absolute','C:/outside.cs'),('leading-slash','/outside.cs'),('dot','a/./file.cs'),('space','name.cs ')]:
        case('inventory-'+label,lambda r,v=value:write(r,'PRIVATE-FILES.txt',v+'\n'),reason='candidate path')
    def change_json(root,action):
        p=root/'PUBLIC-SOURCE-PROVENANCE.json';data=json.loads(p.read_text());action(data);p.write_text(json.dumps(data))
    case('uncertain-classification',post=lambda r:change_json(r,lambda d:d['files'][0].update(classification='Unknown')),reason='Uncertain/private')
    case('uncertain-origin',post=lambda r:change_json(r,lambda d:d['files'][0].update(origin='trust-me')),reason='Unrecognized or uncertain')
    case('hash-mismatch',post=lambda r:change_json(r,lambda d:d['files'][0].update(sha256='0'*64)),reason='immutable base bytes')
    case('manifest-mixedslash',post=lambda r:change_json(r,lambda d:d['files'][0].update(path=d['files'][0]['path'].replace('/','\\'))),reason='Noncanonical')
    case('manifest-parent',post=lambda r:change_json(r,lambda d:d['files'][0].update(path='../escape')),reason='candidate path')
    case('manifest-duplicate',post=lambda r:change_json(r,lambda d:d['files'].append(d['files'][0].copy())),reason='Duplicate normalized provenance')
    case('omitted-payload',lambda r:write(r,'payload.dll','synthetic'),post=lambda r:change_json(r,lambda d:d.update(files=[x for x in d['files'] if x['path']!='payload.dll'])),reason='exactly actual candidate')
    case('public-binary-scope',scope='PublicBinary',reason='Public binary publication remains held')
    case('invalid-scope',scope='PrivateOverride',reason='ValidateSet')
    case('missing-scope',scope=None,reason='mandatory parameters')
    case('missing-inventory',lambda r:(r/'PRIVATE-FILES.txt').unlink(),reason='Tracked-deleted or non-file')
    case('missing-policy',lambda r:(r/'PUBLICATION-HOLD.txt').unlink(),reason='Tracked-deleted or non-file')
    # These changes happen after stage/provenance preparation, so the guard must inspect actual bytes.
    for name,action,reason in [
        ('staged-versus-working',lambda r:write(r,'sample.cs','changed after stage'),'staged/working byte mismatch'),
        ('tracked-deleted',lambda r:(r/'sample.cs').unlink(),'Tracked-deleted'),
        ('untracked-file',lambda r:write(r,'untracked.cs','synthetic'),'exactly actual candidate'),
        ('ignored-binary',lambda r:(write(r,'.gitignore','ignored.dll\n'),write(r,'ignored.dll','synthetic')),'exactly actual candidate'),
        ('working-private-after-stage',lambda r:write(r,'sample.cs','// Proprietary and Confidential\n'),'staged/working byte mismatch'),
    ]:
        root=out/name;shutil.copytree(baseline,root);manifest(root);git(root,'add','-A');action(root);before=snapshot(root)
        cmd=['pwsh','-NoProfile','-NonInteractive','-File',str(source/'scripts/check-public-license.ps1'),'-RepositoryRoot',str(root),'-PublicationScope','CommunitySource'];p=command(cmd)
        passed=p.returncode!=0 and reason in p.stdout+p.stderr and before==snapshot(root)
        receipts.append(dict(case=name,command=cmd,expectedExit=1,actualExit=p.returncode,expectedMessage=reason,stdout=p.stdout,stderr=p.stderr,unchanged=before==snapshot(root),files=before,pass_=passed));print(name,'PASS' if passed else 'FAIL',flush=True)
    # Use an actual Windows directory junction to an external synthetic directory; no admin privileges needed.
    root=out/'junction-escape';shutil.copytree(baseline,root);manifest(root);git(root,'add','-A');external=out/'synthetic-external';external.mkdir();write(external,'payload.cs','synthetic')
    link=root/'linked';junction=command(['cmd','/c','mklink','/J',str(link),str(external)])
    if junction.returncode==0:
        before=snapshot(root);cmd=['pwsh','-NoProfile','-NonInteractive','-File',str(source/'scripts/check-public-license.ps1'),'-RepositoryRoot',str(root),'-PublicationScope','CommunitySource'];p=command(cmd)
        passed=p.returncode!=0 and before==snapshot(root)
        receipts.append(dict(case='junction-escape',command=cmd,expectedExit=1,actualExit=p.returncode,stdout=p.stdout,stderr=p.stderr,unchanged=before==snapshot(root),pass_=passed));print('junction-escape','PASS' if passed else 'FAIL',flush=True)
    else: receipts.append(dict(case='junction-escape',pass_=False,unsupported=junction.stderr));print('junction-escape UNSUPPORTED',flush=True)
    root_link=out/'candidate-root-link';p=command(['cmd','/c','mklink','/J',str(root_link),str(baseline)])
    if p.returncode==0:
        cmd=['pwsh','-NoProfile','-NonInteractive','-File',str(source/'scripts/check-public-license.ps1'),'-RepositoryRoot',str(root_link),'-PublicationScope','CommunitySource'];p=command(cmd)
        receipts.append(dict(case='candidate-root-junction',command=cmd,expectedExit=1,actualExit=p.returncode,stdout=p.stdout,stderr=p.stderr,pass_=p.returncode!=0 and 'Reparse candidate root rejected' in p.stdout+p.stderr))
    else: receipts.append(dict(case='candidate-root-junction',pass_=False,unsupported=p.stderr))
    # Invoke every real package alias: each must refuse before creating a payload.
    for alias in ('package-teqtanium.ps1','package-teqnatium.ps1','package-tectanium.ps1'):
        before=snapshot(source);cmd=['pwsh','-NoProfile','-NonInteractive','-File',str(source/'scripts'/alias),'-Version','99.99.99-alpha.99','-Runtime','portable'];p=command(cmd)
        receipts.append(dict(case=alias,command=cmd,expectedExit=1,actualExit=p.returncode,stdout=p.stdout,stderr=p.stderr,unchanged=before==snapshot(source),pass_=p.returncode!=0 and 'Public binary publication remains held' in p.stdout+p.stderr and before==snapshot(source)))
    # PATH is isolated for one child process; no machine environment is changed.
    exe=shutil.which('pwsh');cmd=[exe,'-NoProfile','-NonInteractive','-File',str(source/'scripts/check-public-license.ps1'),'-RepositoryRoot',str(baseline),'-PublicationScope','CommunitySource'];env=os.environ.copy();env['PATH']=str(out/'missing-runtime');before=snapshot(baseline);p=subprocess.run(cmd,capture_output=True,text=True,env=env)
    receipts.append(dict(case='missing-python-fails-closed',command=cmd,expectedExit=1,actualExit=p.returncode,stdout=p.stdout,stderr=p.stderr,unchanged=before==snapshot(baseline),pass_=p.returncode!=0 and 'requires Python 3.12' in p.stdout+p.stderr and before==snapshot(baseline)))
    fake=out/'unsupported-runtime';fake.mkdir();write(fake,'python.cmd','@exit /b 2\r\n');write(fake,'python3.cmd','@exit /b 2\r\n');env['PATH']=str(fake);p=subprocess.run(cmd,capture_output=True,text=True,env=env)
    receipts.append(dict(case='unsupported-python-fails-closed',command=cmd,expectedExit=1,actualExit=p.returncode,stdout=p.stdout,stderr=p.stderr,pass_=p.returncode!=0 and 'requires Python 3.12' in p.stdout+p.stderr))
    receipts.extend(f.result() for f in pending);executor.shutdown()
    assert all(hashlib.sha256((source/n).read_bytes()).hexdigest()==h for n,h in frozen_tools.items()),'Guard/helper/test source changed during execution; discard run as preliminary'
    result=dict(atUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(),toolHashesBeforeAndAfter=frozen_tools,guardSha256=hashlib.sha256((source/'scripts/check_public_source.py').read_bytes()).hexdigest(),wrapperSha256=hashlib.sha256((source/'scripts/check-public-license.ps1').read_bytes()).hexdigest(),results=receipts,passed=sum(r['pass_'] for r in receipts),total=len(receipts))
    (out/'RESULTS.json').write_text(json.dumps(result,indent=2)+'\n');raise SystemExit(0 if all(r['pass_'] for r in receipts) else 1)
def ci_checkout_regression(output):
    """Use real local file-transport clones, actual ancestor fetch and the frozen entrypoint."""
    source=Path(__file__).resolve().parents[1];out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    commit=git(source,'rev-parse','HEAD');branch=git(source,'branch','--show-current')
    if not branch or git(source,'status','--porcelain'): raise RuntimeError('Regression requires a clean committed source branch')
    tool_names=('scripts/check-public-license.ps1','scripts/check_public_source.py','scripts/test-public-source-guard.py')
    tool_hashes={n:hashlib.sha256((source/n).read_bytes()).hexdigest() for n in tool_names}
    canonical_tool_hashes={n:hashlib.sha256(subprocess.check_output(['git','-C',str(source),'show','HEAD:'+n])).hexdigest() for n in tool_names}
    records=[]
    def record(name,args,expected=0,cwd=None):
        p=command(args,cwd);records.append(dict(case=name,command=args,exit=p.returncode,expectedExit='nonzero' if expected else 0,stdout=p.stdout,stderr=p.stderr));return p
    clone=out/'actual-shallow-clone'
    p=record('real-depth-one-clone',['git','-c','core.autocrlf=false','-c','core.eol=lf','clone','--no-local','--depth','1','--branch',branch,source.as_uri(),str(clone)])
    assert p.returncode==0,p.stderr
    assert git(clone,'rev-parse','HEAD')==commit and git(clone,'rev-parse','--is-shallow-repository')=='true'
    registry=json.loads((clone/'PUBLIC-SOURCE-PROVENANCE.json').read_text());base=registry['baseCommit']
    absent=record('immutable-base-absent-before-fetch',['git','-C',str(clone),'cat-file','-e',base+'^{commit}'],expected=1)
    assert absent.returncode!=0,'Clone unexpectedly contains immutable base'
    before=snapshot(clone)
    cloned_tool_hashes={n:hashlib.sha256((clone/n).read_bytes()).hexdigest() for n in tool_names}
    guard=['pwsh','-NoProfile','-NonInteractive','-File',str(clone/'scripts/check-public-license.ps1'),'-RepositoryRoot',str(clone),'-PublicationScope','CommunitySource']
    rejected=record('actual-entrypoint-shallow-refusal',guard,expected=1)
    assert rejected.returncode!=0 and 'Missing provenance blob' in rejected.stdout+rejected.stderr
    assert snapshot(clone)==before,'Guard changed shallow candidate files'
    # This fetch supplies the same complete history required by checkout fetch-depth:0.
    fetched=record('fetch-full-history',['git','-C',str(clone),'fetch','--unshallow','--no-tags','origin'])
    assert fetched.returncode==0 and git(clone,'rev-parse','--is-shallow-repository')=='false'
    assert git(clone,'rev-parse','HEAD')==commit and snapshot(clone)==before
    present=record('immutable-base-present-after-fetch',['git','-C',str(clone),'cat-file','-e',base+'^{commit}']);assert present.returncode==0
    accepted=record('actual-entrypoint-after-history-fetch',guard)
    assert accepted.returncode==0 and '535 exact staged files' in accepted.stdout
    assert snapshot(clone)==before and git(clone,'rev-parse','HEAD')==commit
    for n,h in cloned_tool_hashes.items():assert hashlib.sha256((clone/n).read_bytes()).hexdigest()==h
    for n,h in canonical_tool_hashes.items():assert hashlib.sha256(subprocess.check_output(['git','-C',str(clone),'show','HEAD:'+n])).hexdigest()==h
    for n,h in tool_hashes.items():assert hashlib.sha256((source/n).read_bytes()).hexdigest()==h
    workflow=(clone/'.github/workflows/license-guard.yml').read_text()
    assert 'fetch-depth: 0' in workflow and 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262' in workflow
    result=dict(atUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(),candidateCommit=commit,immutableBase=base,realFileTransport=True,workflowFetchDepth=0,workflowAssertion='PASS',headAndWorkingFilesUnchanged=True,sourceRawToolHashes=tool_hashes,canonicalToolHashes=canonical_tool_hashes,cloneRawToolHashesBeforeAndAfter=cloned_tool_hashes,results=records,passed=len(records),total=len(records))
    (out/'RESULTS.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));return 0
if __name__=='__main__': main()
