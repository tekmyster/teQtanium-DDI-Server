#!/usr/bin/env python3
# Modified by Tekmyster Industries, LLC — remains GPL-3.0
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline private publish and complete deterministic delivery package."""
import argparse, hashlib, importlib.util, json, os
from pathlib import Path
import shutil, subprocess

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);p.add_argument('--runtime',choices=['portable-net10.0','linux-x64','win-x64'],required=True);p.add_argument('--version',required=True);a=p.parse_args()
    root=Path(__file__).resolve().parent.parent;output=a.output.resolve();packages=a.packages.resolve()
    if output.exists():raise ValueError('Immutable output must be new')
    def git(*args):return subprocess.check_output(['git',*args],cwd=root)
    if git('diff','HEAD','--name-only').strip() or git('ls-files','--others','--exclude-standard').strip():raise ValueError('Commit exact source inputs first')
    output.mkdir(parents=True);payload=output/'payload';sha=lambda b:hashlib.sha256(b).hexdigest()
    def write(name,value):(output/name).write_bytes((json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
    names=git('ls-tree','-r','--name-only','HEAD').decode().splitlines()
    raw=[{'path':n,'sha256':sha((root/n).read_bytes()),'length':(root/n).stat().st_size} for n in names]
    # Use batch cat-file to retain exact canonical Git blobs independent of newline conversion.
    objects=[]
    for line in git('ls-tree','-rz','HEAD').split(b'\0'):
        if line:
            meta,name=line.split(b'\t');objects.append((name.decode(),meta.split()[2].decode()))
    import io
    stream=io.BytesIO(subprocess.check_output(['git','cat-file','--batch'],input=('\n'.join(o for _,o in objects)+'\n').encode(),cwd=root));canonical=[]
    for name,obj in objects:
        fields=stream.readline().split();size=int(fields[2]);b=stream.read(size);assert stream.read(1)==b'\n';canonical.append({'path':name,'sha256':sha(b),'length':size})
    write('SOURCE-RAW-MANIFEST.json',raw);write('SOURCE-CANONICAL-MANIFEST.json',canonical)
    deps=root.parent/'TechnitiumLibrary/bin'
    write('DEPENDENCY-MANIFEST.json',[{'path':f.relative_to(deps).as_posix(),'sha256':sha(f.read_bytes()),'length':f.stat().st_size} for f in sorted(deps.rglob('*')) if f.is_file()])
    write('NUGET-MANIFEST.json',[{'path':f.relative_to(packages).as_posix(),'sha256':sha(f.read_bytes()),'length':f.stat().st_size} for f in sorted(packages.rglob('*.nupkg'))])
    commands=[]
    def run(args,label):
        commands.append(args)
        with (output/(label+'.log')).open('wb') as log:subprocess.run(args,cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
    base=['dotnet','restore','DnsServerApp/DnsServerApp.csproj','--source',str(packages),'--packages',str(output/'nuget-cache'),'--nologo']
    publish=['dotnet','publish','DnsServerApp/DnsServerApp.csproj','-c','Release','--no-restore','--nologo','-o',str(payload)]
    if a.runtime=='portable-net10.0':publish+=['--no-self-contained','-p:UseAppHost=false']
    else:
        base+=['-r',a.runtime,'-p:RuntimeFrameworkVersion=10.0.13'];publish+=['-r',a.runtime,'--self-contained','true','-p:RuntimeFrameworkVersion=10.0.13']
    run(['dotnet','--info'],'dotnet-info');run(base,'restore');run(publish,'publish')
    graphs={}
    for project in ['DnsServerCore','DnsServerCore.ApplicationCommon','DnsServerCore.HttpApi','DnsServerApp']:
        value=json.loads((root/project/'obj/project.assets.json').read_bytes());graphs[project]={k:value.get(k) for k in ['targets','libraries','projectFileDependencyGroups','packageFolders','project']}
    write('PACKAGE-GRAPHS.json',graphs)
    for name in ['start.sh','start.bat','openrc.service','systemd.service']:
        f=payload/name
        if f.exists():f.unlink()
    for name in ['LICENSE','THIRD-PARTY-NOTICES.md']:shutil.copyfile(root/name,payload/name)
    (payload/'tools').mkdir();(payload/'docs').mkdir()
    for name in ['private-delivery.py','private-delivery-signature.ps1']:shutil.copyfile(root/'scripts'/name,payload/'tools'/name)
    shutil.copyfile(root/'docs/PRIVATE-DELIVERY.md',payload/'docs/PRIVATE-DELIVERY.md')
    provenance={'sourceCommit':git('rev-parse','HEAD').decode().strip(),'sourceParent':git('rev-parse','HEAD^').decode().strip(),'runtime':a.runtime,'runtimeFrameworkVersion':'10.0.13','productionOverlayGate':'INCOMPLETE: required manual c1ab5aa345ec4d7f / security f45fdea720309cb4 integration inputs absent'}
    for key,name in [('rawSourceManifestSha256','SOURCE-RAW-MANIFEST.json'),('canonicalSourceManifestSha256','SOURCE-CANONICAL-MANIFEST.json'),('dependencyManifestSha256','DEPENDENCY-MANIFEST.json'),('packageGraphSha256','PACKAGE-GRAPHS.json'),('nugetManifestSha256','NUGET-MANIFEST.json')]:provenance[key]=sha((output/name).read_bytes())
    write('PROVENANCE.json',provenance)
    spec=importlib.util.spec_from_file_location('delivery',root/'scripts/private-delivery.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    result=module.create(payload,output/'release.zip',a.version,output/'PROVENANCE.json',a.runtime)
    write('BUILD.json',{'commands':commands,'result':result,'gitCanonicalDiffClean':True,'gitRawStatus':git('status','--porcelain=v2').decode(),'indexSha256':sha((root/'.git/index').read_bytes()),'scope':'unsigned private build; not release/production acceptance'})
    print(json.dumps(result))
if __name__=='__main__':main()
