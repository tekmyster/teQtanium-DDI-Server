# SPDX-License-Identifier: GPL-3.0-only
"""Validate an isolated exact staged community-source candidate; never publishes."""
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path

PROVENANCE='PUBLIC-SOURCE-PROVENANCE.json'
EXCEPTIONS={'tectanium.windowsservice/program.cs','tectanium.windowsservice/tectanium.windowsservice.csproj'}
PRIVATE=re.compile(r'^(apps/(?:tectanium|teqtanium)\.[^/]+(?:/|$)|(?:tectanium|teqtanium)\.[^/]+/|dnsservercore/(?:.*/)?tectanium/|docs/(?:tectanium|enterprise)/|packaging/tectanium/)',re.I)
SENSITIVE=re.compile(r'(^|/)(?:artifacts?|evidence|captures?|secrets?|credentials?|inventory|worker-management|node_modules|bin|obj)(/|$)|dhcp[-_. ]?q|(^|/)(?:\.env(?:\..*)?|initial-admin-password\.txt|known_hosts|id_rsa|id_ed25519)$',re.I)
COMPILED={'.dll','.exe','.pdb','.so','.dylib','.a','.lib','.o','.obj','.class','.jar','.nupkg','.msi','.msix','.deb','.rpm','.zip','.7z','.gz','.tgz','.tar','.rar','.pcap','.pcapng','.cap','.pfx','.p12','.key','.pem','.vhd','.vhdx','.qcow2','.iso'}
ASSETS={'.png':b'\x89PNG\r\n\x1a\n','.jpg':b'\xff\xd8\xff','.jpeg':b'\xff\xd8\xff','.ico':b'\x00\x00\x01\x00','.gif':b'GIF8','.bmp':b'BM'}
FONTS={'DnsServerCore/www/fonts/FontAwesome.otf'}|{'DnsServerCore/www/fonts/'+name+'.'+ext for name in ('fontawesome-webfont','glyphicons-halflings-regular') for ext in ('eot','ttf','woff','woff2')}
FONT_SIGNATURES={'.otf':b'OTTO','.ttf':b'\x00\x01\x00\x00','.woff':b'wOFF','.woff2':b'wOF2'}
HISTORICAL_JPEG_PNG={'docs/screenshots/'+n+'.png' for n in ('about','ipam','security','syslog','tectanium-dashboard')}
def fail(message): raise ValueError(message)
def relative(value):
    if not isinstance(value,str) or not value or value!=value.strip() or '\x00' in value: fail('Invalid candidate path')
    value=value.replace('\\','/')
    if value.startswith('/') or ':' in value or any(p in ('','.','..') or p.endswith((' ','.')) for p in value.split('/')): fail('Absolute, parent or ambiguous candidate path rejected')
    return value
def unique_object(pairs):
    result={}
    for k,v in pairs:
        if k in result: fail('Duplicate JSON key')
        result[k]=v
    return result
def run(root,*args):
    p=subprocess.run(['git','-C',str(root),*args],capture_output=True)
    if p.returncode: fail('Cannot inspect candidate Git index')
    return p.stdout
def batch_blobs(root,objects):
    if not objects: return {}
    p=subprocess.run(['git','-C',str(root),'cat-file','--batch'],input=('\n'.join(objects)+'\n').encode(),capture_output=True)
    if p.returncode: fail('Cannot inspect candidate object bytes')
    data=p.stdout;offset=0;result={}
    for key in objects:
        end=data.index(b'\n',offset);header=data[offset:end].split();offset=end+1
        if len(header)!=3 or header[1]!=b'blob': fail('Missing provenance blob')
        length=int(header[2]);result[key]=data[offset:offset+length];offset+=length+1
    return result
def checked_path(root,name):
    path=root
    for part in name.split('/'):
        path=path/part
        if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()): fail('Symlink/reparse candidate path rejected')
        if path.exists() and getattr(path.stat(follow_symlinks=False),'st_file_attributes',0)&0x400: fail('Reparse candidate path rejected')
    if not path.is_file(): fail('Tracked-deleted or non-file candidate path rejected')
    if not path.resolve().is_relative_to(root): fail('Candidate path escapes root')
    return path
def check(root,scope):
    if scope not in ('CommunitySource','PublicBinary'): fail('Missing or unrecognized publication scope')
    raw=Path(root).absolute()
    for path in (raw,*raw.parents):
        if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()): fail('Reparse candidate root rejected')
    root=raw.resolve(strict=True)
    if run(root,'rev-parse','--show-toplevel').decode().strip().replace('\\','/').casefold()!=root.as_posix().casefold(): fail('Candidate root must be the isolated Git worktree root')
    policy=checked_path(root,'PUBLICATION-HOLD.txt').read_text(encoding='utf-8-sig').splitlines()
    if policy.count('Publication-Policy: 2')!=1 or policy.count('Community-Source: Authorized')!=1 or policy.count('Public-Binaries: Hold')!=1: fail('Missing or invalid publication policy')
    if scope=='PublicBinary': fail('Public binary publication remains held')
    # Include ignored files copied into the candidate; the private development tree is not a publication candidate.
    names=[relative(n) for n in run(root,'ls-files','--cached','--others','-z').decode('utf-8').split('\0') if n]
    if len({n.casefold() for n in names})!=len(names): fail('Duplicate/case-colliding candidate paths')
    indexed={}
    for row in run(root,'ls-files','--stage','-z').split(b'\0'):
        if not row: continue
        meta,name=row.split(b'\t',1);mode,oid,stage=meta.split()
        if stage!=b'0' or mode not in (b'100644',b'100755'): fail('Unmerged, symlink or submodule index entry rejected')
        indexed[relative(name.decode('utf-8'))]=oid.decode()
    objects=batch_blobs(root,list(dict.fromkeys(indexed.values())))
    blobs={name:objects[oid] for name,oid in indexed.items()}
    manifest=json.loads(checked_path(root,PROVENANCE).read_text(encoding='utf-8-sig'),object_pairs_hook=unique_object)
    if set(manifest)!={'schemaVersion','baseCommit','files'} or manifest['schemaVersion']!=1 or not re.fullmatch('[0-9a-f]{40}',manifest['baseCommit']): fail('Invalid provenance schema/base')
    inherited_objects=[manifest['baseCommit']+':'+relative(e.get('path','')) for e in manifest['files'] if e.get('origin','').startswith('accepted-base:')]
    inherited_blobs=batch_blobs(root,inherited_objects)
    entries={}
    for entry in manifest['files']:
        if set(entry)!={'path','sha256','classification','origin'}: fail('Invalid provenance entry')
        name=relative(entry['path'])
        if name.casefold() in entries: fail('Duplicate normalized provenance entry')
        if entry['classification'] not in ('GPL-covered','ThirdParty-MPL-2.0','PublicBrandingAsset','InheritedFontAsset'): fail('Uncertain/private provenance rejected')
        if not re.fullmatch('[0-9a-f]{64}',entry['sha256']) or not isinstance(entry['origin'],str): fail('Missing exact provenance/hash')
        origin=entry['origin']
        inherited='accepted-base:'+manifest['baseCommit']+':'+name
        if origin==inherited:
            original=inherited_blobs[manifest['baseCommit']+':'+name]
            if hashlib.sha256(original).hexdigest()!=entry['sha256']: fail('Inherited provenance does not match immutable base bytes')
        elif origin=='reviewed-documentation-consistency':
            # Bounded review domain only; this cannot relabel application/runtime implementations.
            allowed=(name.endswith('.md') or name in ('PUBLICATION-HOLD.txt','scripts/check-public-license.ps1','scripts/check_public_source.py','scripts/test-public-source-guard.py','scripts/package-tectanium.ps1','scripts/package-teqnatium.ps1','scripts/package-teqtanium.ps1','.github/workflows/license-guard.yml','.github/workflows/alpha-packages.yml'))
            if not allowed or entry['classification']!='GPL-covered': fail('Reviewed documentation provenance cannot authorize this file')
        else: fail('Unrecognized or uncertain provenance origin')
        if entry['classification']=='InheritedFontAsset' and (name not in FONTS or origin!=inherited): fail('Only exact inherited font assets are permitted')
        entries[name.casefold()]=entry
    if set(entries)!={n.casefold() for n in names if n!=PROVENANCE}: fail('Provenance must cover exactly actual candidate files')
    inventory=[]
    for row in checked_path(root,'PRIVATE-FILES.txt').read_text(encoding='utf-8-sig').splitlines():
        if not row.strip() or row.lstrip().startswith('#'): continue
        name=relative(row)
        if name.casefold() in inventory: fail('Duplicate normalized private inventory entry')
        inventory.append(name.casefold())
    if set(inventory)&{n.casefold() for n in names}: fail('Inventoried private file present in candidate')
    for name in names:
        path=checked_path(root,name);data=path.read_bytes();lower=name.casefold()
        if name not in blobs or (data!=blobs[name] and data.replace(b'\r\n',b'\n')!=blobs[name]): fail('Untracked or staged/working byte mismatch: '+name)
        if PRIVATE.match(name) and lower not in EXCEPTIONS: fail('Reserved private path: '+name)
        if SENSITIVE.search(name): fail('Operational/private candidate path: '+name)
        ext=path.suffix.lower()
        if ext in COMPILED: fail('Binary/archive/secret candidate rejected: '+name)
        if data.startswith((b'MZ',b'\x7fELF',b'PK\x03\x04',b'PK\x05\x06',b'\x1f\x8b',b'7z\xbc\xaf\x27\x1c',b'Rar!',b'\xfe\xed\xfa\xce',b'\xcf\xfa\xed\xfe')) or data[257:262]==b'ustar': fail('Disguised executable/archive candidate rejected: '+name)
        if name!=PROVENANCE:
            entry=entries[lower]
            if hashlib.sha256(blobs[name]).hexdigest()!=entry['sha256']: fail('Provenance hash differs from actual staged bytes: '+name)
            if entry['path']!=name: fail('Noncanonical provenance spelling: '+name)
            if ext in ASSETS:
                signature_ok=data.startswith(ASSETS[ext])
                historical=(name in HISTORICAL_JPEG_PNG and ext=='.png' and data.startswith(b'\xff\xd8\xff') and entry['origin']=='accepted-base:'+manifest['baseCommit']+':'+name)
                if entry['classification']!='PublicBrandingAsset' or not (signature_ok or historical) or data!=blobs[name]: fail('Unclassified/malformed branding asset: '+name)
            elif entry['classification']=='PublicBrandingAsset': fail('Branding classification cannot authorize arbitrary binary')
            if entry['classification']=='InheritedFontAsset':
                signature_ok=data[34:36]==b'LP' if ext=='.eot' else data.startswith(FONT_SIGNATURES.get(ext,b'never-a-font'))
                if not signature_ok or data!=blobs[name]: fail('Invalid inherited font asset bytes')
        font_asset=name!=PROVENANCE and entries[lower]['classification']=='InheritedFontAsset'
        if ext not in ASSETS and not font_asset:
            try: content=data.decode('utf-8-sig')
            except UnicodeDecodeError: fail('Opaque candidate bytes rejected: '+name)
            if '\x00' in content: fail('Opaque candidate bytes rejected: '+name)
            notice_content=content.replace('\r\n','\n')
            if name=='docs/LICENSE-BOUNDARIES.md':
                # Only the exact required notice quoted as a fenced example is documentation.
                notice_content=notice_content.replace('```text\n// Copyright (c) 2026 Tekmyster Industries, LLC. All Rights Reserved.\n// teQtanium Private Commercial — Free for Homelabs & Non-Profits under LICENSE.md Domain B\n// Enterprise use 250+ IPs / 5k qps requires commercial license.\n// Contact: licensing@tekmyster.com | Non-profits: nonprofits@tekmyster.com | https://tekmyster.com\n```','')
            if re.search(r'(?im)^\s*(?://|#|/\*|\*|<!--)?\s*(?:Copyright[^\r\n]*Tekmyster[^\r\n]*All Rights Reserved|Proprietary and Confidential)',notice_content): fail('Private notice in candidate: '+name)
            key_content=content.replace('\r\n','\n')
            key_start='-----BEGIN '+'PRIVATE KEY-----'
            if name=='DnsServerCore/www/index.html' and entries[lower]['origin']=='accepted-base:'+manifest['baseCommit']+':'+name:
                # Only the unchanged inherited textarea's exact format illustration is allowed.
                for control in ('txtDnssecSignZonePemKskPrivateKey','txtDnssecSignZonePemZskPrivateKey','txtDnssecPropertiesPemPrivateKey'):
                    key_content=key_content.replace('<textarea id="'+control+'" class="form-control" rows="4" spellcheck="false" placeholder="'+key_start+'\nMII...\n-----END PRIVATE KEY-----"></textarea>','')
            if re.search(r'-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----',key_content): fail('Private key material rejected: '+name)
    return len(names)
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',required=True);parser.add_argument('--scope',required=True);args=parser.parse_args()
    try:
        count=check(args.root,args.scope)
        print(f'Community source guard passed: {count} exact staged files (canonical Git text; actual candidate content checked); no publication performed.')
    except (ValueError,OSError,UnicodeError,KeyError,TypeError) as error:
        print('Publication guard rejected: '+str(error),file=sys.stderr);sys.exit(1)
