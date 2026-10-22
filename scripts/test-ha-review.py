# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Tekmyster Industries, LLC.
"""New owned synthetic evidence and OS-process qualification, never production."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import platform

spec = importlib.util.spec_from_file_location('ha_review', Path(__file__).with_name('ha-review.py'))
ha = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ha)


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(exist_ok=False, parents=True)
    commands, checks = [], []

    def run(args, expected=0):
        started = time.time_ns()
        p = subprocess.Popen(list(map(str, args)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = p.communicate(timeout=30)
        commands.append(dict(command=list(map(str, args)), pid=p.pid, startedUnixNs=started, exitCode=p.returncode, stdout=stdout, stderr=stderr))
        assert p.returncode == expected, commands[-1]
        return subprocess.CompletedProcess(args, p.returncode, stdout, stderr)

    def save(path, value):
        path.write_bytes(ha.canonical(value))
        return path

    try:
        native = Path(sys.argv[2]).resolve()
        fixture = root / 'native'
        for phase in ('seed', 'unused', 'handoff', 'import', 'restart', 'return', 'reclaim', 'returned-restart'):
            p = run(['dotnet', native, phase, fixture])
            result = json.loads(p.stdout)
            checks.extend(result['checks'])
        holder = subprocess.Popen(['dotnet', str(native), 'hold', str(fixture)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert holder.stdout.readline().strip() == 'owned-native-writer-held'
            blocked = subprocess.run(['dotnet', str(native), 'restart', str(fixture)], capture_output=True, text=True, timeout=30)
            commands.append(dict(command=['dotnet', str(native), 'restart', str(fixture)], exitCode=blocked.returncode, stdout=blocked.stdout, stderr=blocked.stderr))
            assert blocked.returncode != 0 and 'IOException' in blocked.stderr
            checks.append('separate OS process cannot open authoritative store while original writer is retained')
        finally:
            out, err = holder.communicate('\n', timeout=30)
            commands.append(dict(command=['dotnet', str(native), 'hold', str(fixture)], pid=holder.pid, exitCode=holder.returncode, stdout=out, stderr=err))
            assert holder.returncode == 0
        # Review contract consumes actual accepted-core fixture snapshot bytes.
        state = ha.load(fixture / 'handoff-export.json')
        original = next(r for r in state['replicas'] if r['node'] == 'a')
        plan = state['plans'][0]
        old = ha.load(fixture / 'live.json')
        protections = [{k: old[k] for k in ('address', 'client', 'hardware', 'host', 'state', 'expires')}]
        grants = [e for e in original['entries'] if e['state'] == 'Grant' and e.get('protection') is None]
        tx = dict(schema=1, purpose='offline-ha-review', id='55555555555555555555555555555555',
                  scope=plan['scope'], epoch=plan['epoch'], donor='a', receivers=['b', 'c'], members=['a', 'b', 'c'],
                  planHash=ha.digest(plan), coreHash='67b59635c62c2b4e7d6b3867f3be07b582014cb8d8e45f7592aa863d4b103d6b',
                  configurationHash=ha.digest(state.get('configurations')), minimumSequence=original['sequence'],
                  leaseProtectionHash=ha.digest(protections), permanentGrantHash=ha.digest(grants), permanentGrants=grants,
                  vm=dict(id='synthetic-vm', instanceUuid='synthetic-uuid', nics=[dict(key=1, mac='02:00:00:00:00:01')]))
        authority = dict(sequence=original['sequence'], hash=ha.digest(original))
        common = dict(transactionHash=ha.digest(tx), observedAt=int(time.time()), vm=tx['vm'],
                      fence=dict(task='success', nics=[dict(tx['vm']['nics'][0], connected=False, startConnected=False, allowGuestControl=False)]),
                      originalAuthority=copy.deepcopy(authority), originalState=copy.deepcopy(state),
                      authority=[dict(member=n, available=True, authority=copy.deepcopy(authority), state=copy.deepcopy(state), epoch=tx['epoch'], planHash=tx['planHash'], configurationHash=tx['configurationHash']) for n in tx['members']],
                      leaseProtectionHash=tx['leaseProtectionHash'], permanentGrantHash=tx['permanentGrantHash'],
                      originalSurrender=dict(authority, durable=True, originalStore=True),
                      receivers=[dict(member=n, durable=True, authority=copy.deepcopy(authority), state=copy.deepcopy(state)) for n in tx['receivers']],
                      restartedOriginal=dict(authority, durable=True, originalStore=True), restartedState=copy.deepcopy(state))
        txpath = save(root / 'transaction.json', tx)
        journal = root / 'journal'; journal.mkdir()
        evidence = dict(common, stage='FencedReview')
        ep = save(root / 'FencedReview.json', evidence)
        baseargs = [sys.executable, Path(__file__).with_name('ha-review.py'), journal, txpath, ep, 'FencedReview']
        with ha.LocalLock(journal):
            run(baseargs, 2)
        checks.append('separate OS controller refuses held local writer lock')
        # Two simultaneous OS controllers retry the same exact identity. Either
        # busy refusal or idempotent success is valid; only one immutable receipt.
        processes = [subprocess.Popen(list(map(str, baseargs)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        codes = []
        for p in processes:
            out, err = p.communicate(timeout=30)
            commands.append(dict(command=list(map(str, baseargs)), pid=p.pid, exitCode=p.returncode, stdout=out, stderr=err))
            assert p.returncode in (0, 2)
            codes.append(p.returncode)
        assert 0 in codes and len(list(journal.glob('receipt-*.json'))) == 1
        run(baseargs)
        checks.append('simultaneous controllers produce one receipt; fresh process retry is idempotent')
        for stage in ('TakeoverReview', 'RejoinReview'):
            ev = dict(common, stage=stage)
            path = save(root / (stage + '.json'), ev)
            run([sys.executable, Path(__file__).with_name('ha-review.py'), journal, txpath, path, stage])
        checks.append('ordered review stages persist across fresh OS processes while automation remains Disabled')
        negatives = {}
        def bad(name, mutate):
            ev = copy.deepcopy(dict(common, stage='RejoinReview'))
            mutate(ev)
            path = save(root / (name + '.json'), ev)
            before = {p.name: p.read_bytes() for p in journal.glob('receipt-*.json')}
            result = run([sys.executable, Path(__file__).with_name('ha-review.py'), journal, txpath, path, 'RejoinReview'], 2)
            assert {p.name: p.read_bytes() for p in journal.glob('receipt-*.json')} == before
            reply = json.loads(result.stderr)
            assert reply['automation'] == 'Disabled' and reply['retainFence'] is True
            negatives[name] = reply['error']
        bad('missing-member', lambda e: e['authority'].pop())
        bad('partition', lambda e: e['authority'][0].update(available=False))
        bad('stale', lambda e: e.update(observedAt=e['observedAt'] - 61))
        bad('future', lambda e: e.update(observedAt=e['observedAt'] + 10))
        bad('conflicting-authority', lambda e: e['authority'][0]['authority'].update(hash='f' * 64))
        bad('fence-task-failed', lambda e: e['fence'].update(task='error'))
        bad('connected-nic', lambda e: e['fence']['nics'][0].update(connected=True))
        bad('guest-control', lambda e: e['fence']['nics'][0].update(allowGuestControl=True))
        bad('adapter-identity', lambda e: e['vm']['nics'][0].update(mac='02:ff:ff:ff:ff:ff'))
        bad('uncommitted-surrender', lambda e: e['originalSurrender'].update(durable=False))
        bad('missing-receiver', lambda e: e['receivers'].pop())
        bad('restart-mismatch', lambda e: e['restartedOriginal'].update(hash='e' * 64))
        bad('lease-erasure-in-bytes', lambda e: e['originalState']['replicas'][0].update(entries=[]))
        bad('receiver-bytes-differ', lambda e: e['receivers'][0]['state']['replicas'][0].update(sequence=99999))
        bad('wrong-epoch', lambda e: e['originalState']['plans'][0].update(epoch='foreign'))
        bad('claimed-hash-without-bytes', lambda e: e['originalAuthority'].update(hash='0' * 64))
        bad('older-original', lambda e: e['originalAuthority'].update(sequence=0))
        bad('missing-fence', lambda e: e.pop('fence'))
        bad('duplicate-member', lambda e: e['authority'].__setitem__(1, copy.deepcopy(e['authority'][0])))
        bad('numeric-fence-flag', lambda e: e['fence']['nics'][0].update(connected=0))
        bad('unknown-protection-state', lambda e: e['originalState']['replicas'][0]['entries'][0].update(state='UnknownQuarantine'))
        # Alternate identity cannot create another operation in this journal.
        alternate = dict(tx, id='66666666666666666666666666666666')
        ap = save(root / 'alternate-transaction.json', alternate)
        alt = dict(common, stage='FencedReview', transactionHash=ha.digest(alternate))
        aep = save(root / 'alternate-evidence.json', alt)
        run([sys.executable, Path(__file__).with_name('ha-review.py'), journal, ap, aep, 'FencedReview'], 2)
        checks.append('alternate operation identity cannot abandon original transaction')
        (journal / 'interrupted.pending').write_text('synthetic interrupted persistence')
        run(baseargs, 2)
        checks.append('interrupted journal requires explicit reconciliation after process restart')
        run([sys.executable, Path(__file__).with_name('ha-review.py'), root / 'unavailable-volume', txpath, ep, 'FencedReview'], 2)
        assert not (root / 'unavailable-volume').exists()
        checks.append('unavailable coordination directory is never recreated')
        fresh = root / 'phase-skip'; fresh.mkdir()
        run([sys.executable, Path(__file__).with_name('ha-review.py'), fresh, txpath, root / 'RejoinReview.json', 'RejoinReview'], 2)
        checks.append('phase skipping refused')
        malformed = root / 'malformed.json'; malformed.write_text('{"schema":1,"schema":1}')
        run([sys.executable, Path(__file__).with_name('ha-review.py'), fresh, malformed, ep, 'FencedReview'], 2)
        checks.append('duplicate JSON fields refused')
        # The Windows Store execution alias is not a readable PE image. Hash
        # the actual runtime image in sys.base_prefix and record the alias.
        interpreter = Path(sys.base_prefix) / ('python.exe' if __import__('os').name == 'nt' else 'bin/python3')
        identities = {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest() for p in [interpreter, Path(__file__), Path(__file__).with_name('ha-review.py'), native, native.with_name('DnsServerCore.dll')]}
        save(root / 'RESULT.json', dict(status='PASS', checks=checks, negativeCases=negatives, process=dict(pid=__import__('os').getpid(), python=sys.version, platform=platform.platform(), identities=identities),
             scope='Synthetic local review and accepted native core mechanics only; no physical fencing, production takeover, packet continuity or distributed controller qualification'))
        print(json.dumps(dict(status='PASS', checks=len(checks), negativeCases=len(negatives))))
    finally:
        save(root / 'commands.json', commands)


if __name__ == '__main__':
    main()
