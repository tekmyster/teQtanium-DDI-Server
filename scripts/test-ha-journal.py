# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Tekmyster Industries, LLC.
"""Fresh-process owned synthetic stored-receipt validation and fault qualification."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('ha_review', Path(__file__).with_name('ha-review.py'))
ha = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ha)


def main():
    root = Path(sys.argv[1]).resolve(); root.mkdir(parents=True, exist_ok=False)
    defect = '--expect-defect' in sys.argv[2:]
    commands, cases = [], []
    state = dict(version=1, plans=[dict(scope='synthetic-journal', epoch='a' * 32, owners=['a', 'b', 'c'])],
                 replicas=[dict(scope='synthetic-journal', epoch='a' * 32, node='a', sequence=9, entries=[])], configurations=None)
    authority = dict(sequence=9, hash=ha.digest(state['replicas'][0]))
    tx = dict(schema=1, purpose='offline-ha-review', id='b' * 32, scope='synthetic-journal', epoch='a' * 32,
              donor='a', members=['a', 'b', 'c'], receivers=['b', 'c'], minimumSequence=9,
              planHash=ha.digest(state['plans'][0]), coreHash='67b59635c62c2b4e7d6b3867f3be07b582014cb8d8e45f7592aa863d4b103d6b',
              configurationHash=ha.digest(None), leaseProtectionHash=ha.digest([]), permanentGrants=[], permanentGrantHash=ha.digest([]),
              vm=dict(id='synthetic-journal-vm', instanceUuid='synthetic-journal-uuid', nics=[dict(key=1, mac='02:00:00:00:00:01')]))
    def save(path, value):
        path.write_bytes(ha.canonical(value)); return path
    txpath = save(root / 'transaction.json', tx)
    def evidence(stage, sequence=9):
        current_state = copy.deepcopy(state)
        current_state['replicas'][0]['sequence'] = sequence
        current = dict(sequence=sequence, hash=ha.digest(current_state['replicas'][0]))
        return dict(transactionHash=ha.digest(tx), stage=stage, observedAt=int(time.time()), vm=copy.deepcopy(tx['vm']),
                    fence=dict(task='success', nics=[dict(tx['vm']['nics'][0], connected=False, startConnected=False, allowGuestControl=False)]),
                    originalAuthority=copy.deepcopy(current), originalState=copy.deepcopy(current_state),
                    authority=[dict(member=n, available=True, authority=copy.deepcopy(current), state=copy.deepcopy(current_state), epoch=tx['epoch'], planHash=tx['planHash'], configurationHash=tx['configurationHash']) for n in tx['members']],
                    leaseProtectionHash=tx['leaseProtectionHash'], permanentGrantHash=tx['permanentGrantHash'],
                    originalSurrender=dict(current, durable=True, originalStore=True),
                    receivers=[dict(member=n, durable=True, authority=copy.deepcopy(current), state=copy.deepcopy(current_state)) for n in tx['receivers']],
                    restartedOriginal=dict(current, durable=True, originalStore=True), restartedState=copy.deepcopy(current_state))
    def run(journal, stage, ep, expected):
        args = [sys.executable, str(Path(__file__).with_name('ha-review.py')), str(journal), str(txpath), str(ep), stage]
        started = time.time_ns()
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate(timeout=30)
        commands.append(dict(command=args, pid=p.pid, startedUnixNs=started, exitCode=p.returncode, stdout=out, stderr=err))
        assert p.returncode == expected, commands[-1]
        if expected == 2:
            reply = json.loads(err)
            assert reply['automation'] == 'Disabled' and reply['retainFence'] is True and not out
            return reply
        return json.loads(out)
    def seed(name, count=1):
        folder = root / name; folder.mkdir(); journal = folder / 'journal'; journal.mkdir()
        for stage in ('FencedReview', 'TakeoverReview', 'RejoinReview')[:count]:
            ep = save(folder / (stage + '.json'), evidence(stage))
            run(journal, stage, ep, 0)
        return folder, journal
    def snapshot(journal):
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in journal.iterdir() if p.is_file()}
    def rejection(name, mutate, count=1, stage=None, current_sequence=9, invalid_evidence=False):
        folder, journal = seed(name, count)
        mutate(journal)
        before = snapshot(journal)
        stage = stage or ('TakeoverReview' if count == 1 else 'RejoinReview')
        ev = evidence(stage, current_sequence)
        if invalid_evidence:
            ev.pop('originalAuthority')
        ep = save(folder / 'next.json', ev)
        reply = run(journal, stage, ep, 2)
        if invalid_evidence:
            assert reply['error'] == 'Unsupported stored receipt schema; retain fence'
        assert snapshot(journal) == before, (name, 'journal bytes or inventory changed')
        cases.append(dict(name=name, result='REFUSED', reply=reply, before=before, after=snapshot(journal), preserved=True))
    def change(journal, edit, filename='receipt-00.json'):
        path = journal / filename
        value = ha.load(path); edit(value); save(path, value)
    try:
        if defect:
            folder, journal = seed('schema2-reproduction')
            change(journal, lambda r: r.update(schema=2))
            prior = snapshot(journal)
            ep = save(folder / 'next.json', evidence('TakeoverReview'))
            run(journal, 'TakeoverReview', ep, 0)
            assert (journal / 'receipt-01.json').exists()
            cases.append(dict(name='schema2-admitted-before-repair', result='CONFIRMED DEFECT', before=prior, after=snapshot(journal)))
        else:
            folder, journal = seed('valid-control', 3)
            before = snapshot(journal)
            for stage in ('FencedReview', 'TakeoverReview', 'RejoinReview'):
                run(journal, stage, folder / (stage + '.json'), 0)
            assert snapshot(journal) == before
            cases.append(dict(name='schema1-three-phase-and-exact-retries', result='PASS', preserved=True, before=before, after=snapshot(journal)))
            for value in (2, True, '1', 1.0, None):
                rejection('schema-' + str(value), lambda j, v=value: change(j, lambda r: r.update(schema=v)))
            fields = list(ha.load(journal / 'receipt-00.json'))
            for field in fields:
                rejection('missing-' + field, lambda j, f=field: change(j, lambda r: r.pop(f)))
            for name, edit in [
                ('extra-field', lambda r: r.update(unknown='future')),
                ('authority-extra', lambda r: r['authority'].update(unknown=1)),
                ('authority-null', lambda r: r.update(authority=None)),
                ('sequence-bool', lambda r: r['authority'].update(sequence=True)),
                ('sequence-string', lambda r: r['authority'].update(sequence='9')),
                ('sequence-float', lambda r: r['authority'].update(sequence=9.0)),
                ('sequence-negative', lambda r: r['authority'].update(sequence=-1)),
                ('sequence-overflow', lambda r: r['authority'].update(sequence=2**63)),
                ('sequence-below-pinned', lambda r: r['authority'].update(sequence=8)),
                ('authority-missing-hash', lambda r: r['authority'].pop('hash')),
                ('authority-missing-sequence', lambda r: r['authority'].pop('sequence')),
                ('authority-hash-type', lambda r: r['authority'].update(hash=False)),
                ('authority-hash-invalid', lambda r: r['authority'].update(hash='z' * 64)),
                ('transaction-mismatch', lambda r: r.update(transactionHash='0' * 64)),
                ('evidence-hash-invalid', lambda r: r.update(evidenceHash='invalid')),
                ('scope-unknown', lambda r: r.update(scope='unknown')),
                ('stage-unknown', lambda r: r.update(stage='Unknown')),
                ('stage-integer', lambda r: r.update(stage=99)),
                ('stage-null', lambda r: r.update(stage=None)),
                ('stage-out-of-order', lambda r: r.update(stage='TakeoverReview')),
                ('unsafe-automation', lambda r: r.update(automation='Enabled')),
                ('retain-fence-integer', lambda r: r.update(retainFence=1)),
                ('first-parent-not-null', lambda r: r.update(previousHash='0' * 64)),
            ]:
                rejection(name, lambda j, e=edit: change(j, e))
            for name, data in [('root-null', b'null'), ('root-list', b'[]'), ('root-string', b'"receipt"'),
                               ('truncated', b'{"schema":'), ('duplicate-schema', b'{"schema":1,"schema":1}')]:
                rejection(name, lambda j, b=data: (j / 'receipt-00.json').write_bytes(b))
            rejection('filename-gap', lambda j: (j / 'receipt-00.json').rename(j / 'receipt-01.json'))
            rejection('filename-noncanonical', lambda j: (j / 'receipt-00.json').rename(j / 'receipt-0.json'))
            rejection('filename-out-of-range', lambda j: (j / 'receipt-00.json').rename(j / 'receipt-99.json'))
            def excessive(j):
                data = (j / 'receipt-00.json').read_bytes()
                for index in range(1, 4):
                    (j / ('receipt-%02d.json' % index)).write_bytes(data)
            rejection('too-many-phase-files', excessive)
            rejection('chain-hash-mismatch', lambda j: change(j, lambda r: r.update(previousHash='0' * 64), 'receipt-01.json'), 2)
            # Rehash the parent pointer so these cases isolate authority-history
            # compatibility instead of failing merely on chain checksum mismatch.
            def history_change(j, edit):
                first = ha.load(j / 'receipt-00.json'); edit(first); save(j / 'receipt-00.json', first)
                change(j, lambda r: r.update(previousHash=ha.digest(first)), 'receipt-01.json')
            rejection('history-sequence-regression', lambda j: history_change(j, lambda r: r['authority'].update(sequence=10)), 2, current_sequence=11)
            rejection('history-equal-sequence-conflict', lambda j: history_change(j, lambda r: r['authority'].update(hash='0' * 64)), 2, current_sequence=10)
            rejection('invalid-history-before-current-evidence', lambda j: change(j, lambda r: r.update(schema=2)), stage='FencedReview', invalid_evidence=True)
        result = dict(status='REPRODUCED' if defect else 'PASS', cases=cases,
                      sourceSha256=hashlib.sha256(Path(__file__).with_name('ha-review.py').read_bytes()).hexdigest(),
                      testSourceSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      process=dict(pid=os.getpid(), python=sys.version, actualPython=str(Path(sys.base_prefix) / 'python.exe'), platform=platform.platform()),
                      scope='New owned offline synthetic journal and fresh CLI processes only; unsigned consistency, no provider/native/activation claim')
        save(root / 'RESULT.json', result)
        print(json.dumps(dict(status=result['status'], cases=len(cases))))
    finally:
        save(root / 'commands.json', commands)
        save(root / 'partial-cases.json', cases)


if __name__ == '__main__':
    main()
