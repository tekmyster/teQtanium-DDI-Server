# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Tekmyster Industries, LLC.
"""Owned real-file bounded-read regression tests; no network or provider calls."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ha_review', Path(__file__).with_name('ha-review.py'))
ha = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ha)
original_open = Path.open


def file_hash(path):
    with original_open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json_file(path, size):
    # Legal JSON followed by padding, including files much larger than the cap.
    with original_open(path, 'wb') as stream:
        stream.write(b'{}')
        remaining = size - 2
        while remaining > 0:
            chunk = min(65536, remaining)
            stream.write(b' ' * chunk)
            remaining -= chunk


def observe(path, action=None):
    trace = []
    class Reader:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)
        def read(self, size=-1):
            before = os.fstat(self.stream.fileno()).st_size
            data = self.stream.read(size)
            trace.append(dict(requestedSize=size, actualBytesReturned=len(data), sizeAtRead=before))
            return data
    def opened(p, mode='r', *args, **kwargs):
        stream = original_open(p, mode, *args, **kwargs)
        if p == path and mode == 'rb':
            trace.append(dict(event='real-file-opened', sizeAtOpen=os.fstat(stream.fileno()).st_size))
            if action:
                action(path)
                trace.append(dict(event='controlled-real-file-change-after-open', sizeAfterChange=os.fstat(stream.fileno()).st_size))
            return Reader(stream)
        return stream
    return trace, opened


def main():
    root = Path(sys.argv[1]).resolve()
    fixture = Path(sys.argv[2]).resolve()
    root.mkdir(parents=True, exist_ok=False)
    cases, integrations = [], []
    def dump(name, value):
        (root / name).write_bytes(ha.canonical(value))
    def probe(name, path, expected, action=None):
        trace, opened = observe(path, action)
        before = path.stat().st_size
        with patch.object(Path, 'open', opened):
            try:
                value = ha.load(path)
                outcome = 'valid'
                assert value == {}
            except ValueError as error:
                outcome = 'bound' if str(error) == 'Evidence exceeds review bound' else 'invalid-json'
        assert outcome == expected, (name, outcome)
        reads = [event for event in trace if 'requestedSize' in event]
        assert len(reads) == 1 and reads[0]['requestedSize'] == ha.INPUT_LIMIT + 1
        assert reads[0]['actualBytesReturned'] <= ha.INPUT_LIMIT + 1
        cases.append(dict(name=name, path=str(path), sizeBeforeOpen=before, sizeAfter=path.stat().st_size,
                          sha256=file_hash(path), outcome=outcome, readTrace=trace))
    try:
        for name, size, expected in [('valid', 2, 'valid'), ('below-limit', ha.INPUT_LIMIT - 1, 'valid'),
                                      ('exact-limit', ha.INPUT_LIMIT, 'valid'), ('limit-plus-one', ha.INPUT_LIMIT + 1, 'bound'),
                                      ('oversize', ha.INPUT_LIMIT * 2 + 1, 'bound')]:
            path = root / (name + '.json'); write_json_file(path, size)
            probe(name, path, expected)
        empty = root / 'empty.json'; empty.write_bytes(b''); probe('empty', empty, 'invalid-json')
        invalid = root / 'truncated.json'; invalid.write_bytes(b'{"unfinished":'); probe('truncated', invalid, 'invalid-json')
        growing = root / 'grow-after-open.json'; write_json_file(growing, 2)
        def grow(path):
            with original_open(path, 'ab') as stream:
                remaining = ha.INPUT_LIMIT * 2 - 1
                while remaining > 0:
                    chunk = min(65536, remaining); stream.write(b' ' * chunk); remaining -= chunk
        probe('grow-after-open', growing, 'bound', grow)
        shrinking = root / 'truncate-after-open.json'; write_json_file(shrinking, ha.INPUT_LIMIT)
        def truncate(path):
            with original_open(path, 'r+b') as stream:
                stream.truncate(1)
        probe('truncate-after-open', shrinking, 'invalid-json', truncate)
        missing = root / 'missing.json'
        try:
            ha.load(missing)
            raise AssertionError('Missing file unexpectedly loaded')
        except FileNotFoundError:
            cases.append(dict(name='ordinary-missing-file', path=str(missing), outcome='FileNotFoundError preserved'))

        tx = ha.load(fixture / 'transaction.json')
        ev = ha.load(fixture / 'FencedReview.json'); ev['observedAt'] = int(time.time())
        txpath = root / 'transaction.json'; txpath.write_bytes(ha.canonical(tx))
        evpath = root / 'evidence.json'; evpath.write_bytes(ha.canonical(ev))
        journal = root / 'journal'; journal.mkdir()
        ha.review(journal, tx, ev, 'FencedReview', int(time.time()))
        safe = journal / 'receipt-00.json'; original_safe = safe.read_bytes()
        oversized = root / 'oversize.json'
        for endpoint in ('transaction', 'evidence', 'journal'):
            target = oversized
            selected_tx, selected_ev = txpath, evpath
            if endpoint == 'transaction': selected_tx = oversized
            if endpoint == 'evidence': selected_ev = oversized
            if endpoint == 'journal':
                target = journal / 'receipt-01.json'
                write_json_file(target, ha.INPUT_LIMIT * 2 + 1)
            before_hash = file_hash(target)
            trace, opened = observe(target)
            # Direct main() exercises the exact delivered refusal/error boundary.
            from contextlib import redirect_stderr, redirect_stdout
            from io import StringIO
            stdout, stderr = StringIO(), StringIO()
            args = ['ha-review.py', str(journal), str(selected_tx), str(selected_ev), 'FencedReview']
            with patch.object(sys, 'argv', args), patch.object(Path, 'open', opened), redirect_stdout(stdout), redirect_stderr(stderr):
                code = ha.main()
            reply = json.loads(stderr.getvalue())
            assert code == 2 and reply == dict(automation='Disabled', retainFence=True, error='Evidence exceeds review bound')
            assert not stdout.getvalue() and safe.read_bytes() == original_safe and file_hash(target) == before_hash
            reads = [event for event in trace if 'requestedSize' in event]
            assert len(reads) == 1 and reads[0]['requestedSize'] == ha.INPUT_LIMIT + 1 and reads[0]['actualBytesReturned'] == ha.INPUT_LIMIT + 1
            integrations.append(dict(endpoint=endpoint, exitCode=code, reply=reply, readTrace=trace,
                                     targetSha256=before_hash, lastSafeReceiptSha256=hashlib.sha256(original_safe).hexdigest(), lastSafeReceiptUnchanged=True))
        # Real I/O refusal reaches the same error protocol; the retained safe
        # receipt and intentionally oversized pending fixture remain untouched.
        p = subprocess.run([sys.executable, str(Path(__file__).with_name('ha-review.py')), str(journal), str(missing), str(evpath), 'FencedReview'], capture_output=True, text=True, timeout=30)
        reply = json.loads(p.stderr)
        assert p.returncode == 2 and reply['retainFence'] is True and reply['automation'] == 'Disabled' and safe.read_bytes() == original_safe
        integrations.append(dict(endpoint='ordinary-io-failure', exitCode=p.returncode, reply=reply, lastSafeReceiptUnchanged=True))
        result = dict(status='PASS', finding='HA-INPUT-001', limit=ha.INPUT_LIMIT,
                      process=dict(pid=os.getpid(), python=sys.version, actualPython=str(Path(sys.base_prefix) / 'python.exe'), platform=platform.platform()),
                      sourceSha256=file_hash(Path(__file__).with_name('ha-review.py')), testSourceSha256=file_hash(Path(__file__)),
                      cases=cases, deliveredEndpoints=integrations,
                      observer='Controlled real-stream observer intercepts Path.open only for exact owned input, delegates actual real stream.read(size) unchanged. Growth/truncation is performed after actual open and before actual read; no stat-based admission or fake read payload.',
                      scope='Read cap and local refusal only; no provider/production/activation claim')
        dump('RESULT.json', result)
        print(json.dumps(dict(status='PASS', cases=len(cases), deliveredEndpoints=len(integrations))))
    finally:
        dump('partial-read-traces.json', dict(cases=cases, deliveredEndpoints=integrations))


if __name__ == '__main__':
    main()
