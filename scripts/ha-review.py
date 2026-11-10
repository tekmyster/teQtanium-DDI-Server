# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Tekmyster Industries, LLC.
"""Offline HA evidence review journal. Never executes adapters or enables recovery.

Receipt assertions are untrusted input, not authentication or physical fence proof.
Coordination is restricted to processes using ONE local directory and OS lock.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

INPUT_LIMIT = 8 * 1024 * 1024
PHASES = ('FencedReview', 'TakeoverReview', 'RejoinReview')
RECEIPT_SCOPE = 'Unsigned offline assertions; no production authorization'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    with Path(path).open('rb') as stream:
        raw = stream.read(INPUT_LIMIT + 1)
    require(len(raw) <= INPUT_LIMIT, 'Evidence exceeds review bound')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False, 'Non-finite JSON'))


def valid_hash(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None


def validate_authority(authority):
    require(type(authority) is dict and set(authority) == {'sequence', 'hash'}, 'Invalid authority receipt fields; retain fence')
    require(type(authority['sequence']) is int and 0 <= authority['sequence'] <= 2**63 - 1, 'Invalid authority receipt sequence; retain fence')
    require(valid_hash(authority['hash']), 'Invalid authority receipt hash; retain fence')


def require_successor(previous, current):
    require(previous['sequence'] <= current['sequence'], 'Authority rollback; retain fence')
    if previous['sequence'] == current['sequence']:
        require(previous['hash'] == current['hash'], 'Equal sequence authority conflict; retain fence')


def validate_stored_receipt(saved, index, previous, txhash, filename):
    require(type(index) is int and 0 <= index < len(PHASES), 'Stored receipt phase index outside supported range; retain fence')
    require(type(saved) is dict, 'Invalid stored receipt object; retain fence')
    require(type(saved.get('schema')) is int and saved['schema'] == 1, 'Unsupported stored receipt schema; retain fence')
    require(set(saved) == {'schema', 'transactionHash', 'stage', 'evidenceHash', 'authority', 'previousHash', 'automation', 'retainFence', 'scope'}, 'Invalid stored receipt fields; retain fence')
    require(filename == 'receipt-%02d.json' % index, 'Stored receipt filename/order differs; retain fence')
    require(type(saved['stage']) is str and saved['stage'] == PHASES[index], 'Stored receipt phase/order differs; retain fence')
    require(valid_hash(saved['transactionHash']) and saved['transactionHash'] == txhash, 'Pending transaction differs; no alternate ID or receivers')
    require(valid_hash(saved['evidenceHash']), 'Invalid stored receipt evidence hash; retain fence')
    require(saved['previousHash'] is None if previous is None else valid_hash(saved['previousHash']), 'Invalid stored receipt parent hash; retain fence')
    require(saved['previousHash'] == (digest(previous) if previous else None), 'Review receipt chain differs; retain fence')
    require(type(saved['automation']) is str and saved['automation'] == 'Disabled' and saved['retainFence'] is True, 'Unsafe stored receipt state; retain fence')
    require(type(saved['scope']) is str and saved['scope'] == RECEIPT_SCOPE, 'Unknown stored receipt scope; retain fence')
    validate_authority(saved['authority'])
    if previous is not None:
        require_successor(previous['authority'], saved['authority'])


def state_authority(state, tx):
    require(type(state['version']) is int and state['version'] == 1, 'Unknown allocation snapshot schema')
    plans = [p for p in state['plans'] if p['scope'] == tx['scope']]
    require(len(plans) == 1 and digest(plans[0]) == tx['planHash'] and plans[0]['epoch'] == tx['epoch'] and sorted(plans[0]['owners']) == tx['members'], 'Snapshot plan/epoch/membership differs')
    require(digest(state.get('configurations')) == tx['configurationHash'], 'Snapshot configuration differs')
    replicas = [r for r in state['replicas'] if r['scope'] == tx['scope'] and r['node'] == tx['donor']]
    require(len(replicas) == 1, 'Exact original donor replica required')
    replica = replicas[0]
    require(type(replica['sequence']) is int and replica['sequence'] >= 0, 'Invalid snapshot sequence')
    entries = replica['entries']
    require(len(entries) <= 100000 and len({e['address'] for e in entries}) == len(entries), 'Invalid or duplicate snapshot entries')
    require(all(e['state'] in ('Lease', 'Offer', 'Declined', 'Released', 'Grant') for e in entries), 'Unknown protection state; retain fence')
    return dict(sequence=replica['sequence'], hash=digest(replica)), replica


def validate(tx, evidence, stage, now):
    require(tx['schema'] == 1 and tx['purpose'] == 'offline-ha-review', 'Unknown review contract')
    require(re.fullmatch('[a-f0-9]{32}', tx['id']) is not None, 'Stable transaction ID required')
    members = tx['members']
    require(2 <= len(members) <= 128 and members == sorted(set(members)), 'Pin distinct sorted membership')
    require(tx['donor'] in members and tx['receivers'] == sorted(set(members) - {tx['donor']}), 'Pin all original receivers')
    for key in ('planHash', 'coreHash', 'configurationHash', 'leaseProtectionHash', 'permanentGrantHash'):
        require(re.fullmatch('[a-f0-9]{64}', tx[key]) is not None, 'Invalid ' + key)
    require(tx['epoch'] and tx['scope'], 'Scope and epoch required')
    require(type(tx['minimumSequence']) is int and tx['minimumSequence'] >= 0, 'Invalid minimum authority sequence')
    vm = tx['vm']
    require(vm['id'] and vm['instanceUuid'] and len(vm['nics']) > 0, 'Pin VM and adapters')
    require(len({n['key'] for n in vm['nics']}) == len(vm['nics']), 'Duplicate adapter key')
    require(len({n['mac'] for n in vm['nics']}) == len(vm['nics']), 'Duplicate adapter MAC')
    require(evidence['transactionHash'] == digest(tx) and evidence['stage'] == stage, 'Evidence transaction/stage differs')
    # Time bounds are review hygiene, not proof of observation freshness.
    require(type(evidence['observedAt']) is int and 0 <= now - evidence['observedAt'] <= 60, 'Stale or future evidence; retain fence')
    require(evidence['vm'] == vm, 'VM or adapter identity changed; retain fence')
    fence = evidence['fence']
    require(fence['task'] == 'success' and fence['nics'] == [dict(n, connected=False, startConnected=False, allowGuestControl=False) for n in vm['nics']], 'Fence readback incomplete; retain fence')
    require(all(n[k] is False for n in fence['nics'] for k in ('connected', 'startConnected', 'allowGuestControl')), 'Fence flags must be explicit false booleans')
    views = evidence['authority']
    require(len(views) == len(members) and sorted(v['member'] for v in views) == members, 'Every fixed member must provide latest authority; retain fence')
    authority = evidence['originalAuthority']
    validate_authority(authority)
    require(type(authority['sequence']) is int and authority['sequence'] >= tx['minimumSequence'], 'Original authority older than known state; retain fence')
    require(re.fullmatch('[a-f0-9]{64}', authority['hash']) is not None, 'Invalid authority digest')
    computed, original = state_authority(evidence['originalState'], tx)
    require(computed == authority, 'Original bytes differ from claimed authority')
    protections = []
    for entry in original['entries']:
        protection = entry.get('protection') if entry['state'] == 'Grant' else None
        if entry['state'] in ('Lease', 'Offer', 'Declined') or protection is not None:
            protections.append({k: entry[k] for k in ('address', 'client', 'hardware', 'host')} | dict(state=protection['state'] if protection else entry['state'], expires=protection['expires'] if protection else entry['expires']))
    require(digest(sorted(protections, key=lambda p: p['address'])) == tx['leaseProtectionHash'], 'Original bytes changed lease protections')
    # Pin previously permanent grants; newly surrendered grants may be added.
    require(digest(tx['permanentGrants']) == tx['permanentGrantHash'], 'Pinned grant bytes differ')
    require(all(grant in original['entries'] for grant in tx['permanentGrants']), 'Permanent grant erased or changed')
    for view in views:
        require(view['available'] is True and view['authority'] == authority, 'Unavailable or conflicting latest authority; retain fence')
        require(view['epoch'] == tx['epoch'] and view['planHash'] == tx['planHash'] and view['configurationHash'] == tx['configurationHash'], 'Ownership/configuration changed; retain fence')
        require(state_authority(view['state'], tx)[0] == authority, 'Member snapshot differs from latest original authority')
    require(evidence['leaseProtectionHash'] == tx['leaseProtectionHash'] and evidence['permanentGrantHash'] == tx['permanentGrantHash'], 'Lease protection or permanent grants changed; retain fence')
    if stage != 'FencedReview':
        require(evidence['originalSurrender'] == dict(authority, durable=True, originalStore=True), 'Exact original durable surrender required')
        receipts = evidence['receivers']
        require(len(receipts) == len(tx['receivers']) and sorted(r['member'] for r in receipts) == tx['receivers'], 'Missing receiver receipt')
        for receipt in receipts:
            require(receipt['durable'] is True and receipt['authority'] == authority, 'Receiver lacks exact durable authority')
            require(state_authority(receipt['state'], tx)[0] == authority, 'Receiver bytes differ from durable receipt')
    if stage == 'RejoinReview':
        require(evidence['restartedOriginal'] == dict(authority, durable=True, originalStore=True), 'Rejoin needs exact restarted original authority')
        require(state_authority(evidence['restartedState'], tx)[0] == authority, 'Restarted original bytes differ')
    return authority


class LocalLock:
    def __init__(self, root):
        self.path = root / 'review.lock'

    def __enter__(self):
        self.file = self.path.open('a+b')
        try:
            if os.name == 'nt':
                import msvcrt
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            raise ValueError('Local review writer busy; no alternate directory or expiry takeover')
        return self

    def __exit__(self, *_):
        self.file.close()


def review(root, tx, evidence, stage, now):
    # Caller must pre-create a new owned directory; never create replacement state
    # when an expected coordination volume disappears.
    require(root.is_dir(), 'Review directory unavailable; retain fence')
    with LocalLock(root):
        require(not list(root.glob('*.pending')), 'Incomplete durable review; explicit reconciliation required')
        txhash = digest(tx)
        files = sorted(root.glob('receipt-*.json'))
        require(len(files) <= len(PHASES), 'Journal exceeds phase bound')
        previous = None
        history = []
        for index, file in enumerate(files):
            saved = load(file)
            validate_stored_receipt(saved, index, previous, txhash, file.name)
            require(type(tx['minimumSequence']) is int and saved['authority']['sequence'] >= tx['minimumSequence'], 'Stored receipt precedes pinned authority; retain fence')
            history.append(saved)
            previous = saved
        # Reject incompatible history before evaluating current review evidence.
        authority = validate(tx, evidence, stage, now)
        for saved in history:
            require_successor(saved['authority'], authority)
        position = PHASES.index(stage)
        if position < len(files):
            saved = history[position]
            require(saved['evidenceHash'] == digest(evidence), 'Changed retry evidence requires explicit new review, never overwrite')
            return saved
        require(position == len(files), 'Review phase skipped')
        receipt = dict(schema=1, transactionHash=txhash, stage=stage,
                       evidenceHash=digest(evidence), authority=authority,
                       previousHash=digest(previous) if previous else None,
                       automation='Disabled', retainFence=True,
                       scope=RECEIPT_SCOPE)
        path = root / ('receipt-%02d.json' % position)
        validate_stored_receipt(receipt, position, previous, txhash, path.name)
        pending = path.with_suffix('.pending')
        with pending.open('xb') as stream:
            stream.write(canonical(receipt))
            stream.flush()
            os.fsync(stream.fileno())
        # Exclusive creation preserves receipts; a crash before removal leaves a
        # pending marker and withholds every subsequent transition.
        os.link(pending, path)
        pending.unlink()
        if os.name != 'nt':
            fd = os.open(root, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('transaction')
    parser.add_argument('evidence')
    parser.add_argument('stage', choices=PHASES)
    args = parser.parse_args()
    try:
        result = review(args.directory, load(args.transaction), load(args.evidence), args.stage, int(time.time()))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, IndexError, OSError) as error:
        print(json.dumps(dict(automation='Disabled', retainFence=True, error=str(error))), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
