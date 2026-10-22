// Modified by Tekmyster Industries, LLC — remains GPL-3.0
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const www = process.argv[2] ? path.resolve(process.argv[2]) : path.join(root, 'DnsServerCore/www');
let hiddenId = 'existing-subnet', resetValue = hiddenId, focused = false, open = false, request;
const form = { reset() { hiddenId = resetValue; } };
const input = { form };
const element = { each() { return this; }, find() { return this; }, hide() { return this; }, toggle() { return this; }, empty() { return this; }, text() { return this; }, append() { return this; }, removeAttr() { return this; },
    prop(name,value) { if (name === 'open') open = value; return this; }, trigger(name) { if (name === 'focus') focused = true; return this; } };
const $ = selector => {
    const result = Object.create(element);
    result.val = value => { if (typeof selector === 'string' && selector.includes('#ipamSubnetId') && value !== undefined) { hiddenId = value; resetValue = value; } return result; };
    return result;
};
const context = vm.createContext({ $, document: { getElementById: id => id === 'ipamPrefix' ? input : { reset() {} } }, console,
    HTTPRequest(options) { request = options; }, productCount: () => '', productEmptyRow() {} });
vm.runInContext(fs.readFileSync(path.join(www, 'js/ipam.js'), 'utf8'), context);
context.ipamNew('subnet');
assert.equal(hiddenId, ''); assert.equal(resetValue, ''); assert.equal(open, true); assert.equal(focused, true);
hiddenId = resetValue = 'other-actor-subnet'; context.ipamResetSession();
assert.equal(hiddenId, ''); assert.equal(resetValue, '');
context.ipamProvisionLoad = context.ipamDiscoveryLoad = () => {};
context.sessionData = { token: 'fixture-token', username: 'fixture', info: { permissions: { Settings: { canModify: true }, Administration: { canModify: true } } } };
context.ipamSessionContext();
for (const changed of ['revision', 'permission']) {
    hiddenId = resetValue = 'stale-edit'; open = true;
    context.ipamInventory = { revision: 1 };
    context.sessionData.info.permissions.Settings.canModify = changed === 'revision';
    context.refreshIpam();
    request.success({ response: { inventory: { revision: changed === 'revision' ? 2 : 1, views: [], subnets: [], assignments: [], changes: [] } } });
    assert.equal(hiddenId, ''); assert.equal(open, false);
}
const html = fs.readFileSync(path.join(www, 'index.html'), 'utf8');
assert.match(html, /id="ipamAddSubnet"[^>]*onclick="ipamNew\('subnet'\);">Add subnet/);
console.log('PASS: visible manual Add subnet entry, explicit new-object identity retirement, focus/editor state, actor reset and changed inventory/permission draft retirement prevent stale overwrite.');
