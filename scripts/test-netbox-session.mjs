// Modified by Tekmyster Industries, LLC — remains GPL-3.0
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let request, outcomes = 0, redirects = 0;
const elements = new Map();
function $(selector) {
    if (!elements.has(selector)) elements.set(selector, { textValue: '', value: '', props: {}, length: 0,
        empty() { this.textValue = ''; return this; }, text(v) { if (v !== undefined) this.textValue = v; return this; },
        val(v) { if (v !== undefined) this.value = v; return v === undefined ? this.value : this; },
        prop(k,v) { if (v !== undefined) this.props[k] = v; return this; }, each() { return this; }, find() { return this; },
        hide() { return this; }, append() { return this; }, removeAttr() { return this; }, first() { return this; }, on() { return this; } });
    return elements.get(selector);
}
const context = vm.createContext({ $, document: { getElementById: () => ({ reset() {} }) },
    HTTPRequest(options) { request = options; }, showPageLogin() { redirects++; }, console });
for (const file of ['ddi.js', 'ipam.js']) vm.runInContext(fs.readFileSync(path.join(root, 'DnsServerCore/www/js', file), 'utf8'), context);
for (const change of [{ username: 'reader', token: 'reader-token' }, { username: 'admin', token: 'fresh-admin-token' }, { username: 'peer-admin', token: 'peer-token' }]) {
    context.sessionData = { username: 'admin', token: 'old-admin-token' };
    context.ipamSessionContext();
    context.ddiNetBoxCall('import/preview', {}, 'Loading private review', () => outcomes++);
    const retired = request;
    context.ddiNetBoxPreview = { id: 'prior-publication', changes: [] };
    context.ddiNetBoxImport = { id: 'prior-import', changes: [] };
    context.ddiNetBoxSettings = { enabled: true, running: true };
    context.ipamResetSession(); context.sessionData = change; context.ipamSessionContext();
    const feedback = $('#ddiNetBoxFeedback').textValue;
    retired.success({ response: { preview: { id: 'retired-private-data' } } }); retired.error(); retired.invalidToken();
    assert.equal(outcomes, 0); assert.equal(redirects, 0);
    assert.equal(context.ddiNetBoxPreview, null); assert.equal(context.ddiNetBoxImport, null); assert.equal(context.ddiNetBoxSettings, null);
    assert.equal(context.ddiNetBoxBusy, false); assert.equal($('#ddiNetBoxFeedback').textValue, feedback);
    assert.equal($('#ddiNetBoxApply').props.disabled, true); assert.equal($('#ddiNetBoxImportApply').props.disabled, true);
}
console.log('PASS: NetBox logout/reader, same-user fresh-token and peer-actor cache reset; retired preview/error/expiry callbacks cannot repopulate or redirect current sessions.');
