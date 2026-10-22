import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = fs.readFileSync(path.join(root, 'DnsServerCore/www/js/common.js'), 'utf8');
let request, rendered = '', details = '';
const element = {
    html(value) { if (value !== undefined) rendered = value; return this; },
    find() { return this; }, append(value) { details += value.textValue || ''; return this; },
    text(value) { this.textValue = value; return this; }, textValue: ''
};
const jquery = () => Object.create(element);
jquery.ajax = options => { request = options; };
const context = vm.createContext({ $: jquery, setTimeout() {}, window: { location: '' }, console });
vm.runInContext(source, context);
context.htmlEncode = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
let completed = 0, failed = 0, expired = 0;
const send = () => context.HTTPRequest({ url: '/api/test', method: 'POST', data: { id: 'unchanged' }, token: 'test-only', success() { completed++; }, error() { failed++; }, invalidToken() { expired++; } });
send();
assert.equal(request.headers.Authorization, 'Bearer test-only');
assert.equal(request.data.id, 'unchanged');
request.success({ status: 'ok' });
assert.equal(completed, 1);
request.success({ status: 'error', errorMessage: 'The inventory changed. Reload before saving.' });
assert.equal(completed, 1); assert.equal(failed, 1);
assert.match(rendered, /inventory changed/);
request.success({ status: 'invalid-token' }); assert.equal(expired, 1);
request.success({ status: 'unexpected' }); assert.equal(completed, 1); assert.equal(failed, 2);
assert.match(rendered, /unexpected response/);
request.error({}, 'timeout', 'raw transport details');
assert.match(rendered, /took too long/); assert.doesNotMatch(rendered, /raw transport details/);
request.error({}, 'parsererror', 'SyntaxError: secret payload');
assert.match(rendered, /unreadable response/); assert.doesNotMatch(rendered, /secret payload/);
context.showRequestError({ errorMessage: 'System.InvalidOperationException: backend internals' }, false);
assert.match(rendered, /could not complete/); assert.doesNotMatch(rendered, /System.InvalidOperationException/);
context.showAlert('danger', '<script>unsafe</script>', '<img src=x onerror=unsafe>');
assert.match(rendered, /&lt;script&gt;/); assert.doesNotMatch(rendered, /<img src=x/);
assert.match(rendered, /role="alert"/); assert.match(rendered, /Dismiss notification/);

// Requests issued for a retired authenticated presentation must not execute any
// success/error/expiry/2FA callback or replace a newer session's alerts/loaders.
let current = true, guardedSuccess = 0, guardedFailure = 0, guardedExpiry = 0, guardedOtp = 0;
context.HTTPRequest({ url: '/api/guarded', token: 'fixture-token',
    isCurrent: () => current, success: () => guardedSuccess++, error: () => guardedFailure++,
    invalidToken: () => guardedExpiry++, twoFactorAuthRequired: () => guardedOtp++, objLoaderPlaceholder: element });
const retiredRequest = request;
current = false;
rendered = 'new-session-content'; details = 'new-session-details';
for (const status of ['ok', 'error', 'invalid-token', '2fa-required', 'unexpected'])
    retiredRequest.success({ status, errorMessage: 'retired actor private details' });
for (const status of ['error', 'timeout', 'parsererror', 'abort']) retiredRequest.error({}, status, 'retired transport');
assert.equal(guardedSuccess + guardedFailure + guardedExpiry + guardedOtp, 0);
assert.equal(rendered, 'new-session-content'); assert.equal(details, 'new-session-details');
current = true;
retiredRequest.success({ status: 'ok' }); assert.equal(guardedSuccess, 1);
retiredRequest.success({ status: 'invalid-token' }); assert.equal(guardedExpiry, 1);
context.HTTPRequest({ url: '/api/guarded-text', isTextResponse: true, isCurrent: () => false,
    success: () => guardedSuccess++, error: () => guardedFailure++ });
rendered = 'current-actor-content'; request.success('retired raw response');
assert.equal(guardedSuccess, 1); assert.equal(rendered, 'current-actor-content');

for (const name of fs.readdirSync(path.join(root, 'DnsServerCore/www/js')).filter(name => !name.endsWith('.min.js'))) {
    new vm.Script(fs.readFileSync(path.join(root, 'DnsServerCore/www/js', name), 'utf8'), { filename: name });
}
const html = fs.readFileSync(path.join(root, 'DnsServerCore/www/index.html'), 'utf8');
vm.runInContext(fs.readFileSync(path.join(root, 'DnsServerCore/www/js/product-ux.js'), 'utf8'), context);
assert.equal(context.productDnsValue({ Type: 'A', RDATA: { IPAddress: '192.0.2.10' } }), '192.0.2.10');
assert.equal(context.productDnsValue({ type: 'PTR', rData: { ptrName: 'host.example' } }), 'host.example');
assert.equal(context.productDnsValue({ Type: 'MX', RDATA: { Preference: 10, Exchange: 'mail.example' } }), '10 · mail.example');
assert.equal(context.productDnsValue({ Type: 'OPT', RDATA: { Options: [{ Code: 'ExtendedDnsError', Data: { InfoCode: 'Blocked', ExtraText: 'Security policy blocked the answer.' } }] } }), 'Security policy blocked the answer.');
assert.equal(context.productLabel('FalsePositive'), 'False positive');
assert.equal(context.productCount(1, 'assignment'), '1 assignment');
assert.match(html, /name="viewport"/);
assert.match(fs.readFileSync(path.join(root, 'DnsServerCore/DnsServerCore.csproj'), 'utf8'), /Content Include="www\\js\\product-ux.js"/);
assert.match(html, /value="FalsePositive">False positive/);
assert.match(html, /id="securityDispositionId"/);
assert.doesNotMatch(html, /<pre id="securityEvidence"/);
assert.equal((html.match(/<details(?:\s|>)/g) || []).length, (html.match(/<\/details>/g) || []).length);
const ids = Array.from(html.matchAll(/\bid="([^"]+)"/g), match => match[1]);
assert.equal(new Set(ids).size, ids.length, 'Duplicate DOM identifiers');
// Hidden-input value changes update their default value in browsers: form.reset()
// alone must not retain an old actor's discovery source reference.
let hiddenSourceId = 'previous-actor-source';
const resetElement = { reset() {} };
const resetJquery = selector => {
    const value = { empty() { return this; }, removeAttr() { return this; }, prop() { return this; }, find() { return this; }, hide() { return this; }, append() { return this; }, text() { return this; },
        val(next) { if (selector === '#ipamDiscoveryId' && next !== undefined) hiddenSourceId = next; return this; } };
    return value;
};
const resetContext = vm.createContext({ $: resetJquery, document: { getElementById: () => resetElement }, console });
vm.runInContext(fs.readFileSync(path.join(root, 'DnsServerCore/www/js/ipam.js'), 'utf8'), resetContext);
resetContext.ipamResetSession();
assert.equal(hiddenSourceId, '', 'Discovery hidden source reference survives actor reset');
assert.equal(resetContext.ipamDiscoveryData, null);
assert.equal(resetContext.ipamDiscoveryActiveSourceId, null);
console.log('PASS: shared request outcomes, credential/value preservation, actionable failures, alert escaping/accessibility, retired-request isolation, JavaScript syntax and presentation contracts.');
