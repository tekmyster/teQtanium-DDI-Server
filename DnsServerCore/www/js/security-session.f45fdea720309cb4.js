// Modified by Tekmyster Industries, LLC - remains GPL-3.0.
var securitySessionGeneration = 0;
var securitySessionIdentity = null;
var securitySessionActive = false;
var securityJobs = {};

function securityIdentity() {
    if (!sessionData || !sessionData.token || !sessionData.username || !sessionData.info || !sessionData.info.permissions) return null;
    var permissions = sessionData.info.permissions;
    return JSON.stringify([sessionData.token, sessionData.username, permissions.Settings || {}, permissions.Administration || {}]);
}
function securityRetireSession() {
    securitySessionGeneration++;
    securitySessionIdentity = null;
    var retired = securityJobs; securityJobs = {};
    securityModelTestRequest = null;
    ddiSecurityPolicy = null; securityTimelineResult = null;
    Object.keys(retired).forEach(function (key) { if (retired[key].xhr) retired[key].xhr.abort(); });
    var pane = $('#mainPanelTabPaneSecurity');
    pane.find('canvas').each(function () { if (typeof Chart !== 'undefined' && Chart.getChart) { var chart = Chart.getChart(this); if (chart) chart.destroy(); } });
    pane.find('details').prop('open', false);
    pane.find('input, textarea').val('');
    pane.find('input:checkbox').prop('checked', false);
    pane.find('select').prop('selectedIndex', 0);
    $('#securityRevision, #securityHealth, #securityHealthDetails, #securityEventsBody, #securityEvidence, #securityIndicatorsBody, #securitySimulation, #securitySignalsBody, #securityTimeline, #securityDispositions, #securityPolicyHistory, #securityLlmTestStatus').empty();
    $('#securityDispositionEvent').empty();
    $('#securityManualReference, #securityLlmCancel, .security-edit').hide();
    $('#securityExportTimeline, #securityLlmTest').prop('disabled', true);
    $('#securityFeedback').remove();
}
function securityContext() {
    var identity = securityIdentity();
    if (!securitySessionActive || !identity) return null;
    if (identity !== securitySessionIdentity) { securityRetireSession(); securitySessionIdentity = identity; }
    if (!sessionData.info.permissions.Settings || !sessionData.info.permissions.Settings.canView) return null;
    return { generation: securitySessionGeneration, identity: identity, token: sessionData.token };
}
function securityIsCurrent(context) {
    if (!securitySessionActive) return false;
    if (securitySessionIdentity !== securityIdentity()) { securityRetireSession(); return false; }
    return !!context && context.generation === securitySessionGeneration && context.identity === securitySessionIdentity && !!sessionData.info.permissions.Settings.canView;
}
function securityGuard(context, callback) {
    return function () { if (securityIsCurrent(context)) return callback.apply(this, arguments); };
}
function securityFeedback(context) {
    var rendered = null;
    return {
        html: function (value) {
            if (!securityIsCurrent(context)) return this;
            if (value === '' && rendered !== null) {
                rendered.forEach(function (entry) { if (entry.target.firstChild === entry.child) $(entry.target).empty(); });
                rendered = []; return this;
            }
            var target = $('#securityFeedback');
            if (!target.length) target = $('<div>').attr('id', 'securityFeedback').attr('role', 'status').prependTo('#mainPanelTabPaneSecurity');
            target.html(value); rendered = [];
            target.each(function () { rendered.push({ target: this, child: this.firstChild }); });
            return this;
        },
        find: function (selector) { return (securityIsCurrent(context) ? $('#securityFeedback') : $('<div>')).find(selector); }
    };
}
function securityRequest(path, method, data, success, error, options) {
    var context = securityContext();
    if (!context) return null;
    var model = path === 'model/test' || path === 'events/analyze';
    if ((model && !sessionData.info.permissions.Administration.canModify) || (method === 'POST' && !model && !sessionData.info.permissions.Settings.canModify)) {
        showAlert('danger', 'Access denied', 'Your current permissions do not allow this Security action.', securityFeedback(context)); return null;
    }
    var previous = securityJobs[path];
    var job = { xhr: null }; securityJobs[path] = job;
    if (previous && previous.xhr) previous.xhr.abort();
    var current = function () { return securityIsCurrent(context) && securityJobs[path] === job; };
    var feedback = securityFeedback(context); options = options || {};
    job.xhr = $.ajax({ url: '/api/security/' + path, type: method, data: data || {}, dataType: 'json', timeout: options.timeout || 30000,
        headers: { Authorization: 'Bearer ' + context.token }, cache: false,
        success: function (response) {
            if (!current()) return;
            if (response.status === 'invalid-token') { showPageLogin(); return; }
            if (response.status !== 'ok') { showRequestError(response, false, feedback); if (error) error('response'); return; }
            if (success) success(response, feedback, context);
        },
        error: function (_, reason) {
            if (!current()) return;
            if (reason !== 'abort') showAlert('danger', 'Security request unavailable', reason === 'timeout' ? 'The server took too long to respond. Refresh Security before retrying.' : 'The request could not be completed. Refresh Security before retrying.', feedback);
            if (error) error(reason);
        },
        complete: function () {
            if (!current()) return;
            if (options.complete) options.complete();
            if (securityJobs[path] === job) delete securityJobs[path];
        }
    });
    return job.xhr;
}

var ddiSecurityPolicy = null;
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
var securityModelTestRequest = null;
function securityModelSettings() {
    return { enabled: $('#securityLlmEnabled').prop('checked'), endpoint: $('#securityLlmEndpoint').val(), model: $('#securityLlmModel').val(), apiKeyEnvironment: $('#securityLlmCredential').val(), allowRemote: $('#securityLlmRemote').prop('checked'), shareDomains: $('#securityLlmDomains').prop('checked') };
}
function securityCancelModelTest() {
    if (!securityContext()) return;
    if (securityModelTestRequest) securityModelTestRequest.abort();
}
function securityTestModel() {
    if (securityModelTestRequest) return;
    var context = securityContext();
    if (!context || !sessionData.info.permissions.Administration.canModify) return;
    var output = $('#securityLlmTestStatus').empty().text('Contacting model… This can take up to 30 seconds.');
    $('#securityLlmTest').prop('disabled', true); $('#securityLlmCancel').show();
    securityModelTestRequest = securityRequest('model/test', 'POST', { settings: JSON.stringify(securityModelSettings()) }, function (response) {
        var result = response.response && response.response.analysis;
        if (!result || !result.summary) { output.text('The model returned no usable reply. Check its Chat Completions compatibility.'); return; }
        output.empty().append($('<p>').text('Model replied. Settings have not been saved.'))
            .append($('<p>').text(result.summary).css('white-space', 'pre-wrap'))
            .append($('<p>').addClass('text-muted').text('Synthetic connection check · ' + result.model + ' · ' + productTime(result.timestamp)));
    }, function (status) { output.text(status === 'abort' ? 'Connection test canceled.' : status === 'timeout' ? 'Connection test timed out. Check the model server and try again.' : 'Connection test unavailable. Check the server connection and try again.'); },
    { timeout: 35000, complete: function () { securityModelTestRequest = null; $('#securityLlmCancel').hide(); $('#securityLlmTest').prop('disabled', !sessionData.info.permissions.Administration.canModify); } });
}

function refreshSecurity() {
    if (!securityContext()) return;
    $('#securityRevision').text('Loading security policy…');
    securityRequest('policy/get', 'GET', {}, function (response, feedback, context) {
        var data = response.response;
        ddiSecurityPolicy = data.policy;
        var p = ddiSecurityPolicy;
        $('.security-edit').toggle(sessionData.info.permissions.Settings.canModify);
        $('#securityRevision').text(p.enabled ? (p.mode === 'Block' ? 'Protection enabled' : 'Monitoring enabled') : 'Protection disabled');
        $('#securityEnabled').prop('checked', p.enabled); $('#securityMode').val(p.mode);
        $('#securityAuthoritative').prop('checked', p.inspectAuthoritative); $('#securityAlertThreshold').val(p.alertThreshold);
        $('#securityDeviceThreshold').val(p.deviceThreshold); $('#securityDeviceDns').val(p.deviceDnsResponse); $('#securityDhcpResponse').val(p.dhcpResponse);
        $('#securityMispEnabled').prop('checked', p.misp.enabled); $('#securityMispUrl').val(p.misp.url);
        $('#securityMispCredential').val(p.misp.apiKeyEnvironment); $('#securityMispRefresh').val(p.misp.refreshSeconds); $('#securityMispLifetime').val(p.misp.cacheLifetimeHours);
        var llm = p.llm || {};
        $('#securityLlmEnabled').prop('checked', !!llm.enabled); $('#securityLlmEndpoint').val(llm.endpoint || ''); $('#securityLlmModel').val(llm.model || '');
        $('#securityLlmCredential').val(llm.apiKeyEnvironment || ''); $('#securityLlmRemote').prop('checked', !!llm.allowRemote); $('#securityLlmDomains').prop('checked', !!llm.shareDomains);
        $('#securityLlmEnabled, #securityLlmEndpoint, #securityLlmModel, #securityLlmCredential, #securityLlmRemote, #securityLlmDomains, #securityLlmTest').prop('disabled', !sessionData.info.permissions.Administration.canModify);
        $('#securityMispEnabled, #securityMispUrl, #securityMispCredential, #securityMispRefresh, #securityMispLifetime').prop('disabled', !sessionData.info.permissions.Administration.canModify);
        $('#securityHealth').text('MISP: ' + (!p.misp.enabled ? 'Disabled' : data.mispHealth.lastSuccess ? 'Last updated ' + productTime(data.mispHealth.lastSuccess) : 'Awaiting first update') + ' · Shared signals: ' + (data.signalHealth.status.indexOf('failed') >= 0 ? 'Sync interrupted' : data.signalHealth.lastSuccess ? 'Last delivery completed' : 'Local evidence available'));
        $('#securityHealthDetails').text('Policy revision: ' + p.revision + ' · Cached indicators: ' + data.mispHealth.indicators + ' · Dropped event deliveries: ' + data.droppedEvents + ' · MISP status: ' + data.mispHealth.status + ' · Signal status: ' + data.signalHealth.status);
        var body = $('#securityIndicatorsBody').empty();
        p.indicators.forEach(function (indicator) {
            var row = $('<tr>');
            [productLabel(indicator.kind), indicator.value, indicator.action, indicator.source, indicator.confidence, indicator.clientNetwork || 'All clients', indicator.expires ? productTime(indicator.expires) : 'No expiry'].forEach(function (v) { row.append($('<td>').text(v)); });
            var actions = $('<td>');
            if (sessionData.info.permissions.Settings.canModify) actions.append($('<button class="btn btn-xs btn-default">').text('Remove').on('click', securityGuard(context, function () {
                var next = Object.assign({}, ddiSecurityPolicy, { indicators: ddiSecurityPolicy.indicators.filter(function (i) { return i.id !== indicator.id; }) });
                submitSecurityPolicy(next);
            })));
            row.append(actions); body.append(row);
        });
        productEmptyRow(body, 8, 'No local indicators. Add a domain or address to monitor or block.');
        refreshSecurityEvents();
    }, function () { $('#securityRevision').text('Policy unavailable. Refresh to try again.'); });
}

function submitSecurityPolicy(policy) {
    if (!securityContext()) return;
    securityRequest('policy/set', 'POST', { revision: ddiSecurityPolicy.revision, policy: JSON.stringify(policy) }, function (response, feedback) {
        refreshSecurity(); showAlert('success', 'Saved', 'Security policy updated.', feedback);
    });
}

function saveSecuritySettings() {
    if (!securityContext()) return;
    if (!ddiSecurityPolicy) return;
    var policy = Object.assign({}, ddiSecurityPolicy, {
        enabled: $('#securityEnabled').prop('checked'), mode: $('#securityMode').val(), inspectAuthoritative: $('#securityAuthoritative').prop('checked'),
        alertThreshold: Number($('#securityAlertThreshold').val()), deviceThreshold: Number($('#securityDeviceThreshold').val()),
        deviceDnsResponse: $('#securityDeviceDns').val(), dhcpResponse: $('#securityDhcpResponse').val(),
        llm: securityModelSettings(),
        misp: { enabled: $('#securityMispEnabled').prop('checked'), url: $('#securityMispUrl').val(), apiKeyEnvironment: $('#securityMispCredential').val(), refreshSeconds: Number($('#securityMispRefresh').val()), cacheLifetimeHours: Number($('#securityMispLifetime').val()) }
    });
    submitSecurityPolicy(policy);
}

function addSecurityIndicators() {
    if (!securityContext()) return;
    if (!ddiSecurityPolicy) return;
    var values = $('#securityIndicatorValues').val().split(/\r?\n/).map(function (v) { return v.trim(); }).filter(function (v) { return v && v[0] !== '#'; });
    var expiry = $('#securityIndicatorExpiry').val();
    var additions = values.map(function (v) {
        return { id: crypto.randomUUID(), kind: $('#securityIndicatorKind').val(), value: v, action: $('#securityIndicatorAction').val(), source: $('#securityIndicatorSource').val(),
            confidence: Number($('#securityIndicatorConfidence').val()), expires: expiry ? new Date(expiry).toISOString() : null, clientNetwork: $('#securityIndicatorClient').val() || null, evidence: null };
    });
    submitSecurityPolicy(Object.assign({}, ddiSecurityPolicy, { indicators: ddiSecurityPolicy.indicators.concat(additions) }));
}

function refreshSecurityEvents() {
    if (!securityContext()) return;
    securityRequest('events/list', 'GET', {}, function (response, feedback, context) {
        var events = $('#securityEventsBody').empty();
        response.response.events.slice().reverse().forEach(function (event) {
            var row = $('<tr>');
            [productTime(event.timestamp), event.service, event.clientAddress || (event.device ? event.device.hardwareAddress : ''), event.query || 'Lease request', productLabel(event.action),
                event.behavior ? event.behavior.score + ' / 100' : ''].forEach(function (v, index) {
                    var cell = $('<td>').text(v);
                    if (index === 3) cell.css({ 'max-width': '260px', 'overflow-wrap': 'anywhere', 'white-space': 'normal' });
                    row.append(cell);
                });
            var evidence = $('<td>');
            evidence.append($('<button class="btn btn-xs btn-default">').text('View evidence').on('click', securityGuard(context, function () { securityShowEvidence(event); })));
            row.append(evidence); events.append(row);
        });
        productEmptyRow(events, 7, 'No recent security events.');
        var signals = $('#securitySignalsBody').empty();
        response.response.signals.forEach(function (signal) {
            var row = $('<tr>');
            [signal.node, signal.service, signal.scope, signal.hardwareAddress, signal.score, signal.expires, signal.reason].forEach(function (v) { row.append($('<td>').text(v)); });
            signals.append(row);
        });
        productEmptyRow(signals, 7, 'No active device signals.');
    });
}
function securityShowEvidence(event) {
    var context = securityContext(); if (!context) return;
    var output = $('#securityEvidence').empty();
    output.append($('<h4>').text('Event evidence'));
    productDetails(output, [['Time', productTime(event.timestamp)], ['Server', event.node], ['Service', event.service], ['Client', event.clientAddress || event.device && event.device.hardwareAddress], ['Domain', event.query], ['Query type', event.queryType], ['Response', event.responseCode], ['Action', productLabel(event.action)], ['Reason', productReason(event.reason)]]);
    if (event.device) productDetails(output, [['DHCP scope', event.device.scope], ['Hostname', event.device.hostName], ['Hardware address', event.device.hardwareAddress], ['Site', event.device.site], ['VLAN', event.device.vlan]]);
    if (event.matches && event.matches.length) {
        var matches = $('<ul>'); event.matches.forEach(function (match) { matches.append($('<li>').text(productLabel(match.kind) + ': ' + match.value + ' · ' + match.source + ' · Confidence ' + match.confidence)); });
        output.append($('<h5>').text('Matched indicators')).append(matches);
    }
    if (event.behavior) {
        var behavior = event.behavior;
        output.append($('<h5>').text('Behavior score: ' + behavior.score + ' / 100'));
        productDetails(output, [['Observation window', (behavior.windowMinutes || 5) + ' minutes'], ['Samples', behavior.samples], ['Baseline', 'No learned baseline'], ['Coverage', behavior.sampleLimited ? 'Sample limit reached' : 'Retained observations']]);
        var findings = behavior.findings || [{ contributions: behavior.contributions, windowMinutes: 5 }];
        var names = { DnsTunneling: 'Possible DNS tunneling', DgaPattern: 'Possible generated domains', PeriodicDns: 'Periodic DNS activity' };
        findings.slice().sort(function (a, b) { return (b.score || 0) - (a.score || 0); }).forEach(function (finding, index) {
            var section = output;
            if (index > 0) { section = $('<details>'); section.append($('<summary>').text((names[finding.kind] || 'Additional finding') + ' - ' + finding.windowMinutes + ' minutes')); output.append(section); }
            if (finding.kind) section.append($('<h5>').text((names[finding.kind] || 'Behavioral finding') + ' · ' + finding.windowMinutes + ' minutes · ' + finding.score + ' / 100'));
            if (finding.scope === 'Client') section.append($('<p>').text('Based on this client’s queries across multiple domains.'));
            if (finding.sampleLimited) section.append($('<p>').text('Only the latest 512 observations are included in this finding.'));
            var contributions = $('<ul>'); (finding.contributions || []).forEach(function (c) { contributions.append($('<li>').text(c.points + ' points · ' + c.evidence)); }); section.append(contributions);
        });
        output.append($('<p>').addClass('text-muted').text('Heuristic priority; detection accuracy has not been calibrated.'));
    }
    if (ddiSecurityPolicy && ddiSecurityPolicy.llm && ddiSecurityPolicy.llm.enabled && sessionData.info.permissions.Administration.canModify) {
        var analysis = $('<div>').attr('role', 'status').attr('aria-live', 'polite');
        var explain = $('<button>').attr('type', 'button').addClass('btn btn-default').text('Explain event');
        explain.on('click', securityGuard(context, function () {
            explain.prop('disabled', true); analysis.empty().text('Analyzing event…');
            securityRequest('events/analyze', 'POST', { eventId: event.id }, function (response) {
                var result = response.response.analysis;
                analysis.empty().append($('<h5>').text('Model explanation')).append($('<p>').text(result.summary).css('white-space', 'pre-wrap')).append($('<p>').addClass('text-muted').text('Advisory · ' + result.model + ' · ' + productTime(result.timestamp)));
                explain.prop('disabled', false);
            }, function () { analysis.empty().text('Analysis unavailable. Check the model connection and try again.'); explain.prop('disabled', false); });
        }));
        output.append(explain).append(analysis);
    }
    if (event.additionalMatches) output.append($('<p>').text(event.additionalMatches + ' additional indicator matches.'));
    output.append($('<details>').append($('<summary>').text('Developer data')).append($('<pre>').text(JSON.stringify(event, null, 2))));
    output.attr('tabindex', '-1').trigger('focus');
}

function simulateSecurity() {
    if (!securityContext()) return;
    securityRequest('simulate', 'GET', { query: $('#securitySimQuery').val(), client: $('#securitySimClient').val(), cnames: $('#securitySimCnames').val(), addresses: $('#securitySimAddresses').val() }, function (response) {
        var decision = response.response.decision;
        var output = $('#securitySimulation').empty();
        output.append($('<h4>').text(decision.action)).append($('<p>').text(decision.reason));
        var evidence = $('<ul>');
        decision.matches.forEach(function (match) { evidence.append($('<li>').text(match.kind + ': ' + match.value + ' — source ' + match.source + ' — confidence ' + match.confidence)); });
        output.append(evidence);
        if (decision.additionalMatches) output.append($('<p>').text(decision.additionalMatches + ' additional matches omitted from the bounded evidence sample.'));
    });
}
var securityTimelineResult = null;
function securitySearchTimeline() {
    if (!securityContext()) return;
    var now = new Date(), from = $('#securitySearchFrom').val() || new Date(now.getTime() - 3600000).toISOString(), to = $('#securitySearchTo').val() || now.toISOString();
    securityRequest('events/search', 'GET', { from: from, to: to, client: $('#securitySearchClient').val(), query: $('#securitySearchQuery').val(), limit: 200 }, function (response, feedback, context) {
        securityTimelineResult = response.response.search; var output = $('#securityTimeline').empty(), list = $('<ul>');
        output.append($('<p>').text(securityTimelineResult.events.length ? securityTimelineResult.events.length + ' events found.' : 'No events match this search.'));
        if (securityTimelineResult.truncated || securityTimelineResult.corruptLines) output.append($('<p>').addClass('text-warning').text('Some events could not be included. Narrow the time range to improve coverage.'));
        output.append($('<details>').append($('<summary>').text('Search details')).append($('<p>').text(securityTimelineResult.scanned + ' records scanned · ' + securityTimelineResult.corruptLines + ' unreadable records')));
        var previousChoice = $('#securityDispositionEvent').val(), previousReference = $('#securityDispositionId').val();
        var choices = $('#securityDispositionEvent').empty().append($('<option>').val('').text('Select an event'));
        securityTimelineResult.events.forEach(function (e) {
            var label = productTime(e.timestamp) + ' · ' + (e.query || e.clientAddress || e.service) + ' · ' + productLabel(e.action);
            choices.append($('<option>').val(e.id).text(label));
            var item = $('<li>').text(label + ' · ' + productReason(e.reason) + ' ');
            item.append($('<button>').attr('type', 'button').addClass('btn btn-xs btn-default').text('Review event').on('click', securityGuard(context, function () { choices.val(e.id); securitySelectEvent(); $('#securityDispositionStatus').trigger('focus'); securityShowEvidence(e); }))); list.append(item);
        }); choices.append($('<option>').val('manual').text('Enter an event reference'));
        if (previousChoice === 'manual') { choices.val('manual'); $('#securityDispositionId').val(previousReference); $('#securityManualReference').show(); }
        else if (securityTimelineResult.events.some(function (event) { return event.id === previousReference; })) { choices.val(previousReference); securitySelectEvent(); }
        else { choices.val(''); securitySelectEvent(); }
        output.append(list); $('#securityExportTimeline').prop('disabled', !securityTimelineResult.events.length);
        securityLoadDispositions();
    });
}
function securityExportTimeline() {
    if (!securityContext()) return;
    if (!securityTimelineResult) return;
    var url = URL.createObjectURL(new Blob([JSON.stringify(securityTimelineResult, null, 2)], { type: 'application/json' }));
    var link = document.createElement('a'); link.href = url; link.download = 'ddi-security-search.json'; link.click(); URL.revokeObjectURL(url);
}
function securityLoadDispositions() {
    if (!securityContext()) return;
    securityRequest('dispositions/list', 'GET', {}, function (response) { var list = $('#securityDispositions').empty(); response.response.dispositions.forEach(function (d) { var item = $('<li>').text(productLabel(d.status) + ' · ' + d.actor + ' · ' + d.notes); item.append($('<details>').append($('<summary>').text('Event reference')).append($('<p>').text(d.eventId))); list.append(item); }); if (!response.response.dispositions.length) list.append($('<li>').text('No analyst reviews yet.')); });
}
function securitySelectEvent() {
    if (!securityContext()) return;
    var selected = $('#securityDispositionEvent').val(); $('#securityManualReference').toggle(selected === 'manual');
    $('#securityDispositionId').val(selected === 'manual' ? '' : selected);
}
function securitySetDisposition() {
    var context = securityContext(); if (!context) return;
    if (!$('#securityDispositionId').val()) { showAlert('warning', 'Select an event', 'Search the timeline and choose an event to review.', securityFeedback(context)); return; }
    securityRequest('dispositions/set', 'POST', { eventId: $('#securityDispositionId').val(), status: $('#securityDispositionStatus').val(), notes: $('#securityDispositionNotes').val() }, securityLoadDispositions);
}
function securityLoadHistory() {
    if (!securityContext()) return;
    securityRequest('policy/history', 'GET', {}, function (response) { var list = $('#securityPolicyHistory').empty(); response.response.policies.forEach(function (p) { list.append($('<li>').text('Revision ' + p.revision + ': ' + (p.enabled ? 'enabled' : 'disabled') + ', ' + p.mode + ', ' + p.indicators + ' local indicators')); }); });
}
function securityRollback() {
    if (!securityContext()) return;
    if (!ddiSecurityPolicy) return;
    securityRequest('policy/rollback', 'POST', { revision: ddiSecurityPolicy.revision, targetRevision: $('#securityRollbackRevision').val() }, function () { refreshSecurity(); securityLoadHistory(); });
}

// Chain the installed IPAM page hooks; neither installed main/common nor IPAM is changed.
if (typeof showPageLogin === 'function') {
    var securityOriginalShowPageLogin = showPageLogin;
    showPageLogin = function () { securitySessionActive = false; securityRetireSession(); return securityOriginalShowPageLogin.apply(this, arguments); };
}
if (typeof showPageMain === 'function') {
    var securityOriginalShowPageMain = showPageMain;
    showPageMain = function () { securityRetireSession(); securitySessionActive = true; securityContext(); return securityOriginalShowPageMain.apply(this, arguments); };
}
