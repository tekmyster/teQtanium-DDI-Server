// SPDX-License-Identifier: GPL-3.0-or-later
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
var operationsRequest = null, operationsGeneration = 0, operationsCharts = {};
function operationsNumber(value) { return value == null ? 'Unavailable' : value.toLocaleString(); }
function operationsTime(value) { return value ? productTime(value) : 'Not recorded'; }
function operationsCard(target, heading, value, detail) {
    var card = $('<div>').addClass('col-sm-3');
    var body = $('<div>').addClass('panel-body').append($('<h5>').text(heading)).append($('<p>').addClass('operations-value').text(value)).append($('<p>').addClass('text-muted').text(detail));
    card.append($('<div>').addClass('panel panel-default operations-card').append(body));
    target.append(card);
}
function operationsChart(id, series, buckets, unit) {
    var colors = ['#6caaf5', '#efad62', '#d981a2', '#b5a0ef', '#83bfb5'];
    var data = { labels: buckets.map(function (b) { return moment(b.time).local().format('HH:mm:ss'); }), datasets: series.map(function (s, i) {
        return { label: s[0], data: buckets.map(function (b) { return b[s[1]]; }), borderColor: colors[i], backgroundColor: 'transparent', borderDash: i ? [4 + i * 2, 3] : [], borderWidth: 2, pointRadius: 2, fill: false, spanGaps: false };
    }) };
    if (operationsCharts[id]) { operationsCharts[id].data = data; operationsCharts[id].update(); return; }
    operationsCharts[id] = new Chart(document.getElementById(id).getContext('2d'), { type: 'line', data: data,
        options: { maintainAspectRatio: false, animation: { duration: 0 }, elements: { line: { tension: 0 } }, scales: { yAxes: [{ ticks: { beginAtZero: true, precision: 0 }, scaleLabel: { display: true, labelString: unit } }], xAxes: [{ ticks: { maxTicksLimit: 5 } }] } }
    });
}
function operationsTotals(target, totals) {
    productDetails(target, [['Completed requests', operationsNumber(totals.requests)], ['Successful', operationsNumber(totals.success)], ['Failed', operationsNumber(totals.failed)], ['Canceled', operationsNumber(totals.cancelled)], ['Timed out', operationsNumber(totals.timedOut)], ['Busy / rejected', operationsNumber(totals.busy)], ['Provider usage reported', operationsNumber(totals.usageReported)], ['Usage missing', operationsNumber(totals.usageMissing)], ['Usage invalid', operationsNumber(totals.usageInvalid)], ['Reported input tokens', operationsNumber(totals.inputTokens)], ['Reported output tokens', operationsNumber(totals.outputTokens)], ['Reported total tokens', operationsNumber(totals.totalTokens)]]);
    if (totals.saturated) target.append($('<p>').addClass('text-warning').text('One or more counters reached the exact reporting limit. Values are lower bounds.'));
}
function renderOperations(data) {
    $('#operationsScope').text('This node only · Process started ' + operationsTime(data.processStartedAt) + ' · Snapshot ' + operationsTime(data.observedAt));
    var fleet = $('#operationsServices').empty();
    if (data.dhcp) operationsCard(fleet, 'DHCP active leases', operationsNumber(data.dhcp.activeLeases), data.dhcp.enabledScopes + ' enabled / ' + data.dhcp.scopes + ' configured scopes. Unexpired node-local leases; pool availability is not measured.');
    else operationsCard(fleet, 'DHCP', 'Restricted', 'DHCP view permission is required.');
    if (data.ipam) {
        operationsCard(fleet, 'IPAM inventory', productCount(data.ipam.assignments, 'assignment'), productCount(data.ipam.networks, 'network') + ' · Last inventory change ' + operationsTime(data.ipam.lastChange));
        var sourceText = data.ipam.sources.map(function (s) { return productLabel(s.source) + ': ' + s.count; }).join(' · ');
        operationsCard(fleet, 'Inventory sources', data.ipam.netBoxEnabled ? 'NetBox enabled' : 'NetBox disabled', (sourceText || 'No assignments') + ' · Source freshness is not measured.');
    } else { operationsCard(fleet, 'IPAM inventory', 'Restricted', 'Settings view permission is required.'); operationsCard(fleet, 'Inventory sources', 'Restricted', 'Settings view permission is required.'); }
    if (data.protection) {
        var state = data.protection.enabled ? (data.protection.mode === 'Block' ? 'Block' : 'Monitor') : 'Disabled';
        var names = { Disabled: 'Disabled', NoSuccessfulRefresh: 'No successful refresh', Stale: 'Stale', Available: 'Available', Unavailable: 'Unavailable' };
        operationsCard(fleet, 'Protection / MISP', state, 'MISP: ' + names[data.protection.misp.state] + ' · Last successful refresh ' + operationsTime(data.protection.misp.lastSuccess));
    } else operationsCard(fleet, 'Protection / MISP', 'Restricted', 'Settings view permission is required.');
    $('#operationsLlm').toggle(!!data.llm); $('#operationsLlmRestricted').toggle(!data.llm);
    if (!data.llm) return;
    var llm = data.llm, m = llm.metrics, t = m.window, cards = $('#operationsLlmCards').empty();
    var observed = m.configuredObservation;
    $('#operationsModelState').text((llm.enabled ? 'Enabled' : 'Disabled') + ' · ' + (llm.configured ? 'Configured model: ' + llm.configuredModel + ' · Last connection check: ' + (observed ? (observed.outcome === 'Success' ? 'succeeded' : observed.outcome.toLowerCase()) + ' at ' + operationsTime(observed.timestamp) : 'not observed since restart') : 'No saved model connection'));
    var last = m.lastSuccess;
    $('#operationsModelLastSuccess').text(last ? 'Last successful response: ' + last.model + ' · ' + last.source + ' · ' + (last.kind === 'ConnectionTest' ? 'connection test (may use unsaved settings)' : 'event explanation') + ' · ' + operationsTime(last.timestamp) : 'No successful model response since restart.');
    var coverage = t.usageReported + ' of ' + t.requests + ' completed requests include valid provider usage. ' + t.usageMissing + ' missing; ' + t.usageInvalid + ' invalid. No token estimates.';
    $('#operationsCoverage').text(coverage + ' In-flight requests are excluded until they finish. Canceled or timed-out requests may have unknown provider usage.');
    $('#operationsRetention').text((m.windowTruncated ? 'Partial window: only retained requests are shown; the ' + m.retentionLimit + '-request limit was reached.' : m.windowComplete ? 'Full selected window observed.' : 'Partial window: ' + Math.round(m.observedSeconds) + ' seconds observed since process start.') + ' Memory only; counters reset when this process restarts.');
    operationsCard(cards, 'Input tokens', operationsNumber(t.inputTokens), 'Provider-reported prompt tokens · selected window');
    operationsCard(cards, 'Output tokens', operationsNumber(t.outputTokens), 'Provider-reported completion tokens · selected window');
    operationsCard(cards, 'Total tokens', operationsNumber(t.totalTokens), 'Reported input + output · selected window');
    operationsCard(cards, 'Completed requests', operationsNumber(t.requests), t.success + ' successful · ' + t.failed + ' failed · ' + t.cancelled + ' canceled · ' + t.timedOut + ' timed out · ' + t.busy + ' busy');
    var latency = m.successfulLatency;
    $('#operationsLatency').text('In flight: ' + m.inFlight + ' / ' + m.capacity + ' · Successful response latency: p50 ' + (latency.p50Milliseconds == null ? 'unavailable' : (latency.p50Milliseconds / 1000).toFixed(2) + ' s') + ' / p95 ' + (latency.p95Milliseconds == null ? 'unavailable' : (latency.p95Milliseconds / 1000).toFixed(2) + ' s') + ' · ' + productCount(latency.samples, 'sample') + ' in selected window');
    $('#operationsCounterLimit').toggle(t.saturated);
    $('#operationsEmpty').toggle(t.requests === 0).text('No completed model requests in this window. Use Model assistance > Test connection for a benign check.');
    var lifetime = $('#operationsLifetime').empty(); operationsTotals(lifetime, m.sinceRestart);
    var table = $('#operationsTrendRows').empty();
    m.trend.forEach(function (b) { var row = $('<tr>'); [operationsTime(b.time), b.requests, b.success, b.failed, b.cancelled, b.timedOut, b.busy, b.reportedTokens, b.usageReported, b.usageUnknown].forEach(function (v, i) { row.append($('<td>').text(i ? operationsNumber(v) : v)); }); table.append(row); });
    operationsChart('operationsTokenChart', [['Input tokens', 'inputTokens'], ['Output tokens', 'outputTokens']], m.trend, 'Reported tokens / minute');
    operationsChart('operationsRequestChart', [['Successful', 'success'], ['Failed', 'failed'], ['Canceled', 'cancelled'], ['Timed out', 'timedOut'], ['Busy', 'busy']], m.trend, 'Completed requests / minute');
}
function refreshOperations() {
    if (!$('#mainPanelTabPaneDashboard').hasClass('active')) return;
    var generation = ++operationsGeneration;
    var requestedToken = sessionData.token;
    if (operationsRequest) operationsRequest.abort();
    $('#operationsStatus').text('Loading operational metrics…'); $('#operationsBody').hide();
    operationsRequest = $.ajax({ url: '/api/dashboard/operations/get', data: { minutes: $('#operationsWindow').val() || 60 }, dataType: 'json', cache: false, timeout: 15000, headers: { Authorization: 'Bearer ' + sessionData.token },
        success: function (response) {
            if (generation !== operationsGeneration || !sessionData || sessionData.token !== requestedToken) return;
            if (response.status === 'invalid-token') { $('#operationsStatus').text('Session expired. Sign in to view operational metrics.'); showPageLogin(); showAlert('warning', 'Session expired', 'Sign in to view operational metrics.'); return; }
            if (response.status !== 'ok' || !response.response || !response.response.operations) { $('#operationsStatus').text('Operational metrics unavailable. Check your dashboard permissions and refresh.'); return; }
            $('#operationsBody').show(); renderOperations(response.response.operations); $('#operationsStatus').text('Operational snapshot loaded.');
        }, error: function (_, status) { if (generation === operationsGeneration && status !== 'abort') $('#operationsStatus').text('Operational metrics unavailable. Refresh to try again.'); },
        complete: function () { if (generation === operationsGeneration) operationsRequest = null; }
    });
}
