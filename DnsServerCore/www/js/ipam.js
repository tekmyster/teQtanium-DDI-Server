var ipamInventory = null;

// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
var ipamSessionRevision = 0;
var ipamSessionToken = null;
var ipamSessionActor = null;
function ipamResetEditors() {
    ['ipamPrefix', 'ipamAddress'].forEach(function (id) {
        var input = document.getElementById(id);
        if (input && input.form) input.form.reset();
    });
    $('#ipamSubnetId, #ipamAssignmentId').val('');
    $('#ipamNetworkEditor, #ipamAssignmentEditor').prop('open', false);
    $('#ipamSubnetEditorHeading').text('Add subnet');
}
function ipamResetSession() {
    if (typeof ddiResetNetBox === "function") ddiResetNetBox();
    ipamSessionRevision++;
    ipamSessionToken = null;
    ipamSessionActor = null;
    ipamInventory = null;
    ipamProvisionOperation = null;
    ipamProvisionBusy = false;
    ipamDiscoveryData = null;
    ipamDiscoveryBusy = false;
    ipamDiscoveryActiveSourceId = null;
    var discoveryForm = document.getElementById("ipamDiscoveryForm");
    if (discoveryForm) discoveryForm.reset();
    $("#ipamDiscoveryId").val("");
    ipamResetEditors();
    $("#ipamDiscoverySources, #ipamDiscoveryFeedback").empty();
    $("#ipamDiscoveryPanel, #ipamDiscoveryEditor").prop("open", false);
    $("#ipamDiscoveryPanel").hide();
    var form = document.getElementById('ipamProvisionForm');
    if (form) form.reset();
    $('#ipamProvisionSubnet').empty();
    $('#ipamProvisionResult').empty().removeAttr('tabindex');
    $('#ipamProvisionFeedback, #ipamRevision, #ipamInspection, #ipamHistory, #ipamSubnetsBody, #ipamAssignmentsBody').empty();
    $('#ipamProvisionHistory').empty().append($('<li>').text('No requests loaded.'));
    $('#ipamProvisioningPanel').prop('open', false).find('button').prop('disabled', false);
    $('.ipam-edit').hide();
}
function ipamSessionContext() {
    var token = sessionData && sessionData.token;
    var actor = sessionData && sessionData.username;
    if (!token || !actor) return null;
    if (token !== ipamSessionToken || actor !== ipamSessionActor) {
        ipamResetSession();
        ipamSessionToken = token;
        ipamSessionActor = actor;
    }
    return { revision: ipamSessionRevision, token: token, actor: actor };
}
function ipamSessionIsCurrent(context) {
    return !!context && context.revision === ipamSessionRevision &&
        context.token === ipamSessionToken && context.actor === ipamSessionActor &&
        !!sessionData && sessionData.token === context.token && sessionData.username === context.actor;
}
function ipamRequest(path, method, data, success, error) {
    var context = ipamSessionContext();
    if (!context) return;
    HTTPRequest({ url: "/api/ipam/" + path, method: method, data: data || {}, token: context.token,
        isCurrent: function () { return ipamSessionIsCurrent(context); },
        success: success ? function (response) { if (ipamSessionIsCurrent(context)) success(response); } : null,
        error: error ? function () { if (ipamSessionIsCurrent(context)) error(); } : null,
        invalidToken: function () { if (ipamSessionIsCurrent(context)) showPageLogin(); } });
}

function ipamOptions(selector, entries, label) {
    var previous = $(selector).val();
    var select = $(selector).empty();
    entries.forEach(function (entry) { select.append($('<option>').val(entry.id).text(label(entry))); });
    if (entries.some(function (entry) { return entry.id === previous; })) select.val(previous);
}

function refreshIpam() {
    $('#ipamRevision').text('Loading inventory…');
    ipamRequest("list", "GET", {}, function (response) {
        var permissions = sessionData.info.permissions.Settings;
        var inventory = response.response.inventory;
        if (!permissions.canModify || ipamInventory && ipamInventory.revision !== inventory.revision) ipamResetEditors();
        ipamInventory = inventory;
        $("#ddiNetBoxPanel").toggle(sessionData.info.permissions.Administration.canModify && permissions.canModify);
        $(".ipam-edit").toggle(permissions.canModify);
        $("#ipamRevision").text(productCount(ipamInventory.subnets.length, 'network') + ' · ' + productCount(ipamInventory.assignments.length, 'address assignment'));
        ipamOptions("#ipamView", ipamInventory.views, function (v) { return v.name; });
        ipamOptions("#ipamSubnet", ipamInventory.subnets.filter(function (s) { return !s.container; }), function (s) { return s.name + " — " + s.prefix; });
        ipamOptions("#ipamInspectSubnet", ipamInventory.subnets.filter(function (s) { return !s.container; }), function (s) {
            var view = ipamInventory.views.find(function (v) { return v.id === s.viewId; });
            return (view ? view.name : s.viewId) + " / " + s.name + " / " + s.prefix;
        });
        ipamOptions("#ipamProvisionSubnet", ipamInventory.subnets.filter(function (s) { return !s.container && s.viewId === 'default' && s.dhcpScope && s.dnsZone; }), function (s) { return s.name + ' · ' + s.prefix + ' · DNS ' + s.dnsZone + ' · DHCP ' + s.dhcpScope; });
        ipamProvisionLoad();
        ipamOptions("#ipamDiscoverySubnet", ipamInventory.subnets.filter(function (s) { return !s.container; }), function (s) { var v = ipamInventory.views.find(function (v) { return v.id === s.viewId; }); return (v ? v.name : s.viewId) + " / " + s.name + " / " + s.prefix; });
        ipamDiscoveryLoad();
        var table = $("#ipamSubnetsBody").empty();
        ipamInventory.subnets.forEach(function (s) {
            var row = $('<tr>');
            var view = ipamInventory.views.find(function (v) { return v.id === s.viewId; });
            [view ? view.name : s.viewId, s.name, s.prefix, s.container ? "Container" : "Subnet", s.site, s.vlan || "", s.dhcpScope || "", s.dnsZone || "", s.source ? productLabel(s.source) : 'IPAM'].forEach(function (value) { row.append($('<td>').text(value)); });
            var actions = $('<td>');
            if (permissions.canModify) actions.append($('<button class="btn btn-xs btn-default">').text("Edit").on('click', function () {
                $('#ipamSubnetId').val(s.id); $('#ipamView').val(s.viewId); $('#ipamPrefix').val(s.prefix); $('#ipamSubnetName').val(s.name);
                $('#ipamSite').val(s.site); $('#ipamVlan').val(s.vlan || ''); $('#ipamDhcpScope').val(s.dhcpScope); $('#ipamDnsZone').val(s.dnsZone); $('#ipamContainer').prop('checked', s.container);
                $('#ipamSubnetEditorHeading').text('Edit subnet');
                $('#ipamNetworkEditor').prop('open', true); $('#ipamPrefix').trigger('focus');
            }));
            if (permissions.canDelete && !s.source) actions.append($('<button class="btn btn-xs btn-danger">').text("Delete").on('click', function () { ipamDelete('subnet', s.id); }));
            row.append(actions); table.append(row);
        });
        productEmptyRow(table, 10, 'No configured DHCP or reverse DNS networks.');
        var assignments = $("#ipamAssignmentsBody").empty();
        ipamInventory.assignments.forEach(function (a) {
            var row = $('<tr>');
            var subnet = ipamInventory.subnets.find(function (s) { return s.id === a.subnetId; });
            [subnet ? subnet.name : a.subnetId, a.address, a.hostName, a.owner, a.status, a.description, a.source ? productLabel(a.source) : 'IPAM'].forEach(function (value) { row.append($('<td>').text(value)); });
            var actions = $('<td>');
            if (permissions.canModify) actions.append($('<button class="btn btn-xs btn-default">').text("Edit").on('click', function () {
                $('#ipamAssignmentId').val(a.id); $('#ipamSubnet').val(a.subnetId); $('#ipamAddress').val(a.address); $('#ipamHostName').val(a.hostName);
                $('#ipamOwner').val(a.owner); $('#ipamStatus').val(a.status); $('#ipamDescription').val(a.description);
                $('#ipamAssignmentEditor').prop('open', true); $('#ipamAddress').trigger('focus');
            }));
            if (permissions.canDelete && !a.source) actions.append($('<button class="btn btn-xs btn-danger">').text("Delete").on('click', function () { ipamDelete('assignment', a.id); }));
            row.append(actions); assignments.append(row);
        });
        productEmptyRow(assignments, 8, 'No address assignments yet.');
        var history = $('#ipamHistory').empty();
        ipamInventory.changes.slice(-20).reverse().forEach(function (c) { history.append($('<li>').text(productTime(c.timestamp) + ' · ' + c.actor + ' · ' + productLabel(c.operation))); });
        $('#ipamInspection').empty();
    }, function () { $('#ipamRevision').text('Inventory unavailable. Refresh to try again.'); });
}
function ipamNew(kind) {
    var input = document.getElementById(kind === 'subnet' ? 'ipamPrefix' : 'ipamAddress');
    input.form.reset();
    // Hidden input .value also changes its reset value in browsers. A new object must
    // explicitly retire the previous edit identity rather than overwrite that object.
    $(kind === 'subnet' ? '#ipamSubnetId' : '#ipamAssignmentId').val('');
    $(kind === 'subnet' ? '#ipamNetworkEditor' : '#ipamAssignmentEditor').prop('open', true);
    if (kind === 'subnet') $('#ipamSubnetEditorHeading').text('Add subnet');
    $(input).trigger('focus');
}

function ipamSave(kind) {
    if (!ipamInventory) return;
    var data = { revision: ipamInventory.revision };
    if (kind === 'view') {
        data.name = $('#ipamViewName').val(); data.description = $('#ipamViewDescription').val();
    } else if (kind === 'subnet') {
        data.id = $('#ipamSubnetId').val(); data.viewId = $('#ipamView').val(); data.prefix = $('#ipamPrefix').val(); data.name = $('#ipamSubnetName').val();
        data.site = $('#ipamSite').val(); data.vlan = $('#ipamVlan').val(); data.dhcpScope = $('#ipamDhcpScope').val(); data.dnsZone = $('#ipamDnsZone').val(); data.container = $('#ipamContainer').prop('checked');
    } else {
        data.id = $('#ipamAssignmentId').val(); data.subnetId = $('#ipamSubnet').val(); data.address = $('#ipamAddress').val(); data.hostName = $('#ipamHostName').val();
        data.owner = $('#ipamOwner').val(); data.status = $('#ipamStatus').val(); data.description = $('#ipamDescription').val();
    }
    ipamRequest(kind === 'view' ? 'views/set' : kind === 'subnet' ? 'subnets/set' : 'assignments/set', 'POST', data, function () {
        $('#ipamSubnetId, #ipamAssignmentId').val(''); refreshIpam(); showAlert('success', 'Saved', 'IPAM inventory updated.');
    });
}

function ipamDelete(kind, id) {
    if (!confirm('Delete this IPAM ' + kind + '?')) return;
    ipamRequest('delete', 'POST', { kind: kind, id: id, revision: ipamInventory.revision }, refreshIpam);
}

function ipamNextAvailable() {
    var subnet = $('#ipamSubnet').val();
    if (!subnet) return;
    ipamRequest('addresses/nextAvailable', 'GET', { subnetId: subnet }, function (response) { $('#ipamAddress').val(response.response.address); });
}

function inspectIpam() {
    var subnet = $('#ipamInspectSubnet').val();
    if (!subnet) return;
    ipamRequest('subnets/inspect', 'GET', { subnetId: subnet }, function (response) {
        var data = response.response;
        var output = $('#ipamInspection').empty();
        output.append($('<p>').text(data.utilization.knownUsedAddresses + ' known used / ' + data.utilization.usableAddresses + ' usable addresses. ' + data.utilization.intendedAddresses + ' intended; ' + data.utilization.observedAddresses + ' observed.'));
        var findings = $('<ul>');
        data.findings.forEach(function (f) { findings.append($('<li>').text(f.address + ' — ' + productLabel(f.kind) + ': ' + f.detail)); });
        if (!data.findings.length) findings.append($('<li>').text('No reconciliation findings.'));
        output.append(findings);
        var threats = $('<ul>');
        (data.securityFindings || []).forEach(function (f) { threats.append($('<li>').text(f.address + ' — ' + f.action + ' — ' + f.source + ' — ' + f.reason + ' Indicators: ' + f.indicators.join(', '))); });
        if ((data.securityFindings || []).length) output.append($('<h4>').text('Threat intelligence matches')).append(threats);
        var ranges = $('<ul>');
        (data.ranges || []).forEach(function (r) { ranges.append($('<li>').text(productLabel(r.kind) + ' · ' + r.start + ' – ' + r.end)); });
        if ((data.ranges || []).length) output.append($('<h4>').text('DHCP ranges')).append(ranges);
        var observations = $('<ul>');
        data.observations.forEach(function (o) {
            var active = (data.discoveryEvidence || []).find(function (e) { return e.sourceId === o.objectName && e.address === o.address; });
            var source = ipamDiscoveryData && ipamDiscoveryData.sources.find(function (s) { return s.id === o.objectName; });
            var label = { TcpConnect: 'TCP connection', SnmpArp: 'SNMP device / ARP', AzureNic: 'Azure NIC inventory' }[o.source] || productLabel(o.source);
            var text = o.address + ' — ' + label + (source ? ' · ' + source.name : '') + (o.hostName ? ' · ' + o.hostName : '') + (o.clientIdentifier ? ' · ' + o.clientIdentifier : '');
            if (active) text += ' · collected ' + productTime(active.observedAt) + ' · expires ' + productTime(active.expires);
            observations.append($('<li>').text(text));
        });
        output.append($('<h4>').text('Address observations')).append(observations);
    });
}
// Modified by Tekmyster Industries, LLC · remains GPL-3.0.
var ipamProvisionOperation = null;
var ipamProvisionBusy = false;
function ipamProvisionRequest(action, data, success) {
    if (!ipamSessionContext() || ipamProvisionBusy) return;
    ipamProvisionBusy = true;
    $('#ipamProvisionPanel button, #ipamProvisioningPanel button').prop('disabled', true);
    $('#ipamProvisionFeedback').text(action === 'apply' ? 'Reconciling and applying this request…' : 'Loading request…');
    function done() { ipamProvisionBusy = false; $('#ipamProvisioningPanel button').prop('disabled', false); }
    ipamRequest('provisioning/' + action, 'POST', data, function (response) {
        done(); $('#ipamProvisionFeedback').text(''); success(response.response);
    }, function () {
        done(); $('#ipamProvisionFeedback').text('The request could not be confirmed. Review the error above, then reload requests before retrying.');
    });
}
function ipamProvisionPreview() {
    if (!ipamInventory || !$('#ipamProvisionSubnet').val()) { $('#ipamProvisionFeedback').text('Link a subnet to local DNS and DHCP destinations first.'); return; }
    var operationId = crypto.randomUUID().replace(/-/g, '');
    ipamProvisionRequest('preview', { operationId: operationId, revision: ipamInventory.revision,
        subnetId: $('#ipamProvisionSubnet').val(), address: $('#ipamProvisionAddress').val(), hostName: $('#ipamProvisionHost').val(),
        hardwareAddress: $('#ipamProvisionHardware').val(), owner: $('#ipamProvisionOwner').val() }, function (data) {
        ipamProvisionRender(data.operation); refreshIpam();
    });
}
function ipamProvisionAction(action, recover) {
    if (!ipamSessionContext() || !ipamProvisionOperation || ipamProvisionOperation.actor !== sessionData.username) return;
    ipamProvisionRequest(action, { operationId: ipamProvisionOperation.id, digest: ipamProvisionOperation.digest, recover: !!recover }, function (data) {
        ipamProvisionRender(data.operation); refreshIpam();
    });
}
function ipamProvisionRender(operation) {
    if (!ipamSessionContext() || operation.actor !== sessionData.username) return;
    ipamProvisionOperation = operation;
    var output = $('#ipamProvisionResult').empty();
    var titles = { Preview: 'Review host', Approved: 'Approved · address held', Applying: 'Outcome pending · address held', RecoveryRequired: 'Reconciliation needed · address held', Completed: 'Configuration saved', Compensated: 'Owned changes removed', Cancelled: 'Request cancelled' };
    output.append($('<h4>').text(titles[operation.state] || 'Request status'));
    var facts = $('<dl>');
    var destination = JSON.parse(operation.preconditions);
    facts.append($('<dt>').text('DHCP service')).append($('<dd>').text(destination.enabled ? 'Enabled · client lease acquisition is not verified' : 'Disabled · reservation configuration only; clients are not being served'));
    [['Address', operation.intent.address], ['Host', operation.intent.hostName], ['Hardware address', operation.intent.hardwareAddress],
        ['DNS destination', operation.subnet.dnsZone + ' · A record · 300 second TTL'], ['DHCP destination', operation.subnet.dhcpScope + ' · reservation'],
        ['DNS outcome', operation.dnsOutcome], ['DHCP outcome', operation.dhcpOutcome], ['Request reference', operation.id], ['Updated', new Date(operation.updated).toLocaleString()]].forEach(function (pair) { facts.append($('<dt>').text(pair[0])).append($('<dd>').text(pair[1])); });
    output.append(facts).append($('<p>').text(operation.detail));
    if (!sessionData.info.permissions.Settings.canModify) { output.attr('tabindex', '-1').trigger('focus'); return; }
    function button(label, action, primary, recover) {
        output.append($('<button type="button" style="margin: 0 8px 8px 0;">').addClass('btn ' + (primary ? 'btn-primary' : 'btn-default')).text(label).prop('disabled', ipamProvisionBusy).on('click', function () { ipamProvisionAction(action, recover); }));
    }
    if (operation.state === 'Preview') { output.append($('<p>').text('Approval expires ' + new Date(operation.expires).toLocaleTimeString() + '. Approval holds the address; Apply configures the services.')); button('Approve request', 'approve', true); button('Cancel request', 'cancel'); }
    if (operation.state === 'Approved') { button('Apply approved request', 'apply', true); button('Cancel request', 'cancel'); }
    if (operation.state === 'Applying' || operation.state === 'RecoveryRequired') {
        button('Reconcile same request', 'apply', true);
        var recovery = $('<details>').append($('<summary>').text('Remove owned changes'));
        recovery.append($('<p>').text('Remove only this request’s unchanged DNS record and DHCP reservation. A changed object or live client lease keeps the address held for review.'));
        recovery.append($('<button type="button" class="btn btn-default">').text('Remove this request’s owned changes').prop('disabled', ipamProvisionBusy).on('click', function () { ipamProvisionAction('apply', true); })); output.append(recovery);
    }
    output.attr('tabindex', '-1').trigger('focus');
}
function ipamProvisionLoad() {
    var context = ipamSessionContext();
    if (!context || ipamProvisionBusy) return;
    var history = $('#ipamProvisionHistory').empty().append($('<li>').text('Loading requests…'));
    ipamRequest('provisioning/list', 'GET', {}, function (response) {
        history.empty(); var operations = response.response.operations || [];
        if (!operations.length) history.append($('<li>').text('No provisioning requests yet.'));
        operations.forEach(function (op) {
            history.append($('<li>').append($('<button type="button" class="btn btn-default" style="white-space: normal; max-width: 100%; text-align: left; overflow-wrap: anywhere; margin: 4px 0;">').text(op.intent.hostName + ' · ' + op.intent.address + ' · ' + ({ Completed: 'Configured', RecoveryRequired: 'Needs reconciliation', Approved: 'Approved', Preview: 'Awaiting approval', Applying: 'Outcome pending', Cancelled: 'Cancelled', Compensated: 'Recovered' }[op.state] || 'Status unavailable')).on('click', function () { if (ipamSessionIsCurrent(context)) ipamProvisionRender(op); })));
        });
    }, function () { history.empty().append($('<li>').text('Requests could not be loaded. Try Reload requests.')); });
}

// Active collection is manual and requires current Administration + Settings permissions.
var ipamDiscoveryData = null;
var ipamDiscoveryBusy = false;
var ipamDiscoveryActiveSourceId = null;
function ipamDiscoveryAllowed() {
    return sessionData && sessionData.info && sessionData.info.permissions.Administration.canView && sessionData.info.permissions.Settings.canView;
}
function ipamDiscoveryFields(changed) {
    var kind = $('#ipamDiscoveryKind').val();
    if (changed) $('#ipamDiscoveryPort').val(kind === 'SnmpArp' ? 161 : 443);
    $('.discovery-targets').toggle(kind !== 'AzureNic');
    $('.discovery-credential').toggle(kind !== 'TcpConnect');
    $('.discovery-azure').toggle(kind === 'AzureNic');
}
function ipamDiscoveryNew() {
    document.getElementById('ipamDiscoveryForm').reset();
    $('#ipamDiscoveryId').val(''); ipamDiscoveryFields();
    $('#ipamDiscoveryName').trigger('focus');
}
function ipamDiscoveryEdit(s) {
    $('#ipamDiscoveryId').val(s.id); $('#ipamDiscoveryName').val(s.name); $('#ipamDiscoveryKind').val(s.kind);
    $('#ipamDiscoverySubnet').val(s.subnetId); $('#ipamDiscoveryTargets').val(s.targets); $('#ipamDiscoveryPort').val(s.port);
    $('#ipamDiscoveryCredential').val(s.credentialReference); $('#ipamDiscoverySubscription').val(s.subscription); $('#ipamDiscoveryGroup').val(s.resourceGroup);
    $('#ipamDiscoveryLimit').val(s.maxResults); $('#ipamDiscoveryTimeout').val(s.timeoutMs); $('#ipamDiscoveryFresh').val(s.freshSeconds); $('#ipamDiscoveryApproval').val(s.approvalReference);
    ipamDiscoveryFields(); $('#ipamDiscoveryEditor').prop('open', true); $('#ipamDiscoveryName').trigger('focus');
}
function ipamDiscoverySave(source) {
    if (!ipamInventory || ipamDiscoveryBusy) return;
    var kind = $('#ipamDiscoveryKind').val();
    var s = source || { id: $('#ipamDiscoveryId').val(), name: $('#ipamDiscoveryName').val(), kind: kind,
        subnetId: $('#ipamDiscoverySubnet').val(), targets: kind === 'AzureNic' ? '' : $('#ipamDiscoveryTargets').val().trim(), port: kind === 'AzureNic' ? 443 : Number($('#ipamDiscoveryPort').val()),
        credentialReference: kind === 'TcpConnect' ? '' : $('#ipamDiscoveryCredential').val().trim(), subscription: kind === 'AzureNic' ? $('#ipamDiscoverySubscription').val().trim() : '', resourceGroup: kind === 'AzureNic' ? $('#ipamDiscoveryGroup').val().trim() : '',
        maxResults: Number($('#ipamDiscoveryLimit').val()), timeoutMs: Number($('#ipamDiscoveryTimeout').val()), freshSeconds: Number($('#ipamDiscoveryFresh').val()), approvalReference: $('#ipamDiscoveryApproval').val().trim(), enabled: false };
    ipamRequest('discovery/sources/set', 'POST', { revision: ipamInventory.revision, source: JSON.stringify(s) }, function (response) {
        if (!source) $('#ipamDiscoveryId').val(response.response.source.id);
        $('#ipamDiscoveryFeedback').text(s.enabled ? 'Source enabled for manual collection.' : 'Source saved disabled. Review its approved scope before qualification.'); refreshIpam();
    });
}
function ipamDiscoveryRun(s, qualify) {
    if (ipamDiscoveryBusy) return;
    ipamDiscoveryBusy = true;
    ipamDiscoveryActiveSourceId = s.id;
    $('#ipamDiscoveryFeedback').text('Collecting ' + s.name + '… Last-known evidence remains visible.');
    ipamDiscoveryRender();
    ipamRequest('discovery/run', 'POST', { sourceId: s.id, qualify: !!qualify }, function (response) {
        ipamDiscoveryBusy = false; ipamDiscoveryActiveSourceId = null;
        var r = response.response.run;
        $('#ipamDiscoveryFeedback').text(r.detail);
        refreshIpam();
    }, function () {
        ipamDiscoveryBusy = false; ipamDiscoveryActiveSourceId = null;
        $('#ipamDiscoveryFeedback').text('Collection could not be confirmed. Reload sources to review the saved outcome before retrying.'); ipamDiscoveryLoad();
    });
}
function ipamDiscoveryLoad() {
    var allowed = ipamDiscoveryAllowed();
    $('#ipamDiscoveryPanel').toggle(!!allowed);
    if (!allowed) { $('#ipamDiscoverySources').empty(); ipamDiscoveryData = null; return; }
    if (!ipamDiscoveryData) $('#ipamDiscoverySources').text('Loading sources…');
    ipamRequest('discovery/status', 'GET', {}, function (response) {
        var wasPending = ipamDiscoveryData && (ipamDiscoveryData.pendingPersistence || []).length > 0;
        ipamDiscoveryData = response.response;
        if (wasPending && !(ipamDiscoveryData.pendingPersistence || []).length) $('#ipamDiscoveryFeedback').text('Outcome saved. Refresh inventory before editing the source.');
        ipamDiscoveryRender();
    }, function () {
        $('#ipamDiscoverySources').empty().append($('<p>').text('Sources unavailable. Check your current permissions and reload.'));
    });
}
function ipamDiscoveryRender() {
    if (!ipamDiscoveryData || !ipamDiscoveryAllowed()) return;
    var data = ipamDiscoveryData, output = $('#ipamDiscoverySources').empty();
    $('#ipamDiscoveryEditor').toggle(data.canModify).find('button').prop('disabled', ipamDiscoveryBusy); ipamDiscoveryFields();
    if (!data.sources.length) output.append($('<p>').text('No active discovery sources configured. Add an approved target scope to begin.'));
    data.sources.forEach(function (s) {
        var r = data.runs.find(function (r) { return r.sourceId === s.id; });
        var subnet = ipamInventory && ipamInventory.subnets.find(function (n) { return n.id === s.subnetId; });
        var box = $('<section class="well well-sm" style="margin-top: 12px;">');
        box.append($('<h4>').text(s.name + ' · ' + (s.enabled ? 'Enabled' : 'Disabled')));
        var kinds = { TcpConnect: 'TCP connection', SnmpArp: 'SNMP device / ARP', AzureNic: 'Azure NIC inventory' };
        var view = subnet && ipamInventory.views.find(function (v) { return v.id === subnet.viewId; });
        box.append($('<p>').text(kinds[s.kind] + ' · ' + (subnet ? (view ? view.name : subnet.viewId) + ' / ' + subnet.name + ' / ' + subnet.prefix : 'Subnet unavailable') + ' · ' + (s.kind === 'AzureNic' ? s.subscription + ' / ' + s.resourceGroup : s.targets + ' · port ' + s.port)));
        box.append($('<p>').text('Limit ' + s.maxResults + ' · request ' + s.timeoutMs + ' ms · fresh for ' + s.freshSeconds + ' seconds · approval: ' + (s.approvalReference || 'Required before collection')));
        var pendingSave = (data.pendingPersistence || []).indexOf(s.id) >= 0;
        if (pendingSave) box.append($('<p role="status">').text('Collection stopped. Saving its outcome is pending because inventory storage is unavailable. Restore storage and reload sources; collection will not run again.'));
        if (r) {
            box.append($('<p>').text('Last attempt: ' + productTime(r.attemptedAt) + ' · ' + (pendingSave ? 'Saving outcome' : { Running: 'Collecting', Complete: 'Complete', Failed: 'Failed', Cancelled: 'Cancelled', Interrupted: 'Interrupted' }[r.status] || 'Unknown')));
            box.append($('<p>').text('Last complete collection: ' + (r.lastSuccess ? productTime(r.lastSuccess) : 'Never')));
            if (!pendingSave) box.append($('<p>').text(r.detail));
        } else box.append($('<p>').text('Not collected. Save an approval reference, then qualify this exact scope.'));
        if (data.canModify) {
            function action(label, callback, disabled) { box.append($('<button type="button" class="btn btn-default" style="margin: 0 6px 8px 0; white-space: normal;">').text(label).prop('disabled', !!disabled).on('click', callback)); }
            action('Edit source', function () { ipamDiscoveryEdit(s); }, ipamDiscoveryBusy || data.active.indexOf(s.id) >= 0);
            action(s.enabled ? 'Collect now' : 'Qualify approved scope', function () { ipamDiscoveryRun(s, !s.enabled); }, ipamDiscoveryBusy || data.active.length > 0 || !s.approvalReference);
            action(s.enabled ? 'Disable' : 'Enable manual collection', function () { ipamDiscoverySave(Object.assign({}, s, { enabled: !s.enabled })); }, ipamDiscoveryBusy || data.active.indexOf(s.id) >= 0 || !s.enabled && (!r || r.status !== 'Complete' || !r.lastSuccess || Date.now() - new Date(r.lastSuccess).getTime() > s.freshSeconds * 1000));
            if (ipamDiscoveryActiveSourceId === s.id || data.active.indexOf(s.id) >= 0) action('Cancel collection', function () {
                ipamRequest('discovery/cancel', 'POST', { sourceId: s.id }, function (response) { $('#ipamDiscoveryFeedback').text(response.response.cancellationRequested ? 'Cancellation requested. Reload sources for the final saved outcome.' : 'No active collection found. Reload sources to review its outcome.'); });
            }, false);
            if (data.canDelete) action('Remove source', function () { if (confirm('Remove this source and its observations? IPAM assignments remain.')) ipamRequest('discovery/sources/delete', 'POST', { revision: ipamInventory.revision, sourceId: s.id }, refreshIpam); }, ipamDiscoveryBusy || data.active.indexOf(s.id) >= 0);
        }
        if (r && r.evidence.length) {
            var table = $('<table class="table table-striped table-condensed">');
            table.append($('<thead>').append($('<tr>').append(['Address / identity', 'Evidence and confidence', 'Freshness', 'Collected / expires'].map(function (x) { return $('<th>').text(x); }))));
            var body = $('<tbody>');
            r.evidence.forEach(function (e) {
                var current = r.scopeCurrent !== false && e.present && new Date(e.expires).getTime() > Date.now();
                var row = $('<tr>');
                row.append($('<td>').text(e.address + (e.hostName ? ' · ' + e.hostName : '') + (e.clientIdentifier ? ' · ' + e.clientIdentifier : '')));
                var meaning = { ConnectionConfirmed: 'TCP connection accepted; service health unverified', DeviceReported: 'Device report; ARP cache age and endpoint reachability unknown', ProviderReported: 'Provider configuration; endpoint reachability unverified' };
                row.append($('<td>').text(meaning[e.confidence] || e.confidence));
                row.append($('<td>').text(r.scopeCurrent === false ? 'Scope review required' : current ? (pendingSave ? 'Last-known; outcome not saved' : r.status === 'Complete' ? 'Current' : 'Last-known; source ' + r.status.toLowerCase()) : (e.present ? 'Expired' : 'Missing from latest collection')));
                row.append($('<td>').text(productTime(e.observedAt) + ' / ' + productTime(e.expires))); body.append(row);
            });
            table.append(body);
            var evidenceDetails = $('<details>');
            var freshCount = r.evidence.filter(function (e) { return r.scopeCurrent !== false && e.present && new Date(e.expires).getTime() > Date.now(); }).length;
            evidenceDetails.append($('<summary>').text(r.scopeCurrent === false ? 'Historical observations · scope review required' : 'Observations: ' + freshCount + ' current · ' + (r.evidence.length - freshCount) + ' expired or missing'));
            evidenceDetails.append($('<div class="table-responsive">').append(table));
            box.append(evidenceDetails);
        } else if (r && r.status === 'Complete') box.append($('<p>').text('No matching positive evidence returned. This does not prove that addresses are unused.'));
        output.append(box);
    });
}
