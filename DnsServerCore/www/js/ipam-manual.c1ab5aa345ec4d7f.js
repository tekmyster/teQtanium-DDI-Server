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
    ipamSessionRevision++;
    ipamSessionToken = null;
    ipamSessionActor = null;
    ipamInventory = null;
    ipamResetEditors();
    $('#ipamRevision, #ipamInspection, #ipamHistory, #ipamSubnetsBody, #ipamAssignmentsBody').empty();
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
    // The installed request helper renders feedback before calling error callbacks.
    // Guard its placeholder as well as callbacks so retired requests stay silent.
    var renderedFeedback = null;
    var feedback = {
        html: function (value) {
            if (!ipamSessionIsCurrent(context)) return this;
            if (value === '' && renderedFeedback !== null) {
                // The old common.js timer calls html('') on this exact placeholder.
                // Clear only this notification's alert nodes, never a newer message.
                renderedFeedback.forEach(function (entry) {
                    if (entry.target.firstChild === entry.child) $(entry.target).html('');
                });
                renderedFeedback = [];
                return this;
            }
            var target = $('.AlertPlaceholder');
            target.html(value);
            if (value !== '') {
                renderedFeedback = [];
                target.each(function () { renderedFeedback.push({ target: this, child: this.firstChild }); });
            }
            return this;
        },
        find: function (selector) { return (ipamSessionIsCurrent(context) ? $('.AlertPlaceholder') : $('<div>')).find(selector); }
    };
    HTTPRequest({ url: "/api/ipam/" + path, method: method, data: data || {}, token: context.token,
        objAlertPlaceholder: feedback,
        isCurrent: function () { return ipamSessionIsCurrent(context); },
        success: success ? function (response) { if (ipamSessionIsCurrent(context)) success(response, feedback); } : null,
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
    ipamRequest(kind === 'view' ? 'views/set' : kind === 'subnet' ? 'subnets/set' : 'assignments/set', 'POST', data, function (response, feedback) {
        $('#ipamSubnetId, #ipamAssignmentId').val(''); refreshIpam(); showAlert('success', 'Saved', 'IPAM inventory updated.', feedback);
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
        data.observations.forEach(function (o) { observations.append($('<li>').text(o.address + ' — ' + productLabel(o.source) + ' — ' + (o.hostName || '') + ' — ' + (o.clientIdentifier || ''))); });
        output.append($('<h4>').text('DNS and DHCP observations')).append(observations);
    });
}

// The installed main.js predates IPAM session hooks. Retire drafts before either
// page transition while preserving the existing sign-in/sign-out behavior.
if (typeof showPageLogin === 'function') {
    var ipamOriginalShowPageLogin = showPageLogin;
    showPageLogin = function () { ipamResetSession(); return ipamOriginalShowPageLogin.apply(this, arguments); };
}
if (typeof showPageMain === 'function') {
    var ipamOriginalShowPageMain = showPageMain;
    showPageMain = function () { ipamResetSession(); return ipamOriginalShowPageMain.apply(this, arguments); };
}
