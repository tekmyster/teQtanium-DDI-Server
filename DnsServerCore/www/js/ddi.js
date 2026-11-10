var ddiNetBoxPreview = null;
var ddiDhcpNodes = [];
function ddiRequest(path, method, data, success, error, alerts) {
    HTTPRequest({ url: '/api/' + path, method: method, data: data || {}, token: sessionData.token, success: success, error: error, objAlertPlaceholder: alerts, invalidToken: showPageLogin });
}
function ddiAddress(number) { return [24, 16, 8, 0].map(function (shift) { return (number >>> shift) & 255; }).join('.'); }
function ddiLeaseState(state) { return { Lease: 'Active lease', Offer: 'Pending offer', Declined: 'Quarantined', Grant: 'Transferred', Released: 'Released' }[state] || 'Unknown'; }
function ddiActiveLeaseCount(data, scope, owner) {
    var local = data.state.replicas.find(function (r) { return r.scope === scope && r.node === owner; }), entries = local ? local.entries : [], count = entries.filter(function (e) { return e.state === 'Lease' && new Date(e.expires) > new Date(); }).length;
    data.state.replicas.filter(function (r) { return r.scope === scope && r.node !== owner; }).forEach(function (r) {
        count += r.entries.filter(function (e) { return e.state === 'Grant' && e.borrower === owner && e.protection && e.protection.state === 'Lease' && new Date(e.protection.expires) > new Date() && !entries.some(function (own) { return own.address === e.address; }); }).length;
    }); return count;
}
function ddiRefreshDhcp() {
    $('#ddiDhcpHealth').text('Loading DHCP status…');
    ddiRequest('ddi/dhcp/state/get', 'GET', {}, function (response) {
        var data = response.response, target = $('#ddiDhcpState').empty();
        ddiDhcpNodes = data.nodes || [data.node]; $('#ddiDhcpAddGroup').prop('disabled', ddiDhcpNodes.length < 2);
        if (!$('#ddiDhcpOwners').val()) $('#ddiDhcpOwners').val(ddiDhcpNodes.join(','));
        var health = data.health.indexOf('recovery') >= 0 || data.health.indexOf('Recovery') >= 0 ? 'Recovery required' : data.health.indexOf('failed') >= 0 ? 'Sync interrupted' : data.health.indexOf('completed') >= 0 ? 'Last sync completed' : 'Sync not started';
        $('#ddiDhcpHealth').text(data.node + ' · ' + health);
        $('#ddiDhcpBootstrap').toggle(sessionData.info.permissions.DhcpServer.canModify);
        data.state.plans.forEach(function (plan) {
            target.append($('<h4>').text(plan.scope));
            var configuration = (data.state.configurations || []).find(function (c) { return c.scope === plan.scope; });
            var status = (data.scopeStatus || []).find(function (s) { return s.scope === plan.scope; });
            target.append($('<p>').text(status && status.matchesOwnership ? (status.enabled ? 'Serving on this server' : 'Stopped on this server') : 'Configuration needs attention. Restore the scope to its shared address settings before serving.'));
            var table = $('<table>').addClass('table table-condensed'), body = $('<tbody>'), diagnostics = $('<details>').append($('<summary>').text('Synchronization details'));
            table.append($('<thead>').append($('<tr>').append($('<th>').text('Server')).append($('<th>').text('Active leases')).append($('<th>').text('Transferred addresses')))).append(body);
            diagnostics.append($('<p>').text('Ownership version: ' + plan.epoch + ' · Settings revision: ' + (configuration ? configuration.revision : 'initial')));
            plan.owners.forEach(function (owner) {
                var replica = data.state.replicas.find(function (r) { return r.scope === plan.scope && r.node === owner; });
                var activeCount = ddiActiveLeaseCount(data, plan.scope, owner);
                body.append($('<tr>').append($('<td>').text(owner)).append($('<td>').text(replica || activeCount ? activeCount : 'Awaiting sync')).append($('<td>').text(replica ? replica.entries.filter(function (e) { return e.state === 'Grant'; }).length : '—')));
                diagnostics.append($('<p>').text(owner + ' · Last change: ' + (replica ? replica.sequence : 'not received')));
            }); target.append($('<div>').addClass('table-responsive').append(table)).append(diagnostics);
            if (sessionData.info.permissions.DhcpServer.canModify) ddiRenderHandoff(target, plan, data);
        });
        if (!data.state.plans.length) target.append($('<p>').text('No shared scopes yet. Set up a scope to synchronize DHCP across servers.'));
    }, function () { $('#ddiDhcpHealth').text('Status unavailable. Refresh to try again.'); });
}
function ddiRenderHandoff(target, plan, data) {
    if (plan.owners.length < 2) return;
    var local = data.state.replicas.find(function (r) { return r.scope === plan.scope && r.node === data.node; });
    if (!local) return;
    var transferable = local.entries.filter(function (e) { return !e.authorityOwner && ['Lease', 'Offer', 'Declined'].indexOf(e.state) >= 0 && new Date(e.expires) > new Date(); }).slice(0, 256);
    if (!transferable.length) return;
    var details = $('<details>').css('margin-top', '15px').append($('<summary>').text('Transfer addresses'));
    var form = $('<form>'), receiver = $('<select>').addClass('form-control'), choices = $('<div>'), output = $('<p>').attr({ role: 'status', 'aria-live': 'polite' }), button = $('<button>').attr('type', 'submit').addClass('btn btn-primary').text('Review transfer'), request = null, reviewed = false;
    var review = $('<div>').hide(), back = $('<button>').attr('type', 'button').addClass('btn btn-default').text('Back').hide(), alerts = $('<div>'), technical = $('<details>').append($('<summary>').text('Technical details')).append(alerts).hide();
    plan.owners.filter(function (n) { return n !== data.node; }).forEach(function (n) { receiver.append($('<option>').val(n).text(n)); });
    form.append($('<p>').text('Move selected addresses to another server. Existing clients keep their lease expiry.'));
    var table = $('<table>').addClass('table table-hover table-condensed'), body = $('<tbody>');
    table.append($('<thead>').append($('<tr>').append($('<th>').text('Select')).append($('<th>').text('Address')).append($('<th>').text('Device')).append($('<th>').text('Status')).append($('<th>').text('Expires')))).append(body);
    transferable.forEach(function (e) { var address = ddiAddress(e.address); body.append($('<tr>').append($('<td>').append($('<input>').attr({ type: 'checkbox', value: address, 'aria-label': 'Select ' + address }))).append($('<td>').text(address)).append($('<td>').text(e.host || e.hardware || e.client)).append($('<td>').text(ddiLeaseState(e.state))).append($('<td>').text(new Date(e.expires).toLocaleString()))); });
    choices.append($('<div>').addClass('table-responsive').append(table));
    var receiverLabel = $('<label>').text('Receiving server').css('display', 'block').append(receiver);
    form.append(choices).append($('<div>').addClass('form-group').css('max-width', '360px').append(receiverLabel)).append(review).append(button).append(document.createTextNode(' ')).append(back).append(output).append(technical);
    back.on('click', function () { reviewed = false; request = null; review.hide(); back.hide(); choices.find('input').prop('disabled', false); receiver.prop('disabled', false); button.text('Review transfer').trigger('focus'); });
    form.on('submit', function (event) {
        event.preventDefault();
        if (!request) {
            var addresses = choices.find('input:checked').map(function () { return this.value; }).get();
            if (!addresses.length) { output.text('Select at least one address.'); return; }
            var bytes = new Uint8Array(16); window.crypto.getRandomValues(bytes);
            request = { scope: plan.scope, addresses: addresses.join(','), receiver: receiver.val(), expectedSequence: local.sequence, requestId: Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('') };
            choices.find('input').prop('disabled', true); receiver.prop('disabled', true);
        }
        if (!reviewed) {
            reviewed = true;
            var count = request.addresses.split(',').length;
            review.empty().show().append($('<p>').text(count + (count === 1 ? ' address will' : ' addresses will') + ' move from ' + data.node + ' to ' + request.receiver + '.')).append($('<p>').addClass('text-warning').text('This server will stop assigning these addresses. Returning them is not yet supported.'));
            back.show(); button.text('Transfer addresses').trigger('focus'); output.text(''); return;
        }
        back.hide(); button.prop('disabled', true).text('Transferring…'); output.text('Waiting for both servers to confirm the transfer.');
        ddiRequest('ddi/dhcp/handoff', 'POST', request, function (response) {
            review.hide();
            if (response.response.receiverAcknowledged) { output.text('Transfer complete. Refresh DHCP status to see the updated addresses.'); button.text('Transferred'); }
            else { output.text('Addresses released by this server. The receiving server has not confirmed; retry delivery when its connection returns.'); button.prop('disabled', false).text('Retry delivery'); }
        }, function () {
            technical.show();
            var stale = alerts.text().indexOf('Owner state changed') >= 0;
            output.text(stale ? 'The lease list changed. Refresh DHCP status before trying again.' : 'Transfer could not be confirmed. Retry the same transfer when the connection returns.');
            button.prop('disabled', stale).text(stale ? 'Refresh required' : 'Retry transfer');
        }, alerts);
    }); details.append(form); target.append(details);
}
function ddiBootstrapDhcp() {
    var groups = [];
    $('#ddiDhcpGroupRows tr').each(function () { var row = $(this); groups.push({ name: row.find('.ddi-ha-name').val(), region: row.find('.ddi-ha-region').val(), primary: row.find('.ddi-ha-primary').val(), secondary: row.find('.ddi-ha-secondary').val() }); });
    ddiRequest('ddi/dhcp/plan/set', 'POST', { scope: $('#ddiDhcpScope').val(), owners: $('#ddiDhcpOwners').val(), haGroups: JSON.stringify(groups) }, ddiRefreshDhcp);
}
function ddiAddHaGroup() {
    var used = [];
    $('#ddiDhcpGroupRows select').each(function () { used.push($(this).val()); });
    var remaining = ddiDhcpNodes.filter(function (n) { return used.indexOf(n) < 0; }); if (remaining.length < 2) return;
    var row = $('<tr>'), count = $('#ddiDhcpGroupRows tr').length;
    row.append($('<td>').append($('<input>').attr('required', true).addClass('form-control ddi-ha-name').val(count ? 'Recovery ' + count : 'Local HA')));
    row.append($('<td>').append($('<input>').attr('required', true).addClass('form-control ddi-ha-region').val(count ? 'Recovery' : 'Local')));
    ['primary', 'secondary'].forEach(function (role, index) { var select = $('<select>').addClass('form-control ddi-ha-' + role); ddiDhcpNodes.forEach(function (n) { select.append($('<option>').val(n).text(n)); }); select.val(remaining[index]); row.append($('<td>').append(select)); });
    row.append($('<td>').append($('<button>').attr('type', 'button').addClass('btn btn-default').text('Remove').on('click', function () { row.remove(); }))); $('#ddiDhcpGroupRows').append(row);
}
function ddiLookupHistory() {
    ddiRequest('ddi/dhcp/history/lookup', 'GET', { address: $('#ddiHistoryAddress').val(), timestamp: $('#ddiHistoryTime').val() }, function (response) {
        var data = response.response, output = $('#ddiHistoryResult').empty();
        output.append($('<p>').text(data.device ? data.device.node + ' / ' + data.device.scope + ' / ' + data.device.lease.client + ' / ' + data.device.lease.hardware + ' / ' + (data.device.lease.host || '') : 'No unambiguous observation at that time.'));
        output.append($('<p>').text(data.coverage));
    });
}
// Modified by Tekmyster Industries, LLC — remains GPL-3.0.
var ddiNetBoxSettings = null, ddiNetBoxImport = null, ddiNetBoxCanDelete = false, ddiNetBoxBusy = false;
function ddiResetNetBox() {
    ddiNetBoxPreview = null; ddiNetBoxImport = null; ddiNetBoxSettings = null; ddiNetBoxCanDelete = false; ddiNetBoxBusy = false;
    $('#ddiNetBoxPreview, #ddiNetBoxImport, #ddiNetBoxMappings, #ddiNetBoxSubnetReferences, #ddiNetBoxInterfaceReferences, #ddiNetBoxScope').empty();
    $('#ddiNetBoxPanel').prop('open', false).hide();
    $('#ddiNetBoxPanel form').each(function () { this.reset(); });
    $('#ddiNetBoxFeedback').text('Load settings to configure scoped reviews.'); $('#ddiNetBoxRun').text('No scheduled review loaded.'); $('#ddiNetBoxPublication').text('No publication outcome loaded.');
    ddiNetBoxButtons();
}
function ddiNetBoxButtons() {
    $('#ddiNetBoxPanel button, #ddiNetBoxPanel input, #ddiNetBoxPanel select').prop('disabled', ddiNetBoxBusy);
    $('#ddiNetBoxSave').prop('disabled', ddiNetBoxBusy || !ddiNetBoxSettings);
    var changes = ddiNetBoxPreview ? ddiNetBoxPreview.changes : [];
    $('#ddiNetBoxApply').prop('disabled', ddiNetBoxBusy || !ddiNetBoxPreview || !ddiNetBoxPreview.id || !changes.some(function (c) { return ['Create', 'Update', 'Delete'].indexOf(c.operation) >= 0; }) || changes.some(function (c) { return c.operation === 'Conflict'; }));
    $('#ddiNetBoxDeleteReview').prop('disabled', ddiNetBoxBusy || !ddiNetBoxCanDelete || !$('#ddiNetBoxPreview input:checked').length);
    if (!ddiNetBoxCanDelete) $('#ddiNetBoxPreview input').prop('disabled', true);
    $('#ddiNetBoxImportApply').prop('disabled', ddiNetBoxBusy || !ddiNetBoxImport || !$('#ddiNetBoxImport input:checked').length);
    $('#ddiNetBoxCancel').prop('disabled', ddiNetBoxBusy || !ddiNetBoxSettings || !ddiNetBoxSettings.running);
}
function ddiNetBoxCall(path, data, loading, done) {
    if (ddiNetBoxBusy) return;
    ddiNetBoxBusy = true; ddiNetBoxButtons(); $('#ddiNetBoxFeedback').text(loading);
    ipamRequest('netbox/' + path, 'POST', data || {}, function (response) {
        ddiNetBoxBusy = false; done(response.response); ddiNetBoxButtons();
    }, function () {
        ddiNetBoxBusy = false; $('#ddiNetBoxFeedback').text('Could not finish this request. Check the error above, reload current status and prepare a new review before retrying.'); ddiNetBoxButtons();
    });
}
function ddiNetBoxNumber(row, name, value, label) {
    return $('<input>').attr({ type: 'number', min: 1, 'aria-label': label }).addClass('form-control ' + name).css('min-width', '85px').val(value == null ? '' : value);
}
function ddiLoadNetBox() {
    ddiNetBoxCall('settings/get', {}, 'Loading NetBox settings and current outcomes…', function (data) {
        var settings = data.settings, policy = settings.policy || { types: ['prefixes', 'ip-addresses'], subnetIds: [], subnets: [], interfaces: [] };
        ddiNetBoxSettings = settings; ddiNetBoxCanDelete = data.canDelete; ddiNetBoxPreview = null; ddiNetBoxImport = null;
        $('#ddiNetBoxPreview, #ddiNetBoxImport').empty();
        $('#ddiNetBoxEnabled').prop('checked', settings.enabled); $('#ddiNetBoxUrl').val(settings.url); $('#ddiNetBoxCredential').val(settings.apiKeyEnvironment); $('#ddiNetBoxScheme').val(settings.tokenScheme);
        $('#ddiNetBoxPrefixes').prop('checked', policy.types.indexOf('prefixes') >= 0); $('#ddiNetBoxAddresses').prop('checked', policy.types.indexOf('ip-addresses') >= 0);
        var body = $('#ddiNetBoxMappings').empty();
        (ipamInventory ? ipamInventory.views : []).forEach(function (view) {
            var mapping = settings.mappings.find(function (m) { return m.viewId === view.id; }), row = $('<tr>').attr('data-view', view.id);
            row.append($('<td>').append($('<input>').attr({ type: 'checkbox', 'aria-label': 'Include ' + view.name }).addClass('ddi-netbox-publish').prop('checked', !!mapping)));
            row.append($('<td>').text(view.name)); row.append($('<td>').append(ddiNetBoxNumber(row, 'ddi-netbox-vrf', mapping && mapping.vrfId, 'NetBox VRF for ' + view.name).attr('placeholder', 'Global table'))); body.append(row);
        });
        var scope = $('#ddiNetBoxScope').empty(), subnets = $('#ddiNetBoxSubnetReferences').empty(), interfaces = $('#ddiNetBoxInterfaceReferences').empty();
        (ipamInventory ? ipamInventory.subnets : []).forEach(function (subnet) {
            scope.append($('<option>').val(subnet.id).text(subnet.prefix + ' · ' + subnet.name).prop('selected', policy.subnetIds.indexOf(subnet.id) >= 0));
            var m = policy.subnets.find(function (m) { return m.subnetId === subnet.id; }) || {}, row = $('<tr>').attr('data-subnet', subnet.id).append($('<td>').text(subnet.prefix));
            ['site', 'vlan', 'tenant'].forEach(function (name) { row.append($('<td>').append(ddiNetBoxNumber(row, 'ddi-netbox-' + name, m[name + 'Id'], name + ' ID for ' + subnet.prefix))); }); subnets.append(row);
        });
        policy.subnetIds.filter(function (id) { return !ipamInventory || !ipamInventory.subnets.some(function (s) { return s.id === id; }); }).forEach(function (id) {
            var history = ipamInventory ? ipamInventory.changes.filter(function (c) { return c.objectId === id && c.operation === 'subnet.delete' && c.before; }).slice(-1)[0] : null;
            var prefix = history ? JSON.parse(history.before).prefix : 'Missing subnet';
            scope.append($('<option>').val(id).text(prefix + ' · deleted; retained deletion scope').prop('selected', true));
        });
        (ipamInventory ? ipamInventory.assignments : []).forEach(function (address) {
            var m = policy.interfaces.find(function (m) { return m.assignmentId === address.id; }) || {}, row = $('<tr>').attr('data-assignment', address.id).append($('<td>').text(address.address));
            ['device', 'interface', 'tenant'].forEach(function (name) { row.append($('<td>').append(ddiNetBoxNumber(row, 'ddi-netbox-' + name, m[name + 'Id'], name + ' ID for ' + address.address))); }); interfaces.append(row);
        });
        if (!subnets.children().length) subnets.append($('<tr>').append($('<td>').attr('colspan', 4).text('Add local subnets to map existing NetBox references.')));
        if (!interfaces.children().length) interfaces.append($('<tr>').append($('<td>').attr('colspan', 4).text('Add local address intent to map an existing interface.')));
        $('#ddiNetBoxScheduleEnabled').prop('checked', data.schedule.enabled); $('#ddiNetBoxInterval').val(data.schedule.intervalMinutes); $('#ddiNetBoxTimeout').val(data.schedule.timeoutSeconds || 60);
        var run = data.run, labels = { NotStarted: 'No review yet', Running: 'Collecting review', Ready: 'Review ready', ReviewRequired: 'Review needed', Interrupted: 'Interrupted by restart', Failed: 'Collection failed', Cancelled: 'Review cancelled', Blocked: 'Owner permission required', SavingOutcome: 'Saving outcome' };
        settings.running = run.status === 'Running';
        var next = run.nextDue ? ' Next due: ' + new Date(run.nextDue).toLocaleString() + ' (' + Intl.DateTimeFormat().resolvedOptions().timeZone + ').' : '';
        $('#ddiNetBoxRun').text((labels[run.status] || 'Review status unavailable') + '. ' + run.detail + (data.schedule.enabled ? next : ' Schedule disabled.') + (data.schedule.actor ? ' Owner: ' + data.schedule.actor + '.' : ''));
        var publication = data.publication;
        $('#ddiNetBoxPublication').text(!publication || publication.status === 'NotStarted' ? 'No publication submitted yet.' : publication.status === 'Completed' ? 'Last publication acknowledged: ' + publication.applied + ' changes.' : 'Last publication needs reconciliation: ' + publication.applied + ' acknowledged changes. Some submitted outcomes may be unknown. Prepare a fresh review before continuing.');
        $('#ddiNetBoxFeedback').text(settings.enabled ? 'Settings loaded. Prepare a scoped review or open the latest scheduled review.' : 'Integration disabled. Configure the target and scope before enabling reviews.');
    });
}
function ddiSaveNetBox() {
    var mappings = [], subnets = [], interfaces = [];
    function value(row, name) { var text = row.find('.ddi-netbox-' + name).val(); return text === '' ? null : Number(text); }
    $('#ddiNetBoxMappings tr').each(function () { var row = $(this); if (row.find('.ddi-netbox-publish').prop('checked')) mappings.push({ viewId: row.attr('data-view'), vrfId: value(row, 'vrf') }); });
    $('#ddiNetBoxSubnetReferences tr[data-subnet]').each(function () { var row = $(this), site = value(row, 'site'), vlan = value(row, 'vlan'), tenant = value(row, 'tenant'); if (site || vlan || tenant) subnets.push({ subnetId: row.attr('data-subnet'), siteId: site, vlanId: vlan, tenantId: tenant }); });
    $('#ddiNetBoxInterfaceReferences tr[data-assignment]').each(function () { var row = $(this), device = value(row, 'device'), iface = value(row, 'interface'), tenant = value(row, 'tenant'); if (device || iface || tenant) interfaces.push({ assignmentId: row.attr('data-assignment'), deviceId: device || 0, interfaceId: iface || 0, tenantId: tenant }); });
    var types = []; if ($('#ddiNetBoxPrefixes').prop('checked')) types.push('prefixes'); if ($('#ddiNetBoxAddresses').prop('checked')) types.push('ip-addresses');
    var settings = { enabled: $('#ddiNetBoxEnabled').prop('checked'), url: $('#ddiNetBoxUrl').val(), apiKeyEnvironment: $('#ddiNetBoxCredential').val(), tokenScheme: $('#ddiNetBoxScheme').val(), mappings: mappings, policy: { types: types, subnetIds: $('#ddiNetBoxScope').val() || [], subnets: subnets, interfaces: interfaces } };
    ddiNetBoxPreview = null; ddiNetBoxImport = null;
    ddiNetBoxCall('settings/set', { settings: JSON.stringify(settings) }, 'Saving integration settings…', function (data) { ddiNetBoxSettings = data.settings; $('#ddiNetBoxPreview, #ddiNetBoxImport').empty(); $('#ddiNetBoxFeedback').text('Integration settings saved. Prepare a new review.'); });
}
function ddiNetBoxRenderPreview(preview) {
    ddiNetBoxPreview = preview.id ? preview : null;
    var output = $('#ddiNetBoxPreview').empty(), list = $('<ul>');
    if (!preview.changes.length) { output.append($('<p>').text('No changes in the selected scope.')); return; }
    output.append($('<p>').text(preview.changes.length + (preview.changes.length === 1 ? ' object reviewed.' : ' objects reviewed.')));
    preview.changes.forEach(function (c) {
        var fields = JSON.parse(c.fields), item = $('<li>').css('margin-bottom', '10px'), label = c.operation === 'ReviewDeletion' ? 'Deletion needs approval' : c.operation;
        item.append($('<strong>').text(label + ': ' + (fields.prefix || fields.address))).append($('<p>').text(c.reason));
        if (c.operation === 'ReviewDeletion') item.prepend($('<input>').attr({ type: 'checkbox', 'aria-label': 'Review deletion of ' + (fields.prefix || fields.address), value: c.kind + ':' + c.remoteId }).prop('disabled', !ddiNetBoxCanDelete).on('change', ddiNetBoxButtons));
        if (c.operation === 'Delete') item.append($('<p>').addClass('text-warning').text('Publishing this review will delete this managed NetBox object. Local deletion history and current remote ownership will be checked again.'));
        var previous = c.before ? JSON.parse(c.before) : {}, values = $('<dl>');
        var names = { prefix: 'Prefix', address: 'Address', vrf: 'VRF', status: 'Status', dns_name: 'Hostname', description: 'Description', scope_type: 'Site scope type', scope_id: 'Site ID', vlan: 'VLAN ID', tenant: 'Tenant ID', assigned_object_type: 'Interface type', assigned_object_id: 'Interface ID' };
        function display(v) { if (v == null) return 'Not set'; if (typeof v === 'object') return v.name || v.display || v.value || v.id || 'Reference'; return String(v); }
        Object.keys(names).forEach(function (name) {
            if (!(name in fields)) return;
            var next = display(fields[name]), before = display(previous[name]);
            if (c.operation === 'Update' && before === next) return;
            values.append($('<dt>').text(names[name])).append($('<dd>').text(c.operation === 'Update' ? before + ' → ' + next : next));
        }); item.append($('<details>').append($('<summary>').text(c.operation === 'Delete' || c.operation === 'ReviewDeletion' ? 'Current object before deletion' : 'Mapped field details')).append(values)); list.append(item);
    }); output.append(list);
}
function ddiPreviewNetBox() {
    ddiNetBoxPreview = null;
    ddiNetBoxCall('preview', {}, 'Reading NetBox and preparing the publication diff…', function (data) { ddiNetBoxRenderPreview(data.preview); $('#ddiNetBoxFeedback').text('Review prepared. Resolve conflicts before publication; deletion candidates remain unchanged until individually reviewed.'); });
}
function ddiReadNetBoxPreview() {
    ddiNetBoxPreview = null;
    ddiNetBoxCall('preview/get', {}, 'Opening the latest saved review…', function (data) { ddiNetBoxRenderPreview(data.preview); $('#ddiNetBoxFeedback').text(data.preview.id ? 'Saved review loaded. Check the mapped fields before publication.' : 'No saved review yet. Prepare a publication review.'); });
}
function ddiReviewNetBoxDeletions() {
    var keys = $('#ddiNetBoxPreview input:checked').map(function () { return this.value; }).get(); ddiNetBoxPreview = null;
    ddiNetBoxCall('deletions/preview', { keys: keys.join(',') }, 'Rechecking selected managed deletions…', function (data) { ddiNetBoxRenderPreview(data.preview); $('#ddiNetBoxFeedback').text('Deletion review prepared. Publishing will delete only the individually selected managed objects shown here, along with any other reviewed creates or updates.'); });
}
function ddiApplyNetBox() {
    if (!ddiNetBoxPreview) return;
    var id = ddiNetBoxPreview.id; ddiNetBoxPreview = null;
    ddiNetBoxCall('apply', { previewId: id }, 'Publishing the reviewed changes…', function (data) { $('#ddiNetBoxPreview').empty().append($('<p>').text(data.result.applied + (data.result.applied === 1 ? ' NetBox change acknowledged.' : ' NetBox changes acknowledged.'))); $('#ddiNetBoxPublication').text('Last publication acknowledged: ' + data.result.applied + (data.result.applied === 1 ? ' change.' : ' changes.')); $('#ddiNetBoxFeedback').text('Publication acknowledged. Prepare a new review to reconcile current outcomes.'); });
}
function ddiSaveNetBoxSchedule() {
    ddiNetBoxCall('schedule/set', { schedule: JSON.stringify({ enabled: $('#ddiNetBoxScheduleEnabled').prop('checked'), intervalMinutes: Number($('#ddiNetBoxInterval').val()), timeoutSeconds: Number($('#ddiNetBoxTimeout').val()), mode: 'Review' }) }, 'Saving the review schedule…', function () { $('#ddiNetBoxFeedback').text('Review schedule saved under your current user. Reload status to see its next outcome.'); });
}
function ddiRunNetBoxSchedule() {
    ddiNetBoxCall('schedule/run', {}, 'Starting the scheduled review…', function (data) { if (data.started && ddiNetBoxSettings) { ddiNetBoxSettings.running = true; $('#ddiNetBoxRun').text('Review started. Reload status to see the saved outcome.'); } $('#ddiNetBoxFeedback').text(data.started ? 'Review started. Reload status for its saved outcome.' : 'Review did not start. Check enablement, current owner permissions and interrupted or active work, then save the schedule to resume.'); });
}
function ddiCancelNetBoxSchedule() {
    ddiNetBoxCall('schedule/cancel', {}, 'Requesting cancellation…', function (data) { $('#ddiNetBoxFeedback').text(data.cancelled ? 'Cancellation requested. Reload status to confirm the saved outcome.' : 'No running review to cancel. Reload current status.'); });
}
function ddiPreviewNetBoxImport() {
    ddiNetBoxImport = null;
    ddiNetBoxCall('import/preview', {}, 'Preparing missing local-intent proposals…', function (data) {
        ddiNetBoxImport = data.preview; var output = $('#ddiNetBoxImport').empty(), list = $('<ul>');
        data.preview.changes.forEach(function (c) {
            var item = $('<li>').css('margin-bottom', '10px');
            if (c.operation === 'Propose') item.append($('<input>').attr({ type: 'checkbox', value: c.key, 'aria-label': 'Add local intent for ' + c.natural }).on('change', ddiNetBoxButtons));
            item.append($('<strong>').text((c.operation === 'Propose' ? 'Available proposal: ' : 'Preserved: ') + c.natural)).append($('<p>').text(c.reason));
            item.append($('<p>').text('Name: ' + (c.name || 'Not set') + ' · Status: ' + productLabel(c.status) + ' · Description: ' + (c.description || 'Not set'))); list.append(item);
        }); output.append(data.preview.changes.length ? list : $('<p>').text('No reverse-import proposals in the selected scope.'));
        $('#ddiNetBoxFeedback').text('Reverse review prepared. Select individual missing intent; existing local inventory remains authoritative.');
    });
}
function ddiApplyNetBoxImport() {
    if (!ddiNetBoxImport) return;
    var id = ddiNetBoxImport.id, keys = $('#ddiNetBoxImport input:checked').map(function () { return this.value; }).get(); ddiNetBoxImport = null;
    ddiNetBoxCall('import/apply', { previewId: id, keys: keys.join(',') }, 'Adding selected manual intent…', function (data) {
        $('#ddiNetBoxImport').empty().append($('<p>').text(data.imported + (data.imported === 1 ? ' selected object added to local IPAM. Refresh inventory to see it.' : ' selected objects added to local IPAM. Refresh inventory to see them.')));
        $('#ddiNetBoxFeedback').text('Selected local intent saved. DNS, DHCP and devices were unchanged.');
    });
}
$(function () {
    $('#ddiNetBoxPanel form').first().on('input change', function () {
        ddiNetBoxPreview = null; ddiNetBoxImport = null;
        $('#ddiNetBoxPreview, #ddiNetBoxImport').empty();
        $('#ddiNetBoxFeedback').text('Integration settings changed. Save them and prepare a new review.'); ddiNetBoxButtons();
    });
});
