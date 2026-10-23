# SPDX-License-Identifier: GPL-3.0-only
# Modified by Tekmyster Industries, LLC — remains GPL-3.0.
# Opt-in single-controller VMware recovery. Configuration, credentials and state stay outside Git.
param([Parameter(Mandatory)][string]$Config, [switch]$Once)
$ErrorActionPreference='Stop'
$configuration=Get-Content -LiteralPath $Config -Raw|ConvertFrom-Json
$credentials=Get-Content -LiteralPath $configuration.credentials -Raw|ConvertFrom-Json
$directory=[IO.Path]::GetFullPath($configuration.stateDirectory)
[IO.Directory]::CreateDirectory($directory)|Out-Null
$writer=[IO.File]::Open((Join-Path $directory 'controller.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
$configurationHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($configuration.nodes|ConvertTo-Json -Depth 100 -Compress))))
$sessions=@{}; $originalSessions=@{}; $failures=@{}
function Save([string]$path,$value) {
    $bytes=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 100))
    $pending=$path+'.tmp'; $stream=[IO.File]::Open($pending,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes);$stream.Flush($true)} finally {$stream.Dispose()}
    [IO.File]::Move($pending,$path,$true)
}
function Api($node,[string]$path,[hashtable]$fields=@{},[string]$token='') {
    $body=($fields.GetEnumerator()|ForEach-Object {[uri]::EscapeDataString([string]$_.Key)+'='+[uri]::EscapeDataString([string]$_.Value)}) -join '&'
    $arguments=@('--cacert',$configuration.caCertificate,'--ssl-revoke-best-effort','--silent','--show-error','--fail','--connect-timeout','3','--max-time','8','--data','@-',('https://'+$node.address+':53443/api/'+$path))
    if($token) {$arguments+=@('--header',('Authorization: Bearer '+$token))}
    $raw=$body|& curl.exe @arguments 2>$null; $code=$LASTEXITCODE
    if($code -in @(7,28)) {throw [Net.Sockets.SocketException]::new(10060)}
    if($code -ne 0) {throw "TLS/API transport rejected for $($node.owner); exit $code"}
    $reply=$raw|ConvertFrom-Json
    if($reply.status -ne 'ok') {throw [UnauthorizedAccessException]::new("Authenticated API rejected $path on $($node.owner)")}
    return $reply
}
function Login($node) {
    $key=if($node.apiCredentialKey){$node.apiCredentialKey}else{$node.address}
    return (Api $node 'user/login' @{user=$credentials.$key.apiUser;pass=$credentials.$key.apiPassword}).token
}
function FreshPrivileges($node) {
    $fresh=Login $node
    if($fresh -eq $originalSessions[$node.owner]) {throw 'A distinct fresh administrative session is required'}
    $key=if($node.apiCredentialKey){$node.apiCredentialKey}else{$node.address}
    $profile=(Api $node 'admin/users/get' @{user=$credentials.$key.apiUser;includeGroups='true'} $fresh).response
    if($profile.memberOfGroups -notcontains 'Administrators' -or $profile.recentSessionRemoteAddress -ne $configuration.managementSource) {throw 'Fresh administrative role or target-seen source differs from configuration'}
    $settings=(Api $node 'settings/get' @{} $fresh).response
    $null=Api $node 'settings/set' @{defaultRecordTtl=$settings.defaultRecordTtl} $fresh
    $sessions[$node.owner]=$fresh
    return @{owner=$node.owner;source=$profile.recentSessionRemoteAddress;freshReadModify=$true;originalRetained=[bool]$originalSessions[$node.owner]}
}
function TaskComplete($reference) {
    $seconds=90;if($configuration.taskTimeoutSeconds){$seconds=[int]$configuration.taskTimeoutSeconds};if($seconds -lt 1 -or $seconds -gt 90){throw 'VMware task timeout must be between 1 and 90 seconds'};$deadline=[DateTime]::UtcNow.AddSeconds($seconds)
    do {
        $task=Get-View -Server $connection -Id $reference
        if($task.Info.State -eq 'success') {return}
        if($task.Info.State -eq 'error') {throw 'Pinned VMware reconfiguration failed'}
        Start-Sleep -Milliseconds 250
    } while([DateTime]::UtcNow -lt $deadline)
    throw 'Pinned VMware operation timed out; retain the fence and inspect task state'
}
function NicState($vm,$saved,[bool]$restore) {
    $view=Get-View -Server $connection -Id $vm.Id
    $devices=@($view.Config.Hardware.Device|Where-Object {$_ -is [VMware.Vim.VirtualEthernetCard]})
    if($devices.Count -eq 0 -or $devices.Count -ne $saved.Count) {throw 'Pinned VM adapter inventory changed'}
    $spec=[VMware.Vim.VirtualMachineConfigSpec]::new()
    $spec.DeviceChange=@(foreach($device in $devices) {
        $old=@($saved|Where-Object {$_.key -eq $device.Key -and $_.mac -eq $device.MacAddress})
        if($old.Count -ne 1) {throw 'Pinned VM adapter identity changed'}
        $device.Connectable.Connected=if($restore){$old[0].connected}else{$false}
        $device.Connectable.StartConnected=if($restore){$old[0].startConnected}else{$false}
        $device.Connectable.AllowGuestControl=if($restore){$old[0].allowGuestControl}else{$false}
        $edit=[VMware.Vim.VirtualDeviceConfigSpec]::new();$edit.Operation='edit';$edit.Device=$device;$edit
    })
    TaskComplete ($view.ReconfigVM_Task($spec))
    $readback=Get-View -Server $connection -Id $vm.Id
    if(@($readback.Config.Hardware.Device|Where-Object {$_ -is [VMware.Vim.VirtualEthernetCard]}).Count -ne $saved.Count) {throw 'Adapter inventory changed during physical fence application'}
    foreach($device in @($readback.Config.Hardware.Device|Where-Object {$_ -is [VMware.Vim.VirtualEthernetCard]})) {
        $matches=@($saved|Where-Object {$_.key -eq $device.Key -and $_.mac -eq $device.MacAddress})
        if($matches.Count -ne 1){throw 'Adapter identity changed during physical fence application'}
        $old=$matches[0]
        $expectedConnected=if($restore){$old.connected}else{$false};$expectedStart=if($restore){$old.startConnected}else{$false};$expectedGuest=if($restore){$old.allowGuestControl}else{$false}
        if($device.Connectable.Connected -ne $expectedConnected -or $device.Connectable.StartConnected -ne $expectedStart -or $device.Connectable.AllowGuestControl -ne $expectedGuest) {throw 'Physical VMware fence/readback did not match'}
    }
}
function ProhibitedTarget($node,$vm=$null,$view=$null) {
    return ($node.vmName -ieq 'DDI01' -or $node.vmId -ieq 'VirtualMachine-vm-12041' -or $node.instanceUuid -ieq '5028e8f6-a593-a184-4e04-524d6e3762bb' -or
        ($vm -and ($vm.Name -ieq 'DDI01' -or $vm.Id -ieq 'VirtualMachine-vm-12041')) -or ($view -and $view.Config.InstanceUuid -ieq '5028e8f6-a593-a184-4e04-524d6e3762bb'))
}
function Guest($node,$vm,[string]$command) {
    # DDI01 GuestOps caused two VMX crashes. No opt-in can bypass this exclusion.
    if(ProhibitedTarget $node $vm) {throw 'DDI01 GuestOps is prohibited; retain fence and use separately qualified recovery access'}
    if(!$configuration.guestOperationsQualified) {throw 'Guest recovery provider is not independently qualified; retain fence'}
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($command))
    $guestCredential=[pscredential]::new($credentials.($node.address).sshUser,(ConvertTo-SecureString $credentials.($node.address).sshPassword -AsPlainText -Force))
    $reply=Invoke-VMScript -Server $connection -VM $vm -GuestCredential $guestCredential -ScriptType Bash -ScriptText ("printf '%s' '$encoded' | base64 -d | tr -d '\r' | bash -e")
    if($reply.ExitCode -ne 0) {throw "Root guest operation failed on pinned VM $($node.owner)"}
    return $reply.ScriptOutput
}
function HasDynamicCapacity($plan) {
    [uint64]$cursor=$plan.first
    $ranges=@($plan.excluded)+@($plan.reservations|ForEach-Object {[pscustomobject]@{first=$_.address;last=$_.address}})
    foreach($range in @($ranges|Where-Object {$_}|Sort-Object {[uint64]$_.first})) {
        if([uint64]$range.last -lt $cursor -or [uint64]$range.first -gt [uint64]$plan.last){continue}
        if([uint64]$range.first -gt $cursor){return $true}
        $cursor=[Math]::Max($cursor,([uint64]$range.last+1))
    }
    return $cursor -le [uint64]$plan.last
}
function AssertAuthority($state,$plan,$donor,[bool]$exact) {
    $plans=@($state.plans|Where-Object scope -CEQ $plan.scope)
    if($plans.Count -ne 1 -or ($plans[0]|ConvertTo-Json -Depth 100 -Compress) -cne ($plan|ConvertTo-Json -Depth 100 -Compress)){throw 'Immutable plan/epoch differs; retain fence'}
    $known=@($state.replicas|Where-Object {$_.node -ceq $donor.node -and $_.scope -ceq $donor.scope})
    if($known.Count -gt 1 -or ($known.Count -eq 1 -and [long]$known[0].sequence -gt [long]$donor.sequence)){throw 'Newer donor authority known; retain fence'}
    if($exact -and ($known.Count -ne 1 -or ($known[0]|ConvertTo-Json -Depth 100 -Compress) -cne ($donor|ConvertTo-Json -Depth 100 -Compress))){throw 'Persisted donor authority differs from exact original export; retain fence'}
}
function Recover($failed,$survivors,[string]$scope,[string]$demand) {
    $operationPath=Join-Path $directory ('operation-'+$failed.owner+'-'+([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($scope))))+'.json')
    $operation=if(Test-Path -LiteralPath $operationPath){Get-Content -LiteralPath $operationPath -Raw|ConvertFrom-Json}else{$null}
    if($operation -and $operation.phase -eq 'Completed' -and $operation.demand -eq $demand) {return}
    if(!$operation -or $operation.phase -eq 'Completed') {
        try {$null=Login $failed;return} catch [Net.Sockets.SocketException] { }
    }
    if((ProhibitedTarget $failed) -or !$configuration.guestOperationsQualified) {throw 'Recovery guest provider unavailable for this target; automation must remain Disabled'}
    # Capability gate: this historical adapter has unbounded synchronous guest/copy calls
    # and unused-recovery API lacks a separately verifiable durable receipt. A config
    # boolean and in-memory state readback cannot establish those capabilities.
    throw 'Automatic recovery provider unsupported: bounded remote operations and durable unused-recovery receipts are required; retain saved transaction and fence. Keep automation Disabled.'
    Import-Module VMware.VimAutomation.Core
    $script:connection=Connect-VIServer -Server $credentials.vcenter.server -Credential ([pscredential]::new($credentials.vcenter.user,(ConvertTo-SecureString $credentials.vcenter.password -AsPlainText -Force))) -Force
    $vm=VMware.VimAutomation.Core\Get-VM -Server $connection -Id $failed.vmId
    $view=Get-View -Server $connection -Id $vm.Id
    if(ProhibitedTarget $failed $vm $view){throw 'Resolved DDI01 target is prohibited'}
    if($vm.Id -cne $failed.vmId -or $vm.Name -cne $failed.vmName -or $view.Config.InstanceUuid -ne $failed.instanceUuid) {throw 'VM name/ID/instance UUID does not match the enrolled recovery target'}
    if(!$operation -or $operation.phase -eq 'Completed') {
        $operation=[pscustomobject]@{id=[Guid]::NewGuid().ToString('N');configurationHash=$configurationHash;vmId=$failed.vmId;instanceUuid=$failed.instanceUuid;vmName=$failed.vmName;coreSha256=$failed.coreSha256;phase='Prepared';owner=$failed.owner;scope=$scope;demand=$demand;receivers=@($survivors.owner|Sort-Object);adapters=@($view.Config.Hardware.Device|Where-Object {$_ -is [VMware.Vim.VirtualEthernetCard]}|ForEach-Object {@{key=$_.Key;mac=$_.MacAddress;connected=($_.Connectable.Connected -or ($vm.PowerState -eq 'PoweredOff' -and $_.Connectable.StartConnected));startConnected=$_.Connectable.StartConnected;allowGuestControl=$_.Connectable.AllowGuestControl}});freshAccess=@()}
        Save $operationPath $operation
    } elseif(($operation.receivers -join ',') -ne (@($survivors.owner|Sort-Object) -join ',')) {throw 'Resume the saved recovery with its original receivers'}
    if($operation.configurationHash -cne $configurationHash -or $operation.id -cnotmatch '^[a-f0-9]{32}$' -or $operation.owner -cne $failed.owner -or $operation.scope -cne $scope -or
       $operation.vmId -cne $failed.vmId -or $operation.vmName -cne $failed.vmName -or $operation.instanceUuid -cne $failed.instanceUuid -or
       $operation.coreSha256 -cne $failed.coreSha256 -or $operation.phase -notin @('Prepared','Fenced','Surrendered','Imported')) {throw 'Saved recovery identity differs; retain fence for explicit reconciliation'}
    # Recoverable errors retain this fence. An unverified fence never grants capacity.
    NicState $vm $operation.adapters $false
    $operation.phase='Fenced';Save $operationPath $operation
    if($vm.PowerState -eq 'PoweredOff') {$null=Start-VM -Server $connection -VM $vm -Confirm:$false}
    $null=Wait-Tools -Server $connection -VM $vm -TimeoutSeconds 180
    $null=Guest $failed $vm 'set -eu; test "$(id -u)" = 0; systemctl stop dns.service; test "$(systemctl show dns.service -p MainPID --value)" = 0; if ss -lunp | grep -E ":67 "; then exit 1; fi'
    if($failed.executable -notmatch '^/opt/[A-Za-z0-9_./-]+/DnsServerApp$' -or $failed.store -notmatch '^/[A-Za-z0-9_./-]+/dhcp-allocation.json$') {throw 'Unsafe executable or original journal path'}
    if($failed.coreSha256 -notmatch '^[A-Fa-f0-9]{64}$') {throw 'A qualified core binary hash is required'}
    $minimumSequence=0;foreach($survivor in $survivors){$known=@($states[$survivor.owner].state.replicas|Where-Object {$_.node -ceq $failed.owner -and $_.scope -ceq $scope});foreach($replica in $known){$minimumSequence=[Math]::Max($minimumSequence,[long]$replica.sequence)}}
    $request=@{minimumSequence=$minimumSequence;executable=$failed.executable;coreSha256=$failed.coreSha256;store=$failed.store;owner=$failed.owner;scope=$scope;receivers=($operation.receivers -join ',');id=$operation.id;output=('/var/tmp/teqtanium-unused-'+$operation.id+'.json')}
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Compress)))
    $command=@'
set -eu
umask 077
python3 - <<'PY'
import base64,os,pathlib,shutil,subprocess,uuid
r=__import__('json').loads(base64.b64decode('REQUEST'))
assert uuid.UUID(hex=r['id']).hex==r['id']
store=pathlib.Path(r['store'])
backup=pathlib.Path('/var/backups')/('teqtanium-unused-'+r['id'])
backup.mkdir(mode=0o700,exist_ok=True)
for suffix in ('','.required'):
 source=pathlib.Path(str(store)+suffix);assert source.is_file()
 destination=backup/source.name
 if not destination.exists():
  with source.open('rb') as src,destination.open('xb') as dst:
   shutil.copyfileobj(src,dst);dst.flush();os.fsync(dst.fileno())
archive=backup/'configuration-before.tar.gz'
if not archive.exists():
 pending=backup/'configuration-before.tmp'
 subprocess.run(['tar','--exclude=./stats','--exclude=./cache.bin','--exclude=./apps/Query Logs (Sqlite)','-czf',str(pending),'-C',str(store.parent),'.'],check=True)
 with pending.open('rb') as f:os.fsync(f.fileno())
 os.replace(pending,archive)
fd=os.open(backup,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
PY
service_user=$(systemctl show dns.service -p User --value); test -n "$service_user"
runuser -u "$service_user" -- python3 - <<'PY'
import base64,hashlib,json,os,pathlib,subprocess
r=json.loads(base64.b64decode('REQUEST'))
assert hashlib.sha256(pathlib.Path(r['executable']).with_name('DnsServerCore.dll').read_bytes()).hexdigest().upper()==r['coreSha256'].upper(),'Recovery binary differs from qualified core'
state=json.loads(pathlib.Path(r['store']).read_text())
replica=next((x for x in state['replicas'] if x['node']==r['owner'] and x['scope']==r['scope']),None)
sequence=replica['sequence'] if replica else 0
assert sequence>=r['minimumSequence'],'Original journal is older than current peer authority; retain fence'
subprocess.run([r['executable'],'--dhcp-recover-unused',r['store'],r['owner'],r['scope'],r['receivers'],r['id'],str(sequence),r['output']],check=True)
PY
'@
    $null=Guest $failed $vm ($command.Replace('REQUEST',$encoded))
    $operation.phase='Surrendered';Save $operationPath $operation
    $snapshotPath=Join-Path $directory ($operation.id+'-original-owner.json')
    $guestCredential=[pscredential]::new($credentials.($failed.address).sshUser,(ConvertTo-SecureString $credentials.($failed.address).sshPassword -AsPlainText -Force))
    Copy-VMGuestFile -Server $connection -VM $vm -GuestCredential $guestCredential -GuestToLocal -Source $request.output -Destination $snapshotPath -Force|Out-Null
    $snapshot=[IO.File]::ReadAllText($snapshotPath)
    $export=$snapshot|ConvertFrom-Json
    $plan=@($export.plans|Where-Object scope -CEQ $scope)
    $donor=@($export.replicas|Where-Object {$_.node -ceq $failed.owner -and $_.scope -ceq $scope})
    if($plan.Count -ne 1 -or $donor.Count -ne 1) {throw 'Original export lacks exact plan/donor'}
    $division=@($donor[0].unusedRecoveries|Where-Object id -CEQ $operation.id)
    if($division.Count -ne 1 -or ($division[0].receivers -join ',') -cne ($operation.receivers -join ',')) {throw 'Original export recovery identity differs'}
    foreach($survivor in $survivors) {
        $current=$states[$survivor.owner].state
        AssertAuthority $current $plan[0] $donor[0] $false
        $operation.freshAccess+=FreshPrivileges $survivor
        $null=Api $survivor 'ddi/dhcp/recoverUnusedOwner' @{owner=$failed.owner;scope=$scope;recoveryId=$operation.id;state=$snapshot} $sessions[$survivor.owner]
        $observed=(Api $survivor 'ddi/dhcp/state/get' @{} $sessions[$survivor.owner]).response
        if($observed.node -cne $survivor.owner){throw 'Receiver node identity differs'}
        AssertAuthority $observed.state $plan[0] $donor[0] $true
    }
    $operation.phase='Imported';Save $operationPath $operation
    # All receivers now have the grants and the ORIGINAL journal has revoked donor
    # authority. A cold-booted guest may need carrier before its static IP exists.
    try {
        NicState $vm $operation.adapters $true
        $address=$failed.address
        $start='set -eu; for attempt in $(seq 1 60); do if ip -4 -o address show | grep -F " '+$address+'/"; then break; fi; sleep 1; done; ip -4 -o address show | grep -F " '+$address+'/"; systemctl start dns.service; systemctl is-active dns.service'
        $null=Guest $failed $vm $start
        $operation.freshAccess+=FreshPrivileges $failed
        $rejoined=(Api $failed 'ddi/dhcp/state/get' @{} $sessions[$failed.owner]).response
        if($rejoined.node -cne $failed.owner){throw 'Rejoined node identity differs'}
        AssertAuthority $rejoined.state $plan[0] $donor[0] $true
    } catch {
        NicState $vm $operation.adapters $false
        $operation.phase='Imported';Save $operationPath $operation
        throw
    }
    foreach($survivor in $survivors) {
        try {$null=Api $survivor 'settings/get' @{} $originalSessions[$survivor.owner]}
        catch [UnauthorizedAccessException] {
            # A long-running controller's original token may expire naturally.
            # Fresh source-aware read/modify already passed; never log it out or
            # mistake expiry for an unavailable owner and start another recovery.
        }
    }
    $operation.phase='Completed';Save $operationPath $operation
}
try {
    if(@($configuration.nodes).Count -lt 2 -or @($configuration.nodes.owner|Select-Object -Unique).Count -ne $configuration.nodes.Count) {throw 'Configure at least two distinct pinned owners'}
    foreach($node in $configuration.nodes) {
        if($node.owner -cnotmatch '^[a-z0-9][a-z0-9.-]{0,252}$'){throw 'Pin a safe canonical owner identity'}
        $parsed=$null
        if($node.address -notmatch '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' -or ![Net.IPAddress]::TryParse([string]$node.address,[ref]$parsed)) {throw 'Pin each owner to an IPv4 management address'}
    }
    $polls=0
    do {
        foreach($pendingSave in @(Get-ChildItem -LiteralPath $directory -Filter '*.tmp')) {
            if(!(Test-Path -LiteralPath ($pendingSave.FullName -replace '\.tmp$',''))){throw 'Uncommitted recovery journal requires reconciliation'}
        }
        $live=@();$offline=@();$states=@{}
        foreach($node in $configuration.nodes) {
            try {
                if(!$sessions[$node.owner]) {$sessions[$node.owner]=Login $node;$originalSessions[$node.owner]=$sessions[$node.owner]}
                try {$state=(Api $node 'ddi/dhcp/state/get' @{} $sessions[$node.owner]).response}
                catch [UnauthorizedAccessException] {$sessions[$node.owner]=Login $node;$state=(Api $node 'ddi/dhcp/state/get' @{} $sessions[$node.owner]).response}
                if($state.node -ne $node.owner) {throw 'Authenticated node identity differs from configuration'}
                $states[$node.owner]=$state;$live+=$node;$failures[$node.owner]=0
            } catch [Net.Sockets.SocketException] {
                $failures[$node.owner]++;if($failures[$node.owner] -ge 3){$offline+=$node}
            }
        }
        # Once fencing/surrender has begun, finishing the saved transaction no
        # longer depends on a client continuing to retry or its demand flag.
        foreach($pendingFile in @(Get-ChildItem -LiteralPath $directory -Filter '*.json')) {
            # Historical journals must never be abandoned when adopting the new namespace.
            # Only structurally recognizable snapshot exports are non-transaction documents.
            if($pendingFile.Name -notlike 'operation-*.json') {
                $document=Get-Content -LiteralPath $pendingFile.FullName -Raw|ConvertFrom-Json
                if($pendingFile.Name -match '^[a-f0-9]{32}-original-owner\.json$' -and $document.plans -and $document.replicas -and !$document.phase){continue}
                throw 'Legacy or unknown recovery record requires explicit reconciliation; no new transaction permitted'
            }
            $pending=Get-Content -LiteralPath $pendingFile.FullName -Raw|ConvertFrom-Json
            if(!$pending.phase){throw 'Invalid operation journal; retain fence'};if($pending.phase -eq 'Completed'){continue}
            $target=@($configuration.nodes|Where-Object owner -eq $pending.owner)
            $receivers=@($live|Where-Object owner -in $pending.receivers)
            if($target.Count -ne 1 -or $receivers.Count -ne $pending.receivers.Count){throw 'Pending recovery requires its original target and receivers; retain the saved fence'}
            Recover $target[0] $receivers $pending.scope $pending.demand
        }
        foreach($node in $live) {
            foreach($status in @($states[$node.owner].scopeStatus|Where-Object {$_.enabled -and $_.overflowRequestedUtc})) {
                $plan=@($states[$node.owner].state.plans|Where-Object scope -eq $status.scope)[0]
                # An unreserved client cannot gain capacity from a reservation-only
                # scope. Such demand must not cycle an otherwise recoverable VM.
                if(!(HasDynamicCapacity $plan)){continue}
                foreach($failed in @($offline|Where-Object owner -in $plan.owners)) {
                    $receivers=@($live|Where-Object owner -in $plan.owners)
                    foreach($receiver in $receivers) {
                        $other=@($states[$receiver.owner].state.plans|Where-Object scope -eq $status.scope)[0]
                        if(($plan|ConvertTo-Json -Depth 100 -Compress) -cne ($other|ConvertTo-Json -Depth 100 -Compress)) {throw 'Survivors disagree about immutable allocation membership'}
                        if(!(Resolve-DnsName -Name $configuration.dnsProbeName -Server $receiver.address -Type A -DnsOnly -ErrorAction Stop)) {throw 'Surviving DNS availability must pass before fencing'}
                    }
                    Recover $failed $receivers $status.scope ([string]$status.overflowRequestedUtc)
                }
            }
        }
        $polls++
        if(!$Once -or $polls -lt 3){Start-Sleep -Seconds 5}
    } while(!$Once -or $polls -lt 3)
} finally {$writer.Dispose()}


