# SPDX-License-Identifier: Apache-2.0
"""Fixed, version-qualified calls into the local Proxmox Perl implementation.

The string is source code, never constructed from request fields. Static Perl
eval blocks catch provider exceptions; no string eval or dynamic method exists.
"""

SOURCE = r'''
use strict;
use warnings;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use PVE::INotify;
use PVE::RPCEnvironment;
use PVE::API2::Qemu;
use PVE::API2::Tasks;
use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::QemuServer::Monitor qw(mon_cmd);
use PVE::ProcFSTools;
use PVE::Storage;
use PVE::HA::Config;

die "root required\n" if $> != 0;
open(my $answer, '>&', \*STDOUT) or die "response unavailable\n";
open(STDOUT, '>', '/dev/null') or die "output unavailable\n";
my $json = JSON::PP->new->canonical->utf8;
my $raw = do { local $/; <STDIN> };
die "request bound\n" if length($raw) > 1048576;
my $request = $json->decode($raw);
my $action = $request->{action};
my $node = PVE::INotify::nodename();
open(my $machine_file, '<', '/etc/machine-id') or die "identity unavailable\n";
my $machine = <$machine_file>; chomp($machine); close($machine_file);
die "identity invalid\n" unless $machine =~ /^[0-9a-f]{32}$/;
PVE::INotify::inotify_init();
my $rpcenv = PVE::RPCEnvironment->init('priv', atfork => sub { close($answer); });
$rpcenv->init_request();
$rpcenv->set_language('C');
$rpcenv->set_user('root@pam');

sub identity {
    my ($vmid, $conf) = @_;
    my $smbios = PVE::QemuServer::parse_smbios1($conf->{smbios1} // '');
    my @ids = ($smbios->{uuid} // '', $conf->{vmgenid} // '');
    foreach my $id (@ids) {
        die "FICC_VM_IDENTITY_UNAVAILABLE\n"
            unless $id =~ /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
        $id = lc($id); $id =~ s/-//g;
        die "FICC_VM_IDENTITY_UNAVAILABLE\n" if $id eq ('0' x 32);
    }
    return sprintf('%08x', $vmid) . substr(sha256_hex($json->encode({
        machine => $machine, smbios => $ids[0], generation => $ids[1],
    })), 0, 24);
}

sub describe {
    my ($vmid, $conf, $stats) = @_;
    $conf //= PVE::QemuConfig->load_config($vmid);
    my $uuid = identity($vmid, $conf);
    $stats //= PVE::QemuServer::vmstatus($vmid, 1)->{$vmid};
    die "FICC_VM_UNAVAILABLE\n" unless $stats;
    my $state = $stats->{status} eq 'stopped' ? 'off' :
        (($stats->{qmpstatus} // '') eq 'paused' ? 'paused' : 'running');
    return {uuid => $uuid, name => $conf->{name} // "VM $vmid", state => $state,
        vcpus => 0 + ($stats->{cpus} // 0), memory_kib => int(($stats->{mem} // 0) / 1024),
        max_memory_kib => int(($stats->{maxmem} // 0) / 1024),
        definition => sha256_hex($conf->{digest})};
}

sub status_rows {
    my ($ids) = @_;
    my @rows;
    my $stats = PVE::QemuServer::vmstatus(undef, 1);
    foreach my $uuid (@$ids) {
        my $data;
        my $ok = eval {
            my $vmid = hex(substr($uuid, 0, 8));
            die "FICC_VM_UNAVAILABLE\n" unless $stats->{$vmid};
            $data = describe($vmid, undef, $stats->{$vmid});
            die "FICC_VM_IDENTITY_CHANGED\n" unless $data->{uuid} eq $uuid;
            1;
        };
        push(@rows, $ok ? {uuid => $uuid, data => $data} : {uuid => $uuid,
            error => {code => 'vm_identity_unavailable', message => 'The VM identity or status cannot be verified.'}});
    }
    return \@rows;
}

sub power {
    my ($action, $expected) = @_;
    my $vmid = hex(substr($expected->{uuid}, 0, 8));
    my $worker = sub {
        my $ok = eval {
        PVE::QemuConfig->lock_config_full($vmid, 10, sub {
            my $conf = PVE::QemuConfig->load_config($vmid);
            my $current = describe($vmid, $conf);
            foreach my $field ('uuid', 'state', 'definition') {
                die "FICC_VM_CHANGED\n" unless $current->{$field} eq $expected->{$field};
            }
            die "FICC_VM_CONFIGURATION_UNSUPPORTED\n"
                if PVE::QemuConfig->is_template($conf) || $conf->{lock} || $conf->{vmstate}
                || $conf->{hookscript} || scalar(keys %{$conf->{pending} // {}})
                || PVE::HA::Config::vm_is_ha_managed($vmid);
            PVE::QemuConfig->check_lock($conf);
            my $storecfg = PVE::Storage::config();
            if ($action eq 'start') {
                die "FICC_VM_STATE_CONFLICT\n" unless $current->{state} eq 'off';
                my $ok = eval { PVE::QemuServer::vm_start_nolock($storecfg, $vmid, $conf,
                    {timeout => 60}, {}); 1; };
                die "FICC_VM_PROVIDER_FAILED\n" unless $ok;
            } else {
                die "FICC_VM_STATE_CONFLICT\n" unless $current->{state} eq 'running';
                my $ok = eval { PVE::QemuServer::_do_vm_stop($storecfg, $vmid,
                    0, 0, 60, 1, 0, 0); 1; };
                die "FICC_VM_PROVIDER_FAILED\n" unless $ok;
            }
        });
        1;
        };
        if (!$ok) {
            my $failure = $@;
            die($failure =~ /^FICC_VM_[A-Z_]+\n$/ ? $failure : "FICC_VM_PROVIDER_FAILED\n");
        }
    };
    my $upid = $rpcenv->fork_worker('ficcvm' . $action, $vmid, 'root@pam', $worker);
    return {uuid => $expected->{uuid}, state => 'accepted', task => {upid => $upid, state => 'running'}};
}

my $result;
if ($action eq 'list') {
    my $vms = PVE::API2::Qemu->vmlist({node => $node, full => 0});
    die "inventory bound\n" if scalar(@$vms) > 4096;
    my @ids;
    foreach my $vm (sort {$a->{vmid} <=> $b->{vmid}} @$vms) {
        my $id = eval { identity($vm->{vmid}, PVE::QemuConfig->load_config($vm->{vmid})); };
        $id //= sprintf('%08x', $vm->{vmid}) . ('0' x 24);
        push(@ids, $id);
    }
    my $offset = $request->{parameters}->{offset};
    my $limit = $request->{parameters}->{limit};
    my @selected = $offset < @ids ? @ids[$offset .. (($offset + $limit < @ids ? $offset + $limit : scalar(@ids)) - 1)] : ();
    my $end = $offset + @selected;
    $result = {results => status_rows(\@selected), total => scalar(@ids),
        next_offset => $end < @ids ? $end : undef, truncated => $end < @ids ? JSON::PP::true : JSON::PP::false,
        inventory_digest => sha256_hex(join('', @ids))};
} elsif ($action eq 'status') {
    $result = {results => status_rows($request->{parameters}->{uuids})};
} elsif ($action eq 'apply') {
    my @rows;
    foreach my $expected (@{$request->{parameters}->{intent}->{expected}}) {
        my $row = eval { power($request->{parameters}->{intent}->{action}, $expected); };
        $row //= {uuid => $expected->{uuid}, state => 'unknown',
            error => {code => 'vm_outcome_unknown', message => 'The provider did not return a task identity.'}};
        push(@rows, $row);
    }
    $result = {results => \@rows};
} elsif ($action eq 'console' || $action eq 'console-bind') {
    PVE::Cluster::cfs_update();
    my $uuid = $request->{parameters}->{uuids}->[0];
    my $vmid = hex(substr($uuid, 0, 8));
    my $conf = PVE::QemuConfig->load_config($vmid);
    my $current = describe($vmid, $conf);
    die "console identity changed\n" unless $current->{uuid} eq $uuid && $current->{state} ne 'off';
    die "console unavailable\n" if ($conf->{vga} // 'std') =~ /^(none|serial[0-3])(?:,|$)/;
    $result = {uuid => $uuid, protocol => 'vnc', audio => JSON::PP::false, authentication => 'rfb-password'};
    if ($action eq 'console-bind') {
        my $password = $request->{parameters}->{password};
        die "credential invalid\n" unless $password =~ /^[A-Za-z0-9]{8}$/;
        my $pid = PVE::QemuServer::Helpers::vm_running_locally($vmid);
        my $start = $pid && PVE::ProcFSTools::read_proc_starttime($pid);
        die "process unavailable\n" unless $pid && $start;
        mon_cmd($vmid, 'set_password', protocol => 'vnc', password => $password);
        mon_cmd($vmid, 'expire_password', protocol => 'vnc', time => '+30');
        $result->{pid} = 0 + $pid;
        $result->{start} = 0 + $start;
        $result->{path} = PVE::QemuServer::Helpers::vnc_socket($vmid);
    }
} elsif ($action eq 'tasks') {
    my @tasks;
    foreach my $upid (@{$request->{parameters}->{upids}}) {
        my $value = eval { PVE::API2::Tasks->read_task_status({node => $node, upid => $upid}); };
        my $task = {upid => $upid, state => $value ? $value->{status} : 'unknown'};
        if ($value && $value->{status} eq 'stopped') {
            my $exit = $value->{exitstatus};
            $exit = 'FICC_VM_TASK_STATUS_UNAVAILABLE' unless defined($exit) && length($exit) <= 256 && $exit !~ /[\x00-\x1f\x7f]/;
            $task->{exitstatus} = $exit;
        }
        push(@tasks, $task);
    }
    $result = {tasks => \@tasks};
} else {
    die "action denied\n";
}
print {$answer} $json->encode($result);
close($answer);
'''
