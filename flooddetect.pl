#!/usr/bin/perl 
#
## Flood detection tool by Claudiu Filip - claudiu@mysql.ro

use Net::Pcap;
sub loop_exit { Net::Pcap::breakloop($pcap); }
sub fail() { print STDERR "$IP telnet FAILED!\n"; }; 

local $pcap;
my @exceptions		= ('192.168.1.');			# Exceptions list
my $bgp_peer		= '192.168.1.1';			# BGP Peer that needs to be cleared
my $dev				= 'eth0';					# Monitorized interface
my $threshold		= 6500;						# Maximum limit of pps
my $timeinterval	= 10;						# Time Interval to read from the interface
my $nr_packets		= 50000;					# Max number of packedts to read
my $max_loss		= 3000 * $timeinterval;		# Max number of lost packets
my $snap_length		= 128;						# How muh to read from a packet
my $packetsnapshot	= 20;						# Number of captured packets
my $snapshotto		= 4;						# Snapshot time out
my $promisc 		= 1;						# Put interface in promiscuous mode
my $to_ms			= 0;
my $filter_str		= '';						# Some tcpdump fillter if we need any
my $optimize		= 1;						# Optimize filter
my $netmask			= 0;
my $log_path		= '/tmp/';					# Where we should save the tcpdump snapshots
my $IP				= '127.0.0.1';				# bgpd IP address
my $err;
my %count;
my $filter			= '';

local $dumper;
$pcap = Net::Pcap::open_live($dev, $snap_length, $promisc, $to_ms, \$err);
$pcap || die "Can't create packet descriptor. Error was $err";

if ( Net::Pcap::compile($pcap, \$filter, $filter_str, $optimize, $netmask) == -1 ) {
	$err = Net::Pcap::geterr($pcap);
	die "Invalid filter: $filter_str (error was: $err)\n";
} else {
	Net::Pcap::setfilter($pcap, $filter);
}

local $SIG{ALRM} = \&loop_exit;
my $start_time = time();
alarm $timeinterval;
my $exitcode = Net::Pcap::loop($pcap, $nr_packates, \&process_packet, '');
my $message = '';
my @add2bgp = ();
my $subject = 'FLOOD';
my $maxx = 0; my $loss_ip = '';
while (($key, $value) = each %count) {
	$key2 = sprintf("%d.%d.%d.%d", ord(substr($key,0,1)),ord(substr($key,1,1)),ord(substr($key,2,1)),ord(substr($key,3,1)));
	$key = $key2;

	my $nr = map { $key =~ /$_/x } @exceptions;
	next if $nr > 0;
	if ($value > $maxx) {
		$maxx = $value;
		$loss_ip = $key;
	}

	if (($value/$timeinterval) > $threshold) {
		###### FLOOOOOOOOOOOOD
		$subject .= ' '.$key;
		$message .= "\nFlood TO ". $key . "\t(".int($value/$timeinterval).' pps - Max. limit '.$threshold.')';
		push @add2bgp, $key;
	}
}

if ($message eq '') {
	if (($stats{ps_drop}+$stats{ps_ifdrop}) > $max_loss) {			## Flood rto $loss_ip
		$subject .= ' '.$loss_ip;
		$message .= "\nFlood TO ".$loss_ip ."\t(".int($maxx/$timeinterval).' pps = Max. limit '.$threshold.')\npackets loss by filter \t'.$stats{ps_drop}."\nAllowed Max number of lost packets ".$max loss;
		push @add2bgp, $loss_ip;
	}
}

if ($message ne '') {
	use Net::Telnet::Cisco;
	my $session = Net::Telnet::Cisco->new(Host => $IP, 
		Port => '2605',
		Timeout => 20,
		Errmode => \&fail);
	$ok = $session->cmd(String => 'p[',
		Prompt => '/bgpd[\$#>]/');
	$ok = $session->cmd(String => 'enable',
		Prompt => '/assword/',
		Timeout => 20);
	$ok = $session->cmd(String => 'p[',
		Prompt => '/bgpd[\$#>]/',
		Timeout => 20);
	$ok = $session->cmd(String => 'conf t',
		Timeout => 20,
		Prompt => '/bgpd\(config\)[\$#>]/');
	for ($i=0; $i<=$#add2bgp; $i++ ) {
		$key = $add2bgp[$i];
		$ok = $session->cmd(String => "access-list flood permit $key/32 exact-match",
			Timeout => 20,
			Prompt => '/bgpd\(config\)[\$#>]/');
		$ok = $session->cmd(String => "router bgp 65000",
			Timeout => 20,
			Prompt => '/bgpd\(config-router\)[\$#>]/');
		$ok = $session->cmd(String => "exit", 
			Timeout => 20,
			Prompt => '/bgpd\(config\)[\$#>]/');
	}
	$ok = $session->cmd(String => "exit",
		Prompt => '/bgpd[\$#>]/',
		Timeout => 20);
	$ok = $session->cmd(String => "clear ip bgp $bgp_peer out",
		Prompt => '/bgpd[\$#>]/',
		Timeout => 20);
	$ok = $session->cmd(String => "wr me",
		Prompt => '/bgpd[\$#>]/',
		Timeout => 20);

