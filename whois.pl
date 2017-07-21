#!/opt/local/bin/perl

package Whois;
use strict;
use warnings;

use parent 'Net::Server::PreFork';
use Socket6;
use IO::Socket::INET6;
use Net::Whois::Raw;
use Net::CIDR;

sub process_request {
	(my $request = <>) =~ s/[.]([^.]+)\x{0d}\x{0a}/.$1/;

	if ($1) {
		print whois($request);
	} else {
		print whois($request, 'whois.radb.net');
	}
}

Whois->run(
	user			=> "nobody",
	#group			=> "nobody",	# FreeBSD?
	group			=> "nogroup",	# Debian9
	port			=> 43,
	ipv			=> '*',
	pid_file		=> "/var/tmp/whois.pl.pid",
	background		=> 1,
	setsid			=> 1,
	#reverse_lookups	=> 1,
	#allow			=> "domain\.tld",
	#cidr_allow		=> '192.168.1.0/24',
	min_servers		=> 1,	  #min number of children
	max_servers		=> 10,	 #max number of children
	min_spare_servers	=> 1,	  #fork if we don't have this many waiting
	max_spare_servers	=> 5,	  #kill if we have this many waiting
	max_requests		=> 1000, #num of requests before killing a child	
);
