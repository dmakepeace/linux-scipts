#!/usr/bin/perl -w
# analyze_sshd_log.pl analyzes the /var/log/secure.log
# for successful and failed login attempts. It will log
# the output in the user's home directory 'secure.log'
# MUST BE ROOT TO RUN

my $secure_log="/var/log/secure";
my $output_file="/tmp/secure.log";
open SECURE, '<',  $secure_log;
open OUTLOG, '>', $output_file;
my %failed_list;
my %accept_list;
my $login_id;
my $ip;
my $cnt;

while (<SECURE>) {
	# Check for failed login attempts. Show user name and IP.
	if (/(Failed password for)(?: invalid user)? (?<user>\S+) (?:.*) (?<ip>\d+.\d+.\d+.\d+)/) {
		if (!defined ($failed_list{$+{user} ."-". $+{ip}})) {
			#printf "Failed login for user: '%-12s' (%s)\n", $+{user}, $+{ip} ;
			$failed_list{$+{user} ."-". $+{ip}}=1;
		} else { $failed_list{$+{user} ."-". $+{ip}} += 1; }
	}
	# Check for successful login attempts. 
	if (/(Accepted password for) (?<user>\w+) (?:.*) (?<ip>\d+.\d+.\d+.\d+)/) {
		if (!defined ($accept_list{$+{user} ."-". $+{ip}})) {
			#printf "Successful login for user: '%-12s' (%s)\n", $+{user}, $+{ip} ;
			$accept_list{$+{user} ."-". $+{ip}}=1;
		} else {$accept_list{$+{user} ."-". $+{ip}} += 1;}
	}
}

print OUTLOG `date`;
print OUTLOG "\n===== Failed Login's =====\n";
foreach $key (keys %failed_list) {
	$cnt = $failed_list{$key} - 1;
	if ($key =~ /(?<name>\w+)-(?<ip>\d+.\d+.\d+.\d+)/) {
		$login_id = $+{name};
		$ip = $+{ip};
#		print "Login: $login_id\nIP: $ip\n";
	}
	if ($cnt < 2) {
		printf OUTLOG "Failed login for user: '%-12s' (%s)\n", $login_id, $ip;
	} else {  printf OUTLOG "Failed login for user: '%-12s' (%s)\t+ %d more times (not shown)\n", $login_id, $ip, $cnt; }
}

print OUTLOG "\n===== Successful Login's =====\n";
foreach $key (keys %accept_list) {
	$cnt = $accept_list{$key} - 1 ;
	if ($key =~ /(?<name>\w+)-(?<ip>\d+.\d+.\d+.\d+)/) {
                $login_id = $+{name};
                $ip = $+{ip};
#		print "Login: $login_id\nIP: $ip\n";
       }
       if ($cnt < 2) {
	       printf OUTLOG "Successful login for user: '%-12s' (%s)\n", $login_id, $ip;
	} else {  printf OUTLOG "Successful login for user: '%-12s' (%s)\t+ %d more times (not shown)\n", $login_id, $ip, $cnt; }

}

printf "Output created. See /tmp/secure.log\n";

close SECURE;
close OUTLOG;
