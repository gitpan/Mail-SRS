use strict;
use warnings;
use blib;

use Test::More tests => 23;

use_ok('Mail::SRS');

my $srs = new Mail::SRS(
				Secret	=> "foo",
					);
ok(defined $srs, 'Created an object');
isa_ok($srs, 'Mail::SRS');
isa_ok($srs, 'Mail::SRS::Shortcut');
isa_ok($srs, 'Mail::SRS::Guarded');
my @secret = $srs->get_secret;
is($secret[0], 'foo', 'Can still call methods on new object');

my $source = 'user@host.tld';
my @alias = map { "alias$_\@host$_\.tld$_" } (0..5);

my $srs0 = $srs->forward($source, $alias[0]);
ok(length $srs0, 'Made a new address');
like($srs0, qr/^SRS0/, 'It is an SRS0 address');
my $old0 = $srs->reverse($srs0);
ok(length $old0, 'Reversed the address');
is($old0, $source, 'The reversal was idempotent');

my $srs1 = $srs->forward( $srs0, $alias[1]);
# print STDERR "Composed is $srs1\n";
ok(length $srs1, 'Made another new address with the SRS address');
like($srs1, qr/^SRS1/, 'It is an SRS1 address');
my $old1 = $srs->reverse($srs1);
ok(length $old1, 'Reversed the address again');
like($old1, qr/^SRS0/, 'It is the original SRS0 address');
my $orig = $srs->reverse($old1);
is($orig, $source, 'Got back the original sender');

my @tests = qw(
	user@domain-with-dash.com
	user-with-dash@domain.com
	user+with+plus@domain.com
	user%with!everything&everything=@domain.somewhere
		);
my $alias = 'alias@host.com';
foreach (@tests) {
	my $srs0addr = $srs->forward($_, $alias);
	my $oldaddr = $srs->reverse($srs0addr);
	is($oldaddr, $_, 'Idempotent on ' . $_);
	my $srs1addr = $srs->forward($srs0addr, $alias);
	my $srs0rev = $srs->reverse($srs1addr);
	is($srs0rev, $srs0addr, 'Idempotent on ' . $srs0addr);
}
