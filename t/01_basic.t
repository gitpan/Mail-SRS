use strict;
use warnings;
use blib;

use Test::More tests => 29;

use_ok('Mail::SRS');

my $srs = new Mail::SRS(
				Secret	=> "foo",
					);
ok(defined $srs, 'Created an object');
isa_ok($srs, 'Mail::SRS');
my @secret = $srs->get_secret;
is($secret[0], 'foo', 'Secret was stored OK');
$srs->set_secret('bar', @secret);
@secret = $srs->get_secret;
is($secret[0], 'bar', 'Secret was updated OK');
is($secret[1], 'foo', 'Old secret was preserved');

my $h = $srs->hash_create("foo");
ok(defined $h, 'Hashing seems to work');
ok($srs->hash_verify($h, "foo"), 'Hashes verify OK');
ok(! $srs->hash_verify("random", "foo"), 'Bad hashes fail hash verify');
ok(! $srs->hash_verify($h, "bar"), 'Wrong data fails hash verify');

my $t = $srs->timestamp_create();
ok(defined $t, 'Created a timestamp');
ok(length $t == 2, 'Timestamp is 2 characters');
ok($srs->timestamp_check($t), 'Timestamp verifies');
my $notlong = 60 * 60 * 24 * 3;
my $ages = 60 * 60 * 24 * 50;
ok($srs->timestamp_check($srs->timestamp_create(time() - $notlong)),
		'Past timestamp is OK');
ok(! $srs->timestamp_check($srs->timestamp_create(time() - $ages)),
		'Antique timestamp fails');
ok(! $srs->timestamp_check($srs->timestamp_create(time() + $notlong)),
		'Future timestamp fails');
ok(! $srs->timestamp_check($srs->timestamp_create(time() + $ages)),
		'Future timestamp fails');

my $source = "user\@host.tld";
my @alias = map { "alias$_\@host$_\.tld$_" } (0..5);
my $new0 = $srs->forward($source, $alias[0]);
ok(length $new0, 'Made a new address');
like($new0, qr/^SRS/, 'It is an SRS address');
my $old0 = $srs->reverse($new0);
ok(length $old0, 'Reversed the address');
ok($old0 eq $source, 'The reversal was idempotent');

my $new1 = $srs->forward( $new0, $alias[1]);
# print STDERR "Composed is $new1\n";
ok(length $new1, 'Made another new address with the SRS address');
like($new1, qr/^SRS/, 'It is an SRS address');
my $old1 = $srs->reverse($new1);
ok(length $old1, 'Reversed the address again');
ok($old1 eq $source, 'Got back the original sender');

my @tests = qw(
	user@domain-with-dash.com
	user-with-dash@domain.com
	user+with+plus@domain.com
	user%with!everything&everything=@domain.somewhere
		);
my $alias = "alias\@host.com";
foreach (@tests) {
	my $srsaddr = $srs->forward($_, $alias);
	my $oldaddr = $srs->reverse($srsaddr);
	is($oldaddr, $_, 'Idempotent on ' . $_);
}
