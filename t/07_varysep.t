use strict;
use warnings;
use blib;

use Test::More tests => 33;

BEGIN { use_ok('Mail::SRS'); }
BEGIN { use_ok('Mail::SRS::Guarded'); }
BEGIN { use_ok('Mail::SRS::Reversible'); }

foreach my $subclass (qw(Guarded Reversible)) {
	my $class = "Mail::SRS::$subclass";
	my $srs0 = $class->new(
			Secret		=> "foo",
			Separator	=> "+",
				);
	my $srs1 = $class->new(
			Secret		=> "foo",
			Separator	=> "-",
				);

	my @tests = qw(
		user@domain-with-dash.com
		user-with-dash@domain.com
		user+with+plus@domain.com
		user=with=equals@domain.com
		user%with!everything&everything=@domain.somewhere
			);
	my $alias0 = 'alias@host.com';
	my $alias1 = 'name@forwarder.com';

	foreach (@tests) {
		my $srs0addr = $srs0->forward($_, $alias0);
		my $orig0 = $srs0->reverse($srs0addr);
		is($orig0, $_, 'Idempotent on ' . $_);

		my $srs1addr = $srs1->forward($srs0addr, $alias1);
		my $srs1rev = $srs1->reverse($srs1addr);
		is($srs1rev, $srs0addr, 'Idempotent on ' . $srs0addr);

		my $orig1 = $srs0->reverse($srs1rev);
		is($orig1, $_, 'Dually idempotent on ' . $_);
	}
}
