use 5.006;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Mail::SRS',
    'VERSION_FROM'	=> 'lib/Mail/SRS.pm', # finds $VERSION
    'PREREQ_PM'		=> {
				'Digest::HMAC_SHA1'	=> 1.01,
				'Test::More'		=> 0.40,
				'MLDBM'				=> 2.01,
				'Storable'			=> 2.04,
				'DB_File'			=> 1.806,
				'Mail::Address'		=> 1.60,
			}, # e.g., Module::Name => 1.1
	ABSTRACT_FROM => 'lib/Mail/SRS.pm', # retrieve abstract from module
	AUTHOR     => 'Shevek <cpan@anarres.org>',
	clean		=> { FILES => 'test.db' },
);

sub MY::postamble {
	my $self = shift;
	my $old = $self->MM::postamble(@_);
	chomp($old);
	my $new = <<'EON';

.PHONY : teach aux readme

teach : all
	$(PERL) -Mblib eg/simple.pl

aux : readme

readme : lib/Mail/SRS.pm
	perldoc -t lib/Mail/SRS.pm > README

EON
	return $old . $new;
}
