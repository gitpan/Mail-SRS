package Mail::SRS::Reversable;

use strict;
use warnings;
use base 'Mail::SRS';
use Carp;

=head1 NAME

Mail::SRS::Reversable - A fully reversable Sender Rewriting Scheme

=head1 SYNOPSIS

	use Mail::SRS::Reversable;
	my $srs = new Mail::SRS::Reversable(...);

=head1 DESCRIPTION

See Mail::SRS for details of the standard SRS subclass interface.
This module provides the methods compile() and parse(). It operates
without store.

=head1 SEE ALSO

Mail::SRS

=cut

sub compile {
	my ($self, $sendhost, $senduser) = @_;

	my $timestamp = $self->timestamp_create();

	# This has to be done in compile, because we might need access
	# to it for storing in a database.
	my $hash = $self->hash_create($timestamp, $sendhost, $senduser);

	# Note that there are 4 fields here and that sendhost may
	# not contain a + sign. Therefore, we do not need to escape
	# + signs anywhere in order to reverse this transformation.
	return join($self->separator,
					$Mail::SRS::SRSTAG,
					$hash, $timestamp, $sendhost, $senduser);
}

sub parse {
	my ($self, $user) = @_;

	unless ($user =~ m/^\Q$Mail::SRS::SRSTAG$self->{Separator}\E/oi) {
		die "Reverse address does not start with $Mail::SRS::SRSTAG.";
	}

	# The 5 here matches the number of fields we encoded above. If
	# there are more + signs, then they belong in senduser anyway.
	my (undef, $hash, $timestamp, $sendhost, $senduser) =
					split(qr/\Q$self->{Separator}\E/, $user, 5);
	# Again, this must match as above.
	unless ($self->hash_verify($hash,$timestamp,$sendhost,$senduser)) {
		die "Invalid hash";
	}

	unless ($self->timestamp_check($timestamp)) {
		die "Invalid timestamp";
	}

	return ($sendhost, $senduser);
}

1;
