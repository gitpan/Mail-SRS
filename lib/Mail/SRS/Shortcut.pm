package Mail::SRS::Shortcut;

use strict;
use warnings;
use vars qw(@ISA);
use Carp;
use Mail::SRS qw(:all);

@ISA = qw(Mail::SRS);

=head1 NAME

Mail::SRS::Shortcut - A shortcutting Sender Rewriting Scheme

=head1 SYNOPSIS

	use Mail::SRS::Shortcut;
	my $srs = new Mail::SRS::Shortcut(...);

=head1 DESCRIPTION

WARNING: Using the simple Shortcut strategy is a very bad idea. Use the
Guarded strategy instead. The weakness in the Shortcut strategy is
documented at http://www.anarres.org/projects/srs/

See Mail::SRS for details of the standard SRS subclass interface.
This module provides the methods compile() and parse(). It operates
without store, and shortcuts around all middleman resenders.

=head1 SEE ALSO

L<Mail::SRS>

=cut

sub compile {
	my ($self, $sendhost, $senduser) = @_;

	if ($senduser =~ s/^$SRS0RE//io) {
		# We just do the split because this was hashed with someone else's
		# secret key and we can't check it.
		# hash, timestamp, host, user
		(undef, undef, $sendhost, $senduser) =
						split(qr/\Q$SRSSEP\E/, $senduser, 4);
		# We should do a sanity check. After all, it might NOT be
		# an SRS address, unlikely though that is. We are in the
		# presence of malicious agents.
	}
	elsif ($senduser =~ s/$SRS1RE//io) {
		# Introduce compatibility with the guarded format?
		# SRSHOST, hash, timestamp, host, user
		(undef, undef, undef, $sendhost, $senduser) =
						split(qr/\Q$SRSSEP\E/, $senduser, 6);
	}

	my $timestamp = $self->timestamp_create();

	# This has to be done in compile, because we might need access
	# to it for storing in a database.
	my $hash = $self->hash_create($timestamp, $sendhost, $senduser);

	# Note that there are 5 fields here and that sendhost may
	# not contain a + sign. Therefore, we do not need to escape
	# + signs anywhere in order to reverse this transformation.
	return $SRS0TAG . $self->separator .
			join($SRSSEP, $hash, $timestamp, $sendhost, $senduser);
}

sub parse {
	my ($self, $user) = @_;

	unless ($user =~ s/$SRS0RE//oi) {
		die "Reverse address does not match $SRS0RE.";
	}

	# The 4 here matches the number of fields we encoded above. If
	# there are more + signs, then they belong in senduser anyway.
	my ($hash, $timestamp, $sendhost, $senduser) =
					split(qr/\Q$SRSSEP\E/, $user, 4);
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
