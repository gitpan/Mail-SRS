package Mail::SRS::Guarded;

use strict;
use warnings;
use vars qw(@ISA);
use Carp;
use Mail::SRS qw(:all);
use Mail::SRS::Shortcut;

@ISA = qw(Mail::SRS::Shortcut);

=head1 NAME

Mail::SRS::Guarded - A guarded Sender Rewriting Scheme (recommended)

=head1 SYNOPSIS

	use Mail::SRS::Guarded;
	my $srs = new Mail::SRS::Guarded(...);

=head1 DESCRIPTION

See Mail::SRS for details of the standard SRS subclass interface.
This module provides the methods compile() and parse(). It operates
without store, and guards against gaming the shortcut system.

=head1 SEE ALSO

Mail::SRS

=cut

sub compile {
	my ($self, $sendhost, $senduser) = @_;

	if ($senduser =~ m/^\Q$SRSWRAP$SRSSEP\E/io) {
		# We just do the split because this was hashed with someone else's
		# secret key and we can't check it.
		# SRSWRAP, host, srs0addr
		my (undef, $srshost, $srsuser) =
						split(qr/\Q$SRSSEP\E/, $senduser, 3);
		# We should do this sanity check. After all, it might NOT be
		# an SRS address, unlikely though that is. We are in the presence
		# of malicious agents. We can check more rigorously than this...
		if (defined $srshost and defined $srsuser) {
			return join($SRSSEP,
							$SRSWRAP, $srshost, $srsuser);
		}
	}
	elsif ($senduser =~ s/^\Q$SRSTAG$SRSSEP\E//io) {
		# Implementors please note, the last one was m//, this is s///
		return join($SRSSEP,
						$SRSWRAP, $sendhost, $senduser);
	}

	return $self->SUPER::compile($sendhost, $senduser);
}

sub parse {
	my ($self, $user) = @_;

	if ($user =~ m/^\Q$SRSWRAP$SRSSEP\E/oi) {
		my (undef, $srshost, $srsuser) =
						split(qr/\Q$SRSSEP\E/, $user, 3);
		unless (defined $srshost and defined $srsuser) {
			die "Invalid wrapped SRS address";
		}
		return ($srshost, "$SRSTAG$SRSSEP$srsuser");
	}

	return $self->SUPER::parse($user);
}

1;
