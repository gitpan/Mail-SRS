package Mail::SRS;

use strict;
use warnings;
use vars qw($VERSION @ISA @EXPORT_OK %EXPORT_TAGS
				$SRSTAG $SRSWRAP $SRSSEP);
use Exporter;
use Carp;
use Digest::HMAC_SHA1;

$VERSION = "0.18";
@ISA = qw(Exporter);

$SRSTAG = "SRS0";
$SRSWRAP = "SRS1";
$SRSSEP = "=";

@EXPORT_OK = qw($SRSTAG $SRSWRAP $SRSSEP);
%EXPORT_TAGS = (
		all	=> \@EXPORT_OK,
			);

=head1 NAME

Mail::SRS - Interface to Sender Rewriting Scheme

=head1 SYNOPSIS

	use Mail::SRS;
	my $srs = new Mail::SRS(
		Secret     => [ .... ],    # scalar or array
		MaxAge     => 49,          # days
		HashLength => 4,           # base64 characters: 4 x 6bits
		HashMin    => 4,           # base64 characters
			);
	my $srsaddress = $srs->forward($sender, $alias);
	my $sender = $srs->reverse($srsaddress);

=head1 DESCRIPTION

The Sender Rewriting Scheme preserves .forward functionality in an
SPF-compliant world.

SPF requires the SMTP client IP to match the envelope sender
(return-path).  When a message is forwarded through an intermediate
server, that intermediate server may need to rewrite the return-path
to remain SPF compliant.  If the message bounces, that intermediate
server needs to validate the bounce and forward the bounce to the
original sender.

SRS provides a convention for return-path rewriting which allows
multiple forwarding servers to compact the return-path. SRS also
provides an authentication mechanism to ensure that purported bounces
are not arbitrarily forwarded.

SRS is documented at http://spf.pobox.com/srs.html and many points
about the scheme are discussed at http://www.anarres.org/projects/srs/

For a better understanding of this code and how it functions, please
run the interactive walkthrough in eg/simple.pl in this distribution.
To run this from the build directory, type "make teach".

=head1 METHODS

=head2 $srs = new Mail::SRS(...)

Construct a new Mail::SRS object and return it. Available parameters
are:

=over 4

=item Secret

A key for the cryptographic algorithms. This may be an array or a single
string. A string is promoted into an array of one element.

=item MaxAge

The maximum number of days for which a timestamp is considered
valid. After this time, the timestamp is invalid.

=item HashLength

The number of bytes of base64 encoded data to use for the cryptographic
hash. More is better, but makes for longer addresses which might
exceed the 64 character length suggested by RFC2821. This defaults to
4, which gives 4 x 6 = 24 bits of cryptographic information, which
means that a spammer will have to make 2^24 attempts to guarantee
forging an SRS address.

=item HashMin

The shortest hash which we will allow to pass authentication. Since we
allow any valid prefix of the full SHA1 HMAC to pass authentication,
a spammer might just suggest a hash of length 0. We require at least
HashMin characters, which must all be correct. Naturally, this must
be no greater than HashLength and will default to HashLength unless
otherwise specified.

=back

Some subclasses require other parameters. See their documentation for
details.

=cut

sub new {
	my $class = shift;

	if ($class eq 'Mail::SRS') {
		require Mail::SRS::Guarded;
		return new Mail::SRS::Guarded(@_);
	}

	my $self = ($#_ == 0) ? { %{ (shift) } } : { @_ };
	$self->{Secret} = [ $self->{Secret} ]
					unless ref($self->{Secret}) eq 'ARRAY';
	$self->{MaxAge} = 31 unless $self->{MaxAge};
	$self->{HashLength} = 4 unless $self->{HashLength};
	$self->{HashMin} = $self->{HashLength} unless $self->{HashMin};
	return bless $self, $class;
}

=head2 $srsaddress = $srs->forward($sender, $alias)

Map a sender address into a new sender and a cryptographic cookie.
Returns an SRS address to use as the new sender.

There are alternative subclasses, some of which will return SRS
compliant addresses, some will simply return non-SRS but valid RFC821
addresses. See the interactive walkthrough for more information on this
("make teach").

=cut

sub forward {
	my ($self, $sender, $alias) = @_;

	$sender =~ m/^(.*)\@([^\@]+)$/
					or die "Sender '$sender' contains no @";
	my ($senduser, $sendhost) = ($1, $2);
	$senduser =~ m/\@/ and die 'Sender username may not contain an @';

	# We don't require alias to be a full address, just a domain will do
	if ($alias =~ m/^(.*)\@([^@]+)$/) {
		$alias = $2;
	}
	my $aliashost = $alias;

	# Subclasses may override the compile() method.
	my $srsdata = $self->compile($sendhost, $senduser);
	return "$srsdata\@$aliashost";
}

=head2 $sender = $srs->reverse($srsaddress)

Reverse the mapping to get back the original address. Validates
all cryptographic and timestamp information. Returns the original
sender address.

=cut

sub reverse {
	my ($self, $address) = @_;

	$address =~ m/^(.*)\@([^@])+$/ or croak 'Address contains no @';
	my ($user, $host) = ($1, $2);

	my ($sendhost, $senduser) = eval { $self->parse($user); };

	if ($@) {
		warn "Parse returned error in `$user': $@";
		return undef;
	}

	return "$senduser\@$sendhost";
}

=head2 $srs->compile($sendhost, $senduser)

This method, designed to be overridden by subclasses, takes as
parameters the original host and user and must compile a new username
for the SRS transformed address. It is expected that this new username
will be joined on $SRSSEP, and will contain a hash generated from
$self->hash_create(...), and possibly a timestamp generated by
$self->timestamp_create().

=cut

sub compile {
	croak "How did Mail::SRS::compile get called? " .
					"All subclasses override it";
}

=head2 $srs->parse($srsuser)

This method, designed to be overridden by subclasses, takes an
SRS-transformed username as an argument, and must reverse the
transformation produced by compile(). It is required to verify any
hash and timestamp in the parsed data, using $self->hash_verify($hash,
...) and $self->timestamp_check($timestamp).

=cut

sub parse {
	croak "How did Mail::SRS::parse get called? " .
					"All subclasses override it";
}

=head2 $srs->timestamp_create([$time])

Return a two character timestamp representing 'today', or $time if
given. $time is a Unix timestamp (seconds since the aeon).

=cut

# We have two options. We can either encode an send date or an expiry
# date. If we encode a send date, we have the option of changing
# the expiry date later. If we encode an expiry date, we can send
# different expiry dates for different sources/targets, and we don't
# have to store them.

my @BASE64 = ('A'..'Z', 'a'..'z', '0'..'9', '+', '/');
my %BASE64 = map { $BASE64[$_] => $_ } (0..63);
my $TICKSLOTS = scalar(@BASE64) * scalar(@BASE64);	# Two chars
my $PRECISION = 60 * 60 * 24;	# One day

sub timestamp_create {
	my ($self, $time) = @_;
	$time = time() unless defined $time;
	# Since we only mask in the bottom few bits anyway, the
	# % $TICKSLOTS isn't needed.
	$time = int($time / $PRECISION) % $TICKSLOTS;
	# print "Time is $time\n";
	my $out = $BASE64[$time & 63];
	$time = int($time / 64);
	return $BASE64[$time & 63] . $out;
}

=head2 $srs->timestamp_check($timestamp)

Return 1 if a timestamp is valid, undef otherwise. There are 4096
possible timestamps, used in a cycle. At any time, $srs->{MaxAge}
timestamps in this cycle are valid, the last one being today. A
timestamp from the future is not valid, neither is a timestamp from
too far into the past. Of course if you go far enough into the future,
the cycle wraps around, and there are valid timestamps again, but the
likelihood of a random timestamp being valid is 4096/$srs->{MaxAge},
which is usually quite small: 1 in 132 by default.

=cut

sub timestamp_check {
	my ($self, $timestamp) = @_;
	my $time = 0;
	foreach (split(//, $timestamp)) {
		$time = $time * 64 + $BASE64{$_};
	}
	my $now = int(time() / $PRECISION) % $TICKSLOTS;
	# print "Time is $time, Now is $now\n";
	$now += $TICKSLOTS while $now < $time;
	return 1 if $now <= ($time + $self->{MaxAge});
	return undef;
}

=head2 $srs->time_check($time)

Similar to $srs->timestamp_check($timestamp), but takes a Unix time, and
checks that an alias created at that Unix time is still valid. This is
designed for use by subclasses with storage backends.

=cut

sub time_check {
	my ($self, $time) = @_;
	return 1 if time() <= ($time + ($self->{MaxAge} * $PRECISION));
	return undef;
}

=head2 $srs->hash_create(@data)

Returns a cryptographic hash of all data in @data. Any piece of data
encoded into an address which must remain inviolate should be hashed,
so that when the address is reversed, we can check that this data has
not been tampered with. You must provide at least one piece of data
to this method (otherwise this system is both cryptographically weak
and there may be collision problems with sender addresses).

=cut

sub hash_create {
	my ($self, @args) = @_;

	my @secret = $self->get_secret;
	croak "Cannot create a cryptographic MAC without a secret"
					unless @secret;
	my $hmac = new Digest::HMAC_SHA1($secret[0]);
	foreach (@args) {
		$hmac->add($_);
	}
	my $hash = $hmac->b64digest;
	return substr($hash, 0, $self->{HashLength});
}

=head2 $srs->hash_verify($hash, @data)

Verify that @data has not been tampered with, given the cryptographic
hash previously output by $srs->hash_create(); Returns 1 or undef.
All known secrets are tried in order to see if the hash was created
with an old secret.

=cut

sub hash_verify {
	my ($self, $hash, @args) = @_;
	return undef unless length $hash >= $self->{HashMin};
	my @secret = $self->get_secret;
	croak "Cannot verify a cryptographic MAC without a secret"
					unless @secret;
	foreach my $secret (@secret) {
		my $hmac = new Digest::HMAC_SHA1($secret);
		foreach (@args) {
			$hmac->add($_);
		}
		return 1 if substr($hmac->b64digest, 0, length($hash)) eq $hash;
	}
	return undef;
}

=head2 $srs->set_secret($new, @old)

Add a new secret to the rewriter. When an address is returned, all
secrets are tried to see if the hash can be validated. Don't use "foo".

=cut

sub set_secret {
	my $self = shift;
	$self->{Secret} = [ @_ ];
}

=head2 $srs->get_secret()

Return the list of secrets. These are secret. Don't publish them.

=cut

sub get_secret {
	return @{$_[0]->{Secret}};
}

=head1 EXPORTS

Given :all, this module exports three variables.

=over 4

=item $SRSSEP

The SRS separator. The choice of separator was fairly arbitrary. It
cannot be any of the following:

=over 4

=item / +

Used in Base64.

=item -

Used in domains.

=item ! %

Used in bang paths and source routing.

=item :

Cannot be used in a Windows NT or Apple filename.

=item ; | *

Shell or regular expression metacharacters are probably to be avoided.

=back

=item $SRSTAG

The SRS0 tag.

=item $SRSWRAP

The SRS1 tag.

=back

=head1 EXTENDING Mail::SRS

Write a subclass. If people mail me asking for callbacks with the
hash data from the standard subclasses, I will provide them. Callback
hooks have not been provided in this release candidate.

=head1 WARNING: MAJOR CHANGES since v0.15

=over 4

=item The separator character is now C<=>.

=item The cryptographic scheme is now HMAC with SHA1.

=item Only a prefix of the MAC is used.

=back

This API is still a release candidate and should remain relatively
stable.

=head1 BUGS

Email address parsing for quoted addresses is not yet done properly.

=head1 SEE ALSO

L<Mail::SRS::Guarded>, L<Mail::SRS::DB>, L<Mail::SRS::Reversable>,
"make teach", eg/*, http://www.anarres.org/projects/srs/

=head1 AUTHOR

	Shevek
	CPAN ID: SHEVEK
	cpan@anarres.org
	http://www.anarres.org/projects/

=head1 COPYRIGHT

Copyright (c) 2004 Shevek. All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
