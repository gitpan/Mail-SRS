package Mail::SRS;

# ----------------------------------------------------------
#			 Mail::SRS
#
# 		       Meng Weng Wong
#		  <mengwong+spf@pobox.com>
# $Id: SRS.pm,v 1.10 2004/01/09 20:00:50 devel Exp $
#
# http://spf.pobox.com/srs.html
#
# ----------------------------------------------------------

use Text::Template;
use Params::Validate;
use Carp;
use strict;
use 5.006;

# $Revision: 1.10 $
our $DEBUG;

use vars qw($VERSION);

$VERSION = "0.10";

=head1 NAME

Mail::SRS - OO interface to Sender Rewriting Scheme

=head1 SYNOPSIS

  http://spf.pobox.com/srs.html

  use Mail::SRS;
  my $srs = Mail::SRS->new
    (bounce_delimiter  => '+',
     sender_delimiter  => '-',
     cookie_delimiter  => '-',
     alias_delimiter   => '=',
     address_delimiter => '#',
     secret            => [ 'my secret', 'older secrets', ... ],
     format            => 'bounce[% $bounce_delimiter . $sender . $cookie_delimiter . $cookie . $alias_delimiter . $alias_user %]@[% $alias_host %]';
     max_age           => 30, # days
     validator         => sub {
       my %o = @_; # cookie, sender, alias
       ...
       return; # valid.
       return "550 No more bounces accepted to that address.";
       return "550 Bounces not accepted to that address.";
     },
     extractor         => sub {
       my ($self, $address) = @_;
       ...
       return ($sender, $cookie, $alias_user, $alias_host);
     },
    );

  $srs->set_secret('new secret');
  $srs->set_secret('newer secret', $srs->get_secret);

  my ($new_sender, $cookie) = $srs->forward(sender => 'sender@example.com',
                                            alias  => 'alias@forwarder.com',
                                            rcpts  => [ 'rcpt@example.net' ]);

  # $new_sender is your new return-path.
  # when you get mail to that return-path, you can recover the original data with:

  my ($sender, $alias, $response) = $srs->reverse(address => $new_sender);

=head1 DESCRIPTION

The Sender Rewriting Scheme preserves .forward functionality
in an SPF-compliant world.

This module should be considered alpha at this time.
Documentation is incomplete.  Pobox.com decided to publish
Mail::SRS to CPAN anyway because there seems to be a fair
amount of interest out there in implementing SRS.

SPF requires an SMTP client IP to match the envelope sender
(return-path).  When a message is forwarded through an
intermediate server, that intermediate server may need to
rewrite the return-path to remain SPF compliant.  If the
message bounces, that intermediate server needs to validate
the bounce and forward the bounce to the original sender.

SRS provides a convention for return-path rewriting which
allows multiple forwarding servers to compact the
return-path.  SRS also provides an authentication mechanism
to ensure that purported bounces are not arbitrarily
forwarded.

SRS is documented at http://spf.pobox.com/srs.html

A given SRS address is valid for one month by default.

Cookies are relatively unique.

You may wish to limit the number of bounces you will convey
to a given SRS sender.  The C<rcpts> argument to C<forward>
lets you encode the approximate number of recipients into
the cookie; you can thus limit a given SRS address to a
specified number of uses by passing C<reverse()> a
C<validator> callback which performs a local database lookup
against the cookie,sender,alias tuple.

=head1 METHODS

=head2 new

  my $srs = Mail::SRS->new
    (sender_delimiter  => '-',
     cookie_delimiter  => '-',
     alias_delimiter   => '=',
     address_delimiter => '#',
     secret            => [ 'my secret', 'older secrets', ... ],
     format            => 'bounce+[% $sender . $cookie_delimiter . $cookie . $alias_delimiter . $alias_user %]@[% $alias_host %]';
     max_age           => 30, # days
     validator         => sub {
       my %o = @_; # cookie, sender, alias
       ...
       return; # valid.
       return "550 No more bounces accepted to that address.";
       return "550 Bounces not accepted to that address.";
     },
     extractor         => sub {
       my ($self, $address) = @_;
       ...
       return ($sender, $cookie, $alias_user, $alias_host);
     },
    );

=head2 forward

  my ($new_sender, $cookie) = $srs->forward(sender => 'sender@example.com',
                                            alias  => 'alias@forwarder.com',
                                            rcpts  => [ 'rcpt@example.net' ]);

  # $new_sender is your new return-path.

=head2 reverse

  # $new_sender is the return-path produced by ->forward().
  # when you get mail to that return-path, you can recover the original data with:

  my ($sender, $alias, $response) = $srs->reverse(address => $new_sender);

=head2 set_secret, get_secret

  $srs->set_secret('new secret');
  $srs->set_secret('newer secret', $srs->get_secret);

=cut

sub new {
  my $class = shift;
  my %o = validate(@_, { bounce_delimiter  => 0,
			 sender_delimiter  => 0,
			 cookie_delimiter  => 0,
			 address_delimiter => 0,
			 alias_delimiter   => 0,
			 format            => 0,
			 validator         => 0,
			 extractor_args    => 0,
			 extractor         => 0,
			 secret            => 0 });
  $o{bounce_delimiter}  ||= "+";
  $o{sender_delimiter}  ||= "-";
  $o{cookie_delimiter}  ||= "-";
  $o{alias_delimiter}   ||= "=";
  $o{address_delimiter} ||= "#";
  $o{max_age}           ||= 30;
  $o{format}            ||= 'bounce[% $bounce_delimiter . $sender . $cookie_delimiter . $cookie . $alias_delimiter . $alias_user %]@[% $alias_host %]';
  $o{validator}         ||= sub { return "OK" };
  $o{extractor_args}    ||= sub { my $self = shift; return ($self->{cookie_delimiter}, $self->{alias_delimiter}, '@') };
  $o{extractor}         ||= sub {
    my ($self, $address, @delimiters) = @_;
    print STDERR "extractor: got @_\n" if $DEBUG;
    my ($rest, @return) = $address;
    #$rest =~ s/^bounce+/$1/i or return;
    my $last = '';
    for (reverse(@delimiters), "bounce$self->{bounce_delimiter}") {
      print STDERR "looking at $rest between '$_' and '$last'\n" if $DEBUG;
      ((my $tmp), $rest) = between($rest, $_, $last);
      unshift @return, $tmp;
      $last = $_;
      print STDERR "rest: $rest, return: @return\n" if $DEBUG;
    }
    #$return[0] = $self->decode($return[0]); # decode the sender
    #$return[2] = $self->decode($return[2]); # decode the alias_user
    #$return[3] = $self->decode($return[3]); # decode the alias_host
    print STDERR "final return: @return\n" if $DEBUG;
    return @return;
  };
  bless \%o, $class;
}

sub forward {
  my $self = shift;
  my %o = validate(@_, { sender => 1,
			 alias  => 1,
			 rcpts  => 1 });
  croak "no secret set -- can't use forward method" unless $self->get_secret;
  @o{qw(alias_user alias_host)} = snip('@', $o{alias});
  my @rcpts = ref $o{rcpts} ? @{$o{rcpts}} : $o{rcpts};

  my $munged_sender = $o{sender};
  if ($munged_sender =~ s/^bounce\Q$self->{bounce_delimiter}\E//i) {
    my ($local, $host) = snip('@', $munged_sender);
    $munged_sender = $local . $self->{address_delimiter} . $self->encode($host);
  } else {
    $munged_sender = $self->encode($munged_sender);
  }

  # sender_for_cookie is ${sender}${alias_delimiter}${alias}
  my $sender_for_cookie = join("",
			       $self->decode($munged_sender), # FIXME shouldn't decode this again
			       $self->{alias_delimiter},
			       $o{alias});

  print "=> sender: $sender_for_cookie\n" if $DEBUG;

  my $cookie = $self->makecookie(sender => $sender_for_cookie,
				 punches => scalar @rcpts);

  my %f = (%o, %{$self});
  $f{sender} = $munged_sender;
  $f{cookie} = $cookie;
  $f{alias}      = $self->encode($o{alias});
  $f{alias_user} = $self->encode($o{alias_user});
  $f{alias_host} = $self->encode($o{alias_host});
  my $template = Text::Template->new(TYPE   => 'string',
				     SOURCE => $self->{format},
				     DELIMITERS => [qw([% %])]);
  my ($forward_sender) = $template->fill_in(HASH => \%f);
  return wantarray ? ($forward_sender, $cookie)
                   :  $forward_sender;
}

sub reverse {
  my $self = shift;
  my %o = validate(@_, { address        => 1,
			 validator      => 0,
			 extractor_args => 0,
			 extractor      => 0 });
  croak "no secret set -- can't use reverse method" unless $self->get_secret;
  my $response;
  $o{validator}      ||= $self->{validator};
  $o{extractor_args} ||= $self->{extractor_args};
  $o{extractor}      ||= $self->{extractor};

  my ($user, $host, @bounceparts) = $self->valid_return_path
    ( address        => $o{address},
      validator      => $o{validator},
      extractor_args => $o{extractor_args},
      extractor      => $o{extractor},
      response       => \$response
    ) or return ($o{address}, undef, $response);

  my $alias = "$user\@$host";
  my $sender = "";
  if (@bounceparts) {
    my ($local, $host) = snip($self->{address_delimiter}, pop(@bounceparts));
    $sender = (@bounceparts ? "bounce$self->{bounce_delimiter}" : "") .
      join('@', join($self->{sender_delimiter},
		     @bounceparts,
		     $local), $self->decode($host));
  }

  return ($self->decode($sender), $alias, $response);
}

sub set_secret {
  my ($self, @secrets) = @_;
  $self->{secret} = [@secrets];
}

sub get_secret {
  @{shift()->{secret}}
}

# private methods

sub encode {
  my ($self, $address) = @_;
  for my $d (uniq(@{$self}{qw(sender_delimiter cookie_delimiter address_delimiter alias_delimiter)})) {
    $address =~ s/(\Q$d\E+)/$d$1/gx;
  }
  $address =~ s/\@/$self->{address_delimiter}/g;
  return $address;
}

sub decode {
  my ($self, $address) = @_;
  my $ad = $self->{address_delimiter};
  $address =~ s/(?<!\Q$ad\E)\Q$ad\E(?!\Q$ad\E)/@/g;
  for my $d (uniq(@{$self}{qw(sender_delimiter cookie_delimiter address_delimiter alias_delimiter)})) {
    $address =~ s/\Q$d\E(\Q$d\E+)/$1/g;
  }
  return $address;
}

# algorithm stuff copied from mengwong's SRS.pm
my @base64 = ("a".."z", "A".."Z", 0..9, ".", "/");

=head1 ALGORITHM

Cookies are needed so a reversing host doesn't become an
open relay.

We are concerned that an attacker will try to forge or
replay cookies.

We approach the replay problem by limiting the validity of a
cookie in time and in the number of punches permitted that
cookie.

We approach the forgery problem by using a secret string in
the creation and validation of the cookie.

Punches: When we create a cookie, we do so knowing how many
recipients are being used for that cookie; and we multiply
that number by a modest ratio which allows for downstream
.forwarding to multiple accounts.  We encode that recipient
count into the cookie and expose it in the salt.

Time: When we create a cookie, we do so knowing the current
time.  We encode the current time, with limited precision,
into the cookie and expose it in the salt.

The salt of a standard crypt cookie can represent 12 bits of
data, being m([a-zA-Z0-9./]{2}): each character is one of
64 bytes; two characters afford 4096 or 2**12 combinations.

* Let us specify that an SRS cookie may expect as few as 2 and
  as many as 8 discrete punches.  More punches than 8 shall be
  considered "infinite".

  Using 2 bits, an SRS cookie can specify a maximum punch count of 2, 4, 8, or infinite.

    0 = 2
    1 = 4
    2 = 8
    3 = infinite

That leaves 10 bits.

* Let us specify that an SRS cookie shall expire after 1 month.

  Day precision is sufficient.  To store 256 days, we need 8 bits.

* Reserved: That leaves 2 bits reserved for future use.

* SRS cookie:

       8      2   2
  [  day   ][ p][rr]

We test an SRS cookie for time-validity by decoding the salt
to reveal the time slot and the punch count; we then confirm
that the time slot and punch count were not forged by
recrypting the cookie against the asserted data plus the
secret.

=cut

my $TICKSLOTS = 256;

sub time2tick {
  # the cookie ticks slowly, at the rate of one tick per 24 hour period
  my $precision = 24*60*60;
  my $time = shift;
  my $tick = ($time / $precision) % $TICKSLOTS;
  return $tick;
}

sub makesalt {
  #
  # my $salt = makesalt(punches => 2, reserved => 0, time => time()); # defaults
  #
  my %o = @_;
  my $punches = $o{punches} || 2;

  my $punch_rep = punch2rep($punches);

  my $tick = (defined $o{tick} && ($o{tick} > 0 && $o{tick} < $TICKSLOTS) # handle makesalt(tick=>123) undocumented feature
	      ? $o{tick}
	      : time2tick($o{time} || time)); # handle makesalt(time=>1059166850)

  # we reserve a field whose value can be 0,1,2,3.
  my $reserved  = int($o{reserved} || 0);
  $reserved = 0 if $reserved < 0;
  $reserved = 3 if $reserved > 3;

  # print STDERR "tick = $tick";
  # print STDERR "punchrep = $punch_rep";

  my $saltnum = ($tick << 4) + ($punch_rep << 2) + ($reserved << 0);
  # $saltnum is now a number in the range of 0 to 4095.

  # print STDERR "saltnum = $saltnum";
  my $salt = join "", @base64[int($saltnum / 64), $saltnum % 64];
  return $salt;
}

sub baseindex {
  my $char = shift;
  for my $i (0..$#base64) {
    return $i if $base64[$i] eq $char;
  }
  return "";
}

sub readsalt {
  #
  # my %saltdata = readsalt(".."); # %salt = (punches => 2, reserved => 0, tick => 123);
  #
  my $salt = shift;

  $salt =~ tr/*/./; # technically speaking, rfc821 addresses shouldn't have two .. in a row, so fix that by converting . to *.

  my @F = split //, $salt;

  my $saltnum = baseindex($F[0])*64 + baseindex($F[1]);

  # print STDERR "saltnum = $saltnum";

  my %saltdata;

  $saltdata{reserved}  =           $saltnum % 4;        $saltnum >>= 2;
  $saltdata{punches}   = rep2punch($saltnum % 4);   $saltnum >>= 2;
  $saltdata{tick}      =           $saltnum;

  # while (my ($k, $v) = each %saltdata) { print STDERR "$k: $v"; }

  return %saltdata;
}

sub punch2rep {
  return int(log(shift()-1)/ log(2));
  # perl -le 'for (2..17) { print STDERR "$_: " . int(log($_-1)/log(2)) }'
  #  2 punches: $punch_rep = 0
  #  4 punches: $punch_rep = 1
  #  8 punches: $punch_rep = 2
  # >8 punches: $punch_rep = 3
}

sub rep2punch {
  return 2**(shift()+1);
}

sub makecookie {
  my $self = shift;
  my %o = @_;

  my $sender  = $o{sender}  || "";
  my $punches = $o{punches} || 2;
  my $secret  = $o{secret}  || $self->{secret}->[0];

  $punches    = 2  if $punches < 2;
  $punches    = 16 if $punches > 16;

  $punches = rep2punch(punch2rep($punches));

  my $time = time;

  my $cookie = crypt(lc($sender) . $punches . time2tick($time) . $secret,
		     "\$1\$" .                                         # trigger md5 crypt
		     makesalt(time=>$time, punches=>$punches));

  $cookie =~ tr/./*/;

  $cookie =~ s/^\$1\$(..)\$(.{11}).*/$1$2/; # take the first 11 chars of the 22 char result

  # print STDERR "makecookie(sender=>$sender, punches=>$punches, secret=>$secret) = $cookie";

  return $cookie;
}

sub cookie_is_valid {
  my $self = shift;
  #
  # if (cookie_is_valid(cookie=>$cookie, sender=>$sender_minus_cookie, max_age => 30)) { ... }
  #
  my %o = validate(@_, { cookie    => 1,
			 sender    => 1,
			 address   => 1,
			 alias     => 1,
			 max_age   => 0,
			 validator => 1,
			 response  => 1 });

  $o{max_age} ||= $self->{max_age};

  # validate the cookie
  my $salt = substr($o{cookie},0,2);
  my %saltdata = readsalt($salt);
  my $now_tick = time2tick(time);

  #print STDERR "now_tick = $now_tick; salt tick = $saltdata{tick}\n";

  if (($now_tick - $saltdata{tick}) % $TICKSLOTS > $o{max_age}) { return 0 }

  my $expected = $self->makecookie(sender => $o{sender},
				   punches => $saltdata{punches},
				   tick => $saltdata{tick});
  #print STDERR "cookie according to $o{sender} plus punches/tick data = $expected";
  return 0 if $expected ne $o{cookie};

  if ($o{response}) {
    if ($o{validator} and ref $o{validator} eq "CODE") {
      ${$o{response}} = eval { $o{validator}->(address   => $o{address},
					       cookie    => $o{cookie},
					       sender    => $o{sender},
					       alias     => $o{alias},
					       punches   => $saltdata{punches},
					       tick      => $saltdata{tick},
					       now_tick  => $now_tick);
			     };
      if ($@) { warn "error in validator: $@"; return 1; }
      return 1 if not ${$o{response}};
      return 1 if     ${$o{response}} =~ /^(ok|allow|permit)$/i;
      return 0;
    }
    else {
      ${$o{response}} = "OK";
      return 1;
    }
  }

  # todo: count the number of punches against the local db record.

  return 1;
}

sub snip {
  my ($delim, $string, $count) = @_;
  if (defined $delim) {
    $count ||= 2;
    return split /(?:(?<!\Q$delim\E)\Q$delim\E(?!\Q$delim\E))/i, $string, $count;
  } else {
    return $string
  }
}

sub between {
  my ($string, $left_delim, $right_delim) = map { scalar CORE::reverse($_) } @_;
  my ($right, $rest) = snip($right_delim, $string);
  unless ($rest) { $rest = $right; $right = '' }
  no warnings 'uninitialized';
  print STDERR "- right: " . ($right) . "\n" if $DEBUG;
  print STDERR "- rest: "  . ($rest)  . "\n"   if $DEBUG;

  my ($middle, $left) = snip($left_delim, $rest);
#  my ($rest, $right) = rsnip($right_delim, $string);
#  my ($middle, $left) = rsnip($left_delim, $rest);

  print STDERR "- middle: " . ($middle) . "\n" if $DEBUG;
  print STDERR "- left: "   . ($left)   . "\n" if $DEBUG;

  return (map { scalar reverse $_ } ($middle, join($left_delim, $right, $left)));
}

sub uniq {
  my %seen;
  $seen{$_}++ for @_;
  return keys %seen
}

sub valid_return_path {
  my $self = shift;
  my %o = validate(@_, { address        => 1,
			 validator      => 1,
			 extractor_args => 1,
			 extractor      => 1,
			 response       => 1,
			 max_age        => 0
		       });

  # the extractor needs to get:
  #  address
  # and return
  #  cookie
  #  sender
  #  alias_user
  #  alias_host
  # sender, alias_user, and alias_host should *not* be decoded by the extractor.

  print "<= sender: $o{address}\n" if $DEBUG;

  my @extra;
  if ($o{extractor_args}) {
    if      (ref $o{extractor_args} eq 'CODE') {
      @extra = $o{extractor_args}->($self, $o{address})
    } elsif (ref $o{extractor_args} eq 'ARRAY') {
      @extra = @{$o{extractor_args}}
    } else {
      croak "Don't know how to deal with extractor_args: $o{extractor_args}";
    }
  }
  my ($sender, $cookie, $alias_user, $alias_host) = $o{extractor}->($self, $o{address}, @extra);
  return unless $sender and $cookie;

  warn "sender: $sender\n" if $DEBUG;
  warn "cookie: $cookie\n" if $DEBUG;
  warn "alias_user: $alias_user\n" if $DEBUG;
  warn "alias_host: $alias_host\n" if $DEBUG;

  my @bounceparts = snip($self->{sender_delimiter}, $sender, -1);

  my $d_alias_user = $self->decode($alias_user);
  my $d_alias_host = $self->decode($alias_host);
  my $d_alias      = $d_alias_user . '@' . $d_alias_host;

  my $sender_minus_cookie = $self->decode($sender) . $self->{alias_delimiter} . $d_alias;

  print "<= sender_minus_cookie: $sender_minus_cookie\n" if $DEBUG;

  if (not $self->cookie_is_valid(cookie    => $cookie,
				 sender    => $sender_minus_cookie,
				 address   => $o{address},
				 max_age   => $o{max_age},
				 alias     => $d_alias,
				 validator => $o{validator},
				 response  => $o{response},
				)) { # print STDERR "invalid cookie!";
				     return; }

  return ($d_alias_user, $d_alias_host, @bounceparts);
}

1;
