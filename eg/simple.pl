use strict;
use Mail::SRS;

my $srs = new Mail::SRS(
				Secret	=> "foo",	# Please, PLEASE change this!
					);

# A mail from a@source.com goes to b@forwarder.com and gets forwarded
# to c@target.com.

my $source = "a\@source.com";
my $alias = "b\@forwarder.com";
my $target = "c\@target.com";
my $final = "d\@final.com";

my $srsdb = "/tmp/srs-eg.db";

sub presskey {
	print "\nPress <enter> ==================================\n";
	<>;
	print "\n" x 6;
}

print << "EOM";

Imagine a mail:
	$source --> $alias
The return path of the mail is originally $source.

Imagine a redirector:
	$alias REDIRECTS TO $target

If $alias resends the mail with return path $source,
SPF at $target will reject it, so we must rewrite the return
path so that it comes from the domain of $alias.

EOM

my $newsource = $srs->forward($source, $alias);

print << "EOM";
So when $alias forwards the mail, it rewrites the return path
according to SRS, to get:
	$newsource

This is what the \$srs->forward() method does.
EOM

presskey;

print << "EOM";
If the mail bounces, the mail goes back to the forwarder, which
applies the reverse transformation to get:
EOM

my $oldsource = $srs->reverse($newsource);

print << "EOM";
	$oldsource

This is what the \$srs->reverse() method does.

The extra fields in the funny-looking address encode the timestamp when
the forwards transformation was performed and a cryptographic hash. The
timestamp ensures that we don't forward bounces back ad infinitum,
but only for (say) one month. The cryptographic hash ensures that
SRS addresses for a particular host cannot be forged. When
$alias gets a returned mail, it can check the hash with its
secret data to make sure this is a real SRS address.
EOM

presskey;

print << "EOM";
If $target is in fact a forwarder, sending to $final,
then $target must rewrite the sender again. However, bounces
need only go to $source, not to $alias. So $target rewrites
the address to:
EOM

my $newnewsource = $srs->forward($newsource, $target);

print << "EOM";
	$newnewsource

Exactly the same points apply, and this time the cryptographic
hash is generated with $alias\'s secret.
EOM

presskey;

print << "EOM";
Now, when either $final or $target performs the reverse
transformation, it will get the address for bounces:
EOM

my $newoldsource = $srs->reverse($newnewsource);

print << "EOM";
	$newoldsource
EOM

presskey;

use Mail::SRS::Reversable;
$srs = new Mail::SRS::Reversable(
				Secret	=> "foo",
					);
my $revsource = $srs->forward($newsource, $final);

print << "EOM";
This code provides for two other possible types of transformation.
The first is the fully reversable transformation, and is provided by a
subclass of Mail::SRS called Mail::SRS::Reversable. This subclass
rewrites
	$newsource
to
	$revsource

This is excessively long and breaks the 64 character limit required
by RFC821 and RFC2821. This package is provided for randomness and
completeness, and its use is NOT RECOMMENDED.

The next test will write to a file called $srsdb

Abort now if this file is not writable, or you do not want this script
to write to that file.
EOM

presskey;

use Mail::SRS::DB;
$srs = new Mail::SRS::DB(
				Secret		=> "foo",
				Database	=> $srsdb,
					);
my $dbsource = $srs->forward($source, $final);
my $dbrev = $srs->reverse($dbsource);
$srs = undef;	# garb!
unlink($srsdb);

print << "EOM";
The other mechanism provided by this code is a database driven system.
In this case, the address
	$source
is rewritten to
	$dbsource
and any bounces will be looked up in the database to retrieve
	$dbrev
The new address $dbsource is also cryptographic,
and is used as a database key to find the original address and any
timeout or reuse information. The source of Mail::SRS::DB provides
a good example for people wanting to build more complex rewriting
schemes.

IMPORTANT: While the database mechanism provides the same functionality
as SRS, the new return path is NOT an SRS address, and therefore does
NOT start with "SRS+". This is so that database rewriting schemes and
`true' SRS schemes can operate seamlessly on the `same' internet.
EOM
