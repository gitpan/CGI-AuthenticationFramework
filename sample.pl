#!/usr/bin/perl

use strict;
use CGI::AuthenticationFramework;
use DBI;
use CGI;
my $cgi = new CGI;

# == connect to the database
my $dbh = DBI->connect("DBI:mysql:database=dev;host=localhost",'root','pass123') || die $DBI::errstr;

# == create the authentication link
my $sec = CGI::AuthenticationFramework->new({
	dbh	=> $dbh,
	cgi	=> $cgi
	});

# == create the tables
$sec->setup_database();	# run this only once for performance.. No damage to keep it there

# == do we go through, or block access.. This is where the rubber meets the road
$sec->secure();

# == once we get through that, we can send our headers
print $sec->header();

# == We can call some additional functions
print "<a href=\"?func=logout\">Logout</a>\n";
print "<a href=\"?func=password\">Change password</a>\n";

print "<p>\n";
print "This is the secret message.<br>\n";
print "Username is $sec->{username}<br>\n";
print "Session ID is $sec->{session}<br>\n";
print "</p>";

# == when we're done, we call the finish function.  This clears the data connection, and prints the footer code
$sec->finish();
