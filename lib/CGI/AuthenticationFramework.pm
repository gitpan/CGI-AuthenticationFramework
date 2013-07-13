package CGI::AuthenticationFramework;

use 5.006;
use strict;
use warnings;
use CGI;					# obvious CGI operations
use CGI::Cookie;				# to handle the cookies
use CGI::Pretty;
use Digest::MD5  qw(md5 md5_hex md5_base64);	# to encrypt the password
use Auth::Yubikey_WebClient;			# for Yubikey support

=head1 NAME

CGI::AuthenticationFramework - A CGI authentication framework that utilizes mySQL for the user and session management

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Allows the login authentication, registration of user accounts, and password reset of webbased users.

Sample CGI script :-

	#!/usr/bin/perl

	use strict;
	use CGI::AuthenticationFramework;
	use DBI;
	use CGI;
	my $cgi = new CGI;
	
	# == connect to the database
	my $dbh = DBI->connect("DBI:mysql:database=DATABASE;host=SERVERNAME",'username','password') || die $DBI::errstr;

	# == create the authentication link
	my $sec = CGI::AuthenticationFramework->new({
        	dbh     => $dbh,
        	cgi     => $cgi
        	});
	
	# == create the tables
	$sec->setup_database(); # run this only once for performance.. No damage to keep it there
	
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
	print "<a href=\"#\">Me again</a>\n";
	
	# == when we're done, we call the finish function.  This clears the data connection, and prints the footer code
	$sec->finish();


=head1 FUNCTIONS

=head2 new

Creates a new authentication connection

	my $sec = CGI::AuthenticationFramework->new({
		dbh     => $dbh,
		cgi     => $cgi
	});


=head3 Options

=head4 dbh

Defined the database handle to use

=head4 cgi

Defines the CGI handle to use

=head4 cookie

The name of the cookie (default is 'my_cookie')

=head4 header

Default header code to include

=head4 footer

Default footer code to include

=head4 yubikey

To enable yubikey support, set to 1.

When you enable yubikey support, you have to set the yubi_id and yubi_api fields as well.  To get these, you need to sign up at L<https://upgrade.yubico.com/getapikey/>

=head4 timeout

Defines the timeout before a user has to log on again.  Default is 600 seconds.

=cut

sub new
{
	my ($class,$options_ref) = @_;
	my $self = {};

	bless $self, ref $class || $class;

	$self->{_headersent} = 0;

	if(! defined $options_ref)
	{
		die "You did not pass any options to the CGI::Authenticator class!";
	}
	my %options = %{$options_ref};

	if(defined $options{cgi})
	{
		$self->{cgi} = $options{cgi};
	}
	else
	{
		die "You did not pass a CGI handle to the authenticator";
	}
	if(defined $options{dbh})
	{
		$self->{dbh} = $options{dbh};
	}
	else
	{
		die "You did not pass a dbh handle to the authenticator";
	}

	# set the default cookie id, or overwrite it if required
	$self->{cookie} = $options{cookie} ? $options{cookie} : 'my_cookie';

	# set the default header and footer code (if necessary)
	$self->{header} = $options{header} ? $options{header} : $self->{cgi}->start_html . $self->{cgi}->h1('Default page') . $self->{cgi}->a({href=>$self->{cgi}->url},"Home");
	$self->{footer} = $options{footer} ? $options{footer} : $self->{cgi}->hr . $self->{cgi}->i('Powered by Perl') . $self->{cgi}->end_html;

	# set the timeout field
	$self->{timeout} = $options{timeout} ? $options{timeout} : 0;	
	# set the yubikey field
	$self->{yubikey} = $options{yubikey} ? $options{yubikey} : 0;	
	$self->{yubi_id} = $options{yubi_id} ? $options{yubi_id} : '';
	$self->{yubi_api}= $options{yubi_api}? $options{yubi_api}: '';

	if($self->{yubikey} == 1)
	{
		if($self->{yubi_id} eq '' || $self->{yubi_api} eq '')
		{
			die "You need to set the yubi_id field.  Obtain this from https://upgrade.yubico.com/getapikey/";
		}
	}
	# Read the cookie
	my %cookies = fetch CGI::Cookie;
	if($cookies{$self->{cookie}})
	{	
		$self->{session} = $cookies{$self->{cookie}}->value;
	}

	return $self;
}

=head2 secure

The main gatekeeper.. Checks if the session is valid.  If not, pass control to the login screen.  If the session is still valid, the timeout is reset, and control is returned to the main program.

=cut

sub secure
{
	my ($self) = @_;

	if($self->session_valid)
	{
		$self->session_refresh();
		if($self->{cgi}->param('func') eq 'logout')
		{
			$self->logout();
		}
		if($self->{cgi}->param('func') eq 'password')
		{
			$self->change_password();
		}
	}
	else
	{
		$self->login();
	}
}

=head2 header

Works identical to CGI::header.  The only difference is the adding of a cookie to the header, and passing the header value if defined from the new function.

=cut

sub header
{
	my ($self,$opt_ref) = @_;

	if($self->{_headersent} == 1)
	{
		return;
	}

	my $cookie = new CGI::Cookie(-name=>$self->{cookie},-value=>$self->{session});

	my %opts;
       	if($opt_ref)
	{
		%opts = %{$opt_ref};
	}
	$opts{Cookie} = $cookie;
	$self->{_headersent} = 1;
	return CGI::header({%opts}) . $self->{header};

}

sub logout
{
	my ($self) = @_;

	# delete any old sessions for this user (if they should exist)
	$self->{dbh}->do('delete from tbl_session where session=?',undef,$self->{session});
	$self->login();
}

sub change_password
{
	my ($self) = @_;

	# we encrypt the password as soon as it hits us.  We don't want to pass unencrypted passwords
	# through the system
	my $pass1 = $self->{cgi}->param('pass1') ? $self->encrypt($self->{cgi}->param('pass1')) : '';
	my $pass2 = $self->{cgi}->param('pass2') ? $self->encrypt($self->{cgi}->param('pass2')) : '';

	if($pass1 eq '' || $pass2 eq '')
	{
		print $self->header();
		$self->change_password_form();
		$self->finish();
	}
	else
	{
		# are they actually the same
		if($pass1 ne $pass2)
		{
			$self->error("The two passwords do not match.");
		}
		# are they long enough ?
		if(length($pass1) <= 7)
		{
			$self->error("The password you chose is not long enough.");
		}
		if($self->{dbh}->do("update tbl_users set password = ? where username = ?",undef,$pass1,$self->{username}))
		{
			$self->log('password','User has successfully changed their password');
			$self->error("Password changed");
		}
		else
		{
			$self->error("Cannot change password : " . $DBI::errstr);
		}
	}
}

sub change_password_form
{
	my ($self) = @_;

	my $schema = <<SCHEMA
pass1,Password,password,20
pass2,Confirm,password,20
SCHEMA
;
	$self->form($schema,'Change password','password','Change your password');
}

sub login_form
{
	my ($self) = @_;

	my $cgi = $self->{cgi};	# making the code more readable

	# Fieldname,Description,type,size
	my $schema = <<SCHEMA
username,Username,text,30
password,Password,password,50
SCHEMA
;
	if($self->{yubikey} == 1)
	{
		$schema .= "yubiotp,Yubikey,password,50";
	}
	$self->form($schema,"Login","login","Login here");
}

sub read_login_form
{

	my ($self) = @_;
	my $cgi = $self->{cgi};
	return ($cgi->param('username'),$cgi->param('password'),$cgi->param('yubiotp'));
}

sub login
{
	my ($self) = @_;

	my $func = $self->{cgi}->param('func') ? $self->{cgi}->param('func') : '';
	
	if($func ne 'login')
	{
		print $self->header();
		$self->login_form();
		$self->finish();
	}
	else
	{
		my ($user,$pass,$yubi) = $self->read_login_form();

		if($self->authenticate($user,$pass,$yubi))
		{
			$self->log('logon','User logged on successfully');
			$self->session_create();
		}
		else
		{
			$self->{username} = $user;
			$self->log('logon','Access denied');
			$self->error('Access denied');
		}
	}
}

sub session_create
{
	my ($self) = @_;

	# create a new session key.. hopefully random enough..
	$self->{session} = $self->encrypt(time . $ENV{REMOTE_ADDR} . $$ . rand(1000));

	# delete any old sessions for this user (if they should exist)
	$self->{dbh}->do('delete from tbl_session where username=?',undef,$self->{username});

	# Preparing to insert the new session
	my $sth = $self->{dbh}->prepare('insert into tbl_session (username,session,session_time) values(?,?,from_unixtime(?))');

	# and inserting it
	if(!$sth->execute($self->{username},$self->{session},time))
	{
		$self->error("Could not create session : " .$DBI::errstr);
	}
}

sub session_refresh
{
	my ($self) = @_;
	# update the timestamp of the session so it doesn't time out
	$self->{dbh}->do('update tbl_session set session_time = CURRENT_TIMESTAMP where session = ?',undef,$self->{session});
}

sub session_valid
{
	my ($self) = @_;

	# check if the session is still valid.  If it is, set the username and return 1
	# if not, return 0

	my $sth = $self->{dbh}->prepare("select username from tbl_session where session = ? and session_time > date_sub(current_timestamp,INTERVAL " . $self->{timeout} . " SECOND)");

	if($sth->execute($self->{session}))
	{
		my @ary = $sth->fetchrow_array();
		my $u = $ary[0] ? $ary[0] : '';
		$sth->finish();

		if($u ne '')
		{
			$self->{username} = $u;
			return 1;
		}
	}
	return 0;
}

sub authenticate
{
	my ($self,$user,$pass,$yubi) = @_;

	my $sth = $self->{dbh}->prepare('select username,yubikey from tbl_users where username = ? and password = ?');

	if($sth->execute($user,$self->encrypt($pass)))
	{
		my ($u,$y) = $sth->fetchrow_array();

		$sth->finish();

		if(lc($u) eq lc($user))
		{
			$self->{username} = $u;

			if($self->{yubikey} == 0)
			{
				return 1;
			}
			else
			{
				# Let's do the yubikey authentication here...

				# Was a OTP provided from the command line?
				#
				if(lc($yubi) !~ /^[cbdefghijklnrtuv]{44}$/)
				{
					$self->error('You will need your yubikey to authenticate.');
				}
				else
				{
					# Does the Yubikey validate?
   					my $yb = Auth::Yubikey_WebClient->new({
        					id	=> $self->{yubi_id},
        					api 	=> $self->{yubi_api}});

					my $result = $yb->otp($yubi);
					my $id = lc(substr($yubi,0,12));

					if($result ne 'OK')
					{
						$self->log('yubikey',"The supplied ($id) yubikey did not validate - $result");
						$self->error("Yubikey access denied - $result");
					}
					else
					{
						# Do we have a code in the table?
						if($y eq '')
						{
							# There is no Yubikey id in the database.  We will set it now
							if($self->{dbh}->do("update tbl_users set yubikey = ? where username = ?",undef,lc($id),$self->{username}))
							{
								$self->log('yubikey',"User associated yubikey $id");
								return 1;
							}
						}
						else
						{
							if($y ne $id)
							{
								$self->log('yubikey',"Access denied due to unknown yubikey ($id)");
								$self->error("Access denied - unknown Yubikey");
							}
							else
							{
								$self->log('yubikey','Valid yubikey supplied');
								return 1;
							}
						}

					}
				}
			}
		}
		else
		{
			return 0;
		}
	}
	else
	{
		$self->error("Access denied error : " . $DBI::errstr);
		return 0;
	}
	return 0;
}

sub error
{
	my ($self,$text) = @_;

	print $self->header();
	print $self->{cgi}->h3($text);
	$self->finish();
}

=head2 finish

Function to send the footer, and sign everything off.  Call this function last (or if you want to terminate the program

=cut

sub finish
{
	my ($self) = @_;

	print $self->{footer};
	$self->{dbh}->disconnect();
	exit(0);
}

=head2 form

Generates an HTML form based on a schema

form (schema,submit text,hidden func field)

=cut

sub form
{
	my ($self,$schema,$submit,$func,$title) = @_;
	
	my $cgi = $self->{cgi};

	print $cgi->h2($title);
	print $cgi->start_table;
	print $cgi->start_form({-action=>$cgi->url});;
	foreach my $f (split(/\n/,$schema))
	{
		chomp($f);
		my ($fn,$desc,$type,$size) = split(/\,/,$f);
		print $cgi->start_Tr;
			print $cgi->th($desc);
			print $cgi->start_td;
			if($type eq 'text')
			{
				print $cgi->textfield(-name=>$fn,
		    			-size=>$size);
			}
			elsif($type eq 'password')
			{
				print $cgi->password_field(-name=>$fn,
					-size=>$size);
			}
			else
			{
				print "Unknown schema type : $type";
			}
			print $cgi->end_td;
		print $cgi->end_Tr;
	}
	print $cgi->Tr($cgi->th("&nbsp;"),
			$cgi->th($cgi->submit(-value=>$submit))
			);
	print $cgi->hidden(-name=>'func',-value=>$func,-override=>1);
	print $cgi->end_form;
	print $cgi->end_table;
}

=head2 setup_database

Call this module once to setup the database tables.  Running it multiple times will only introduce excessive load on the DB, but won't delete any tables.

It will create the tables tbl_users, tbl_session, and tbl_logs.

=cut

sub setup_database
{
	my ($self) = @_;

	# create user table
	#
	if(!$self->{dbh}->do('select 1 from tbl_users'))
	{
		if(!$self->{dbh}->do('create table tbl_users (id integer auto_increment primary key,username varchar(200),password varchar(200),yubikey varchar(12),token varchar(200))'))
		{
			$self->error($DBI::errstr);
		}
		if(!$self->{dbh}->do('alter table tbl_users add unique (username)'))
		{
			$self->error($DBI::errstr);
		}
		if(!$self->{dbh}->do("insert into tbl_users (username,password) values('admin','" . $self->encrypt('password') . "')"))
		{
			$self->error($DBI::errstr);
		}
	}

	# create session table
	if(!$self->{dbh}->do('select 1 from tbl_session'))
	{
		if(!$self->{dbh}->do('create table tbl_session (id integer auto_increment primary key,session varchar(200),username varchar(200),session_time datetime)'))
		{
			$self->error($DBI::errstr);
		}
		if(!$self->{dbh}->do('alter table tbl_session add unique (session)'))
		{
			$self->error($DBI::errstr);
		}
		if(!$self->{dbh}->do('alter table tbl_session add unique (username)'))
		{
			$self->error($DBI::errstr);
		}

	}

	# create the logs table - we need to have some level of tracking of who does what
	if(!$self->{dbh}->do('select 1 from tbl_logs'))
	{
		if(!$self->{dbh}->do('create table tbl_logs (id integer auto_increment primary key,username varchar(200),eventtype varchar(10),message varchar(250),ip varchar(20),eventtime datetime)'))
		{
			$self->error($DBI::errstr);
		}
	}
}

sub encrypt
{
	my ($self,$input) = @_;

	return md5_hex($input);
}

sub log
{
	my ($self,$type,$msg) = @_;

	my $sth = $self->{dbh}->prepare('insert into tbl_logs (username,eventtype,message,eventtime,ip) values (?,?,?,from_unixtime(?),?)');
	if(!$sth->execute($self->{username},$type,$msg,time,$ENV{REMOTE_ADDR}))
	{
		$self->error("Could not log : " . $DBI::errstr);
	}

}

=head1 AUTHOR

Phil Massyn, C<< <phil at massyn.net> >>

=head TODO

There is still plenty to do.

=item User automated registration

=item User forgot password

=item User lost a yubikey

=item User Administration and mode

=head1 BUGS

Please report any bugs or feature requests to C<bug-cgi-authenticationframework at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=CGI-AuthenticationFramework>.  I will be notified, and then you'llautomatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc CGI::AuthenticationFramework


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=CGI-AuthenticationFramework>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/CGI-AuthenticationFramework>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/CGI-AuthenticationFramework>

=item * Search CPAN

L<http://search.cpan.org/dist/CGI-AuthenticationFramework/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2013 Phil Massyn.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=head1 DISCLAIMER

This module has not been scrutinized yet.  It may very well contain security issues.  Although unintentional, you should excersize caution, and not start deploying production systems on this code.  Any bugs or issues raised will be rectified.  Use this module at own risk.

=cut

1; # End of CGI::AuthenticationFramework
