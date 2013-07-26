package CGI::AuthenticationFramework;

use 5.006;
use strict;
use warnings;
use CGI;					# obvious CGI operations
use CGI::Cookie;				# to handle the cookies
use CGI::Pretty;
use Digest::MD5  qw(md5 md5_hex md5_base64);	# to encrypt the session key
use Auth::Yubikey_WebClient;			# for Yubikey support
use Net::SMTP;					# to send registration & password reminder emails
use POSIX qw(strftime);				# used for no-cache headers
use Captcha::reCAPTCHA;				# the captcha module
use HTML::Entities;

=head1 NAME

CGI::AuthenticationFramework - A CGI authentication framework that utilizes mySQL for the user and session management

=head1 VERSION

Version 0.05

=cut

our $VERSION = '0.05';

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
	print "<a href=\"javascript:void();\" onclick=\"javascript:securefunction('logout');\">Logout</a>\n";
	print "<a href=\"javascript:void();\" onclick=\"javascript:securefunction('password');\">Change password</a>\n";
	
	print "<p>\n";
	print "This is the secret message.<br>\n";
	print "Email Address is $sec->{username}<br>\n";
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

=head4 register

If you need users to register on their own, set the register option to 1.  Default is 0

=head4 forgot

If you need users to have the ability to reset their passwords by emailing a new one to them, set this option to 1.  Default is 0.
=head4 SMTP server settings

If you have register enabled, you need to specify SMTP settings

=head5 smtpserver

The hostname of the SMTP server

=head5 smtpfrom

The from email address to use when sending emails

=head5 smtpuser , smtppass

The smtpuser and smtppass parameters are optional.  If your SMTP server requires you to authenticate, set these two fields.

=head4 captcha

Defined if you want to use a captcha.  Default is 0.

Sign up for a free API from L<https://www.google.com/recaptcha/admin/create> and enter the values in captcha_public and captcha_private

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
	$self->{timeout} = $options{timeout} ? $options{timeout} : 600;	

	# set the register field
	$self->{register} = $options{register} ? $options{register} : 0;
	$self->{forgot}   = $options{forgot}   ? $options{forgot}   : 0;

	$self->{smtpserver} = $options{smtpserver} ? $options{smtpserver} : '';
	$self->{smtpfrom}   = $options{smtpfrom}   ? $options{smtpfrom}   : '';

	$self->{smtpuser}   = $options{smtpuser}   ? $options{smtpuser}   : '';
	$self->{smtppass}   = $options{smtppass}   ? $options{smtppass}   : '';

	if($self->{register} == 1 || $self->{forgot} == 1)
	{
		# if register or forget is set, we need smtpserver, smtpuser and smtppassword
		if($self->{smtpserver} eq '')
		{
			die "You did not set smtpserver";
		}
	}
	
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

	# Read the captcha variables
	$self->{captcha}         = $options{captcha}         ? $options{captcha}         : 0;
	if($self->{captcha} == 1)
	{
		$self->{captcha_public}  = $options{captcha_public}  ? $options{captcha_public}  : '';
		$self->{captcha_private} = $options{captcha_private} ? $options{captcha_private} : '';
		$self->{captcha_object} = Captcha::reCAPTCHA->new;

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

	# We won't allow any type of GET methods
	if($ENV{QUERY_STRING} ne '')
	{
		$self->error('Illegal content posted via GET method');
	}
	if($self->session_valid)
	{
		$self->session_refresh();
		if($self->param('func') eq 'logout')
		{
			$self->logout();
		}
		if($self->param('func') eq 'password')
		{
			$self->change_password();
		}
	}
	else
	{
		if($self->param('func') eq 'register')
		{
			$self->register();
		}
		if($self->param('func') eq 'forgot')
		{
			$self->forgot();
		}
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

	my $cookie = new CGI::Cookie(-name=>$self->{cookie},-value=>$self->{session},-secure=>($ENV{HTTPS}eq 'on' ? 1 : 0));

	my %opts;
       	if($opt_ref)
	{
		%opts = %{$opt_ref};
	}
	$opts{Cookie} = $cookie;
	$self->{_headersent} = 1;

	# no cache
	$opts{Pragma}		= 'no-cache';
	$opts{Last_Modified}	= strftime('%a, %d %b %Y %H:%M:%S GMT', gmtime);
	$opts{expires}		= 'Sat, 26 Jul 1997 05:00:00 GMT';
	$opts{Cache_Control}	= join(', ', qw(
        				private
        				no-cache
        				no-store
        				must-revalidate
        				max-age=0
        				pre-check=0
        				post-check=0
    				));
	return CGI::header({%opts}) . $self->{header} . $self->build_post_js("securefunction",$self->{cgi}->url,"","func");

}

sub forgot
{
	my ($self) = @_;

	my $token = $self->param('token') 	? $self->param('token') 		: '';
	my $user  = $self->param('username')  	? $self->param('username')	: ''; 

	if($self->{forgot} != 1)
	{
		return 0;
	}

	if(!$self->validate_input("md5hex",$token))
	{
		return 0;
	}
	
	if($user eq '')
	{
		my $schema = "username,Email Address,text,40";

		print $self->header();
		$self->form($schema,'Reset your password','forgot','Reset your password',$self->{captcha});
		$self->finish();
	}
	else
	{

                # validate if the captcha is ok
                if(!$self->validate_captcha())
                {
                        return 0;
                }

		my $sth = $self->{dbh}->prepare('select username,token from tbl_users where username = ? and state = 0');
                if($sth->execute($user))
                {
                        my ($user2,$token2) = $self->xss($sth->fetchrow_array());
                        $self->{username} = $user2;
                        $sth->finish();

			if($user2 eq '')
			{
				$self->error("User does not exist");
			}
			else
			{
				if($token eq $token2 && $token ne '')
				{
					# we have a token, and it matches.  Reset the password, and mail it to the user to log in

					my $sth = $self->{dbh}->prepare("update tbl_users set token = '', password = ? where username = ?");
					my $newpass = $self->generate_password();
					my $tokennew = $self->generate_token();

                                	if($sth->execute($self->encrypt($newpass,$tokennew),$user2))
					{
						# On success, let's email it out

						my $url = $self->{cgi}->url;
						my $msg = "Your password has been reset to : $newpass\n\nPlease login at $url";
						$self->send_email($self->{smtpfrom},$user2,"Password has been reset",$msg);
						$self->message("Your password has been reset, and mailed to your email address.");
					}
					else
					{
						$self->error("Could not reset the password : " . $DBI::errstr);
					}


				}
                                elsif($token eq '')
                                {
                                        # Generate a new token, and mail it to the user to click

                                        my $new_token = $self->generate_token();

					my $sth = $self->{dbh}->prepare('update tbl_users set token = ? where username = ?');
					if($sth->execute($new_token,$user2))
					{
						# new token set, now main a link to the user
						my $url = $self->{cgi}->url . "?func=forgot&username=$user2&token=$new_token";

						my $msg = "To reset your password, click here : $url.\n\nIf you did not send this message, ignore it";
						$self->send_email($self->{smtpfrom},$user2,"Reset your password",$msg);

						$self->message("Check your email for the password reset link");
					
					}
					else
					{
						$self->error("can not create new token : " . $DBI::errstr);
					}

                                }
				else
				{
					$self->error("Invalid token to reset the password");
				}
			}
		}
		else
		{
			$self->error($DBI::errstr);
		}
	}
}

sub register
{
	my ($self) = @_;

	# this function only works if the developer wanted registration to be enabled
	if($self->{register} != 1)
	{
		return;
	}

	my $user  = $self->param('username');
	my $token = $self->param('token');

	$self->{username} = $user;

	if($user eq '')
	{
		my $schema = "username,Email Address,text,20";
		print $self->header();
		$self->form($schema,"Register a new account","register","New user registration",$self->{captcha});
		$self->finish();
	}
	else
	{
		# we got a user name...

		# validate if the captcha is ok
		if(!$self->validate_captcha())
		{
			return 0;
		}

		# is it an actual email address?
		if(!$self->validate_input('email',$user))
		{
			$self->error("The provided email address is not a valid email address.");
		}

		# do we already have one of these ?
		my $sth = $self->{dbh}->prepare('select username,token from tbl_users where username = ? and state = 1');
		if($sth->execute($user))
		{
			my ($user2,$token2) = $self->xss($sth->fetchrow_array());
			$self->{username} = $user2;
			$sth->finish();

			if($user2 ne '')
			{
				if($token2 eq '')
				{
					$self->log('register','Account already exists.');
					$self->error('The user account already exists.  Please select another.');
				}
				else
				{
					if($token2 ne $token)
					{
						$self->log('register','Provided token does not validate.');
						$self->error("The token provided does not validate.");
					}
					else
					{
						# confirm that the incoming token was in fact a valid token
						if(!$self->validate_input("md5hex",$token))
						{
							return 0;
						}
	
						# Everything checks out... Enable the account
						my $sth = $self->{dbh}->prepare("update tbl_users set token = '',state = 0 where username = ?");
						if($sth->execute($user2))
						{
							$self->log('register','User has been validated');
							$self->message("Account has been validated.  You can now log on.");
						}
						else
						{
							$self->log('register','Unable to validate the user');
							$self->error("Unable to validate account : " . $DBI::errstr);
						}
					}
				}
			}
			else
			{
				# The user does not exist yet
				my $sth = $self->{dbh}->prepare('insert into tbl_users (username,password,token,state) values(?,?,?,1)');
				
				my $newpass = $self->generate_password();

				my $tokennew = $self->generate_token();

				if($sth->execute($user,$self->encrypt($newpass),$tokennew))
				{
					$self->log('register','New user registered.');
					my $url = $self->{cgi}->url . "?func=register&username=$user&token=$tokennew";

					my $body = "Your account has been setup.  To activate your account, click this link - $url\n\nYour password is : $newpass\n\nYou can change the password once you have logged on.";
					$self->send_email($self->{smtpfrom},$user,"New user Registration",$body);
					$self->message("Registration token sent.  Please check your email.");
				}
				else
				{
					$self->error("Can not create a registration token : " . $DBI::errstr);
				}

			}
		}
		else
		{
			$self->error("Can not check if user exists : " . $DBI::errstr);
		}
	}
}

sub generate_token
{
	my ($self) = @_;

	return md5_hex(time . $ENV{REMOTE_ADDR} . $$ * rand(10000000));
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

	my $pass1 = $self->param('pass1') ? $self->param('pass1') : '';
	my $pass2 = $self->param('pass2') ? $self->param('pass2') : '';

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

		if($self->{dbh}->do("update tbl_users set password = ? where username = ?",undef,$self->encrypt($pass1),$self->{username}))
		{
			$self->log('password','User has successfully changed their password');
			$self->message("Password changed");
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
username,Email Address,text,30
password,Password,password,50
SCHEMA
;
	if($self->{yubikey} == 1)
	{
		$schema .= "yubiotp,Yubikey,password,50";
	}
	$self->form($schema,"Login","login","Login here");

	if($self->{register} == 1)
	{
		print $cgi->a({href=>"?func=register"},"Register");
	}
	if($self->{forgot} == 1)
	{
		print $cgi->a({href=>"?func=forgot"},"Forgot password");
	}
}

sub read_login_form
{

	my ($self) = @_;
	return ($self->param('username'),$self->param('password'),$self->param('yubiotp'));
}

sub login
{
	my ($self) = @_;

	my $func = $self->param('func') ? $self->param('func') : '';
	
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
	$self->{session} = $self->generate_token();

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

	# generate a new session ID to prevent spoofing of cookies
	my $old_session = $self->{session};
	$self->{session} = $self->generate_token();

	$self->{dbh}->do('update tbl_session set session_time = CURRENT_TIMESTAMP,session = ? where session = ?',undef,$self->{session},$old_session);
}

sub session_valid
{
	my ($self) = @_;

	# is the input session field actually a session ?
	if(!$self->validate_input("md5hex",$self->{session}))
	{
		return 0;
	}

	# check if the session is still valid.  If it is, set the username and return 1
	# if not, return 0

	my $sth = $self->{dbh}->prepare("select username from tbl_session where session = ? and session_time > date_sub(current_timestamp,INTERVAL " . $self->{timeout} . " SECOND)");

	if($sth->execute($self->{session}))
	{
		my @ary = $self->xss($sth->fetchrow_array());
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

	my $sth = $self->{dbh}->prepare('select username,yubikey,password from tbl_users where username = ? and state = 0');

	if($sth->execute($user))
	{
		my ($u,$y,$p) = $self->xss($sth->fetchrow_array());
		$sth->finish();

		if(crypt($pass,$p) ne $p)
		{
			$self->error("Access denied");
		}

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

sub message
{
        my ($self,$text) = @_;

        $self->log('message',$text);

        print $self->header();
        print $self->{cgi}->h3($text);
        $self->finish();

}
sub error
{
	my ($self,$text) = @_;

	$self->log('error',$text);

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

form (schema,submit text,hidden func field,title for the header,captcha option,%VALUES)

=cut

sub form
{
	my ($self,$schema,$submit,$func,$title,$captcha,%VALUES) = @_;
	
	my $cgi = $self->{cgi};

	print $cgi->h2($title);
	print $cgi->start_form({-action=>$cgi->url});;
	print $cgi->start_table;

	my $isid = 0;
	foreach my $f (split(/\n/,$schema))
	{
		chomp($f);
		my ($fn,$desc,$type,$size,$sql) = split(/\,/,$f);

		if($fn eq 'id')
		{
			$isid = 1;
		}

		my $value = $VALUES{$fn};

		if($type eq 'hidden')
		{
			print $cgi->hidden(-name=>$fn,-value=>$value);
		}
		else
		{
			print $cgi->start_Tr;
			print $cgi->th($desc);
			print $cgi->start_td;
			if($type eq 'text')
			{
				print $cgi->textfield(
					-name=>$fn,
		    			-size=>$size,
					-value=>$value
					);
			}
			elsif($type eq 'password')
			{
				print $cgi->password_field(
					-name=>$fn,
					-size=>$size,
					-value=>$value
					);
			}
			elsif($type eq 'textarea')
			{
				my ($r,$c) = split(/\|/,$size);
				print $cgi->textarea(
					-name=>$fn,
					-rows=>$r,
					-cols=>$c,
					-value=>$value
					);
			}
			elsif($type eq 'dropdown')
			{
				my $sth = $self->{dbh}->prepare($sql);
				$sth->execute();

				print "<select name=\"$fn\">\n";
				while(my @ary = $self->xss($sth->fetchrow_array()))
				{
					my $sel = $ary[0] eq $value ? 1 : 0;
					print $cgi->option({-value=>$ary[0],-selected=>$sel},$ary[0]);
				}
				print "</select>\n";
			}
			elsif($type eq 'readonly')
			{
				print $value;
				print $cgi->hidden(-name=>$fn,-value=>$value);
			}
			else
			{
				print "Unknown schema type : $type";
			}
			print $cgi->end_td;
			print $cgi->end_Tr;
		}
	}

	print $cgi->Tr($cgi->th("&nbsp;"),
			$cgi->th($cgi->submit(-value=>$submit))
			);

	print $cgi->hidden(-name=>'func',-value=>$func,-override=>1);
	print $cgi->end_table;
        if($captcha == 1)
        {
		print $self->{captcha_object}->get_html( $self->{captcha_public} );
        }

	if($VALUES{id} && $isid == 0)
	{
		print $cgi->hidden(-name=>'id',-value=>$VALUES{id},-override=>1);
	}
	print $cgi->end_form;

}

# call xss after every fetchrow_array
sub xss
{
	my ($self,@input) = @_;

	my @new;
	foreach my $f (@input)
	{
		push(@new,encode_entities($f));
	}
	return @new;
}

=head2 form_update

Updates the data in the table 

input : schema, table name

=cut

sub form_update
{
	my ($self,$schema,$table) = @_;

	my $id = $self->param('id');
	if(!$self->validate_input('number',$id))
	{
		$self->error("id was not what we expected- $id");
	}

	my $sql = "update $table set ";

	my @VALUES;
	foreach my $s (split(/\n/,$schema))
	{
		my ($fn,$desc) = split(/\,/,$s);
		$sql .= "$fn = ?,";

		push(@VALUES,$self->param($fn));
	}
	$sql =~ s/\,$//g;
	$sql .= " where id = ?";

	my $sth = $self->{dbh}->prepare($sql);

	if($sth->execute(@VALUES,$id))
	{
		print "success\n";
	}
	else
	{
		print $DBI::errstr();
	}
}

=head2 form_edit

Shows the edit form after an id was passed to it

input : schema, table, title, button text, func field

=cut

sub form_edit
{
	my ($self,$schema,$table,$title,$button,$func) = @_;

	my $id = $self->param('id');

	if(!$self->validate_input('number',$id))
	{
		$self->error("id was not what we expected- $id");
	}

	my $sth = $self->{dbh}->prepare("select * from $table where id = ?");

	if($sth->execute($id))
	{
		my $R = $sth->fetchrow_hashref();
		$sth->finish();

		$self->form($schema,$button,$func,$title,0,%{$R});
	}
	else
	{
		$self->error("Unable to view id " . $DBI::errstr);
	}

}
=head2 form_insert

Takes the input from a form, and inserts it into a database

Input : schema, table, default values (for readonly fields)

=cut

sub form_insert
{
	my ($self,$schema,$table,%VALUES) = @_;

	my $dbh = $self->{dbh};

	# read the schema, and start constructing the SQL

	my @fields;
	my @values1;
	my @values2;
	foreach my $s (split(/\n/,$schema))
	{
		chomp($s);

		my ($fn,$desc,$type) = split(/\,/,$s);

		push(@fields,$fn);
		push(@values1,"?");
		push(@values2,$type eq 'readonly' ? $VALUES{$fn} : $self->param($fn));
	}

	my $sql = "insert into $table (" . join (",",@fields) . ") values (" . join(",",@values1) . ")";

	return $dbh->do($sql,undef,@values2);
}

=head2 form_list

Show the result of a SQL table

=cut

sub form_list
{
	my ($self,$schema,$table,$title,$linkfield,$func,$where) = @_;

	my $cgi = $self->{cgi};

	print $cgi->h2($title);
	my @fields;
	my @desc;

	my $linkc = '';

	my $c = 0;
	push(@fields,'id');
	foreach my $s (split(/\n/,$schema))
	{
		my ($fn,$de) = split(/\,/,$s);
		push(@fields,$fn);
		push(@desc,$de);
		if($fn eq $linkfield)
		{
			$linkc = $c;
		}
		$c++;
	}

	print $self->build_post_js("submitform$func",$self->{cgi}->url,"func=$func","id");

	print $cgi->start_table({border=>1});
	print $cgi->Tr($cgi->th([@desc]));

	my $sth = $self->{dbh}->prepare('select ' . join(',',@fields) . " from $table $where");
	$sth->execute();
	while(my ($id,@ary) = $self->xss($sth->fetchrow_array()))
	{
		print $cgi->Tr;
		my $c = 0;
		foreach my $f (@ary)
		{
			my $r = '';
			if($c == $linkc)
			{
				$r = "<a href=\"javascript:void();\" onclick=\"javascript:submitform$func($id);\">$f</a>";
			}
			else
			{
				$r = $f;
			}
			print $cgi->td($r);
			$c++;
		}
		print $cgi->end_Tr;
	}

	print $cgi->end_table;
}

=head2 form_create_table

Create a mySQL table based on a schema definition

input : schema, table name

=cut

sub form_create_table
{
	my ($self,$schema,$table) = @_;

	# create the table if it doesn't exist yet
	if(!$self->{dbh}->do('select 1 from ?',undef,$table))
	{
		$self->{dbh}->do("create table $table (id integer auto_increment primary key)");
	}

	# check the fields
	# read all fields from the table
	my $sth = $self->{dbh}->prepare("desc $table");
	$sth->execute();

	my %DB;
	while(my @ary = $self->xss($sth->fetchrow_array()))
	{
		$DB{$ary[0]} = $ary[1];
	}

	foreach my $s (split(/\n/,$schema))
	{
		my ($fn,$de,$ty,$sz,$sql) = split(/\,/,$s);
		if(!$DB{$fn})
		{
			my $sql;
			if($ty eq 'textarea')
			{
				$sql = "text";
			}
			else
			{
				$sql = "varchar($sz)";
			}

			$self->{dbh}->do("alter table $table add column $fn $sql");
		}
	}
}

sub param
{
	my ($self,$c) = @_;

	my $in = $self->{cgi}->param($c);

	# strip unsafe characters
	$in =~ s/[<>\\"\%;\(\)&\0]//g;
	return $in;
}
=head2 setup_database

Call this module once to setup the database tables.  Running it multiple times will only introduce excessive load on the DB, but won't delete any tables.

It will create the tables tbl_users, tbl_session, and tbl_logs.

It will also create the default user 'admin', with it's password 'password'.  Remember to change this password on your first logon.

=cut

sub setup_database
{
	my ($self) = @_;

	# create user table
	#
	if(!$self->{dbh}->do('select 1 from tbl_users'))
	{
		if(!$self->{dbh}->do('create table tbl_users (id integer auto_increment primary key,username varchar(200),password varchar(200),yubikey varchar(12),token varchar(200),state integer default 0)'))
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

	return crypt($input,$self->generate_token());
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

sub generate_password
{
	my ($self) = @_;

	my $cs = "abcdefghijklmnopqrstuvwxyz0123456789";

	my $pass;
	for(my $k=0;$k<8;$k++)
	{
		my $ch = int(rand(length($cs)));
		$pass .= substr($cs,$ch,1);
	}
	return $pass;
}

sub send_email
{
        my ($self,$from,$to,$subject,$body) = @_;

        my $smtp = Net::SMTP->new(
                $self->{smtpserver},
                Hello => $self->{smtpserver},
                Timeout => 60
        ) || $self->error("Could not connect to mail server : $!");

	# TO BE TESTED...
	if($self->{smtpuser} ne '' && $self->{smtppass} ne '')
	{
		$smtp->auth($self->{smtpuser},$self->{smtppass}) || $self->error("Could not authenticate to mail server : $!");
	}

        $smtp->mail($from);
        $smtp->recipient($to);
        $smtp->to($to);

        $smtp->data;

        $smtp->datasend("From: $from\n");
        $smtp->datasend("To: $to\n");
        $smtp->datasend("Subject: $subject\n");
        $smtp->datasend("\n");

        $smtp->datasend($body);

        $smtp->dataend;
        $smtp->quit;
}

sub validate_captcha
{
	my ($self) = @_;

	$self->log('captcha','DEBUG - entering');

	if($self->{captcha} != 1)
	{
		return 1;
	}
	$self->log('captcha','DEBUG - we got past the switch');

	my $challenge = $self->param('recaptcha_challenge_field');
	my $response  = $self->param('recaptcha_response_field');

	if($response)
	{
		$self->log('captcha','DEBUG - got the response');		

        	# Verify submission
        	my $result = $self->{captcha_object}->check_answer($self->{captcha_private}, $ENV{'REMOTE_ADDR'}, $challenge, $response);

        	if ( $result->{is_valid} )
        	{
			$self->log('captcha','DEBUG - is valid');
			return 1;
        	}
        	else
        	{
                	# Error
			$self->log('captcha','DEBUG -- failed');
                	my $error = $result->{error};
			$self->log("captcha","Captcha did not validate - $error");
			return 0;
        	}
	}
	else
	{
		$self->log('captcha','DEBUG - we did not get a response');
	}
	
	return 0;
}

sub build_post_js
{
	my ($self,$procname,$action,$url,$id) = @_;

	my $JS = "<script language=\"javascript\">\n";
	$JS .= "function $procname (id)\n{\n";
	$JS .= "\tvar form = document.createElement(\"FORM\");\n";
	$JS .= "\tform.enctype = \"multipart/form-data\";\n";
	$JS .= "\tform.method = \"post\";\n";
	$JS .= "\tform.action = \"$action\";\n";
	$JS .= "\tform.style.display = \"none\";\n";

	# seperate the url by elements
	foreach my $e (split(/\&/,$url))
	{
		my ($name,$value) = split(/\=/,$e);
		$JS .= "\n";
		$JS .= "\tvar hf$name = document.createElement(\"input\");\n";
		$JS .= "\thf$name.setAttribute(\"type\", \"hidden\");\n";
		$JS .= "\thf$name.setAttribute(\"name\", \"$name\");\n";
		$JS .= "\thf$name.setAttribute(\"value\", \"$value\");\n";
		$JS .= "\tform.appendChild(hf$name);\n";
	}

	if($id)
	{
		$JS .= "\n";
		$JS .= "\tvar hf$id = document.createElement(\"input\");\n";
		$JS .= "\thf$id.setAttribute(\"type\", \"hidden\");\n";
		$JS .= "\thf$id.setAttribute(\"name\", \"$id\");\n";
		$JS .= "\thf$id.setAttribute(\"value\", id);\n";
		$JS .= "\tform.appendChild(hf$id);\n";
	}
	$JS .= "\n";
	$JS .= "\tdocument.body.appendChild(form);\n";
	$JS .= "\tform.submit();\n";
	$JS .= "}\n";
	$JS .= "</script>\n";
	return $JS;
}

sub validate_input
{
	my ($self,$type,$in) = @_;

	if(!$in)
	{
		$in = '';
	}
	if($type eq 'email' && $in =~ /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b/i)
	{
		return 1;
	}
	elsif($type eq 'md5hex' && $in =~ /\b[a-f0-9]{32}\b/)
	{
		return 1;
	}
	elsif($type eq 'number' && $in =~ /\b[0-9]+\b/)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

=head1 AUTHOR

Phil Massyn, C<< <phil at massyn.net> >>

=head1 REVISION
0.05	Fixed xss to check all array elements when calling fetchrow_array
	Replaced all GET with POST functions, and prevent futher usage of GET
	Added form_edit function
	Fixed missing hidden id in form function
	Updated param function to strip unsafe characters

0.04	Updated form to handle hidden field, and input values
	Added textarea, and readonly fields
	Included dropdown with SQL in the schema support
	Added form_create_table
	Added form_insert
	Added form_list
	Added HTML::Entities for encoding output string (prevent cross site scripting)
	Changed the cookie's session ID to reset on every click
	Make the cookie secure

0.03	Added no-cache tags to header function
	Added input validation procedure
	Added input validation for tokens
	Moved valid_email procedure into validate_input
	Fixed omission of $forgot parameter check on sub forgot
	Added reCaptcha

0.02	Added registration option (including Net::SMTP)
	Changed password encryption to a salted hash
	Added forgotten password option
	Logging all messages being displayed

0.01	Initial version

=head1 TODO

There is still plenty to do.

=item User lost a yubikey

=item User Administration and user maintenance console

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
