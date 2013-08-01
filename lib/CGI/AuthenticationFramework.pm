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
use HTML::Entities;				# Pass all output here, to prevent cross site scripting issues

=head1 NAME

CGI::AuthenticationFramework - A CGI authentication framework that utilizes mySQL for the user and session management

=head1 VERSION

Version 0.10

=cut

our $VERSION = '0.10';

=head1 SYNOPSIS

Allows the login authentication, registration of user accounts, and password reset of webbased users.  It also provides a framework for session management, form and list creation, and basic database management, everything you need to build a full web based application.

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

=head4 register_template & forgot_template

Optional template that will be used to send the registration email.  

use %URL% to define the URL that will be clicked by the user.  Use %BASE% for the base URL of the program

=head4 register_subject & forgot_subject

Optional subject that will be used

=head4 register_from & forgot_from

Optional from email address to use

=head4 forgot

If you need users to have the ability to reset their passwords by emailing a new one to them, set this option to 1.  Default is 0.
=head4 SMTP server settings

If you have register enabled, you need to specify SMTP settings

=head5 smtpserver

The hostname of the SMTP server

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

	$self->{title} = $options{title} ? $options{title} : 'Default Application';
	$self->{style} = $options{style} ? $options{style} : 'style.css';

	# set the default cookie id, or overwrite it if required
	$self->{cookie} = $options{cookie} ? $options{cookie} : 'my_cookie';

	# set the default header and footer code (if necessary)
	$self->{header} = $options{header} ? $options{header} : $self->{cgi}->start_html(-title => $self->{title}, -style=>{'src'=>$self->{style}}) . $self->{cgi}->h1($self->{title});
	$self->{footer} = $options{footer} ? $options{footer} : $self->{cgi}->hr . $self->{cgi}->i('Powered by Perl') . $self->{cgi}->end_html;

	# set the timeout field
	$self->{timeout} = $options{timeout} ? $options{timeout} : 600;	

	# set the register field
	$self->{register} = $options{register} ? $options{register} : 0;
	$self->{register_template} = $options{register_template} ? $options{register_template} : 'Click %URL% to activate your account';
	$self->{register_subject}  = $options{register_subject}  ? $options{register_subject}  : 'Activate account';
	$self->{register_from}     = $options{register_from}     ? $options{register_from}     : 'register@localhost';

	# set the forgot field
	$self->{forgot}   = $options{forgot}   ? $options{forgot}   : 0;
	$self->{forgot_template} = $options{forgot_template} ? $options{forgot_template} : 'Click %URL% to reset your password';
	$self->{forgot_subject}  = $options{forgot_subject}  ? $options{forgot_subject}  : 'Password reset';
	$self->{forgot_from}     = $options{forgot_from}     ? $options{forgot_from}     : 'forgot@localhost';

	$self->{smtpserver} = $options{smtpserver} ? $options{smtpserver} : '';

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

	# Customize the feedback messages
	$self->{msg_access_denied}	= $options{msg_access_denied} ? $options{msg_access_denied} : 'Access denied';
	$self->{msg_invalid_id}		= $options{msg_invalid_id}    ? $options{msg_invalid_id}    : 'id is not what we expected';
	$self->{msg_illegal_content}	= $options{msg_illegal_content} ? $options{msg_illegal_content} : 'Illegal content posted via GET';

	$self->{msg_input_invalid}	= $options{msg_input_invalid} ? $options{msg_input_invalid} : '%d did not validate, because we were expecting %t';
	$self->{msg_register_token}	= $options{msg_register_token} ? $options{msg_register_token} : 'Registration token sent.  Please check your email';

	$self->{msg_session_error}	= $options{msg_session_error} ? $options{msg_session_error} : 'Could not create session';

	$self->{msg_yubikey_need}	= $options{msg_yubikey_need} ? $options{msg_yubikey_need} : 'You will need your yubikey to authenticate';

	$self->{msg_password_reset}	= $options{msg_password_reset} ? $options{msg_password_reset} : 'Your password has been reset and sent to you via email.';
	$self->{msg_password_error}	= $options{msg_password_error}	? $options{msg_password_error} : 'Could not reset the password';
	$self->{msg_password_match}	= $options{msg_password_match}  ? $options{msg_password_match} : 'The two passwords do not match';
	$self->{msg_password_strength}	= $options{msg_password_strength}?$options{msg_password_strength} : 'The password is not strong enough';
	$self->{msg_password_success}	= $options{msg_password_success} ?$options{msg_password_success}  : 'Password changed';
	$self->{msg_password_error}	= $options{msg_password_error} 	? $options{msg_password_error} : 'Cannot change password';

	$self->{msg_token_error}	= $options{msg_token_error}	? $options{msg_token_error} : 'Can not create a token';
	$self->{msg_token_invalid}	= $options{msg_token_invalid}	? $options{msg_token_invalid} : 'The supplied token is invalid';

	$self->{msg_account_invalid}	= $options{msg_account_invalid} ? $options{msg_account_invalid} : 'The provided account is not a valid email address';
	$self->{msg_account_validated}	= $options{msg_account_validated} ? $options{msg_account_validated} : 'Your account has been validated.  You may now log on.';
	$self->{msg_account_error}	= $options{msg_account_error}	? $options{msg_account_error} : 'Unable to validate the account';

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

		# We won't allow any type of GET methods
		if($ENV{QUERY_STRING} ne '')
		{
			$self->error($self->{msg_illegal_content});
		}

		$self->session_refresh();
		if($self->param('func') eq 'logout')
		{
			$self->logout();
		}
		if($self->param('func') eq 'password')
		{
			$self->change_password();
		}
		if($self->param('func') =~ /^admin/)
		{
			$self->admin_module();
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
		
		# We won't allow any type of GET methods
		if($ENV{QUERY_STRING} ne '')
		{
			$self->error($self->{msg_illegal_content});
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

	my $ssl = $ENV{HTTPS} ? $ENV{HTTPS} : 'off';
	my $ssll = $ssl eq 'on' ? 1 : 0;

	my $cookie = new CGI::Cookie(-name=>$self->{cookie},-value=>$self->{session},-secure=>$ssll);

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

	return CGI::header({%opts}) . $self->{header} . $self->build_post_js("securefunction",$self->{cgi}->url,"","func") . $self->menu_system;
}

=head2 menu_system

Displays the basic system meny

=cut

sub menu_system
{
	my ($self) = @_;

	my $cgi = $self->{cgi};

	my $r = '';
	if($self->is_admin)
	{
		$r .= $cgi->li($self->funclink('Admin','admin'));
	}

	$r .= $cgi->li($self->funclink('Home',''));

	if($self->{username} eq '')
	{
		if($self->{register} == 1)
		{
			$r .= $cgi->li($self->funclink('Register','register'));
		}
		if($self->{forgot} == 1)
		{
			$r .=  $cgi->li($self->funclink('Forgot password','forgot'));
		}
	}
	else
	{
		$r .= $cgi->li([$self->funclink('Change Password','password'),$self->funclink('Logout','logout')]);
	}

	return $cgi->div({class => 'menu_system'},$cgi->ul($r));
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

	if($token && !$self->validate_input("md5hex",$token))
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
				$self->error($self->{msg_access_denied});
				$self->log('forgot','User does not exist');
			}
			else
			{
				if($token eq $token2 && $token ne '')
				{
					# we have a token, and it matches.  Reset the password, and mail it to the user to log in

					my $sth = $self->{dbh}->prepare("update tbl_users set token = '', password = ? where username = ?");
					my $newpass = $self->generate_password();
					my $tokennew = $self->generate_token();

                                	if($sth->execute($self->encrypt($newpass),$user2))
					{
						# On success, let's email it out

						my %VARS;
						$VARS{BASE} = $self->{cgi}->url;
						$VARS{PASSWORD} = $newpass;

						my $msg = $self->{forgot_reset};
						foreach my $v (keys %VARS)
						{
							$msg =~ s/\%$v\%/$VARS{$v}/g;
						}
						$self->send_email($self->{forgot_from},$user2,$self->{forgot_subject},$msg);
						$self->message($self->{msg_password_reset});
					}
					else
					{
						$self->error($self->{msg_password_error});
					}


				}
                                elsif($token eq '')
                                {
                                        # Generate a new token, and mail it to the user to click

                                        my $new_token = $self->generate_token();

					my $sth = $self->{dbh}->prepare('update tbl_users set token = ? where username = ?');
					if($sth->execute($new_token,$user2))
					{
						my %VARS;
						# new token set, now main a link to the user
						$VARS{URL} = $self->{cgi}->url . "?func=forgot&username=$user2&token=$new_token";
						$VARS{BASE} = $self->{cgi}->url;
						my $msg = $self->{forgot_template};
						foreach my $v (keys %VARS)
						{
							$msg =~ s/\%$v\%/$VARS{$v}/g;
						}
						$self->send_email($self->{forgot_from},$user2,$self->{forgot_subject},$msg);

						$self->message($self->{msg_password_reset});
					
					}
					else
					{
						$self->error($self->{msg_token_error});
					}

                                }
				else
				{
					$self->error($self->{msg_token_invalid});
				}
			}
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
			$self->error($self->{msg_account_invalid});
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
					$self->error($self->{msg_access_denied});
				}
				else
				{
					if($token2 ne $token)
					{
						$self->log('register','Provided token does not validate.');
						$self->error($self->{msg_token_invalid});
					}
					else
					{
						# confirm that the incoming token was in fact a valid token
						if(!$self->validate_input("md5hex",$token))
						{
							return 0;
						}
	
						# Everything checks out... Enable the account
						my $sth = $self->{dbh}->prepare("update tbl_users set token = '',state = 0,validate_ip = ?, validate_timestamp = from_unixtime(?) where username = ?");
						if($sth->execute($ENV{REMOTE_ADDR},time,$user2))
						{
							$self->log('register','User has been validated');
							$self->message($self->{msg_account_validated});
						}
						else
						{
							$self->log('register','Unable to validate the user');
							$self->error($self->{msg_account_invalid});
						}
					}
				}
			}
			else
			{
				# The user does not exist yet
				my $sth = $self->{dbh}->prepare('insert into tbl_users (username,password,token,state,register_ip,register_timestamp) values(?,?,?,1,?,from_unixtime(?))');
				
				my $newpass = $self->generate_password();

				my $tokennew = $self->generate_token();

				if($sth->execute($user,$self->encrypt($newpass),$tokennew,$ENV{REMOTE_ADDR},time))
				{
					$self->log('register','New user registered.');
					#my $url = $self->{cgi}->url . "?func=register&username=$user&token=$tokennew";

					my %VARS;
					# new token set, now main a link to the user
					$VARS{URL} = $self->{cgi}->url . "?func=register&username=$user2&token=$tokennew";
					$VARS{BASE} = $self->{cgi}->url;
					my $msg = $self->{register_template};
					foreach my $v (keys %VARS)
					{
						$msg =~ s/\%$v\%/$VARS{$v}/g;
					}
					$self->send_email($self->{register_from},$user2,$self->{register_subject},$msg);

					$self->message($self->{msg_register_token});
				}
				else
				{
					$self->error($self->{msg_token_error});
				}
			}
		}
	}
}

sub housekeeping
{
	my ($self) = @_;

	# Delete old sessions (at least double the session timeout)
	$self->{dbh}->do('delete from tbl_session where session_time < date_sub(current_timestamp,INTERVAL " . $self->{timeout} * 2 . " SECOND)');

	# Delete old session variables
	$self->{dbh}->do('delete from tbl_session_vars where session not in (select session from tbl_session)');

	# Delete unvalidated user accounts (that was not validated in 24 hours)
	$self->{dbh}->do('delete from tbl_users where register_timestamp < date_sub(current_timestamp,INTERVAL 24 HOUR) and validate_timestamp is null');

	# Delete log files older than 30 days
	$self->{dbh}->do('delete from tbl_logs where eventtime < date_sub(current_timestamp,INTERVAL 30 DAY)');
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
	$self->{dbh}->do('delete from tbl_session_vars where session=?',undef,$self->{session});

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
			$self->error($self->{msg_password_match});
		}

		# is the password strong enough?
		if(!$self->validate_input('password',$pass1))
		{
			$self->error($self->{msg_password_strength});
		}

		if($self->{dbh}->do("update tbl_users set password = ? where username = ?",undef,$self->encrypt($pass1),$self->{username}))
		{
			$self->log('password','User has successfully changed their password');
			$self->message($self->{msg_password_success});
		}
		else
		{
			$self->error($self->{msg_password_error});
		}
	}
}

sub change_password_form
{
	my ($self) = @_;

	my $schema = <<SCHEMA
pass1,Password,password,20,password
pass2,Confirm,password,20,password
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
username,Email Address,text,30,email
password,Password,password,50,password
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
			$self->housekeeping();	# we need to perform housekeeping, we'll do it when a user logs on
			$self->session_create();
		}
		else
		{
			$self->{username} = $user;
			$self->log('logon','Access denied');
			$self->error($self->{msg_access_denied});
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
		$self->error($self->{msg_session_error});
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
	$self->{dbh}->do('update tbl_session_vars set session=? where session = ?',undef,$self->{session},$old_session);
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
		my $a = $ary[1] ? $ary[1] : 0;

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
			$self->error($self->{msg_access_denied});
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
					$self->error($self->{msg_yubikey_need});
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
						$self->error($self->{msg_access_denied});
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
								$self->error($self->{msg_access_denied});
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
		$self->error($self->{msg_access_denied});
		return 0;
	}
	return 0;
}

sub message
{
        my ($self,$text) = @_;

        $self->log('message',$text);

        print $self->header();
        print $self->{cgi}->div({class=>'success'},$text);
        $self->finish();
}
sub error
{
	my ($self,$text) = @_;

	$self->log('error',$text);

	print $self->header();
	print $self->{cgi}->div({class=>'error'},$text);
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

=head3 Schema format (field name, description, type, validation, default, sql)

=head4 fieldname

The field name that will be used in SQL and param calls

=head4 description

The field name that will be displayed

=head4 type

The type of the field, ie text, textarea, dropdown, or password

=head4 size

Defines the size of the field.

=head4 validation

Defines the input data check that will be performed to ensure the input validation is passed.  Options can be email, password, number or text.

=head4 sql

Defines the SQL query to execute that will populate a dropdown list, should you use a dropdown.

=cut

sub form
{
	my ($self,$schema,$submit,$func,$title,$captcha,%VALUES) = @_;
	
	my $cgi = $self->{cgi};

	print $cgi->h2($title);
	print $cgi->start_form({-action=>$cgi->url,-autocomplete=>"off"});;
	print $cgi->start_table;

	my $isid = 0;
	foreach my $f (split(/\n/,$schema))
	{
		chomp($f);
		my ($fn,$desc,$type,$size,$validation,$required,$default,$sql) = split(/\,/,$f);

		if($fn eq 'id')
		{
			$isid = 1;
		}

		my $value = $VALUES{$fn};

		if($value eq '')
		{
			$value = $default;
		}
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
					if($ary[0] eq $value)
					{
						print "<option value=\"$ary[0]\" selected>$ary[0]</option>\n";
					}
					else
					{
						print "<option value=\"$ary[0]\">$ary[0]</option>\n";
					}
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

	$self->log('update','Editing an entry');
	
	my $id = $self->param('id');
	if(!$self->validate_input('number',$id))
	{
		$self->error($self->{msg_invalid_id});
	}

	my $sql = "update $table set ";

	my @VALUES;
	foreach my $s (split(/\n/,$schema))
	{
		my ($fn,$desc,$type,$sz,$valid,$required,$default,$ddsql) = split(/\,/,$s);
		$sql .= "$fn = ?,";

		my $v = $self->param($fn);

		if($type =~ /password/i)
		{
			my $sth = $self->{dbh}->prepare("select $fn from $table where id = ?");
			$sth->execute($self->param('id'));
			my ($oldpw) = $sth->fetchrow_array();
			$sth->finish();

			# if the old password in the table is different to the one passed to us, encrypt it
			if($oldpw ne $v)
			{
				$v = $self->encrypt($v);
			}
		}

		push(@VALUES,$v);
	}
	$sql =~ s/\,$//g;
	$sql .= " where id = ?";

	my $sth = $self->{dbh}->prepare($sql);

	return $sth->execute(@VALUES,$id);
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
		$self->error($self->{msg_invalid_id});
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
		$self->error($self->{msg_invalid_id});
	}

}

=head2 form_delete

Deletes the entry from the table

=cut

sub form_delete
{
	my ($self,$table) = @_;

	$self->log('delete','Deleting entry');

	my $id = $self->param('id');
	if(!$self->validate_input('number',$id))
	{
		$self->error($self->{msg_invalid_id});
	}

	my $sth = $self->{dbh}->prepare("delete from $table where id = ?");

	return $sth->execute($id);
}

=head2 form_insert

Takes the input from a form, and inserts it into a database

Input : schema, table, default values (for readonly fields)

=cut

sub form_insert
{
	my ($self,$schema,$table,%VALUES) = @_;

	my $dbh = $self->{dbh};

	$self->log('insert','Added an entry');
	# read the schema, and start constructing the SQL

	my @fields;
	my @values1;
	my @values2;

	push(@fields,'xx_created_by');
	push(@values2,$self->{username});

	foreach my $s (split(/\n/,$schema))
	{
		chomp($s);

		my ($fn,$desc,$type,$sz,$valid,$required,$default,$sql) = split(/\,/,$s);

		my $v = $self->param($fn);
		if(!$self->validate_input($valid,$v))
		{
			my $m = $self->{msg_input_invalid};
			$m =~ s/\%d/$desc/g;
			$m =~ s/\%t/$valid/g;

			$self->error($m);
		}

		if($type =~ /password/i)
		{
			$v = $self->encrypt($v);
		}
		push(@fields,$fn);
		push(@values1,"?");
		push(@values2,$type eq 'readonly' ? $VALUES{$fn} : $v);
	}

	my $sql = "insert into $table (" . join (",",@fields) . ") values (" . join(",",@values1) . ")";

	return $dbh->do($sql,undef,@values2);
}

=head2 form_list

Show the result of a SQL table

input : schema, table, title, linkfield, next func, where, actions

=cut

sub form_list
{
	my ($self,$schema,$table,$title,$linkfield,$func,$where,$actions) = @_;

	my $cgi = $self->{cgi};

	print $cgi->h2($title);
	my @fields;
	my @desc;

	my $linkc = '';

	my $c = 0;
	push(@fields,'id');
	foreach my $s (split(/\n/,$schema))
	{
		my ($fn,$de,$ty) = split(/\,/,$s);
		if($ty ne 'password' && $ty ne 'textarea')
		{
			push(@fields,$fn);
			push(@desc,$de);
			if($fn eq $linkfield)
			{
				$linkc = $c;
			}
			$c++;
		}
	}

	print $self->build_post_js("submitform$func",$self->{cgi}->url,"func=$func" ,"id");

	my $order = $self->param('order');
	if($order == 0)
	{
		$order = 1;
	}
	else
	{
		$order = 0;
	}

	# We need to have func the same as the one that got us here, not the one we want to be when we move on from this page
	print $self->build_post_js("orderform",$self->{cgi}->url,"func=" . $self->param('func') . "&order=$order","field");

	foreach my $a (split(/\|/,$actions))
	{
		my ($t,$f) = split(/\,/,$a);
		print $self->build_post_js("actions$f",$self->{cgi}->url,"func=$f","id");
	}

	my $orderfield = $self->param('field') ? $self->param('field') : 0;

	my $SQLO = '';
	if($self->validate_input('number',$orderfield))
	{
		$SQLO = " order by " . $fields[$orderfield];

		if($self->validate_input('number',$order))
		{
			if($order == 1)
			{
				$SQLO .= " DESC";
			}
			else
			{
				$SQLO .= " ASC";
			}
		}
	}

	# Build the arrow to show where we're filtering
	my $AR;
	if($order == 0)
	{
		$AR = "&#x25B4;";
	}
	else
	{
		$AR  = "&#x25BE;";
	}

	print $cgi->start_table({border=>1});
	print $cgi->start_Tr();
	$c = 0;
	foreach my $f (@desc)
	{
		my $RR = '';
		if($c == $orderfield)
		{
			$RR = $AR;
		}
		print $cgi->th("<a href=\"javascript:void();\" onclick=\"javascript:orderform($c);\">$f</a> $RR");
		$c++;
	}

	# do we have any actions ?
	foreach my $a (split(/\|/,$actions))
	{
		my ($t,$f) = split(/\,/,$a);
		print $cgi->th($t);
	}
	print $cgi->end_Tr;

	my $sth = $self->{dbh}->prepare('select ' . join(',',@fields) . " from $table $where $SQLO");
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

		# do we have any actions ?
		foreach my $a (split(/\|/,$actions))
		{
			my ($t,$f) = split(/\,/,$a);
			print $cgi->td("<a href=\"javascript:void();\" onclick=\"javascript:actions$f($id);\">$t</a>");
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
		$self->{dbh}->do("create table $table (id integer auto_increment primary key,xx_created_by varchar(200))");
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
		my ($fn,$de,$ty,$sz,$validation,$required,$default,$sql) = split(/\,/,$s);
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
	my ($self,$c,$v) = @_;

	my $in = $self->{cgi}->param($c,$v) ;

	# strip unsafe characters
	$in =~ s/[<>\\"\%;\(\)&\0]//g;
	return $in;
}

=head2 set_variable

Defines a session variable

input : parameter, value

=cut

sub set_variable
{
	my ($self,$param,$value) = @_;

	$self->{dbh}->do('delete from tbl_session_vars where session = ? and param = ?',undef,($self->{session},$param));
	$self->{dbh}->do('insert into tbl_session_vars (session,param,value) values(?,?,?)',undef,($self->{session},$param,$value));
}

=head2 get_variable

Retrieves a session variable

input : parameter

Output : value

=cut
sub get_variable
{
	my ($self,$param) = @_;

	my $sth = $self->{dbh}->prepare('select value from tbl_session_vars where session = ? and param = ?');
	$sth->execute($self->{session},$param);
	my ($result) = $sth->fetchrow_array();
	$sth->finish();

	return $result;
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
		if(!$self->{dbh}->do('create table tbl_users (id integer auto_increment primary key,username varchar(200),password varchar(200),yubikey varchar(12),token varchar(200),state integer default 0,is_admin integer default 0,register_ip varchar(20),register_timestamp datetime,validate_ip varchar(20), validate_timestamp datetime)'))
		{
			$self->error($DBI::errstr);
		}
		if(!$self->{dbh}->do('alter table tbl_users add unique (username)'))
		{
			$self->error($DBI::errstr);
		}
		if(!$self->{dbh}->do("insert into tbl_users (username,password,is_admin,register_ip,register_timestamp,validate_ip,validate_timestamp) values('admin',?,1,?,from_unixtime(?),?,from_unixtime(?))",undef,$self->encrypt('password') , $ENV{REMOTE_ADDR},time,$ENV{REMOTE_ADDR},time))
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

	# Create the session variables table
	if(!$self->{dbh}->do('select 1 from tbl_session_vars'))
	{
		if(!$self->{dbh}->do('create table tbl_session_vars (id integer auto_increment primary key,session varchar(200),param varchar(200),value varchar(255))'))
		{
			$self->error($DBI::errstr);
		}

		if(!$self->{dbh}->do('alter table tbl_session_vars add index (session)'))
		{
			$self->error($DBI::errstr);
		}

		if(!$self->{dbh}-do('alter table tbl_session_vars add index (param)'))
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
	$sth->execute($self->{username},$type,$msg,time,$ENV{REMOTE_ADDR});
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

	if($self->{captcha} != 1)
	{
		return 1;
	}

	my $challenge = $self->param('recaptcha_challenge_field');
	my $response  = $self->param('recaptcha_response_field');

	if($response)
	{
        	# Verify submission
        	my $result = $self->{captcha_object}->check_answer($self->{captcha_private}, $ENV{'REMOTE_ADDR'}, $challenge, $response);

        	if ( $result->{is_valid} )
        	{
			return 1;
        	}
        	else
        	{
                	# Error
                	my $error = $result->{error};
			$self->log("captcha","Captcha did not validate - $error");
			return 0;
        	}
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

sub admin_module
{
	my ($self) = @_;

	# == check if the user is an admin
	if(!$self->is_admin)
	{
		$self->error($self->{msg_access_denied});
	}

	# == if he is, we go on

	# == Define the schema we'll use
	my $SCHEMA = <<SCHEMA
username,Email Address,text,20,email
password,Password,password,20,password
is_admin,Admin,dropdown,5,number,0,select 0 union select 1
SCHEMA
;
	if($self->{yubikey} == 1)
	{
		$SCHEMA .= "yubikey,Yubikey ID,text,12,text";
	}
	my $func = $self->param('func');

	print $self->header();
	print $self->{cgi}->h2('Admin module');

	print $self->funclink('New','adminnew');

	# ============== Edit functions =========== #

	if($func eq 'admineditform')
	{
		$self->form_edit($SCHEMA,"tbl_users","Edit","Edit the entry","admineditit");
	}

	if($func eq 'admineditit')
	{
		if(!$self->form_update($SCHEMA,'tbl_users'))
		{
			print "Error updating item -- " . $DBI::errstr;
		}
	}

	# ================= Delete functions ================== #

	if($func eq 'admindeleteit')
	{
		if(!$self->form_delete('tbl_users'))
		{
			print "Problem deleting : " . $DBI::errstr;
		}
	}

	# =============== New entries ============ #

	if($func eq 'adminnew')
	{
		$self->form($SCHEMA,'Create user','admincreate','Create a new user',0,());
	}

	if($func eq 'admincreate')
	{
		if(!$self->form_insert($SCHEMA,'tbl_users',()))
		{
			print "Problem creating the user -- " . $DBI::errstr;
		}
	}	

	# =========== The main list of entries to display
	if($func eq 'admin' || $func eq 'admincreate' || $func eq 'admindeleteit' || $func eq 'admineditit')
	{
		$self->form_list($SCHEMA,"tbl_users","User list","username","admineditform","","Edit,admineditform|Delete,admindeleteit");
	}
	
	$self->finish();
}

=head2 funclink

Instead of using <a href links, call this function instead.  It will embed a proper javascript substitute to ensure no GET urls are posted

input : text, func

=cut

sub funclink
{
	my ($self,$txt,$f) = @_;

	return $self->{cgi}->a({href=>"javascript:void();", onclick=>"javascript:securefunction(\'$f\');"},$txt);
}
sub validate_input
{
	my ($self,$type,$in) = @_;

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
	elsif($type eq 'password' && $in =~ /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,20}$/)
	{
		return 1;
	}
	elsif($type eq 'text' && $in =~ /\b[0-9A-Za-z\'.]+\b/)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

=head2 schema_dump

Will show a table of the schema (helpful to debug if the schema is buggy)

=cut

sub schema_dump
{
	my ($self,$schema) = @_;

	my @heads = ('fieldname','description','type','size','validation','required','default','dropdown sql');

	my $result = $self->{cgi}->start_table({border=>1});
	$result .= $self->{cgi}->Tr($self->{cgi}->th([@heads]));

	foreach my $f (split(/\n/,$schema))
	{
		#my ($fn,$desc,$type,$size,$validation,$required,$default,$sql) = split(/\,/,$f);
		my @ary = split(/\,/,$f);
		$result .= $self->{cgi}->Tr($self->{cgi}->td([@ary]));	

	}
	$result .= $self->{cgi}->end_table;

	return $result;

}

=head2 is_admin

Will advise if the user is an administrator

=cut

sub is_admin
{
	my ($self) = @_;

	if($self->{username} eq '')
	{
		return 0;
	}
	my $sth = $self->{dbh}->prepare('select is_admin from tbl_users where username = ?');
	$sth->execute($self->{username});
	my @ary = $sth->fetchrow_array();
	$sth->finish();
	return $ary[0];
}

=head1 Additional information

=head2 Using an existing database

All tables need an id field (auto increment primary key), and a varchar of xx_created_by.  The xx_created_by field is populated by the username that created that particular entry.  This is used in scenarios where a filter has to be set on only showing items belonging to the particular user.  See phonebook2.pl for a practical example.

=head1 AUTHOR

Phil Massyn, C<< <phil at massyn.net> >>

=head1 TODO

=head2 Bugs
* Check if readonly fields are truely readonly (the hidden field should not pass something to the database)

=head2 New features
* Add not null to the schema
* Form list -- allow "next page" if it returns more than ie 30 items on a page
* Searching of tables
* Authorization module (ie group membership)
* Include proper CSS and div tags for full template customization
* Ability to have a 2nd table list linked to an earlier selection
* Add a default value to the schema

=head2 Enhancements
* Process for a lost Yubikey
* Log which table and ID was changed (not just that the table was changed)
* Ability to record additional fields during registration
* Change form_* functions to use hashes as inputs, not seperate fields
* Change dropdown & select to use native CGI parameters
* Ability upload files
* Ability to render files (ie if you upload an image, be able to show it in the browser)
* Add a workflow example

=head2 Stuff we won't do
* Split the module into smaller files (because when I run the code on GoDaddy, it becomes a mess to cross reference)

=head1 REVISION
0.10	Do not show "textarea" in a list
	Removed Home link from default header code
	Added additional actions to form_list
	Updated phonebook example
	Fixed bug with default admin user generation
	Fix admin module to use formlist's new actions feature
	Added xx_created_by field to all our created tables
	Added schema_dump procedure to display schemas
	Started adding some basic style sheet detail (system menu)
	Added system menu to changing passwords
	Ability to call is_admin without logged on will not call the database
	System_menu can detect if a user is logged on, and will show one of two menus
	Added more css to error and success messages

0.09	Customize register & forget emails
	Added msg_* to allow customization of feedback messages
	Added admin module
	Added funclink to manage hyperlinks through javascript better
	Delete accounts not validated within 24 hours as part of housekeeping
	Clean up of logs older than 30 days in housekeeping
	Change javascript calls to use native cgi->a calls
	Added a home link to the error messages
	Add timestamp, IP and user agent of machines used to create account and validate account for legal requirements
		- This requires a schema update.  If you had a version prior to 0.09, your database will need to be updated.

0.08	Change order of form_list by clicking headers
	Create tbl_session_vars table
	Added session variables through get_variable and set_variable
	Added housekeeping to remove orphaned table entries
	Fixed dropdown bug not selecting the right value
		- This requires a schema update.  If you had a version prior to 0.08, your database will need to be updated.

0.07	Fixed GET blocking not to prevent register and forget from working
	Added field in database to indicate administrators
	Prevented "password" fields from being displayed in lists
	Added the 2nd field to self param
	Encrypt passwords when using form_insert function
	Encrypt passwords if they're being changed through form_update
	Fixed number validation when validating a 0.
	Added a text input validation

0.06	Added autocomplete to login form
	Added form_delete function
	Added strong password enforcement
	Removed debug logs from captcha procedure
	Added logging when database gets changed

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
