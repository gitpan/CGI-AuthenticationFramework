#!/usr/bin/perl

# Phonebook application built with the CGI::AuthenticationFramework

# In this version, everyone shares the same phone book.  Any change is automatically updated.

use strict;
use CGI::AuthenticationFramework;
#do "AuthenticationFramework.pm";
use DBI;
use CGI;
use CGI::Carp qw(fatalsToBrowser);		# disable when you go live 
my $cgi = new CGI;

# == connect to the database
my $dbh = DBI->connect("DBI:mysql:database=dev;host=localhost",'root','') || die $DBI::errstr;

# == create the authentication link
my $sec = CGI::AuthenticationFramework->new(
	{
		# We must have the dbh and cgi... it's the basis of everything we do
	dbh		=> $dbh,
	cgi		=> $cgi,
		# session timeout 
	timeout 	=> 600,
		# Customize the look and feel
	style		=> 'style.css',
	title		=> 'Phonebook application',
	footer		=> 'Hello world',
		# Customize registration emails
	register 	=> 1,
	forgot		=> 1,
	yubikey		=> 0,
	yubi_id		=> 195,
	yubi_api	=> '12345',
	smtpserver 	=> 'mail.tpg.com.au'
	}
);

# == create the tables
$sec->setup_database();	# run this only once for performance.. No damage to keep it there

# == do we go through, or block access.. This is where the rubber meets the road
$sec->secure();

# == once we get through that, we can send our headers
print $sec->header();

# == We can also show the system meny
print $sec->menu_system();

# ============================================ Let's do an actual application ================================= #

# Let's create some menu items
print $sec->funclink('New','new');

# Let's start with the schema.  This is the framework of all the forms we'll use
# fieldname,description,type,size,validation,required,default,dropdown sql
my $SCHEMA = <<SCHEMA;
firstname,First name,text,40,text,yes
lastname,Last name,text,40,text,yes
email,Email Address,text,50,email,no
phoneno,Phone number,text,40,text,yes
age,Age,text,5,number,yes
gender,Gender,dropdown,10,text,yes,,select 'Male' union select 'Female'
notes,Notes,textarea,10|40,text,no,We can have some default information
SCHEMA
;

#print $sec->schema_dump($SCHEMA);

# == define the SQL tablename to use
my $TABLE = "tbl_phonebook";

# -- is the table created with all the fields?
$sec->form_create_table($SCHEMA,$TABLE);

# -- We will be checking the func variable in our 
my $func = $sec->param('func');

# == edit functions

if($func eq 'editform')
{
	$sec->form_edit($SCHEMA,$TABLE,"Edit","Edit the entry","editit");
	# - use the schema - $SCHEMA
	# - use the table - $TABLE
	# - use the title of the page - Edit
	# - Use the title of the button - Edit the entry
	# - the name of the func to call after the form is completed
}
if($func eq 'editit')
{
	if(!$sec->form_update($SCHEMA,$TABLE))
	{
		print "Error updating item -- " . $DBI::errstr;
	}
}

# == creating new entries

if($func eq 'new')
{
	$sec->form($SCHEMA,'Create user','create','Create a new user',0,());
}

if($func eq 'create')
{
	if(!$sec->form_insert($SCHEMA,$TABLE,()))
	{
		print "Problem creating the entry -- " . $DBI::errstr;
	}
}

# == Deleting entries
if($func eq 'delete')
{
	$sec->form_list($SCHEMA,$TABLE,"Delete list","firstname","deleteit","");
}

if($func eq 'deleteit')
{
	if(!$sec->form_delete($TABLE))
	{
		print "Problem deleting : " . $DBI::errstr;
	}
}

# -- our main page will show what is on the table, or when we click edit.  We also want to show this after something was edited or deleted

if($func eq 'create' || $func eq 'login' || $func eq '' || $func eq 'edit' || $func eq 'editit' || $func eq 'deleteit')
{
	$sec->form_list($SCHEMA,$TABLE,"Edit list","firstname","editform","","Edit,editform|Delete,deleteit");
	# - use the schema - $SCHEMA
	# - on the table - $TABLE
	# - the title of the page - Edit list
	# - the field to highlight - firstname
	# - the name of the func on that link - editform
	# - the where filter - (currently blank)
	# - the additional actions (action,func|action2, func2)
}

# ============================================================================================================= #


# == when we're done, we call the finish function.  This clears the data connection, and prints the footer code
$sec->finish();
