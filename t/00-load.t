#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'CGI::AuthenticationFramework' ) || print "Bail out!\n";
}

diag( "Testing CGI::AuthenticationFramework $CGI::AuthenticationFramework::VERSION, Perl $], $^X" );
