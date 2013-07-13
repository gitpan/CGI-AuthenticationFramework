use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'CGI::AuthenticationFramework',
    AUTHOR              => q{Phil Massyn <phil@massyn.net>},
    VERSION_FROM        => 'lib/CGI/AuthenticationFramework.pm',
    ABSTRACT_FROM       => 'lib/CGI/AuthenticationFramework.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
	'Auth::Yubikey_WebClient'	=> 1,
	'Digest::MD5'			=> 1,
	'CGI::Cookie'			=> 1
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'CGI-AuthenticationFramework-*' },
);
