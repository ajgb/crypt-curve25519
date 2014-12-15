use ExtUtils::MakeMaker;
use Config;

my $extlib = $Config{archname} =~ /(?:amd64|x86_64)/ ? 'curve25519-donna-c64' : 'curve25519-donna';

WriteMakefile(
    NAME              => 'Crypt::Curve25519',
    VERSION_FROM      => 'lib/Crypt/Curve25519.pm',
    PREREQ_PM         => {},
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Crypt/Curve25519.pm', # retrieve abstract from module
       AUTHOR         => 'Alex J. G. Burzyński <ajgb\@cpan.org>') : ()),
    LIBS              => [''], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
    'MYEXTLIB'          => "curve25519-donna-master/$extlib\$(LIB_EXT)",
);

sub MY::postamble {
    return <<EOP;

\$(MYEXTLIB): curve25519-donna-master/Makefile
\tcd curve25519-donna-master && \$(MAKE) \$(PASTHRU)

EOP
}
