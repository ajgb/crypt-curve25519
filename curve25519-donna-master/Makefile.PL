use ExtUtils::MakeMaker;
$Verbose = 1;
use Config;

my $extlib = $Config{archname} =~ /64/ ? 'curve25519-donna-c64' : 'curve25519-donna';
my $extflags = $Config{archname} =~ /64/ ? '' : '-m32';

WriteMakefile(
        NAME   => 'Crypt::Curve25519::curve25519donna',
        SKIP   => [qw(all static_lib static dynamic_lib dynamic)],
        clean  => {'FILES' => "$extlib\$(LIBEEXT)"},
        CCFLAGS => $extflags,
        NO_META => 1,
        NO_MYMETA => 1,
        C => [ "$extlib.c" ],
        OBJECT => "$extlib.o",
);

sub MY::top_targets {
    return <<EOT;

all :: static
pure_all :: static
static ::       $extlib\$(LIB_EXT)
$extlib\$(LIB_EXT): \$(O_FILES)
\t\$(AR) cr $extlib\$(LIB_EXT) \$(O_FILES)
\t\$(RANLIB) $extlib\$(LIB_EXT)

EOT
}

