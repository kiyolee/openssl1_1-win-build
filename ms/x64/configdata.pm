#! /usr/bin/env perl

package configdata;

use strict;
use warnings;

use Exporter;
#use vars qw(@ISA @EXPORT);
our @ISA = qw(Exporter);
our @EXPORT = qw(%config %target %disabled %withargs %unified_info @disablables);

our %config = (
  AR => "lib",
  ARFLAGS => [ "/nologo" ],
  AS => "ml64",
  ASFLAGS => [ "/nologo /Zi" ],
  CC => "cl",
  CFLAGS => [ "/W3 /wd4090 /nologo /O2" ],
  CPP => "\$(CC) /EP /C",
  CPPDEFINES => [  ],
  CPPFLAGS => [  ],
  CPPINCLUDES => [  ],
  CXXFLAGS => [  ],
  HASHBANGPERL => "/usr/bin/env perl",
  LD => "link",
  LDFLAGS => [ "/nologo /debug" ],
  LDLIBS => [  ],
  MT => "mt",
  MTFLAGS => [ "-nologo" ],
  PERL => "C:\\Perl\\bin\\perl.exe",
  RANLIB => "ranlib",
  RC => "rc",
  afalgeng => "",
  b32 => "0",
  b64 => "1",
  b64l => "0",
  bn_ll => "0",
  build_file => "makefile",
  build_file_templates => [  ],
  build_infos => [  ],
  build_type => "release",
  builddir => ".",
  cflags => [  ],
  conf_files => [  ],
  cppflags => [  ],
  cxxflags => [  ],
  defines => [ "NDEBUG" ],
  dirs => [ "crypto", "ssl", "engines", "apps", "test", "util", "tools", "fuzz" ],
  dynamic_engines => "0",
  engdirs => [  ],
  ex_libs => [  ],
  export_var_as_fn => "1",
  includes => [  ],
  lflags => [  ],
  lib_defines => [ "OPENSSL_PIC", "OPENSSL_CPUID_OBJ", "OPENSSL_IA32_SSE2", "OPENSSL_BN_ASM_MONT", "OPENSSL_BN_ASM_MONT5", "OPENSSL_BN_ASM_GF2m", "SHA1_ASM", "SHA256_ASM", "SHA512_ASM", "KECCAK1600_ASM", "RC4_ASM", "MD5_ASM", "AES_ASM", "VPAES_ASM", "BSAES_ASM", "GHASH_ASM", "ECP_NISTZ256_ASM", "X25519_ASM", "PADLOCK_ASM", "POLY1305_ASM" ],
  libdir => "",
  major => "1",
  minor => "1.1",
  openssl_algorithm_defines => [ "OPENSSL_NO_MD2", "OPENSSL_NO_RC5" ],
  openssl_api_defines => [  ],
  openssl_other_defines => [ "OPENSSL_RAND_SEED_OS", "OPENSSL_NO_ASAN", "OPENSSL_NO_CRYPTO_MDEBUG", "OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE", "OPENSSL_NO_DEVCRYPTOENG", "OPENSSL_NO_EC_NISTP_64_GCC_128", "OPENSSL_NO_EGD", "OPENSSL_NO_EXTERNAL_TESTS", "OPENSSL_NO_FUZZ_AFL", "OPENSSL_NO_FUZZ_LIBFUZZER", "OPENSSL_NO_HEARTBEATS", "OPENSSL_NO_MSAN", "OPENSSL_NO_SCTP", "OPENSSL_NO_SSL_TRACE", "OPENSSL_NO_SSL3", "OPENSSL_NO_SSL3_METHOD", "OPENSSL_NO_UBSAN", "OPENSSL_NO_UNIT_TEST", "OPENSSL_NO_WEAK_SSL_CIPHERS", "OPENSSL_NO_DYNAMIC_ENGINE", "OPENSSL_NO_AFALGENG" ],
  openssl_sys_defines => [ "OPENSSL_SYS_WIN64A" ],
  openssl_thread_defines => [ "OPENSSL_THREADS" ],
  openssldir => "",
  options => "--prefix=C:\\Program Files\\OpenSSL-1_1 --with-zlib-include=..\\..\\zlib --with-zlib-lib=..\\..\\zlib\\build-VS2017\\x64\\Release\\libz-static.lib enable-zlib no-asan no-crypto-mdebug no-crypto-mdebug-backtrace no-devcryptoeng no-dynamic-engine no-ec_nistp_64_gcc_128 no-egd no-external-tests no-fuzz-afl no-fuzz-libfuzzer no-heartbeats no-md2 no-msan no-rc5 no-sctp no-ssl-trace no-ssl3 no-ssl3-method no-ubsan no-unit-test no-weak-ssl-ciphers no-zlib-dynamic",
  perl_archname => "MSWin32-x64-multi-thread",
  perl_cmd => "C:\\Perl\\bin\\perl.exe",
  perl_version => "5.26.1",
  perlargv => [ "--prefix=C:\\Program Files\\OpenSSL-1_1", "--with-zlib-include=..\\..\\zlib", "--with-zlib-lib=..\\..\\zlib\\build-VS2017\\x64\\Release\\libz-static.lib", "VC-WIN64A-masm", "no-dynamic-engine", "zlib" ],
  perlenv => {
      "AR" => undef,
      "ARFLAGS" => undef,
      "AS" => undef,
      "ASFLAGS" => undef,
      "BUILDFILE" => undef,
      "CC" => undef,
      "CFLAGS" => undef,
      "CPP" => undef,
      "CPPDEFINES" => undef,
      "CPPFLAGS" => undef,
      "CPPINCLUDES" => undef,
      "CROSS_COMPILE" => undef,
      "CXX" => undef,
      "CXXFLAGS" => undef,
      "HASHBANGPERL" => undef,
      "LD" => undef,
      "LDFLAGS" => undef,
      "LDLIBS" => undef,
      "MT" => undef,
      "MTFLAGS" => undef,
      "OPENSSL_LOCAL_CONFIG_DIR" => undef,
      "PERL" => undef,
      "RANLIB" => undef,
      "RC" => undef,
      "RCFLAGS" => undef,
      "RM" => undef,
      "WINDRES" => undef,
      "__CNF_CFLAGS" => undef,
      "__CNF_CPPDEFINES" => undef,
      "__CNF_CPPFLAGS" => undef,
      "__CNF_CPPINCLUDES" => undef,
      "__CNF_CXXFLAGS" => undef,
      "__CNF_LDFLAGS" => undef,
      "__CNF_LDLIBS" => undef,
  },
  prefix => "C:\\Program Files\\OpenSSL-1_1",
  processor => "",
  rc4_int => "unsigned int",
  sdirs => [ "objects", "md4", "md5", "sha", "mdc2", "hmac", "ripemd", "whrlpool", "poly1305", "blake2", "siphash", "sm3", "des", "aes", "rc2", "rc4", "idea", "aria", "bf", "cast", "camellia", "seed", "sm4", "chacha", "modes", "bn", "ec", "rsa", "dsa", "dh", "sm2", "dso", "engine", "buffer", "bio", "stack", "lhash", "rand", "err", "evp", "asn1", "pem", "x509", "x509v3", "conf", "txt_db", "pkcs7", "pkcs12", "comp", "ocsp", "ui", "cms", "ts", "srp", "cmac", "ct", "async", "kdf", "store" ],
  shlib_major => "1",
  shlib_minor => "1",
  shlib_version_history => "",
  shlib_version_number => "1.1",
  sourcedir => ".",
  target => "VC-WIN64A-masm",
  tdirs => [ "ossl_shim" ],
  version => "1.1.1",
  version_num => "0x1010100fL",
);

our %target = (
  AR => "lib",
  ARFLAGS => "/nologo",
  AS => "ml64",
  ASFLAGS => "/nologo /Zi",
  CC => "cl",
  CFLAGS => "/W3 /wd4090 /nologo /O2",
  CPP => "\$(CC) /EP /C",
  HASHBANGPERL => "/usr/bin/env perl",
  LD => "link",
  LDFLAGS => "/nologo /debug",
  MT => "mt",
  MTFLAGS => "-nologo",
  RANLIB => "CODE(0x2bd0470)",
  RC => "rc",
  _conf_fname_int => [  ],
  aes_asm_src => "aes-x86_64.s vpaes-x86_64.s bsaes-x86_64.s aesni-x86_64.s aesni-sha1-x86_64.s aesni-sha256-x86_64.s aesni-mb-x86_64.s",
  aes_obj => "aes-x86_64.o vpaes-x86_64.o bsaes-x86_64.o aesni-x86_64.o aesni-sha1-x86_64.o aesni-sha256-x86_64.o aesni-mb-x86_64.o",
  apps_aux_src => "win32_init.c",
  apps_init_src => "../ms/applink.c",
  apps_obj => "win32_init.o",
  aroutflag => "/out:",
  asflags => "/c /Cp /Cx",
  asoutflag => "/Fo",
  bf_asm_src => "bf_enc.c",
  bf_obj => "bf_enc.o",
  bin_cflags => "/Zi /Fdapp.pdb",
  bin_lflags => "/subsystem:console /opt:ref",
  bn_asm_src => "bn_asm.c x86_64-mont.s x86_64-mont5.s x86_64-gf2m.s rsaz_exp.c rsaz-x86_64.s rsaz-avx2.s",
  bn_obj => "bn_asm.o x86_64-mont.o x86_64-mont5.o x86_64-gf2m.o rsaz_exp.o rsaz-x86_64.o rsaz-avx2.o",
  bn_ops => "EXPORT_VAR_AS_FN SIXTY_FOUR_BIT",
  build_file => "makefile",
  build_scheme => [ "unified", "windows", "VC-common" ],
  cast_asm_src => "c_enc.c",
  cast_obj => "c_enc.o",
  cflags => "/Gs0 /GF /Gy /MD",
  chacha_asm_src => "chacha-x86_64.s",
  chacha_obj => "chacha-x86_64.o",
  cmll_asm_src => "cmll-x86_64.s cmll_misc.c",
  cmll_obj => "cmll-x86_64.o cmll_misc.o",
  coutflag => "/Fo",
  cppflags => "",
  cpuid_asm_src => "x86_64cpuid.s",
  cpuid_obj => "x86_64cpuid.o",
  defines => [ "ZLIB", "OPENSSL_SYS_WIN32", "WIN32_LEAN_AND_MEAN", "UNICODE", "_UNICODE", "_CRT_SECURE_NO_DEPRECATE", "_WINSOCK_DEPRECATED_NO_WARNINGS", "OPENSSL_USE_APPLINK" ],
  des_asm_src => "des_enc.c fcrypt_b.c",
  des_obj => "des_enc.o fcrypt_b.o",
  disable => [  ],
  dso_cflags => "/Zi /Fddso.pdb",
  dso_extension => "",
  dso_scheme => "win32",
  ec_asm_src => "ecp_nistz256.c ecp_nistz256-x86_64.s x25519-x86_64.s",
  ec_obj => "ecp_nistz256.o ecp_nistz256-x86_64.o x25519-x86_64.o",
  enable => [  ],
  ex_libs => "..\\..\\zlib\\build-VS2017\\x64\\Release\\libz-static.lib ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib",
  exe_extension => "",
  includes => [ "..\\..\\zlib" ],
  keccak1600_asm_src => "keccak1600-x86_64.s",
  keccak1600_obj => "keccak1600-x86_64.o",
  ldoutflag => "/out:",
  lflags => "",
  lib_cflags => "/Zi /Fdossl_static.pdb",
  lib_cppflags => "",
  lib_defines => [ "L_ENDIAN" ],
  md5_asm_src => "md5-x86_64.s",
  md5_obj => "md5-x86_64.o",
  modes_asm_src => "ghash-x86_64.s aesni-gcm-x86_64.s",
  modes_obj => "ghash-x86_64.o aesni-gcm-x86_64.o",
  module_cflags => "",
  module_cxxflags => "",
  module_ldflags => "/dll",
  mtinflag => "-manifest ",
  mtoutflag => "-outputresource:",
  padlock_asm_src => "e_padlock-x86_64.s",
  padlock_obj => "e_padlock-x86_64.o",
  perlasm_scheme => "masm",
  poly1305_asm_src => "poly1305-x86_64.s",
  poly1305_obj => "poly1305-x86_64.o",
  rc4_asm_src => "rc4-x86_64.s rc4-md5-x86_64.s",
  rc4_obj => "rc4-x86_64.o rc4-md5-x86_64.o",
  rc5_asm_src => "rc5_enc.c",
  rc5_obj => "rc5_enc.o",
  rcoutflag => "/fo",
  rmd160_asm_src => "",
  rmd160_obj => "",
  sha1_asm_src => "sha1-x86_64.s sha256-x86_64.s sha512-x86_64.s sha1-mb-x86_64.s sha256-mb-x86_64.s",
  sha1_obj => "sha1-x86_64.o sha256-x86_64.o sha512-x86_64.o sha1-mb-x86_64.o sha256-mb-x86_64.o",
  shared_cflag => "",
  shared_defines => [  ],
  shared_extension => "",
  shared_extension_simple => "",
  shared_ldflag => "/dll",
  shared_rcflag => "",
  shared_target => "win-shared",
  sys_id => "WIN64A",
  template => "1",
  thread_defines => [  ],
  thread_scheme => "winthreads",
  unistd => "<unistd.h>",
  uplink_aux_src => "../ms/uplink.c uplink-x86_64.s",
  uplink_obj => "../ms/uplink.o uplink-x86_64.o",
  wp_asm_src => "wp-x86_64.s",
  wp_obj => "wp-x86_64.o",
);

our %available_protocols = (
  tls => [ "ssl3", "tls1", "tls1_1", "tls1_2", "tls1_3" ],
  dtls => [ "dtls1", "dtls1_2" ],
);

our @disablables = (
  "afalgeng",
  "aria",
  "asan",
  "asm",
  "async",
  "autoalginit",
  "autoerrinit",
  "autoload-config",
  "bf",
  "blake2",
  "camellia",
  "capieng",
  "cast",
  "chacha",
  "cmac",
  "cms",
  "comp",
  "crypto-mdebug",
  "crypto-mdebug-backtrace",
  "ct",
  "deprecated",
  "des",
  "devcryptoeng",
  "dgram",
  "dh",
  "dsa",
  "dso",
  "dtls",
  "dynamic-engine",
  "ec",
  "ec2m",
  "ecdh",
  "ecdsa",
  "ec_nistp_64_gcc_128",
  "egd",
  "engine",
  "err",
  "external-tests",
  "filenames",
  "fuzz-libfuzzer",
  "fuzz-afl",
  "gost",
  "heartbeats",
  "hw(-.+)?",
  "idea",
  "makedepend",
  "md2",
  "md4",
  "mdc2",
  "msan",
  "multiblock",
  "nextprotoneg",
  "ocb",
  "ocsp",
  "pic",
  "poly1305",
  "posix-io",
  "psk",
  "rc2",
  "rc4",
  "rc5",
  "rdrand",
  "rfc3779",
  "rmd160",
  "scrypt",
  "sctp",
  "seed",
  "shared",
  "siphash",
  "sm2",
  "sm3",
  "sm4",
  "sock",
  "srp",
  "srtp",
  "sse2",
  "ssl",
  "ssl-trace",
  "static-engine",
  "stdio",
  "tests",
  "threads",
  "tls",
  "ts",
  "ubsan",
  "ui-console",
  "unit-test",
  "whirlpool",
  "weak-ssl-ciphers",
  "zlib",
  "zlib-dynamic",
  "ssl3",
  "ssl3-method",
  "tls1",
  "tls1-method",
  "tls1_1",
  "tls1_1-method",
  "tls1_2",
  "tls1_2-method",
  "tls1_3",
  "dtls1",
  "dtls1-method",
  "dtls1_2",
  "dtls1_2-method",
);

our %disabled = (
  "afalgeng" => "not-linux",
  "asan" => "default",
  "crypto-mdebug" => "default",
  "crypto-mdebug-backtrace" => "default",
  "devcryptoeng" => "default",
  "dynamic-engine" => "option",
  "ec_nistp_64_gcc_128" => "default",
  "egd" => "default",
  "external-tests" => "default",
  "fuzz-afl" => "default",
  "fuzz-libfuzzer" => "default",
  "heartbeats" => "default",
  "md2" => "default",
  "msan" => "default",
  "rc5" => "default",
  "sctp" => "default",
  "ssl-trace" => "default",
  "ssl3" => "default",
  "ssl3-method" => "default",
  "ubsan" => "default",
  "unit-test" => "default",
  "weak-ssl-ciphers" => "default",
  "zlib-dynamic" => "default",
);

our %withargs = (
  zlib_include => "..\\..\\zlib",
  zlib_lib => "..\\..\\zlib\\build-VS2017\\x64\\Release\\libz-static.lib",
);

our %unified_info = (
);

# The following data is only used when this files is use as a script
my @makevars = (
    'AR',
    'ARFLAGS',
    'AS',
    'ASFLAGS',
    'CC',
    'CFLAGS',
    'CPP',
    'CPPDEFINES',
    'CPPFLAGS',
    'CPPINCLUDES',
    'CROSS_COMPILE',
    'CXX',
    'CXXFLAGS',
    'HASHBANGPERL',
    'LD',
    'LDFLAGS',
    'LDLIBS',
    'MT',
    'MTFLAGS',
    'PERL',
    'RANLIB',
    'RC',
    'RCFLAGS',
    'RM',
);
my %disabled_info = (
    'asan' => {
        macro => 'OPENSSL_NO_ASAN',
    },
    'crypto-mdebug' => {
        macro => 'OPENSSL_NO_CRYPTO_MDEBUG',
    },
    'crypto-mdebug-backtrace' => {
        macro => 'OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE',
    },
    'devcryptoeng' => {
        macro => 'OPENSSL_NO_DEVCRYPTOENG',
    },
    'ec_nistp_64_gcc_128' => {
        macro => 'OPENSSL_NO_EC_NISTP_64_GCC_128',
    },
    'egd' => {
        macro => 'OPENSSL_NO_EGD',
    },
    'external-tests' => {
        macro => 'OPENSSL_NO_EXTERNAL_TESTS',
    },
    'fuzz-afl' => {
        macro => 'OPENSSL_NO_FUZZ_AFL',
    },
    'fuzz-libfuzzer' => {
        macro => 'OPENSSL_NO_FUZZ_LIBFUZZER',
    },
    'heartbeats' => {
        macro => 'OPENSSL_NO_HEARTBEATS',
    },
    'md2' => {
        macro => 'OPENSSL_NO_MD2',
        skipped => [ 'crypto\md2' ],
    },
    'msan' => {
        macro => 'OPENSSL_NO_MSAN',
    },
    'rc5' => {
        macro => 'OPENSSL_NO_RC5',
        skipped => [ 'crypto\rc5' ],
    },
    'sctp' => {
        macro => 'OPENSSL_NO_SCTP',
    },
    'ssl-trace' => {
        macro => 'OPENSSL_NO_SSL_TRACE',
    },
    'ssl3' => {
        macro => 'OPENSSL_NO_SSL3',
    },
    'ssl3-method' => {
        macro => 'OPENSSL_NO_SSL3_METHOD',
    },
    'ubsan' => {
        macro => 'OPENSSL_NO_UBSAN',
    },
    'unit-test' => {
        macro => 'OPENSSL_NO_UNIT_TEST',
    },
    'weak-ssl-ciphers' => {
        macro => 'OPENSSL_NO_WEAK_SSL_CIPHERS',
    },
);
my @user_crossable = qw( AR AS CC CXX CPP LD MT RANLIB RC );
# If run directly, we can give some answers, and even reconfigure
unless (caller) {
    use Getopt::Long;
    use File::Spec::Functions;
    use File::Basename;
    use Pod::Usage;

    my $here = dirname($0);

    my $dump = undef;
    my $cmdline = undef;
    my $options = undef;
    my $target = undef;
    my $envvars = undef;
    my $makevars = undef;
    my $buildparams = undef;
    my $reconf = undef;
    my $verbose = undef;
    my $help = undef;
    my $man = undef;
    GetOptions('dump|d'                 => \$dump,
               'command-line|c'         => \$cmdline,
               'options|o'              => \$options,
               'target|t'               => \$target,
               'environment|e'          => \$envvars,
               'make-variables|m'       => \$makevars,
               'build-parameters|b'     => \$buildparams,
               'reconfigure|reconf|r'   => \$reconf,
               'verbose|v'              => \$verbose,
               'help'                   => \$help,
               'man'                    => \$man)
        or die "Errors in command line arguments\n";

    unless ($dump || $cmdline || $options || $target || $envvars || $makevars
            || $buildparams || $reconf || $verbose || $help || $man) {
        print STDERR <<"_____";
You must give at least one option.
For more information, do '$0 --help'
_____
        exit(2);
    }

    if ($help) {
        pod2usage(-exitval => 0,
                  -verbose => 1);
    }
    if ($man) {
        pod2usage(-exitval => 0,
                  -verbose => 2);
    }
    if ($dump || $cmdline) {
        print "\nCommand line (with current working directory = $here):\n\n";
        print '    ',join(' ',
                          $config{PERL},
                          catfile($config{sourcedir}, 'Configure'),
                          @{$config{perlargv}}), "\n";
        print "\nPerl information:\n\n";
        print '    ',$config{perl_cmd},"\n";
        print '    ',$config{perl_version},' for ',$config{perl_archname},"\n";
    }
    if ($dump || $options) {
        my $longest = 0;
        my $longest2 = 0;
        foreach my $what (@disablables) {
            $longest = length($what) if $longest < length($what);
            $longest2 = length($disabled{$what})
                if $disabled{$what} && $longest2 < length($disabled{$what});
        }
        print "\nEnabled features:\n\n";
        foreach my $what (@disablables) {
            print "    $what\n" unless $disabled{$what};
        }
        print "\nDisabled features:\n\n";
        foreach my $what (@disablables) {
            if ($disabled{$what}) {
                print "    $what", ' ' x ($longest - length($what) + 1),
                    "[$disabled{$what}]", ' ' x ($longest2 - length($disabled{$what}) + 1);
                print $disabled_info{$what}->{macro}
                    if $disabled_info{$what}->{macro};
                print ' (skip ',
                    join(', ', @{$disabled_info{$what}->{skipped}}),
                    ')'
                    if $disabled_info{$what}->{skipped};
                print "\n";
            }
        }
    }
    if ($dump || $target) {
        print "\nConfig target attributes:\n\n";
        foreach (sort keys %target) {
            next if $_ =~ m|^_| || $_ eq 'template';
            my $quotify = sub {
                map { (my $x = $_) =~ s|([\\\$\@"])|\\$1|g; "\"$x\""} @_;
            };
            print '    ', $_, ' => ';
            if (ref($target{$_}) eq "ARRAY") {
                print '[ ', join(', ', $quotify->(@{$target{$_}})), " ],\n";
            } else {
                print $quotify->($target{$_}), ",\n"
            }
        }
    }
    if ($dump || $envvars) {
        print "\nRecorded environment:\n\n";
        foreach (sort keys %{$config{perlenv}}) {
            print '    ',$_,' = ',($config{perlenv}->{$_} || ''),"\n";
        }
    }
    if ($dump || $makevars) {
        print "\nMakevars:\n\n";
        foreach my $var (@makevars) {
            my $prefix = '';
            $prefix = $config{CROSS_COMPILE}
                if grep { $var eq $_ } @user_crossable;
            $prefix //= '';
            print '    ',$var,' ' x (16 - length $var),'= ',
                (ref $config{$var} eq 'ARRAY'
                 ? join(' ', @{$config{$var}})
                 : $prefix.$config{$var}),
                "\n"
                if defined $config{$var};
        }

        my @buildfile = ($config{builddir}, $config{build_file});
        unshift @buildfile, $here
            unless file_name_is_absolute($config{builddir});
        my $buildfile = canonpath(catdir(@buildfile));
        print <<"_____";

NOTE: These variables only represent the configuration view.  The build file
template may have processed these variables further, please have a look at the
build file for more exact data:
    $buildfile
_____
    }
    if ($dump || $buildparams) {
        my @buildfile = ($config{builddir}, $config{build_file});
        unshift @buildfile, $here
            unless file_name_is_absolute($config{builddir});
        print "\nbuild file:\n\n";
        print "    ", canonpath(catfile(@buildfile)),"\n";

        print "\nbuild file templates:\n\n";
        foreach (@{$config{build_file_templates}}) {
            my @tmpl = ($_);
            unshift @tmpl, $here
                unless file_name_is_absolute($config{sourcedir});
            print '    ',canonpath(catfile(@tmpl)),"\n";
        }
    }
    if ($reconf) {
        if ($verbose) {
            print 'Reconfiguring with: ', join(' ',@{$config{perlargv}}), "\n";
	    foreach (sort keys %{$config{perlenv}}) {
	        print '    ',$_,' = ',($config{perlenv}->{$_} || ""),"\n";
	    }
        }

        chdir $here;
        exec $^X,catfile($config{sourcedir}, 'Configure'),'reconf';
    }
}

1;

__END__

=head1 NAME

configdata.pm - configuration data for OpenSSL builds

=head1 SYNOPSIS

Interactive:

  perl configdata.pm [options]

As data bank module:

  use configdata;

=head1 DESCRIPTION

This module can be used in two modes, interactively and as a module containing
all the data recorded by OpenSSL's Configure script.

When used interactively, simply run it as any perl script, with at least one
option, and you will get the information you ask for.  See L</OPTIONS> below.

When loaded as a module, you get a few databanks with useful information to
perform build related tasks.  The databanks are:

    %config             Configured things.
    %target             The OpenSSL config target with all inheritances
                        resolved.
    %disabled           The features that are disabled.
    @disablables        The list of features that can be disabled.
    %withargs           All data given through --with-THING options.
    %unified_info       All information that was computed from the build.info
                        files.

=head1 OPTIONS

=over 4

=item B<--help>

Print a brief help message and exit.

=item B<--man>

Print the manual page and exit.

=item B<--dump> | B<-d>

Print all relevant configuration data.  This is equivalent to B<--command-line>
B<--options> B<--target> B<--environment> B<--make-variables>
B<--build-parameters>.

=item B<--command-line> | B<-c>

Print the current configuration command line.

=item B<--options> | B<-o>

Print the features, both enabled and disabled, and display defined macro and
skipped directories where applicable.

=item B<--target> | B<-t>

Print the config attributes for this config target.

=item B<--environment> | B<-e>

Print the environment variables and their values at the time of configuration.

=item B<--make-variables> | B<-m>

Print the main make variables generated in the current configuration

=item B<--build-parameters> | B<-b>

Print the build parameters, i.e. build file and build file templates.

=item B<--reconfigure> | B<--reconf> | B<-r>

Redo the configuration.

=item B<--verbose> | B<-v>

Verbose output.

=back

=cut

