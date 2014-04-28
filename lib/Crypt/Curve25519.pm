package Crypt::Curve25519;
#ABSTRACT: Generate shared secret using elliptic-curve Diffie-Hellman function

use strict;
use warnings;
use Carp qw( croak );

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = ( 'all' => [ qw(
    curve25519
    curve25519_secret_key
    curve25519_public_key
    curve25519_shared_secret
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
    curve25519_secret_key
    curve25519_public_key
    curve25519_shared_secret
);

require XSLoader;
XSLoader::load('Crypt::Curve25519', $Crypt::Curve25519::{VERSION} ?
    ${ $Crypt::Curve25519::{VERSION} } : ()
);

sub new {
    return bless(\(my $o = 1), ref $_[0] ? ref $_[0] : $_[0] );
}

sub secret_key {
    my ($self, $psk) = (shift, shift);

    my $masked = curve25519_secret_key( pack('H64', $psk) );

    return unpack('H64', $masked);
}

sub public_key {
    my ($self, $sk) = (shift, shift);
    my @args = pack('H64', $sk);
    if ( @_ ) {
        push @args, pack('H64', shift);
    }

    my $pk = unpack('H64', curve25519_public_key( @args ));

    return $pk;
}

sub shared_secret {
    my ($self, $sk, $pk) = @_;

    return unpack('H64', curve25519_shared_secret( pack('H64', $sk), pack('H64', $pk) ));
}

sub generate {
    my ($self, $sk, $bp) = @_;

    return unpack('H64', curve25519( pack('H64', $sk), pack('H64', $bp) ));
}

1;

__END__

=head1 SYNOPSIS

    use Crypt::Curve25519;
    
    # Alice:
    my $alice_secret_key = curve25519_secret_key(random_32_bytes());
    my $alice_public_key = curve25519_public_key( $alice_secret_key );
    
    # Bob:
    my $bob_secret_key = curve25519_secret_key(random_32_bytes());
    my $bob_public_key = curve25519_public_key( $bob_secret_key );
    
    # Alice and Bob exchange their public keys
    my $alice_public_key_hex = unpack('H64', $alice_public_key);
    my $bob_public_key_hex   = unpack('H64', $bob_public_key);
    
    # Alice calculates shared secret to communicate with Bob
    my $shared_secret_with_bob = curve25519_shared_secret(
        $alice_secret_key,
        pack('H64', $bob_public_key_hex)
    );
    
    # Bob calculates shared secret to communicate with Alice
    my $shared_secret_with_alice = curve25519_shared_secret(
        $bob_secret_key,
        pack('H64', $alice_public_key_hex)
    );
    
    # Shared secrets are equal
    die "Something horrible has happend!"
      unless $shared_secret_with_bob eq $shared_secret_with_alice;

This package provides also simplified OO interface:

    use Crypt::Curve25519 ();

    my $c = Crypt::Curve25519->new();

    # Alice:
    my $alice_secret_key_hex = $c->secret_key(random_hexencoded_32_bytes());
    my $alice_public_key_hex = $c->public_key( $alice_secret_key_hex );

    # Bob:
    my $bob_secret_key_hex = $c->secret_key(random_hexencoded_32_bytes());
    my $bob_public_key_hex = $c->public_key( $bob_secret_key_hex );

    # Alice and Bob exchange their public keys

    # Alice calculates shared secret to communicate with Bob
    my $shared_secret_with_bob_hex = $c->shared_secret(
                                    $alice_secret_key_hex,
                                    $bob_public_key_hex);

    # Bob calculates shared secret to communicate with Alice
    my $shared_secret_with_alice_hex = $c->shared_secret(
                                    $bob_secret_key_hex,
                                    $alice_public_key_hex);

    # Shared secrets are equal
    die "Something horrible has happend!"
      unless $shared_secret_with_bob_hex eq $shared_secret_with_alice_hex;

Example functions to generate pseudo-random private secret key:

    sub random_32_bytes {
        return join('', map { chr(int(rand(255))) } 1 .. 32);
    }

    sub random_hexencoded_32_bytes {
       return unpack('H64', random_32_bytes());
    }

=head1 DESCRIPTION

Curve25519 is a state-of-the-art Diffie-Hellman function suitable for a wide
variety of applications.

Given a user's 32-byte secret key, Curve25519 computes the user's 32-byte
public key. Given the user's 32-byte secret key and another user's 32-byte
public key, Curve25519 computes a 32-byte secret shared by the two users. This
secret can then be used to authenticate and encrypt messages between the two
users. 

=func curve25519_secret_key

    my $my_secret_key = curve25519_secret_key($my_random_32byte_string);
    
Using provided 32-byte random string from cryptographically safe source create
masked secret key.

=func curve25519_public_key

    my $public_key = curve25519_public_key($my_secret_key);
    
Using masked secret key generate corresponding 32-byte Curve25519 public key.

=func curve25519_shared_secret

    my $shared_secret = curve25519_shared_secret(
        $my_secret_key, $his_public_key
    );

Using provided keys generate 32-byte shared secret, that both parties can use
without disclosing their private secret keys.

=func curve25519

Access to primitive function is also provided.

    use Crypt::Curve25519 'curve25519';

    my $key = curve25519($my_secret_key, $basepoint);

    # public key
    if ( $basepoint eq pack('H64', '09') ) {
        print "\$key is a public key\n";
    }
    elsif ( $basepoint eq $his_public_key ) {
        print "\$key is a shared secret\n";
    }

Using provided secret key and depending on the 32-byte basepoint generate
32-byte public key or shared secret.

=method new

    my $c = Crypt::Curve25519->new();

Create a new object

=method secret_key

    my $my_secret_key_hex = $c->secret_key( $my_random_32byte_string_hex );
    
Using hex encoded 32-byte random string from cryptographically safe source 
create masked secret key.

=method public_key

    my $public_key_hex = $c->public_key( $my_secret_key_hex );
    
Using hex encoded masked secret key generate corresponding hex encoded 32-byte
Curve25519 public key.

=method shared_secret

    my $shared_secret_hex = $c->shared_secret(
        $my_secret_key_hex, $his_public_key_hex
    );

Using provided hex encoded keys generate 32-byte hex encoded shared secret,
that both parties can use without disclosing their private secret keys.

=method generate

Access to primitive method is also provided.

    my $key_hex = $c->generate($my_secret_key_hex, $basepoint_hex);

    # public key
    if ( $basepoint_hex eq unpack("H64", pack("H64", "09")) ) {
        print "\$key_hex is a public key\n";
    }
    elsif ( $basepoint_hex eq $his_public_key_hex ) {
        print "\$key_hex is a shared secret\n";
    }

Using provided hex encoded secret key and depending on the 32-byte hex
encoded basepoint generate 32-byte hex encoded public key or shared secret.

=head1 SEE ALSO

=over 4

=item * L<http://cr.yp.to/ecdh.html>

=back

=cut

