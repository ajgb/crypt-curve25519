
use Test::More;
BEGIN { use_ok('Crypt::Curve25519') };

my $alice_secret_key = pack('H*', '8ac65d1706b02a0fae4b501583b259eafe0382dadd7aede2992c5f15bf3a3bc4');
my $bob_secret_key = pack('H*', 'f32c0ed0a9cd3d0c390681a981016d9a38ef2f0a6a1830aed346938614df2100');
my $basepoint = pack('H*', '0900000000000000000000000000000000000000000000000000000000000000');

for ( 1 .. 10000 ) {
    my $alice_public_key = curve25519_public_key($alice_secret_key, $basepoint);
    my $bob_public_key = curve25519_public_key($bob_secret_key, $basepoint);

    my $alice_shared_secret = curve25519_shared_secret($alice_secret_key, $bob_public_key); 
    my $bob_shared_secret = curve25519_shared_secret($bob_secret_key, $alice_public_key);

    is($alice_shared_secret, $bob_shared_secret, "Shared secret matched: ". unpack('H*', $alice_shared_secret));

    for my $i ( 0 .. 31 ) {
        my $c = substr($alice_secret_key, $i, 1);
        my $h = substr($bob_public_key, $i, 1);
        substr($alice_secret_key, $i, 1, chr(ord($c) ^ ord($h)));
    }

    for my $i ( 0 .. 31 ) {
        my $c = substr($bob_secret_key, $i, 1);
        my $h = substr($alice_public_key, $i, 1);
        substr($bob_secret_key, $i, 1, chr(ord($c) ^ ord($h)));
    }

    for my $i ( 0 .. 31 ) {
        my $c = substr($basepoint, $i, 1);
        my $h = substr($alice_shared_secret, $i, 1);
        substr($basepoint, $i, 1, chr(ord($c) ^ ord($h)));
    }
}

done_testing();

