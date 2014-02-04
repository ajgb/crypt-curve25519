
use Test::More;
BEGIN { use_ok('Crypt::Curve25519') };

eval {
    curve25519_public_key( pack('H*', "secret too short") );
};
like($@, qr/Secret key requires 32 bytes/, "Secret key requires 32 bytes");

eval {
    curve25519_shared_secret( pack('H*', "0000000000000000000000000000000000000000000000000000000000000000") );
};
like($@, qr/Calculating shared secret requires public key/, "Calculating shared secret requires public key");

eval {
    curve25519_public_key(
        pack('H*', "0000000000000000000000000000000000000000000000000000000000000000"),
        pack('H*', "basepoint too short") 
    );
};
like($@, qr/Basepoint requires 32 bytes/, "Basepoint requires 32 bytes");

eval {
    curve25519_shared_secret(
        pack('H*', "0000000000000000000000000000000000000000000000000000000000000000"),
        pack('H*', "pub key too short") 
    );
};
like($@, qr/Public key requires 32 bytes/, "Public key requires 32 bytes");

done_testing();

