// gcry.cc
// Copyright (C) 2013  Vedant Kumar <vsk@berkeley.edu>, see ~/LICENSE.txt.

#include "util.hh"
#include "gcry.hh"

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <rsa-keypair.sp>\n", argv[0]);
        xerr("Invalid arguments.");
    }

    gcrypt_init();

    gcry_error_t err = 0;
    gcry_sexp_t rsa_parms;
    gcry_sexp_t rsa_keypair;

    err &= gcry_sexp_build(&rsa_parms, NULL, "(genkey (rsa (nbits 4:2048)))");
    if (err) {
        xerr("gcrypt: failed to create rsa params");
    }

    err &= gcry_pk_genkey(&rsa_keypair, rsa_parms);
    if (err) {
        xerr("gcrypt: failed to create rsa key pair");
    }

    char* fname = argv[1];
    err = gcrypt_sexp_to_file(fname, rsa_keypair, 1 << 16);

    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(rsa_parms);

    return err;
}
