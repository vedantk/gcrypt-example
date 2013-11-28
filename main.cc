// main.cc 
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
    char* fname = argv[1];
    gcry_sexp_t rsa_keypair;
    if (gcrypt_file_to_sexp(fname, &rsa_keypair)) {
        xerr("failed to load rsa key pair from file");
    }

    gcry_sexp_t pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
    gcry_sexp_t privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);

    gcry_mpi_t msg;
    gcry_sexp_t data;
    const unsigned char* s = (const unsigned char*) "Hello world.";
    err &= gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, s, 
                         strlen((const char*) s), NULL);
    if (err) {
        xerr("failed to create a mpi from the message");
    }

    err &= gcry_sexp_build(&data, NULL,
                           "(data (flags raw) (value %m))", msg);
    if (err) {
        xerr("failed to create a sexp from the message");
    }

    gcry_sexp_t ciph;
    err &= gcry_pk_encrypt(&ciph, data, pubk);
    if (err) {
        xerr("gcrypt: encryption failed");
    }

    gcry_sexp_t plain;
    err &= gcry_pk_decrypt(&plain, ciph, privk);
    if (err) {
        xerr("gcrypt: decryption failde");
    }

    gcry_mpi_t out_msg = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG);
    printf("Original:\n");
    gcry_mpi_dump(msg);
    printf("\n Decrypted:\n");
    gcry_mpi_dump(out_msg);
    printf("\n");

    if (gcry_mpi_cmp(msg, out_msg)) {
        xerr("data corruption!");
    } 

    printf("Messages match.\n");

    unsigned char obuf[64];
    err = gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char*) &obuf, 
                         sizeof(obuf), NULL, out_msg);
    if (err) {
        xerr("failed to stringify mpi");
    }
    printf("-> %s\n", (char*) obuf);

    gcry_mpi_release(msg);
    gcry_mpi_release(out_msg);
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(pubk);
    gcry_sexp_release(privk);
    gcry_sexp_release(data);
    gcry_sexp_release(ciph);
    gcry_sexp_release(plain);

    return 0;
}
