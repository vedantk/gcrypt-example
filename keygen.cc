// gcry.cc
// Copyright (C) 2013  Vedant Kumar <vsk@berkeley.edu>, see ~/LICENSE.txt.

#include "gcry.hh"

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <rsa-keypair.sp>\n", argv[0]);
        xerr("Invalid arguments.");
    }

    gcrypt_init();

    char* fname = argv[1];
    FILE* lockf = fopen(fname, "wb");
    if (!lockf) {
        xerr("fopen() failed");
    }

    /* Generate a new RSA key pair. */
    printf("RSA key generation can take a few minutes. Your computer \n"
           "needs to gather random entropy. Please wait... \n\n");

    gcry_error_t err = 0;
    gcry_sexp_t rsa_parms;
    gcry_sexp_t rsa_keypair;

    err = gcry_sexp_build(&rsa_parms, NULL, "(genkey (rsa (nbits 4:2048)))");
    if (err) {
        xerr("gcrypt: failed to create rsa params");
    }

    err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
    if (err) {
        xerr("gcrypt: failed to create rsa key pair");
    }

    printf("RSA key generation complete! Please enter a password to lock \n"
           "your key pair. This password must be committed to memory. \n\n");

    /* Grab a key pair password and create an encryption context with it. */
    gcry_cipher_hd_t aes_hd;
    get_aes_ctx(&aes_hd);

    /* Encrypt the RSA key pair. */
    size_t rsa_len = get_keypair_size(2048);
    void* rsa_buf = calloc(1, rsa_len);
    if (!rsa_buf) {
        xerr("malloc: could not allocate rsa buffer");
    }
    gcry_sexp_sprint(rsa_keypair, GCRYSEXP_FMT_CANON, rsa_buf, rsa_len);

    err = gcry_cipher_encrypt(aes_hd, (unsigned char*) rsa_buf, 
                              rsa_len, NULL, 0);
    if (err) {
        xerr("gcrypt: could not encrypt with AES");
    }

    /* Write the encrypted key pair to disk. */
    if (fwrite(rsa_buf, rsa_len, 1, lockf) != 1) {
        perror("fwrite");
        xerr("fwrite() failed");
    }

    /* Release contexts. */
    gcry_sexp_release(rsa_keypair);
    gcry_sexp_release(rsa_parms);
    gcry_cipher_close(aes_hd);
    free(rsa_buf);
    fclose(lockf);

    return 0;
}
