// gcry.hh
// Copyright (C) 2013  Vedant Kumar <vsk@berkeley.edu>, see ~/LICENSE.txt.

#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>

#include <gcrypt.h>

/* Crash routine. */
void xerr(const char* msg);

/* Initialize libgcrypt. */
void gcrypt_init();

/* Estimate the size of the encrypted key pair. */
size_t get_keypair_size(int nbits);

/* Create an AES context out of a user's password. */
void get_aes_ctx(gcry_cipher_hd_t* aes_hd);
