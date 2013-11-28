// gcry.hh
// Copyright (C) 2013  Vedant Kumar <vsk@berkeley.edu>, see ~/LICENSE.txt.

#pragma once

#include <gcrypt.h>

void gcrypt_init();
int gcrypt_sexp_to_file(const char* name, gcry_sexp_t sexp, size_t maxlen);
int gcrypt_file_to_sexp(const char* name, gcry_sexp_t* sexp);
