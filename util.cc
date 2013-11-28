// util.cc
// Copyright (C) 2013  Vedant Kumar <vsk@berkeley.edu>, see ~/LICENSE.txt.

#include "util.hh"

void xerr(const char* msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);
}
