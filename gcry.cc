#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "gcry.hh"
#include "util.hh"

void gcrypt_init()
{
    /* Version check should be the very first call because it
       makes sure that important subsystems are intialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        xerr("gcrypt: library version mismatch");
    }

    gcry_error_t err = 0;

    /* We don't want to see any warnings, e.g. because we have not yet
       parsed program options which might be used to suppress such
       warnings. */
    err &= gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
       process might still be running with increased privileges and that
       the secure memory has not been intialized.  */

    /* Allocate a pool of 16k secure memory.  This make the secure memory
       available and also drops privileges where needed.  */
    err &= gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
       a problem with the secure memory. */
    err &= gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    err &= gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (err) {
        xerr("gcrypt: failed initialization");
    }
}

int gcrypt_sexp_to_file(const char* name, gcry_sexp_t sexp, size_t maxlen)
{
    int err = 0;
    FILE* of = fopen(name, "wb");
    if (of == NULL) {
        return 1;
    }

    void* buf = malloc(maxlen);
    if (buf == NULL) {
        err = 1;
        goto exit1;
    }

    size_t len;
    len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, buf, maxlen);
    if (len == 0) {
        goto exit2;    
    }

    if (fwrite(buf, len, 1, of) != len) {
        err = 1;
        goto exit2;
    }

exit2:
    free(buf);
exit1:
    fclose(of);
    return err;
}

int gcrypt_file_to_sexp(const char* name, gcry_sexp_t* sexp)
{
    int err = 0;
    size_t buflen;
    void* buf;

    int fd = open(name, O_RDONLY);
    if (fd < 0) {
        return 1;
    }

    struct stat sbuf;
    if (fstat(fd, &sbuf) != 0) {
        err = 1;
        goto exit1;
    }

    buflen = sbuf.st_size + 1;
    buf = malloc(buflen);
    if (buf == NULL) {
        err = 1;
        goto exit1;
    }

    if (read(fd, buf, sbuf.st_size) != sbuf.st_size) {
        err = 1;
        goto exit2;
    }

    err = gcry_sexp_new(sexp, buf, buflen, 0);

exit2:
    free(buf);
exit1:
    close(fd);
    return err;
}
