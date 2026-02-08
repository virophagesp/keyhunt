#ifndef LIBBASE58_H
#define LIBBASE58_H

#ifdef __cplusplus
extern "C" {
#endif

extern bool b58tobin(void *bin, size_t *binsz, const char *b58);

extern bool b58enc(char *b58, const void *bin);

#ifdef __cplusplus
}
#endif

#endif