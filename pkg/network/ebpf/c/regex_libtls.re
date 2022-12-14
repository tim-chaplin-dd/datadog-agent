// re2c regex_libtls.re -o regex_libtls.h
#ifdef UNITTEST
#include <assert.h>
#include <stdio.h>
#ifndef __always_inline
#define __always_inline inline
#endif
#endif

// return 1 if the regex match
// return 0 otherwise
static __always_inline int regex_libtls(const char *str, unsigned int len) {
    const char *YYCURSOR = str, *YYLIMIT = str + len, *YYMARKER;
    int count = 0;

    for (;;) {
    /*!re2c
        re2c:define:YYCTYPE = char;
        re2c:yyfill:enable = 0;
        re2c:eof = 0;

        end   = "\x00";
        digit = [0-9];
        alpha = [a-zA-Z];

        libs = "/lib"("ssl"|"crypto"|"gnutls")".so" ([._+-] | digit | alpha)*;

        *    { continue; }
        $    { return count; }
        end  { return count; }
        libs { return 1; }
    */
    }
}

#ifdef UNITTEST
#define TEST(s, size, r) assert(regex_libtls(s, size) == r)
int main() {
    // return 1 when the regex match
    TEST("/usr/libssl.so", sizeof("/usr/libssl.so"), 1);
    TEST("/usr/libsslz.so", sizeof("/usr/libsslz.so"), 0);
    TEST("/usr/libssl.so", sizeof("/usr/libssl.so")-1, 1); // no tailing \0
    TEST("/usr/libssl.so.1", sizeof("/usr/libssl.so.1"), 1);
    TEST("/usr/libcrypto.so.1", sizeof("/usr/libcrypto.so.1"), 1);
    TEST("/usr/libgnutls.so.1", sizeof("/usr/libgnutls.so.1"), 1);
    TEST("/usr/libssl.so.1.2", sizeof("/usr/libssl.so.1.2"), 1);
    TEST("/usr/libcrypto.so.1.2", sizeof("/usr/libcrypto.so.1.2"), 1);
    TEST("/usr/libgnutls.so.1.2", sizeof("/usr/libgnutls.so.1.2"), 1);
    printf("UNITTEST regex_libtls Success\n");
    return 0;
}
#endif
