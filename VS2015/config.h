/* src/config.h.  Generated from config.h.in by configure.  */
/* src/config.h.in.  Generated from configure.ac by autoheader.  */

/* Define this to disable recursing resolution type. */
/* #undef DISABLE_RESOLUTION_RECURSING */

/* Define this to enable the experimental draft dnssec roadblock avoidance. */
/* #undef DNSSEC_ROADBLOCK_AVOIDANCE */

/* Define this to enable the experimental draft edns cookies. */
/* #undef EDNS_COOKIES */

/* The edns cookie option code. */
#define EDNS_COOKIE_OPCODE 10

/* How often the edns client cookie is refreshed. */
#define EDNS_COOKIE_ROLLOVER_TIME (24 * 60 * 60)

/* The edns padding option code. */
#define EDNS_PADDING_OPCODE 12

/* Alternate value for the FD_SETSIZE */
/* #undef FD_SETSIZE */

/* Define this to enable Windows build. */
/* #undef GETDNS_ON_WINDOWS */

/* Define to 1 if you have the `arc4random' function. */
/* #undef HAVE_ARC4RANDOM */

/* Define to 1 if you have the `arc4random_uniform' function. */
/* #undef HAVE_ARC4RANDOM_UNIFORM */

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Whether the C compiler accepts the "format" attribute */
#define HAVE_ATTR_FORMAT 1

/* Whether the C compiler accepts the "unused" attribute */
#define HAVE_ATTR_UNUSED 1

/* Define to 1 if you have the declaration of `arc4random', and to 0 if you
   don't. */
#define HAVE_DECL_ARC4RANDOM 0

/* Define to 1 if you have the declaration of `arc4random_uniform', and to 0
   if you don't. */
#define HAVE_DECL_ARC4RANDOM_UNIFORM 0

/* Define to 1 if you have the declaration of `NID_secp384r1', and to 0 if you
   don't. */
#define HAVE_DECL_NID_SECP384R1 1

/* Define to 1 if you have the declaration of `NID_X9_62_prime256v1', and to 0
   if you don't. */
#define HAVE_DECL_NID_X9_62_PRIME256V1 1

/* Define to 1 if you have the declaration of `sk_SSL_COMP_pop_free', and to 0
   if you don't. */
#define HAVE_DECL_SK_SSL_COMP_POP_FREE 1

/* Define to 1 if you have the declaration of
   `SSL_COMP_get_compression_methods', and to 0 if you don't. */
#define HAVE_DECL_SSL_COMP_GET_COMPRESSION_METHODS 1

/* Define to 1 if you have the declaration of `SSL_CTX_set_ecdh_auto', and to
   0 if you don't. */
#define HAVE_DECL_SSL_CTX_SET_ECDH_AUTO 0

/* Define to 1 if you have the declaration of `strlcpy', and to 0 if you
   don't. */
#define HAVE_DECL_STRLCPY 0

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `ECDSA_SIG_get0' function. */
/* #undef HAVE_ECDSA_SIG_GET0 */

/* Define to 1 if you have the `ENGINE_load_cryptodev' function. */
#define HAVE_ENGINE_LOAD_CRYPTODEV 1

/* Define to 1 if you have the <event2/event.h> header file. */
/* #undef HAVE_EVENT2_EVENT_H */

/* Define to 1 if you have the `event_base_free' function. */
/* #undef HAVE_EVENT_BASE_FREE */

/* Define to 1 if you have the `event_base_new' function. */
/* #undef HAVE_EVENT_BASE_NEW */

/* Define to 1 if you have the <event.h> header file. */
/* #undef HAVE_EVENT_H */

/* Define to 1 if you have the `EVP_md5' function. */
#define HAVE_EVP_MD5 1

/* Define to 1 if you have the `EVP_MD_CTX_new' function. */
/* #undef HAVE_EVP_MD_CTX_NEW */

/* Define to 1 if you have the `EVP_PKEY_base_id' function. */
#define HAVE_EVP_PKEY_BASE_ID 1

/* Define to 1 if you have the `EVP_PKEY_keygen' function. */
#define HAVE_EVP_PKEY_KEYGEN 1

/* Define to 1 if you have the `EVP_sha1' function. */
#define HAVE_EVP_SHA1 1

/* Define to 1 if you have the `EVP_sha224' function. */
#define HAVE_EVP_SHA224 1

/* Define to 1 if you have the `EVP_sha256' function. */
#define HAVE_EVP_SHA256 1

/* Define to 1 if you have the `EVP_sha384' function. */
#define HAVE_EVP_SHA384 1

/* Define to 1 if you have the `EVP_sha512' function. */
#define HAVE_EVP_SHA512 1

/* Define to 1 if you have the <ev.h> header file. */
/* #undef HAVE_EV_H */

/* Define to 1 if you have the `fcntl' function. */
#define HAVE_FCNTL 1

/* Define to 1 if you have the `FIPS_mode' function. */
#define HAVE_FIPS_MODE 1

/* Whether getaddrinfo is available */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have the `getauxval' function. */
#define HAVE_GETAUXVAL 1

/* Define to 1 if you have the `getentropy' function. */
/* #undef HAVE_GETENTROPY */

/* Define to 1 if you have the `HMAC_CTX_free' function. */
/* #undef HAVE_HMAC_CTX_FREE */

/* Define to 1 if you have the `HMAC_CTX_new' function. */
/* #undef HAVE_HMAC_CTX_NEW */

/* If you have HMAC_Update */
#define HAVE_HMAC_UPDATE 1

/* Define to 1 if you have the `inet_ntop' function. */
#define HAVE_INET_NTOP 1

/* Define to 1 if you have the `inet_pton' function. */
#define HAVE_INET_PTON 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* if the function 'ioctlsocket' is available */
/* #undef HAVE_IOCTLSOCKET */

/* Define to 1 if you have the <libev/ev.h> header file. */
/* #undef HAVE_LIBEV_EV_H */

/* Define to 1 if you have the `idn' library (-lidn). */
/* #undef HAVE_LIBIDN */

/* Define if we have LibreSSL */
/* #undef HAVE_LIBRESSL */

/* Define to 1 if you have the `unbound' library (-lunbound). */
/* #undef HAVE_LIBUNBOUND */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Does libuv have the new uv_time_cb signature */
/* #undef HAVE_NEW_UV_TIMER_CB */

/* Define to 1 if you have the <openssl/bn.h> header file. */
#define HAVE_OPENSSL_BN_H 1

/* Define to 1 if you have the `OPENSSL_config' function. */
#define HAVE_OPENSSL_CONFIG 1

/* Define to 1 if you have the <openssl/conf.h> header file. */
#define HAVE_OPENSSL_CONF_H 1

/* Define to 1 if you have the <openssl/dsa.h> header file. */
#define HAVE_OPENSSL_DSA_H 1

/* Define to 1 if you have the <openssl/engine.h> header file. */
#define HAVE_OPENSSL_ENGINE_H 1

/* Define to 1 if you have the <openssl/err.h> header file. */
#define HAVE_OPENSSL_ERR_H 1

/* Define to 1 if you have the <openssl/rand.h> header file. */
#define HAVE_OPENSSL_RAND_H 1

/* Define to 1 if you have the <openssl/rsa.h> header file. */
#define HAVE_OPENSSL_RSA_H 1

/* Define to 1 if you have the <openssl/ssl.h> header file. */
#define HAVE_OPENSSL_SSL_H 1

/* Have pthreads library */
#define HAVE_PTHREADS 1

/* Define to 1 if you have the `SHA512_Update' function. */
/* #undef HAVE_SHA512_UPDATE */

/* Define if you have the SSL libraries installed. */
#define HAVE_SSL /**/

/* Define if you have libssl with host name verification */
/* #undef HAVE_SSL_HN_AUTH */

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/sha2.h> header file. */
/* #undef HAVE_SYS_SHA2_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/sysctl.h> header file. */
#define HAVE_SYS_SYSCTL_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the `TLS_client_method' function. */
/* #undef HAVE_TLS_CLIENT_METHOD */

/* Define if you have libssl with tls 1.2 */
#define HAVE_TLS_v1_2 1

/* Define to 1 if you have the `ub_ctx_set_stub' function. */
/* #undef HAVE_UB_CTX_SET_STUB */

/* Define this when libunbound is compiled with the --enable-event-api option.
   */
/* #undef HAVE_UNBOUND_EVENT_API */

/* Define to 1 if you have the <unbound-event.h> header file. */
/* #undef HAVE_UNBOUND_EVENT_H */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <uv.h> header file. */
/* #undef HAVE_UV_H */

/* Define to 1 if you have the <windows.h> header file. */
/* #undef HAVE_WINDOWS_H */

/* Define to 1 if you have the <winsock2.h> header file. */
/* #undef HAVE_WINSOCK2_H */

/* Define to 1 if you have the <winsock.h> header file. */
/* #undef HAVE_WINSOCK_H */

/* Define to 1 if you have the <ws2tcpip.h> header file. */
/* #undef HAVE_WS2TCPIP_H */

/* Do not set this */
/* #undef KEEP_CONNECTIONS_OPEN_DEBUG */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* limit for dynamically-generated DNS options */
#define MAXIMUM_UPSTREAM_OPTION_SPACE 3000

/* The maximum number of cname referrals. */
#define MAX_CNAME_REFERRALS 100

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "users@getdnsapi.net"

/* Define to the full name of this package. */
#define PACKAGE_NAME "getdns"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "getdns 1.0.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "getdns"

/* Define to the home page for this package. */
#define PACKAGE_URL "https://getdnsapi.net"

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.0.0"

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define this to enable printing of scheduling debugging messages. */
/* #undef SCHED_DEBUG */

/* Define this to enable printing of dnssec debugging messages. */
/* #undef SEC_DEBUG */

/* Define this enable printing of server debugging messages. */
/* #undef SERVER_DEBUG */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define this to enable printing of stub debugging messages. */
/* #undef STUB_DEBUG */

/* Define this to enable native stub DNSSEC support. */
#define STUB_NATIVE_DNSSEC 1

/* System configuration dir */
#define SYSCONFDIR sysconfdir

/* Default trust anchor file */
#define TRUST_ANCHOR_FILE "/etc/unbound/getdns-root.key"

/* Define this to enable DSA support. */
#define USE_DSA 1

/* Define this to enable ECDSA support. */
#define USE_ECDSA 1

/* Define this to enable an EVP workaround for older openssl */
/* #undef USE_ECDSA_EVP_WORKAROUND */

/* Define this to enable GOST support. */
#define USE_GOST 1

/* Needed for sync stub resolver functions */
#define USE_MINI_EVENT 1

/* Define this to enable TCP fast open. */
/* #undef USE_OSX_TCP_FASTOPEN */

/* Define this to enable SHA256 and SHA512 support. */
#define USE_SHA2 1

/* Define this to enable TCP fast open. */
#define USE_TCP_FASTOPEN 1

/* Whether the windows socket API is used */
/* #undef USE_WINSOCK */

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT32_T */

/* Define for Solaris 2.5.1 so the uint64_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT64_T */

/* Define for Solaris 2.5.1 so the uint8_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT8_T */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to the type of an unsigned integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint16_t */

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint32_t */

/* Define to the type of an unsigned integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint64_t */

/* Define to the type of an unsigned integer type of width exactly 8 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint8_t */



#ifdef GETDNS_ON_WINDOWS
/* On windows it is allowed to increase the FD_SETSIZE
 * (and nescessary to make our custom eventloop work)
 * See: https://support.microsoft.com/en-us/kb/111855
 */
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif

#define PRIsz "%Iu"
#else
#define PRIsz "%zu"
#endif

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

/* the version of the windows API enabled */
#ifndef WINVER
#define WINVER 0x0600 // 0x0502
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 // 0x0502
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifndef USE_WINSOCK
#define ARG_LL "%ll"
#else
#define ARG_LL "%I64"
#endif

/* detect if we need to cast to unsigned int for FD_SET to avoid warnings */
#ifdef HAVE_WINSOCK2_H
#define FD_SET_T (u_int)
#else
#define FD_SET_T 
#endif



#ifdef __cplusplus
extern "C" {
#endif

#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

#if !defined(HAVE_STRLCPY) || !HAVE_DECL_STRLCPY || !defined(strlcpy)
size_t strlcpy(char *dst, const char *src, size_t siz);
#else
#ifndef __BSD_VISIBLE
#define __BSD_VISIBLE 1
#endif
#endif
#if !defined(HAVE_ARC4RANDOM) || !HAVE_DECL_ARC4RANDOM
uint32_t arc4random(void);
#endif
#if !defined(HAVE_ARC4RANDOM_UNIFORM) || !HAVE_DECL_ARC4RANDOM_UNIFORM 
uint32_t arc4random_uniform(uint32_t upper_bound);
#endif
#ifndef HAVE_ARC4RANDOM
void explicit_bzero(void* buf, size_t len);
int getentropy(void* buf, size_t len);
void arc4random_buf(void* buf, size_t n);
void _ARC4_LOCK(void);
void _ARC4_UNLOCK(void);
#endif
#ifdef COMPAT_SHA512
#ifndef SHA512_DIGEST_LENGTH
#define SHA512_BLOCK_LENGTH             128
#define SHA512_DIGEST_LENGTH            64
#define SHA512_DIGEST_STRING_LENGTH     (SHA512_DIGEST_LENGTH * 2 + 1)
typedef struct _SHA512_CTX {
        uint64_t        state[8];
        uint64_t        bitcount[2];
        uint8_t buffer[SHA512_BLOCK_LENGTH];
} SHA512_CTX;
#endif /* SHA512_DIGEST_LENGTH */
void SHA512_Init(SHA512_CTX*);
void SHA512_Update(SHA512_CTX*, void*, size_t);
void SHA512_Final(uint8_t[SHA512_DIGEST_LENGTH], SHA512_CTX*);
unsigned char *SHA512(void* data, unsigned int data_len, unsigned char *digest);
#endif /* COMPAT_SHA512 */

#ifndef HAVE_INET_PTON
int inet_pton(int af, const char* src, void* dst);
#endif /* HAVE_INET_PTON */

#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src, char *dst, size_t size);
#endif

#ifdef __cplusplus
}
#endif

/** Use on-board gldns */
#define USE_GLDNS 1
#ifdef HAVE_SSL
#  define GLDNS_BUILD_CONFIG_HAVE_SSL 1
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#include <errno.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifndef PRIu64
#define PRIu64 "llu"
#endif

#ifdef HAVE_ATTR_FORMAT
#  define ATTR_FORMAT(archetype, string_index, first_to_check) \
    __attribute__ ((format (archetype, string_index, first_to_check)))
#else /* !HAVE_ATTR_FORMAT */
#  define ATTR_FORMAT(archetype, string_index, first_to_check) /* empty */
#endif /* !HAVE_ATTR_FORMAT */

#if defined(DOXYGEN)
#  define ATTR_UNUSED(x)  x
#elif defined(__cplusplus)
#  define ATTR_UNUSED(x)
#elif defined(HAVE_ATTR_UNUSED)
#  define ATTR_UNUSED(x)  x __attribute__((unused))
#else /* !HAVE_ATTR_UNUSED */
#  define ATTR_UNUSED(x)  x
#endif /* !HAVE_ATTR_UNUSED */

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_LIBUNBOUND
# include <unbound.h>
# ifdef HAVE_UNBOUND_EVENT_H
#  include <unbound-event.h>
# else
#  ifdef HAVE_UNBOUND_EVENT_API
#   ifndef _UB_EVENT_PRIMITIVES
#    define _UB_EVENT_PRIMITIVES
struct ub_event_base;
struct ub_ctx* ub_ctx_create_ub_event(struct ub_event_base* base);
typedef void (*ub_event_callback_t)(void*, int, void*, int, int, char*);
int ub_resolve_event(struct ub_ctx* ctx, const char* name, int rrtype, 
        int rrclass, void* mydata, ub_event_callback_t callback, int* async_id);
#   endif
#  endif
# endif
#endif

