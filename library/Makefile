
# Also see "include/mbedtls/config.h"

CFLAGS	?= -O2
WARNING_CFLAGS ?=  -Wall -W -Wdeclaration-after-statement
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../include -D_FILE_OFFSET_BITS=64
LOCAL_SIMD_CFLAGS =
LOCAL_AVX2_CFLAGS =
LOCAL_LDFLAGS =

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

ifdef ARM64
LOCAL_SIMD_CFLAGS += -march=armv8-a+crypto -mcpu=cortex-a53
else
ifdef ARM
LOCAL_SIMD_CFLAGS += -march=armv7-a -mfloat-abi=softfp -mfpu=neon
else
ifndef NOINTEL
LOCAL_SIMD_CFLAGS += -maes -mssse3
LOCAL_AVX2_CFLAGS += -mavx2
endif
endif
endif

# MicroBlaze specific options:
# CFLAGS += -mno-xl-soft-mul -mxl-barrel-shift

# To compile on Plan9:
# CFLAGS += -D_BSD_EXTENSION

# if were running on Windows build for Windows
ifdef WINDOWS
WINDOWS_BUILD=1
endif

# To compile as a shared library:
ifdef SHARED
# all code is position-indep with mingw, avoid warning about useless flag
ifndef WINDOWS_BUILD
LOCAL_CFLAGS += -fPIC -fpic
endif
endif

SOEXT_TLS=so.10
SOEXT_X509=so.0
SOEXT_CRYPTO=so.2

DLEXT=so
# OSX shared library extension:
# DLEXT=dylib

# Windows shared library extension:
ifdef WINDOWS_BUILD
DLEXT=dll
endif

OBJS_CRYPTO=	aes.o		aesni.o		arc4.o		\
		aesarm.simd.o	aesasm.o	aesasm_wrap.o	\
		aesctr.simd.o					\
		aesasm_hard.o	aead_chacha20_poly1305.o	\
		asn1parse.o	asn1write.o	base64.o	\
		bignum.o	blowfish.o	camellia.o	\
		ccm.o		cipher.o	cipher_wrap.o	\
		chacha20.o					\
		chacha20_vec.simd.o	chacha20_avx.avx2.o	\
		cmac.o		ctr_drbg.o	des.o		\
		dhm.o		ecdh.o		ecdsa.o		\
		ecjpake.o	ecp.o				\
		ecp_curves.o	entropy.o	entropy_poll.o	\
		error.o		gcm.o		havege.o	\
		hmac_drbg.o	md.o		md2.o		\
		md4.o		md5.o		md_wrap.o	\
		memory_buffer_alloc.o		oid.o		\
		padlock.o	pem.o		pk.o		\
		pk_wrap.o	pkcs12.o	pkcs5.o		\
		pkparse.o	pkwrite.o	platform.o	\
		poly1305.o					\
		ripemd160.o	rsa_internal.o	rsa.o  		\
		sha1.o		sha256.o	sha512.o	\
		sha1_armv8.simd.o	sha256_armv8.simd.o	\
		threading.o	timing.o	version.o	\
		version_features.o		xtea.o		\
		md5asm.o	sha1asm.o	sha256asm.o

OBJS_X509=	certs.o		pkcs11.o	x509.o		\
		x509_create.o	x509_crl.o	x509_crt.o	\
		x509_csr.o	x509write_crt.o	x509write_csr.o

OBJS_TLS=	debug.o		net_sockets.o		\
		ssl_cache.o	ssl_ciphersuites.o	\
		ssl_cli.o	ssl_cookie.o		\
		ssl_srv.o	ssl_ticket.o		\
		ssl_tls.o

.SILENT:

.PHONY: all static shared clean

ifndef SHARED
all: static
else
all: shared static
endif

static: libmbedcrypto.a libmbedx509.a libmbedtls.a

shared: libmbedcrypto.$(DLEXT) libmbedx509.$(DLEXT) libmbedtls.$(DLEXT)

# tls
libmbedtls.a: $(OBJS_TLS)
	echo "  AR    $@"
	$(AR) -rc $@ $(OBJS_TLS)
	echo "  RL    $@"
	$(AR) -s $@

libmbedtls.$(SOEXT_TLS): $(OBJS_TLS) libmbedx509.so
	echo "  LD    $@"
	$(CC) -shared -Wl,-soname,$@ -L. -lmbedcrypto -lmbedx509 $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_TLS)

libmbedtls.so: libmbedtls.$(SOEXT_TLS)
	echo "  LN    $@ -> $<"
	ln -sf $< $@

libmbedtls.dylib: $(OBJS_TLS)
	echo "  LD    $@"
	$(CC) -dynamiclib $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_TLS)

libmbedtls.dll: $(OBJS_TLS) libmbedx509.dll
	echo "  LD    $@"
	$(CC) -shared -Wl,-soname,$@ -Wl,--out-implib,$@.a -o $@ $(OBJS_TLS) -lws2_32 -lwinmm -lgdi32 -L. -lmbedcrypto -lmbedx509 -static-libgcc $(LOCAL_LDFLAGS) $(LDFLAGS)

# x509
libmbedx509.a: $(OBJS_X509)
	echo "  AR    $@"
	$(AR) -rc $@ $(OBJS_X509)
	echo "  RL    $@"
	$(AR) -s $@

libmbedx509.$(SOEXT_X509): $(OBJS_X509) libmbedcrypto.so
	echo "  LD    $@"
	$(CC) -shared -Wl,-soname,$@ -L. -lmbedcrypto $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_X509)

libmbedx509.so: libmbedx509.$(SOEXT_X509)
	echo "  LN    $@ -> $<"
	ln -sf $< $@

libmbedx509.dylib: $(OBJS_X509)
	echo "  LD    $@"
	$(CC) -dynamiclib $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_X509)

libmbedx509.dll: $(OBJS_X509) libmbedcrypto.dll
	echo "  LD    $@"
	$(CC) -shared -Wl,-soname,$@ -Wl,--out-implib,$@.a -o $@ $(OBJS_X509) -lws2_32 -lwinmm -lgdi32 -L. -lmbedcrypto -static-libgcc $(LOCAL_LDFLAGS) $(LDFLAGS)

# crypto
libmbedcrypto.a: $(OBJS_CRYPTO)
	echo "  AR    $@"
	$(AR) -rc $@ $(OBJS_CRYPTO)
	echo "  RL    $@"
	$(AR) -s $@

libmbedcrypto.$(SOEXT_CRYPTO): $(OBJS_CRYPTO)
	echo "  LD    $@"
	$(CC) -shared -Wl,-soname,$@ $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_CRYPTO)

libmbedcrypto.so: libmbedcrypto.$(SOEXT_CRYPTO)
	echo "  LN    $@ -> $<"
	ln -sf $< $@

libmbedcrypto.dylib: $(OBJS_CRYPTO)
	echo "  LD    $@"
	$(CC) -dynamiclib $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@ $(OBJS_CRYPTO)

libmbedcrypto.dll: $(OBJS_CRYPTO)
	echo "  LD    $@"
	$(CC) -shared -Wl,-soname,$@ -Wl,--out-implib,$@.a -o $@ $(OBJS_CRYPTO) -lws2_32 -lwinmm -lgdi32 -static-libgcc $(LOCAL_LDFLAGS) $(LDFLAGS)

%.simd.o: %.c
	echo "  SIMD  $<"
	$(CC) $(LOCAL_SIMD_CFLAGS) $(LOCAL_CFLAGS) $(CFLAGS) -c $< -o $@

%.avx2.o: %.c
	echo "  AVX2  $<"
	$(CC) $(LOCAL_SIMD_CFLAGS) $(LOCAL_AVX2_CFLAGS) $(LOCAL_CFLAGS) $(CFLAGS) -c $< -o $@

.c.o:
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c $<

.S.o:
	echo "  ASM   $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -c $<

clean:
ifndef WINDOWS
	rm -f *.o libmbed*
else
	del /Q /F *.o libmbed*
endif
