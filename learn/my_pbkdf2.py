import ctypes
import platform

__all__ = ["pbkdf2"]

name = "libssl.%s" % ("dylib" if platform.system() == "Darwin" else "so")

libssl = ctypes.CDLL("libssl.dylib")
libssl.PKCS5_PBKDF2_HMAC_SHA1.restype = ctypes.c_int

def cBuf(data):
	return ctypes.create_string_buffer(data, len(data))

def pbkdf2(password, salt, iterations, outlen):
	targetbuf = cBuf("\0" * outlen)
	ret = libssl.PKCS5_PBKDF2_HMAC_SHA1(
			cBuf(password), len(password),
			cBuf(salt), len(salt),
			iterations, outlen,
			ctypes.byref(targetbuf))
	return targetbuf.raw if ret else None

