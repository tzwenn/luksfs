#!/usr/bin/env python

import struct
import getpass
import math

from Crypto.Hash import SHA, SHA256, SHA512, RIPEMD
from Crypto.Cipher import AES

import my_pbkdf2

__all__ = ["LUKSDevice"]

# Constants from on-disk-format, section 5
LUKS_MAGIC        = "LUKS\xba\xbe"
LUKS_DIGESTSIZE   = 20
LUKS_SALTSIZE     = 32
LUKS_NUMKEYS      = 8
LUKS_KEY_DISABLED = 0x0000DEAD
LUKS_KEY_ENABLED  = 0x00AC71F3
LUKS_STRIPES      = 4000

hash_func_by_spec = {
	"sha1": SHA,
	"sha256": SHA256,
	"sha512": SHA512,
	"ripemd160": RIPEMD,
}

str_split_chunks = lambda s, size: (s[i:i + size] for i in xrange(0, len(s), size))

class BlockDevice(file):

	def __init__(self, fileName, block_size=512):
		file.__init__(self, fileName, "rb")
		self._block_size = block_size

	def blockRead(self, index, count=1):
		self.seek(index * self._block_size)
		return self.read(self._block_size * count)

	@property
	def block_size(self):
		return self._block_size


class Cryptor(object):

	def __init__(self, cipherName, cipherMode, key):
		assert cipherName == "aes"  # Cannot do anything else atm. Sorry

		self.cipherMode = cipherMode
		self.key = key
		self.iv_size = AES.block_size

		if cipherMode == "ecb":
			self.mode = AES.MODE_ECB
		elif cipherMode == "cbc-plain":
			self.IV = self._iv_plain
			self.mode = AES.MODE_CBC
		elif cipherMode == "xts-plain64":
			self.IV = self._iv_plain64
			raise NotImplementedError
		elif cipherMode.startswith("cbc-essiv:"):
			hashFuncSpec = cipherMode.partition(':')[2]
			self.hash_func = hash_func_by_spec[hashFuncSpec]
			self.IV = self._iv_essiv
			self.mode = AES.MODE_CBC
		else:
			raise Exception("Unsupported chipher mode")

	def IV(self, index):
		return "\0" * self.iv_size

	def _iv_plain(self, index):
		return struct.pack("<I", index & (2 ** 32 - 1)).ljust(self.iv_size, "\0")[:self.iv_size]

	def _iv_plain64(self, index):
		return struct.pack("<Q", index & (2 ** 64 - 1)).ljust(self.iv_size, "\0")[:self.iv_size]

	def _iv_essiv(self, index):
		salt = self.hash_func.new(self.key).hexdigest().decode('hex')[:self.iv_size]
		c = AES.new(salt, AES.MODE_ECB)
		return c.encrypt(self._iv_plain64(index))

	def decrypt(self, index, data):
		c = AES.new(self.key, self.mode, self.IV(index))
		return c.decrypt(data)


class LUKSKeyslot(object):

	slotFmt = ">II32sII"
	slotSz = struct.calcsize(slotFmt)

	def __init__(self, data):
		self.status, self.iterations, \
			self.salt, self.start_sector, \
			self.af_stripes = struct.unpack(self.slotFmt, data)
		self.active = self.status == LUKS_KEY_ENABLED
		assert self.active or (self.status == LUKS_KEY_DISABLED)

	def __bool__(self):
		return self.active


class LUKSDevice(object):

	headerFmt = ">6sH32s32s32sII20s32sI40s"
	headerSz = struct.calcsize(headerFmt)

	def __init__(self, block_file):
		self.file = block_file
		self._key = None
		self._readHeader()
		self._readKeyslots()
		self.hash_func = hash_func_by_spec[self.hashSpec]

	def _strip(self, s):
		return s.partition("\0")[0]

	def _readHeader(self):
		self.magic, self.version, \
			self.cipherName, self.cipherMode, \
			self.hashSpec, self.payloadOffset, \
			self.keylen, self.mkDigest, \
			self.mkDigestSalt, self.iterations, \
			self.uuid = struct.unpack(self.headerFmt, self.file.read(self.headerSz))

		assert self.magic == LUKS_MAGIC

		self.cipherMode = self._strip(self.cipherMode)
		self.hashSpec = self._strip(self.hashSpec)
		self.cipherName = self._strip(self.cipherName)
		self.uuid = self._strip(self.uuid)

	def _readKeyslots(self):
		self.keyslots = [LUKSKeyslot(self.file.read(LUKSKeyslot.slotSz)) for i in xrange(LUKS_NUMKEYS)]

	def _newCryptor(self, key):
		return Cryptor(self.cipherName, self.cipherMode, key)

	def blockRead(self, index, count=1):
		"""Reads sector at index."""
		return "".join(self.crytor.decrypt(sec, self.file.blockRead(sec)) for sec in xrange(index, index + count))

	def blockReadBytes(self, index, count):
		"""Reads count bytes from sector starting at index."""
		blockCount = int(math.ceil(float(count) / self.block_size))
		return self.blockRead(index, blockCount)[:count]

	def _xor(self, b1, b2):
		return "".join(chr(ord(a1) ^ ord(a2)) for a1, a2 in zip(b1, b2))

	def _af_diffuse(self, data):
		P = lambda s: self.hash_func.new(s).hexdigest().decode('hex')
		P_mag = len(P("abc"))

		blocks = str_split_chunks(data, P_mag)
		return "".join(P(struct.pack(">I", i) + b) for i, b in enumerate(blocks))[:len(data)]
	
	def _AFmerge(self, splitKey):
		blocks = list(str_split_chunks(splitKey, self.keylen))
		d_n_1 = reduce(lambda d, s: self._af_diffuse(self._xor(d, s)), blocks[:-1], "\0" * self.keylen)
		assert len(d_n_1) == self.keylen
		return self._xor(d_n_1, blocks[-1])

	def _masterKeyFromSlot(self, slot, passphrase):
		pbkdf_pwd = my_pbkdf2.pbkdf2(passphrase, slot.salt, slot.iterations, self.keylen)

		# FIXME: Don't abuse instance var here
		self.crytor = self._newCryptor(pbkdf_pwd)
		# FIXME: looks like the reference implementation works on whole blocks
		splitKey = self.blockReadBytes(slot.start_sector, self.keylen * slot.af_stripes)
		return self._AFmerge(splitKey)

	def _matchesKey(self, candidate):
		pbkdf_pwd = my_pbkdf2.pbkdf2(candidate, self.mkDigestSalt, self.iterations, LUKS_DIGESTSIZE)
		return pbkdf_pwd == self.mkDigest

	# Public

	@property
	def block_size(self):
		return self.file.block_size

	def activeSlots(self):
		return (slot for slot in self.keyslots if slot.active)

	def findKeyForPassphrase(self, passphrase):
		for i, slot in enumerate(self.activeSlots()):
			candidate = self._masterKeyFromSlot(slot, passphrase)
			if self._matchesKey(candidate):
				return candidate
		return None


if __name__ == "__main__":
	import sys
	dev = LUKSDevice(BlockDevice("../testdata/Alphabet512_ecb.img" if len(sys.argv) < 2 else sys.argv[1]))
	# pwd = "password0"
	pwd = getpass.getpass("Enter password: ")
	if dev.findKeyForPassphrase(pwd):
		print "Key matches"
	else:
		print "No available key with this passphrase"
