#!/usr/bin/env python

import struct
import pbkdf2
import getpass

from Crypto.Hash import SHA, SHA256, SHA512, RIPEMD

hash_func_by_spec = {
	"sha1": SHA,
	"sha256": SHA256,
	"sha512": SHA512,
	"ripemd160": RIPEMD,
}


class LUKSKeyslot(object):

	slotFmt = ">II32sII"
	slotSz = struct.calcsize(slotFmt)

	def __init__(self, data):
		self.status, self.iterations, \
			self.salt, self.start_sector, \
			self.anti_forensic_stripes = struct.unpack(self.slotFmt, data)
		self.active = self.status == 0x00AC71F3

	def __bool__(self):
		return self.active


class LUKSDevice(object):

	headerFmt = ">6sH32s32s32sII20s32sI40s"
	headerSz = struct.calcsize(headerFmt)

	def __init__(self, fName):
		self.fName = fName
		self.file = open(fName)
		self.readHeader()
		self.readKeyslots()

	def _strip(self, s):
		return s.partition("\0")[0]

	def readHeader(self):
		self.magic, self.version, \
			self.chiff_name, self.chiff_mode, \
			self.hash_spec, self.data_offset, \
			self.keylen, self.master_checksum, \
			self.master_salt, self.iterations, \
			self.uuid = struct.unpack(self.headerFmt, self.file.read(self.headerSz))

		assert self.magic == "LUKS\xba\xbe"

		self.chiff_mode = self._strip(self.chiff_mode)
		self.hash_spec = self._strip(self.hash_spec)
		self.chiff_name = self._strip(self.chiff_name)
		self.uuid = self._strip(self.uuid)

	def readKeyslots(self):
		self.keyslots = [LUKSKeyslot(self.file.read(LUKSKeyslot.slotSz)) for i in xrange(8)]

	def findKeyForPassphrase(self, passphrase):
		hash_func = hash_func_by_spec[self.hash_spec]
		for slot in self.keyslots:
			if slot.active:
				keygen = pbkdf2.PBKDF2(passphrase, slot.salt, slot.iterations, digestmodule=hash_func)
				key = keygen.read(self.keylen)

if __name__ == "__main__":
	import sys
	dev = LUKSDevice("../testdata/Alphabet512.img" if len(sys.argv) < 2 else sys.argv[1])
	pwd = "password0"
	# pwd = getpass.getpass("Enter password: ")
