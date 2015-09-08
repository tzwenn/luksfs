import os
import stat
import fcntl
import struct
import platform

__all__ = ["BlockDevice", "LUKSException"]

DKIOCGETBLOCKCOUNT = 1074291737
DKIOCGETBLOCKSIZE = 1074029592

BLKGETSIZE64 = 2148012658
BLKSSZGET = 4712


class LUKSException(Exception):
	pass


class BlockDevice(file):

	def __init__(self, fileName, block_size=512):
		file.__init__(self, fileName, "rb")
		mode = os.stat(fileName).st_mode
		if stat.S_ISREG(mode):
			self._block_size = block_size
			self._calc_block_count()
		elif stat.S_ISBLK(mode):
			self._read_block_count()
		else:
			raise LUKSException("Unsupported file")

	def _read_fcntl(self, opt, fmt="L"):
		ret = fcntl.ioctl(self.fileno(), opt, "\0" * struct.calcsize(fmt))
		return struct.unpack(fmt, ret)[0]

	def _calc_block_count(self):
		self.seek(0, 2)  # Seek to end
		self._block_count = self.tell() / self._block_size
		self.seek(0)     # Seek to start

	def _read_block_count(self):
		if platform.system() == "Darwin":
			self._block_size = self._read_fcntl(DKIOCGETBLOCKSIZE, "I")
			self._block_count = self._read_fcntl(DKIOCGETBLOCKCOUNT)
		elif platform.system() == "Linux":
			self._block_size = self._read_fcntl(BLKSSZGET)
			self._block_count = self._read_fcntl(BLKGETSIZE64) / self._block_size
		else:
			raise NotImplementedError

	def blockRead(self, index, count=1):
		self.seek(index * self._block_size)
		return self.read(self._block_size * count)

	@property
	def block_size(self):
		return self._block_size

	@property
	def block_count(self):
		return self._block_count
