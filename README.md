# LUKSfs

Provides a (read-only) unencrypted image of a LUKS-encrypted device or file system image.

## What you need
- Python 2.7
- FUSE
- fusepy
- PyCrypto
- OpenSSL

## Usage

Just run ```luksfs``` with either a block device or an image as source and a mount destination.

```
$ mkdir /tmp/luks_mount
$ ./luksfs /path/to/luks/device_or_image /tmp/luks_mount
Enter password:
"/path/to/luks/device_or_image" opened. Press ^C to unmount.
```

Now keep this command running and mount the actual file system using typical loop mount.

```
$ open /tmp/luks_mount/decrypted.img # On OS X
$ mount -o loop /tmp/luks_mount/decrypted.img /mountpoint # On Linux
```

## Known issues

- Can only decrypt AES
- No support of aes-xts-plain64 so far
- PBKDF2 just with SHA1 right now