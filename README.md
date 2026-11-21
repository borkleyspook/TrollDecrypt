# TrollDecrypt
iOS IPA Decrypter for TrollStore

## How do I install TrollDecrypt?
In order to install TrollDecrypt you can either:
* Get it on [Havoc](https://havoc.app/package/trolldecrypt)!
* Download the latest release [here](https://github.com/donato-fiore/TrollDecrypt/releases)
* Build from source

## How to build
1. Install [theos](https://theos.dev/docs/installation)
2. Run the commands below
```
git clone https://github.com/donato-fiore/TrollDecrypt.git
cd TrollDecrypt
make package
```

## FoulDecrypt15 static decryption
TrollDecrypt also supports the FoulDecrypt15 static decryption method, ported from
`Decryption/FoulDecrypt.mm` and backed by the `kerninfra/` kernel R/W framework.
For every image (main executable, frameworks and extensions) TrollDecrypt first
tries this method, which decrypts the Mach-O directly on disk with the private
`mremap_encrypted()` syscall. If it fails, TrollDecrypt automatically falls back
to the original live-process (`task_for_pid`) decryption path.

* When a slice's `cryptoff` is 16K aligned, no kernel access is needed.
* When `cryptoff` is only 4K aligned, `kerninfra` patches Apple's
  `apple_protect_pager` so the syscall can decrypt the correct bytes. This path
  requires a jailbroken device with **libkrw** available (the build enables
  `USE_LIBKRW=1` and links libkrw statically through the kerninfra subproject).
  On a stock TrollStore device the fallback method is used automatically.

## Credits / Thanks
- [wh1te4ever](https://github.com/wh1te4ever) for TrollDecryptor
- [opa334](https://github.com/opa334) for some pieces of code
- [super.user](https://superuser.carrd.co) for the original app icon
- The FoulDecrypt15 / kerninfra projects for the static decryption backend