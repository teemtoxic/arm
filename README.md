# NMMS unlocker — GitHub Actions ARM runner

Protected APK: `NMMS 2.0_5.2.0-protected-v3.apk`
Protector: **OnDev Encryptor / OnDev Shield V3** (`on.dev.shellv3`)

## Why this exists

The real DEX is not in the APK. It sits encrypted in `assets/ondev/p` (22,242,864 bytes).
`libondevx.so` decrypts it at runtime inside `Application.attachBaseContext`, then feeds
the plaintext to `InMemoryDexClassLoader`.

`lib/arm64-v8a/libondevx.so` is **not stripped** — it still has `.symtab` and full DWARF4
`.debug_info/.debug_str/.debug_line`. So the internal function is known exactly:

| symbol | offset | signature |
|---|---|---|
| `nx_decrypt` | `0x1ea3c` | `jobjectArray nx_decrypt(JNIEnv*, jclass, byte[] k, byte[] certHash, byte[] p)` |
| `hkdf` | `0x20488` | `(const u8* salt, size_t saltLen, const u8* ikm, size_t ikmLen, const u8* info, size_t infoLen, u8* out, size_t outLen)` |
| `nx_inspect` | `0x1e9d4` | anti-tamper probe |
| `nx_watch` | `0x1e9d8` | ptrace / hook watcher |
| `nx_scrub` | `0x1f94c` | wipes keys from memory |

`nx_decrypt` reads `k`, appends the APK signing-cert hash, runs HKDF-SHA256 to build an
AES-256 key + IV, AES-CBC-decrypts `p`, checks the `"ODEX"` container magic, unpacks the
slice table, and returns a `ByteBuffer[]` — one buffer per embedded DEX.

We don't need to reimplement any of that. We just need to **call it on a real aarch64 CPU**.

## What the runner does

`ubuntu-24.04-arm` is GitHub's free ARM64 runner (public repos, unlimited minutes).
aarch64 is aarch64 — this lib loads natively. No emulator, no qemu, no phone, no root.

1. `harness/nxrun.c` builds a **synthetic JNIEnv** (the full 233-entry
   `JNINativeInterface_` vtable, with `GetArrayLength`, `GetByteArrayRegion`,
   `FindClass`, `NewObjectArray`, `SetObjectArrayElement` and `NewDirectByteBuffer`
   implemented against plain C buffers).
2. `dlopen()`s `input/libondevx.so`, resolves the load base via `dlinfo(RTLD_DI_LINKMAP)`,
   gets `nx_decrypt` at `base + 0x1ea3c`.
3. Computes `certHash = sha256(sha256(META-INF/CERT.RSA))` — the exact value
   `ShellAppFactoryV3.certSetHashFromApk()` produces.
4. Calls `nx_decrypt`, then walks the returned `ByteBuffer[]` and writes every slice
   to `payload.bin`.
5. Parses the `"ODEX"` container (`magic | u16 count | {u8 nameLen, name, u32 off, u32 len}*`)
   and emits one `.dex` per slice into `out/`.

## Layout

```
input/libondevx.so     <- lib/arm64-v8a/libondevx.so   (783,120 B)
input/k                <- assets/ondev/k               (69 B)
input/p                <- assets/ondev/p               (22,242,864 B)
input/CERT.RSA         <- META-INF/CERT.RSA            (1,177 B)
harness/nxrun.c        <- the JNIEnv shim + caller
harness/logshim.c      <- stub liblog.so (Android-only otherwise)
.github/workflows/unpack.yml
```

The 143 MB APK itself is **not** committed — only the four artifacts above, ~22.5 MB total.

## Running it

```bash
git init -b main
git add .
git commit -m "nmms unpack"
git remote add origin https://github.com/<you>/nmms-unpack.git
git push -u origin main
```

Then: **Actions → nmms-unpack → Run workflow**.

Grab `nmms-decrypted` from the run's Artifacts. Inside:

- `payload.bin` — raw decrypted payload
- `out/classes*.dex` — the real application code
- `run.log` — every JNI call the library made, plus the cert hash it was fed

## If `nx_decrypt` returns NULL

That means the key/cert binding rejected us. The run log will say so, and the
"Diagnose on failure" step dumps the symbol table. Things to try, in order:

1. `nx_offset` input — run workflow_dispatch with a different offset. The offset is only
   known-good for this exact `libondevx.so` build (`0x1ea3c` from `.symtab`).
2. **Wrong cert hash form.** `ShellAppFactoryV3` may hash the cert *bytes* of the signature
   block, or use `sha256(sha256(certDER))` over the ASN.1 SEQUENCE with/without the
   trailing signed-attributes. Edit the `SHA256` section in `nxrun.c` — it already prints
   the value it produces so you can compare.
3. **`k[4]` flag byte.** In `nx_decrypt`: `k[4] == 0x11` appends the cert hash to the IKM.
   Other values skip it or use a literal key path. If cert binding is broken, patch
   `input/k` byte 4 and re-run — the harness passes `k` through untouched.
4. **32-bit route.** `lib/armeabi-v7a/libondevx.so` has the same symbols (`nx_decrypt`
   @ `0xee81` Thumb). It needs `qemu-arm-static` + an armhf rootfs on the runner, which
   is more work but fully offline. Not needed unless (1)–(3) all fail.

## After you have the DEX

The modder's additions are in `assets/TgSellerOfKing`, `lib*/libTgSellerOfKing.so`,
`contact.tg.sellerofking`, `libsnehakimakichut.so`, Telegram `@on_modz`. The added
"NMMS LOGIN SYSTEM" dialog will be a smali class referencing
`https://nmms-af49b-default-rtdb.firebaseio.com`. Official login must stay.

Rebuild with `_tools/apkforge/apkforge.py`, sign with `_tools/uber-apk-signer.jar`.
