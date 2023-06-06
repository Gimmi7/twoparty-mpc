# twoparty-client

## Build for Android

Assuming we want to build twoparty-client for **aarch64-linux-android**:

### add compile target with rustup:

```shell
rustup target add  aarch64-linux-android
```

### install ndk tools with android studio

### config cargo to use ndk clang to compile for **aarch64-linux-android**

```toml
# the config located at  ~/.cargo/config.toml

[target.aarch64-linux-android]
ar = "/Users/me/Library/Android/sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "/Users/me/Library/Android/sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android33-clang"
```

### set ar and for clang to compile sepc256k1-sys

As **sepc256k1-sys** is porting from c, **sepc256k1-sys** use cc to compile c , so it will need below binary:

* aarch64-linux-android-ar
* aarch64-linux-android-clang

for simply, you can run there commands in ndk bin

```shell
cp llvm-ar  aarch64-linux-android-ar
cp aarch64-linux-android33-clang  aarch64-linux-android-clang
```

### compile with cargo

```shell
cargo build --target aarch64-linux-android --release
```

## Test tips

Android Studio emulator use 10.0.2.2 as loopback interface, so when test server and client on same computer, the client
should replace localhost with 10.0.2.2 .

## References

* [https://www.inrush.cn/2018/07/04/Java-%E8%B0%83%E7%94%A8-Rust/](https://www.inrush.cn/2018/07/04/Java-%E8%B0%83%E7%94%A8-Rust/)
* [android emulator network address space](https://developer.android.com/studio/run/emulator-networking)