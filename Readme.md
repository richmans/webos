# WEBOS

## installation
I only ever did this on osx, so that's where this is tested. 
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install cargo-xbuild bootimage
brew install qemu
# on linux: apt install qemu
rustup override add nightly
rustup component add rust-src
rustup component add llvm-tools-preview
```
## Run the thing!
`cargo xrun`