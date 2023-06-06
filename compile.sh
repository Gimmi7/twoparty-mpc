yum install gcc -y
echo | curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source \"$HOME/.cargo/env\"
rustup update && rustup install nightly && rustup default nightly
source \"$HOME/.cargo/env\"
rustc --version
cargo build --release
