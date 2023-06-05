use std::env;

fn main() {
    // Set the CARGO environment variable to the Cargo executable
    env::set_var("CARGO", "cargo");
}