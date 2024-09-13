use vergen::{generate_cargo_keys, ConstantsFlags};

fn main() {
    // Generate the 'cargo:' key output
    generate_cargo_keys(ConstantsFlags::all()).expect("Unable to generate the cargo keys!");

    // Add C++17 flag for PyTorch
    println!("cargo:rustc-env=CXXFLAGS=-std=c++17");
}
