use std::process::exit;

extern crate argon2;
extern crate chacha20poly1305;

pub mod common;
pub mod controllers;
pub mod encryption;
pub mod error;
pub mod generator;

fn main() {
    controllers::run().unwrap_or_else(|err| {
        println!("{}", err);
        exit(1);
    });
}
