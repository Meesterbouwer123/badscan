// using this lib.rs file makes it so the entire project (excluding main.rs) becomes a library that main.rs depends on
// this avoids having to write these mod statements in the main.rs file
// (yes it's purely asthetic)
pub mod config;
pub mod interface;
pub mod protocols;
pub mod scanner;