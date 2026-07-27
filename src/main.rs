mod cli;
mod commands;

use clap::Parser;
use cli::Cli;

fn main() {
    if let Err(error) = commands::run(Cli::parse()) {
        eprintln!("{error}");
        std::process::exit(1);
    }

    // TODO: add support for batch functionality.
}
