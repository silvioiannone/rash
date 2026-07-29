use clap::{Parser, ValueEnum};

/// Available hashing algorithms.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum AvailableAlgo {
    Md5,
    Sha256,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Hash algorithm to use.
    #[arg(value_enum)]
    pub algo: AvailableAlgo,

    /// Compare the given hash with the one resulting from the input (stdin or file).
    #[arg(short, long)]
    pub compare: Option<String>,

    /// File for which the hash will be computed.
    #[arg(short, long, value_name = "FILE")]
    pub file: Option<String>,

    /// Verify that the given hash is valid.
    #[arg(short, long)]
    pub verify: Option<String>,
}

#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Cli::command().debug_assert();
}
