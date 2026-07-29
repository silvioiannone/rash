use crate::cli::{
    AvailableAlgo::{self},
    Cli,
};
use rash::algo::{Algo, HashingError, ValidationError, md5::Md5, sha224::Sha224, sha256::Sha256};
use std::{
    fmt::{self, Display},
    fs::File,
    io::{self, BufRead, BufReader, Error},
};

/// An error produced while running the CLI that causese `rash` to exit with a non-0 status code.
#[derive(Debug)]
pub enum RashError {
    Io(Error),
    Validation(ValidationError),
    Hashing(HashingError),
    Mismatch { expected: String, resolved: String },
}

impl Display for RashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RashError::Io(error) => write!(f, "{error}"),
            RashError::Validation(error) => write!(f, "{error}"),
            RashError::Hashing(error) => write!(f, "{error}"),
            RashError::Mismatch { expected, resolved } => write!(
                f,
                "Expected hash doesn't match resolved one.\nExpected: {expected} - Resolved: {resolved}"
            ),
        }
    }
}

impl std::error::Error for RashError {}

impl From<io::Error> for RashError {
    fn from(error: io::Error) -> Self {
        RashError::Io(error)
    }
}

impl From<ValidationError> for RashError {
    fn from(error: ValidationError) -> Self {
        RashError::Validation(error)
    }
}

impl From<HashingError> for RashError {
    fn from(error: HashingError) -> Self {
        RashError::Hashing(error)
    }
}

/// Execute the CLI based on the parsed arguments.
pub fn run(cli: Cli) -> Result<(), RashError> {
    let algo: Box<dyn Algo> = match cli.algo {
        AvailableAlgo::Md5 => Box::new(Md5::new()),
        AvailableAlgo::Sha256 => Box::new(Sha256::new()),
        AvailableAlgo::Sha224 => Box::new(Sha224::new()),
    };

    if let Some(hash) = cli.verify {
        return algo.validate(&hash).map_err(RashError::from);
    }

    let reader: Box<dyn BufRead> = if let Some(path) = cli.file {
        Box::new(BufReader::new(File::open(path)?))
    } else {
        Box::new(BufReader::new(io::stdin()))
    };

    let hash = algo.hash(reader)?;

    if let Some(expected) = cli.compare {
        return if expected == hash {
            Ok(())
        } else {
            Err(RashError::Mismatch {
                expected,
                resolved: hash,
            })
        };
    }

    println!("{hash}");

    Ok(())
}
