use crate::cli::{AvailableAlgo, Cli};
use rash::algo::{Algo, ValidationError, md5::Md5};
use std::{
    fmt::{self, Display},
    fs,
    io::{self, Error, Read},
};

/// An error produced while running the CLI that causese `rash` to exit with a non-0 status code.
#[derive(Debug)]
pub enum RashError {
    Io(Error),
    Validation(ValidationError),
    Mismatch { expected: String, resolved: String },
}

impl Display for RashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RashError::Io(error) => write!(f, "{error}"),
            RashError::Validation(error) => write!(f, "{error}"),
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

/// Execute the CLI based on the parsed arguments.
pub fn run(cli: Cli) -> Result<(), RashError> {
    let algo = Box::new(match cli.algo {
        AvailableAlgo::Md5 => Md5::new(),
    });

    let mut buffer = Vec::new();

    if let Some(hash) = cli.verify {
        return algo.validate(&hash).map_err(RashError::from);
    }

    if let Some(path) = cli.file {
        buffer = fs::read(&path)?;
    } else {
        io::stdin().read_to_end(&mut buffer)?;
    }

    let hash = algo.hash(&buffer);

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
