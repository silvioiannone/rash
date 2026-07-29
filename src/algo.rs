use std::{error::Error, fmt::Display, io::BufRead};

pub mod md5;
pub mod sha256;

pub type HashingResult = Result<String, HashingError>;
pub type ValidationResult = Result<(), ValidationError>;

// An error returned when hashing the input.
#[derive(Debug, Clone, PartialEq)]
pub struct HashingError(pub String);

impl Error for HashingError {}

impl Display for HashingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hashing error: {}", self.0)
    }
}

// A validation error.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError(pub String);

impl Error for ValidationError {}

impl Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Validation error: {}", self.0)
    }
}

/// This trait must be implemented for every new hashing algorithm that has to be integrated with
/// `rash`.
///
/// ### Example
///
/// ```
/// use std::io::BufRead;
/// use rash::algo::{Algo, HashingResult, ValidationResult};
///
/// #[derive(Default)]
/// struct MyAlgo {};
///
/// impl Algo for MyAlgo {
///     fn hash(&self, buffer: Box<dyn BufRead>) -> HashingResult {
///         return Ok("MyAlgoHash".to_string());
///     }
///
///     fn validate(&self, hash: &str) -> ValidationResult {
///         return Ok(());
///     }
/// }
/// ```
pub trait Algo {
    /// Hash the input.
    fn hash(&self, reader: Box<dyn BufRead>) -> HashingResult;

    /// Validate a hash.
    fn validate(&self, hash: &str) -> ValidationResult;

    /// Create a new instance of self.
    fn new() -> Self
    where
        Self: Sized + Default,
    {
        Self::default()
    }
}
