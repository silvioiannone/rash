use std::{fmt::Display, io::BufRead};

pub mod md5;

pub type ValidationResult = Result<(), ValidationError>;

// A validation error.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError(pub String);

impl std::error::Error for ValidationError {}

impl Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Validation error: {}", self.0)
    }
}

/// This trait must be implemented for every new hashing algorithm that has to be integrated with
/// `rash`.
///
/// ### Examaple
///
/// ```
/// use std::io::BufRead;
/// use rash::algo::{Algo, ValidationResult};
///
/// #[derive(Default)]
/// struct MyAlgo {};
///
/// impl Algo for MyAlgo {
///     fn hash(&self, buffer: Box<dyn BufRead>) -> String {
///         return "MyAlgoHash".to_string();
///     }
///
///     fn validate(&self, hash: &str) -> ValidationResult {
///         return Ok(());
///     }
/// }
/// ```
pub trait Algo {
    /// Hash the input.
    fn hash(&self, reader: Box<dyn BufRead>) -> String;

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
