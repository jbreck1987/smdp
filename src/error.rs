/*
Defines the public facing Error type. Following the Hyper error model.
In this model, all errors are Opaque and associated errors can be accessed by
downcasting.
*/

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    Parse,
    Format,
}
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    cause: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}
impl Error {
    // Basic constructor
    pub fn new(
        kind: ErrorKind,
        cause: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            kind,
            cause: Some(cause.into()),
        }
    }
    // Build new Parse variant from arbitrary error.
    pub fn into_parse<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: ErrorKind::Parse,
            cause: Some(Box::new(err)),
        }
    }
    // Build new Format variant from arbitrary error.
    pub fn into_format<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: ErrorKind::Format,
            cause: Some(Box::new(err)),
        }
    }
    pub fn is_parse(&self) -> bool {
        self.kind == ErrorKind::Parse
    }
    pub fn is_format(&self) -> bool {
        self.kind == ErrorKind::Format
    }
    //pub fn cause<E>(&self) -> Option<&(dyn std::error::Error + Sync + Send + 'static)> {
    //    self.cause.as_deref()
    //}
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Downgrade the trait bounds of the inner
        self.cause
            .as_deref()
            .map(|s| s as &(dyn std::error::Error + 'static))
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.cause {
            Some(cause) => write!(f, "Kind: {:?}, Error: {}", self.kind, cause),
            _ => write!(f, "{:?} Error", self.kind),
        }
    }
}

pub(crate) type SmdpResult<T> = Result<T, Error>;
