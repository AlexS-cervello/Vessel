use std::{env::VarError, string::FromUtf8Error};

#[derive(Debug)]
pub enum Error {
    Generic(Box<dyn std::error::Error>),
    Var(VarError),
    DatabaseAlreadyExist(String),
    File(std::io::Error),
    Json(serde_json::Error),
    Argon(argon2::Error),
    ChaCha(chacha20poly1305::aead::Error),
    Str(FromUtf8Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Generic(ref err) => {
                write!(f, "Error: {}", err)
            }
            Self::Var(ref err) => {
                write!(f, "Variable error: {}", err)
            }
            Self::DatabaseAlreadyExist(ref err) => {
                write!(f, "That database already exists: {}", err)
            }
            Self::File(ref err) => {
                write!(f, "File error: {}", err)
            }
            Self::Json(ref err) => {
                write!(f, "Json error: {}", err)
            }
            Self::Argon(ref err) => {
                write!(f, "Cipher error: {}", err)
            }
            Self::ChaCha(ref _err) => {
                write!(f, "Incorrect password")
            }
            Self::Str(ref err) => {
                write!(f, "String error: {}", err)
            }
        }
    }
}

impl From<Box<dyn std::error::Error>> for Error {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        Self::Generic(err)
    }
}
impl From<VarError> for Error {
    fn from(err: VarError) -> Self {
        Self::Var(err)
    }
}
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::File(err)
    }
}
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}
impl From<argon2::Error> for Error {
    fn from(err: argon2::Error) -> Self {
        Self::Argon(err)
    }
}
impl From<chacha20poly1305::aead::Error> for Error {
    fn from(err: chacha20poly1305::aead::Error) -> Self {
        Self::ChaCha(err)
    }
}
impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Self::Str(err)
    }
}
