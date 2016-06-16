// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

use std::io;
use std::error;
use std::fmt;
use std::string;

use openssl::ssl;
use uuid;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Ssl(ssl::error::SslError),
    UuidParse(uuid::ParseError),
    MessageParse(&'static str),
    Utf8(string::FromUtf8Error),
    Other(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::Ssl(ref err) => write!(f, "SSL error: {}", err),
            Error::UuidParse(ref err) => write!(f, "uuid error: {}", err),
            Error::MessageParse(s) => write!(f, " message parse error: {}", s),
            Error::Utf8(ref err) => write!(f, " from utf8 error: {}", err),
            Error::Other(s) => write!(f, "{}", s),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        // Both underlying errors already impl `Error`, so we defer to their
        // implementations.
        match *self {
            Error::Io(ref err) => err.description(),
            Error::Ssl(ref err) => err.description(),
            // FIXME: Not working with stable Rust right now?
            // Error::UuidParse(ref err) => err.description(),
            Error::UuidParse(_) => "uuid parse error",
            Error::MessageParse(s) => s,
            Error::Utf8(ref err) => err.description(),
            Error::Other(s) => s,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref err) => Some(err),
            Error::Ssl(ref err) => Some(err),
            // FIXME: Not working with stable Rust right now?
            // Error::UuidParse(ref err) => Some(err),
            Error::UuidParse(_) => None,
            Error::MessageParse(_) => None,
            Error::Utf8(ref err) => Some(err),
            Error::Other(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<ssl::error::SslError> for Error {
    fn from(err: ssl::error::SslError) -> Error {
        Error::Ssl(err)
    }
}

impl From<uuid::ParseError> for Error {
    fn from(err: uuid::ParseError) -> Error {
        Error::UuidParse(err)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Error {
        Error::Utf8(err)
    }
}

/// Error values returned from the command line option parser.
pub enum ConfigError {
    /// The user has given the `-h' or `--help' options.
    HelpRequested(super::getopts::Options),
    /// No listen address was specified.
    NoListenAddress,
    /// No workspace directory was specified.
    NoWorkspace,
    /// No UUID was specified.
    NoUuid,
    /// The UUID given could not be parsed.
    InvalidUuid(super::uuid::ParseError),
    /// Some error during option parsing happened, for example an
    /// invalid option was given.
    GetOptError(super::getopts::Fail)
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConfigError::HelpRequested(_) =>
                write!(f, "help requested"),
            ConfigError::NoListenAddress =>
                write!(f, "no listen address given"),
            ConfigError::NoWorkspace =>
                write!(f, "no workspace directory given"),
            ConfigError::NoUuid =>
                write!(f, "no node UUID given"),
            ConfigError::InvalidUuid(e) =>
                write!(f, "UUID is invalid: {}", e),
            ConfigError::GetOptError(ref e) =>
                write!(f, "{}", e)
        }
    }
}

