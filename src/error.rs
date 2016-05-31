// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

use std::io;
use std::error;
use std::fmt;

use openssl::ssl;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Ssl(ssl::error::SslError)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::Ssl(ref err) => write!(f, "SSL error: {}", err),
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
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Io(ref err) => Some(err),
            Error::Ssl(ref err) => Some(err),
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

