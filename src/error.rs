use std::fmt;
use std::error::Error;

pub type EpiResult<T> = Result<T, EpiError>;

#[derive(PartialEq, Clone, Debug)]
pub enum EpiError {
    // General/HTTP
    Unauthorized,
    DatabaseError, // We do not pass the database error cause because it should not be displayed to the user
    RemoteError,
    MissingVar,

    // Auth
    InvalidState,
    UnknownSession,
    UnknownUser,
    TokenError
}

impl fmt::Display for EpiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use EpiError::*; // Without this, in the match we must write "EpiError::Unauthorized, ..."

        write!(f, "{}", match self {
            Unauthorized => "You must be logged to do that",
            DatabaseError => "Database connection error, this is bad : report this to the server hoster",
            RemoteError => "Remote API threw an error or an invalid response, if you didn't edit the requests this is bad : report this to the devs",
            MissingVar => "Server setup error : Missing one of the .env var (did you copy the .env.example to .env?)",
            InvalidState => "Your auth state is invalid for your request (trying to login while already logged?)",
            UnknownSession => "Can't find out who you are (session expired?) please try again",
            UnknownUser => "Can't find you in the CRI, are you still at the EPITA? Contact the devs if you are",
            TokenError => "Token creation failed, this is bad : report this to the devs"
        })
    }
}

impl Error for EpiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
