use alloc::boxed::Box;
use alloc::string::String;
use core::fmt;
use regex_automata::meta::BuildError as RaBuildError;

/// Result type for this crate with specific error enum.
pub type Result<T> = ::core::result::Result<T, Error>;

pub type ParseErrorPosition = usize;

/// An error as the result of parsing, compiling or running a regex.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Error {
    /// An error as a result of parsing a regex pattern, with the position where the error occurred
    ParseError(ParseErrorPosition, ParseError),
    /// An error as a result of compiling a regex
    CompileError(Box<CompileError>),
    /// An error as a result of running a regex
    RuntimeError(RuntimeError),
}

/// An error for the result of parsing a regex pattern.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// General parsing error
    GeneralParseError(String),
    /// Opening parenthesis without closing parenthesis, e.g. `(a|b`
    UnclosedOpenParen,
    /// Invalid repeat syntax
    InvalidRepeat,
    /// Synsema: a repetition count that does not fit in 32 bits, e.g. `a{4294967296}`
    RepeatCountTooLarge,
    /// Synsema: a repetition count with its minimum greater than its maximum, e.g. `a{3,2}`
    RepeatCountOutOfOrder,
    /// Pattern too deeply nested
    RecursionExceeded,
    /// Backslash without following character
    TrailingBackslash,
    /// Invalid escape
    InvalidEscape(String),
    /// Unicode escape not closed
    UnclosedUnicodeName,
    /// Invalid hex escape
    InvalidHex,
    /// Invalid codepoint for hex or unicode escape
    InvalidCodepointValue,
    /// Invalid character class
    InvalidClass,
    /// Unknown group flag
    UnknownFlag(String),
    /// Changing Unicode inside a pattern not supported
    ChangingUnicodeModeUnsupported,
    /// Invalid back reference
    InvalidBackref,
    /// Quantifier on lookaround or other zero-width assertion
    TargetNotRepeatable,
    /// Couldn't parse group name
    InvalidGroupName,
    /// Invalid group id in escape sequence
    InvalidGroupNameBackref(String),
}

/// An error as the result of compiling a regex.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum CompileError {
    /// Regex crate error
    InnerError(RaBuildError),
    /// Look-behind assertion without constant size
    LookBehindNotConst,
    /// Variable-length lookbehind requires feature flag
    VariableLookBehindRequiresFeature,
    /// Error building reverse DFA (pattern, error)
    DfaBuildError(String, String),
    /// Couldn't parse group name
    InvalidGroupName,
    /// Invalid group id in escape sequence
    InvalidGroupNameBackref(String),
    /// Invalid back reference
    InvalidBackref(usize),
    /// Once named groups are used you cannot refer to groups by number
    NamedBackrefOnly,
    /// Feature not supported yet
    FeatureNotYetSupported(String),
    /// Subroutine call to non-existent group
    SubroutineCallTargetNotFound(String, usize),
    /// Left-recursive subroutine call detected
    LeftRecursiveSubroutineCall(String),
    /// Unbounded recursive subroutine call detected
    NeverEndingRecursion,
    /// The compiled program exceeded the configured maximum size. Subroutine
    /// calls are inlined at compile time, so a self- or mutually-recursive
    /// pattern can expand without bound even when the recursion-depth cap is
    /// respected; this bounds the emitted VM instruction vector instead.
    PatternTooComplex,
    /// Unexpected general error
    UnexpectedGeneralError(String),
    /// The pattern combined with the active options can never produce a match. For example,
    /// setting `find_not_empty` on a pattern whose analysis shows it can only ever produce
    /// zero-length matches.
    PatternCanNeverMatch,
    /// An unresolved AST node was encountered during analysis (internal error)
    UnresolvedAstNode(usize, String),
    /// Synsema: what the regex takes before a search reads any text (the compiled program and
    /// what each of its searches needs to start) is larger than the limit set with
    /// `RegexBuilder::program_size_limit`. Compiling stops at the first piece that finds it over
    /// the limit, so `reached` is little more than `limit` however large the whole would be.
    ProgramTooLarge {
        /// The limit, in bytes
        limit: usize,
        /// What had been counted when it stopped, in bytes
        reached: usize,
    },
    /// Synsema: a positive look-behind that is not of one fixed size has a capture group in it,
    /// or a subroutine call (which writes the group it calls), e.g. `(?<=(a|ab))c`. What such a
    /// group holds is not one thing (see `Compiler::compile_lookaround`).
    LookBehindWritesGroup,
    /// Synsema: a look-around can run a `\K`: one written in it, or in a group it calls, e.g.
    /// `(?<=\K\w)\w`. `\K` sets where the match starts, and what a look-around reads is not part
    /// of the match (see `analyze::look_around_runs_keep_out`).
    KeepOutInLookAround,
}

/// An error as the result of executing a regex.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RuntimeError {
    /// Max stack size exceeded for backtracking while executing regex.
    StackOverflow,
    /// Max limit for backtracking count exceeded while executing the regex.
    /// Configure using
    /// [`RegexBuilder::backtrack_limit`](struct.RegexBuilder.html#method.backtrack_limit).
    BacktrackLimitExceeded,
    /// Synsema: the search needed a step and its budget had none left
    /// (`Regex::find_input_with_steps`, `Regex::captures_input_with_steps`).
    StepLimitExceeded,
}

#[cfg(feature = "std")]
impl ::std::error::Error for Error {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::GeneralParseError(s) => write!(f, "General parsing error: {}", s),
            ParseError::UnclosedOpenParen => {
                write!(f, "Opening parenthesis without closing parenthesis")
            }
            ParseError::InvalidRepeat => write!(f, "Invalid repeat syntax"),
            ParseError::RepeatCountTooLarge => {
                write!(f, "Repetition count is too large (the largest is 4294967295)")
            }
            ParseError::RepeatCountOutOfOrder => {
                write!(f, "Repetition count has its minimum greater than its maximum")
            }
            ParseError::RecursionExceeded => write!(f, "Pattern too deeply nested"),
            ParseError::TrailingBackslash => write!(f, "Backslash without following character"),
            ParseError::InvalidEscape(s) => write!(f, "Invalid escape: {}", s),
            ParseError::UnclosedUnicodeName => write!(f, "Unicode escape not closed"),
            ParseError::InvalidHex => write!(f, "Invalid hex escape"),
            ParseError::InvalidCodepointValue => {
                write!(f, "Invalid codepoint for hex or unicode escape")
            }
            ParseError::InvalidClass => write!(f, "Invalid character class"),
            ParseError::UnknownFlag(s) => write!(f, "Unknown group flag: {}", s),
            ParseError::ChangingUnicodeModeUnsupported => {
                write!(f, "Changing Unicode mode inline is not supported")
            }
            ParseError::InvalidBackref => write!(f, "Invalid back reference"),
            ParseError::InvalidGroupName => write!(f, "Could not parse group name"),
            ParseError::InvalidGroupNameBackref(s) => {
                write!(f, "Invalid group name in back reference: {}", s)
            }
            ParseError::TargetNotRepeatable => write!(f, "Target of repeat operator is invalid"),
        }
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CompileError::InnerError(e) => write!(f, "Regex error: {}", e),
            CompileError::LookBehindNotConst => {
                write!(f, "Look-behind assertion without constant size")
            },
            CompileError::VariableLookBehindRequiresFeature => {
                write!(f, "Variable-length lookbehind requires the 'variable-lookbehinds' feature")
            },
            CompileError::DfaBuildError(pattern, e) => {
                write!(f, "Failed to build DFA for {}: {}", pattern, e)
            },
            CompileError::InvalidGroupName => write!(f, "Could not parse group name"),
            CompileError::InvalidGroupNameBackref(s) => write!(f, "Invalid group name in back reference: {}", s),
            CompileError::InvalidBackref(g) => write!(f, "Invalid back reference to group {}", g),
            CompileError::NamedBackrefOnly => write!(f, "Numbered backref/call not allowed because named group was used, use a named backref instead"),
            CompileError::FeatureNotYetSupported(s) => write!(f, "Regex uses currently unimplemented feature: {}", s),
            CompileError::SubroutineCallTargetNotFound(s, ix) => {
                write!(f, "Subroutine call target not found at position {}: {}", ix, s)
            }
            CompileError::LeftRecursiveSubroutineCall(s) => {
                write!(f, "Left-recursive subroutine call detected: {}", s)
            }
            CompileError::NeverEndingRecursion => {
                write!(f, "Never-ending recursive subroutine call detected")
            }
            CompileError::PatternTooComplex => {
                write!(
                    f,
                    "Pattern is too complex: it exceeded the configured maximum number of VM \
                     instructions. Try increasing the `max_prog_size` limit or simplifying the \
                     pattern."
                )
            }
            CompileError::UnexpectedGeneralError(s) => {
                write!(f, "Unexpected general compilation error: {}", s)
            }
            CompileError::PatternCanNeverMatch => {
                write!(f, "Pattern can never match: the regex is zero-width only but find_not_empty is set")
            }
            CompileError::UnresolvedAstNode(ix, node) => {
                write!(f, "Unresolved AST node encountered during analysis at position {}: {}", ix, node)
            }
            CompileError::LookBehindWritesGroup => write!(
                f,
                "A look-behind of variable length has a capture group or a subroutine call in it: \
                 use (?:...) if the group is only for grouping, capture outside the look-behind, \
                 or give the look-behind one fixed length"
            ),
            CompileError::KeepOutInLookAround => write!(
                f,
                "A look-around has \\K in it, or calls a group that has it: \\K sets where the \
                 match starts, and what a look-around reads is not part of the match; write \\K \
                 outside the look-around"
            ),
            CompileError::ProgramTooLarge { limit, .. } => {
                write!(f, "Compiled regex exceeds the size limit of {} bytes", limit)
            }
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RuntimeError::StackOverflow => write!(f, "Max stack size exceeded for backtracking"),
            RuntimeError::BacktrackLimitExceeded => {
                write!(f, "Max limit for backtracking count exceeded")
            }
            RuntimeError::StepLimitExceeded => write!(f, "Step budget of the search exceeded"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::ParseError(position, parse_error) => {
                write!(f, "Parsing error at position {}: {}", position, parse_error)
            }
            Error::CompileError(compile_error) => {
                write!(f, "Error compiling regex: {}", compile_error)
            }
            Error::RuntimeError(runtime_error) => {
                write!(f, "Error executing regex: {}", runtime_error)
            }
        }
    }
}

impl From<CompileError> for Error {
    fn from(compile_error: CompileError) -> Self {
        Error::CompileError(Box::new(compile_error))
    }
}
