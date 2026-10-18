//! Bounded canonical request/result codec for native command-line adapters.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_arguments: usize,
    pub max_argument_bytes: usize,
    pub max_stdin_bytes: usize,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub environment_allowlist: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRequest {
    pub invocation_id: [u8; 16],
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub stdin: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessResult {
    pub exit_code: i32,
    pub timed_out: bool,
    pub cancelled: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Truncated,
    Bound,
    Utf8,
    Nul,
    Environment,
    Trailing,
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CodecError {}

impl ProcessRequest {
    pub fn encode(&self, limits: &Limits) -> Result<Vec<u8>, CodecError> {
        validate_request(self, limits)?;
        let mut output = Vec::new();
        output.extend_from_slice(&self.invocation_id);
        write_u32(&mut output, self.arguments.len())?;
        for argument in &self.arguments {
            write_bytes(&mut output, argument.as_bytes())?;
        }
        write_u32(&mut output, self.environment.len())?;
        for (name, value) in &self.environment {
            write_bytes(&mut output, name.as_bytes())?;
            write_bytes(&mut output, value.as_bytes())?;
        }
        write_bytes(&mut output, &self.stdin)?;
        Ok(output)
    }

    pub fn decode(input: &[u8], limits: &Limits) -> Result<Self, CodecError> {
        let mut reader = Reader::new(input);
        let invocation_id = reader
            .take(16)?
            .try_into()
            .map_err(|_| CodecError::Truncated)?;
        let argument_count = reader.u32()? as usize;
        if argument_count > limits.max_arguments {
            return Err(CodecError::Bound);
        }
        let mut arguments = Vec::with_capacity(argument_count);
        for _ in 0..argument_count {
            arguments.push(reader.string(limits.max_argument_bytes)?);
        }
        let environment_count = reader.u32()? as usize;
        if environment_count > limits.environment_allowlist.len() {
            return Err(CodecError::Environment);
        }
        let mut environment = BTreeMap::new();
        for _ in 0..environment_count {
            let name = reader.string(128)?;
            let value = reader.string(limits.max_argument_bytes)?;
            if !limits
                .environment_allowlist
                .contains(&name.to_ascii_uppercase())
                || environment
                    .insert(name.to_ascii_uppercase(), value)
                    .is_some()
            {
                return Err(CodecError::Environment);
            }
        }
        let stdin = reader.bytes(limits.max_stdin_bytes)?.to_vec();
        if !reader.done() {
            return Err(CodecError::Trailing);
        }
        let request = Self {
            invocation_id,
            arguments,
            environment,
            stdin,
        };
        validate_request(&request, limits)?;
        Ok(request)
    }
}

impl ProcessResult {
    pub fn encode(&self, limits: &Limits) -> Result<Vec<u8>, CodecError> {
        if self.stdout.len() > limits.max_stdout_bytes
            || self.stderr.len() > limits.max_stderr_bytes
            || self.timed_out && self.cancelled
        {
            return Err(CodecError::Bound);
        }
        let mut output = Vec::new();
        output.extend_from_slice(&self.exit_code.to_le_bytes());
        output.push(u8::from(self.timed_out));
        output.push(u8::from(self.cancelled));
        output.extend_from_slice(&[0, 0]);
        write_bytes(&mut output, &self.stdout)?;
        write_bytes(&mut output, &self.stderr)?;
        Ok(output)
    }

    pub fn decode(input: &[u8], limits: &Limits) -> Result<Self, CodecError> {
        let mut reader = Reader::new(input);
        let exit_code = i32::from_le_bytes(
            reader
                .take(4)?
                .try_into()
                .map_err(|_| CodecError::Truncated)?,
        );
        let timed_out = flag(reader.take(1)?[0])?;
        let cancelled = flag(reader.take(1)?[0])?;
        if reader.take(2)? != [0, 0] || timed_out && cancelled {
            return Err(CodecError::Bound);
        }
        let stdout = reader.bytes(limits.max_stdout_bytes)?.to_vec();
        let stderr = reader.bytes(limits.max_stderr_bytes)?.to_vec();
        if !reader.done() {
            return Err(CodecError::Trailing);
        }
        Ok(Self {
            exit_code,
            timed_out,
            cancelled,
            stdout,
            stderr,
        })
    }
}

fn validate_request(request: &ProcessRequest, limits: &Limits) -> Result<(), CodecError> {
    if request.arguments.len() > limits.max_arguments
        || request.stdin.len() > limits.max_stdin_bytes
        || request.environment.len() > limits.environment_allowlist.len()
    {
        return Err(CodecError::Bound);
    }
    for argument in &request.arguments {
        validate_text(argument, limits.max_argument_bytes)?;
    }
    let mut names = BTreeSet::new();
    for (name, value) in &request.environment {
        let canonical = name.to_ascii_uppercase();
        if !limits.environment_allowlist.contains(&canonical) || !names.insert(canonical) {
            return Err(CodecError::Environment);
        }
        validate_text(name, 128)?;
        validate_text(value, limits.max_argument_bytes)?;
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize) -> Result<(), CodecError> {
    if value.len() > maximum {
        return Err(CodecError::Bound);
    }
    if value.as_bytes().contains(&0) {
        return Err(CodecError::Nul);
    }
    Ok(())
}

fn write_u32(output: &mut Vec<u8>, value: usize) -> Result<(), CodecError> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| CodecError::Bound)?
            .to_le_bytes(),
    );
    Ok(())
}

fn write_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CodecError> {
    write_u32(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn flag(value: u8) -> Result<bool, CodecError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CodecError::Bound),
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self.offset.checked_add(length).ok_or(CodecError::Bound)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(CodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| CodecError::Truncated)?,
        ))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], CodecError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(CodecError::Bound);
        }
        self.take(length)
    }

    fn string(&mut self, maximum: usize) -> Result<String, CodecError> {
        let bytes = self.bytes(maximum)?;
        if bytes.contains(&0) {
            return Err(CodecError::Nul);
        }
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| CodecError::Utf8)
    }

    const fn done(&self) -> bool {
        self.offset == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            max_arguments: 8,
            max_argument_bytes: 128,
            max_stdin_bytes: 1024,
            max_stdout_bytes: 1024,
            max_stderr_bytes: 1024,
            environment_allowlist: BTreeSet::from([String::from("WVB_MODE"), String::from("TEMP")]),
        }
    }

    #[test]
    fn request_and_result_round_trip_with_exact_bounds() {
        let request = ProcessRequest {
            invocation_id: [7; 16],
            arguments: vec![String::from("alpha"), String::from("two words")],
            environment: BTreeMap::from([(String::from("WVB_MODE"), String::from("test"))]),
            stdin: b"input".to_vec(),
        };
        assert_eq!(
            ProcessRequest::decode(&request.encode(&limits()).unwrap(), &limits()).unwrap(),
            request
        );
        let result = ProcessResult {
            exit_code: 17,
            timed_out: false,
            cancelled: false,
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
        };
        assert_eq!(
            ProcessResult::decode(&result.encode(&limits()).unwrap(), &limits()).unwrap(),
            result
        );
    }

    #[test]
    fn rejects_ambient_environment_nul_trailing_and_oversized_streams() {
        let mut request = ProcessRequest {
            invocation_id: [7; 16],
            arguments: vec![String::from("ok")],
            environment: BTreeMap::from([(String::from("PATH"), String::from("ambient"))]),
            stdin: Vec::new(),
        };
        assert_eq!(request.encode(&limits()), Err(CodecError::Environment));
        request.environment.clear();
        request.arguments[0] = String::from("bad\0argument");
        assert_eq!(request.encode(&limits()), Err(CodecError::Nul));

        let mut encoded = ProcessResult {
            exit_code: 0,
            timed_out: false,
            cancelled: false,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
        .encode(&limits())
        .unwrap();
        encoded.push(1);
        assert_eq!(
            ProcessResult::decode(&encoded, &limits()),
            Err(CodecError::Trailing)
        );
    }

    #[test]
    fn malformed_process_corpus_never_panics_or_allocates_unboundedly() {
        let mut state = 0xa076_1d64_78bd_642f_u64;
        for length in 0..1024 {
            let mut bytes = vec![0_u8; length];
            for byte in &mut bytes {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                *byte = state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes()[3];
            }
            let _ = ProcessRequest::decode(&bytes, &limits());
            let _ = ProcessResult::decode(&bytes, &limits());
        }
    }
}
