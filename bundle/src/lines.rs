//! Bounded, sanitized line splitting for debug output relayed into host logs.

/// One complete line with control characters replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Lossy UTF-8 without the newline; control characters other than tab become U+FFFD.
    pub text: String,
    /// Bytes past the limit were dropped up to the next newline.
    pub truncated: bool,
}

/// Splits an untrusted byte stream into lines of at most `limit` bytes.
#[derive(Debug)]
pub struct Lines {
    limit: usize,
    line: Vec<u8>,
    truncated: bool,
}

impl Lines {
    /// Starts an empty splitter; `limit` bounds the buffered bytes of one line.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            line: Vec::new(),
            truncated: false,
        }
    }

    /// Consumes a chunk and returns every line it completes.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Line> {
        let mut lines = Vec::new();
        for chunk in bytes.split_inclusive(|&byte| byte == b'\n') {
            let (body, complete) = match chunk.strip_suffix(b"\n") {
                Some(body) => (body, true),
                None => (chunk, false),
            };
            let room = self.limit - self.line.len();
            self.truncated |= body.len() > room;
            self.line.extend_from_slice(&body[..body.len().min(room)]);
            if complete {
                lines.push(self.take());
            }
        }
        lines
    }

    /// Returns the unterminated remainder at end of stream, if any.
    pub fn finish(&mut self) -> Option<Line> {
        (!self.line.is_empty() || self.truncated).then(|| self.take())
    }

    fn take(&mut self) -> Line {
        let line = Line {
            text: sanitize(&self.line),
            truncated: self.truncated,
        };
        self.line.clear();
        self.truncated = false;
        line
    }
}

/// Keeps one source line one log line: no terminal escapes, carriage returns or NULs.
fn sanitize(bytes: &[u8]) -> String {
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| {
            if c.is_control() && c != '\t' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str, truncated: bool) -> Line {
        Line {
            text: text.into(),
            truncated,
        }
    }

    #[test]
    fn lines_span_chunks_and_keep_the_unterminated_tail() {
        let mut lines = Lines::new(64);
        assert_eq!(lines.push(b"first\nsec"), [line("first", false)]);
        assert_eq!(
            lines.push(b"ond\n\nthird"),
            [line("second", false), line("", false)]
        );
        assert_eq!(lines.finish(), Some(line("third", false)));
        assert_eq!(lines.finish(), None);
    }

    #[test]
    fn long_lines_are_cut_once_and_the_next_line_is_intact() {
        let mut lines = Lines::new(4);
        assert!(lines.push(b"abc").is_empty());
        assert_eq!(
            lines.push(b"defgh\nok\n"),
            [line("abcd", true), line("ok", false)]
        );
        assert!(lines.push(b"toolong").is_empty());
        assert_eq!(lines.finish(), Some(line("tool", true)));
    }

    #[test]
    fn control_characters_cannot_forge_or_hide_log_lines() {
        let mut lines = Lines::new(64);
        assert_eq!(
            lines.push(b"\x1b[31mred\x1b[0m\tnul\0 cr\r\n\xff\n"),
            [
                line("\u{FFFD}[31mred\u{FFFD}[0m\tnul\u{FFFD} cr", false),
                line("\u{FFFD}", false),
            ]
        );
    }
}
