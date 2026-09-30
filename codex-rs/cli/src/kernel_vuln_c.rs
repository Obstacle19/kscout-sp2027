//! Bounded C lexer and function extractor used by kernel CVE rules.

use anyhow::Result;

#[derive(Clone, Debug)]
pub(super) struct CToken {
    pub(super) text: String,
    line: usize,
    conditional_depth: u32,
}

#[derive(Clone, Debug)]
pub(super) struct FunctionBody {
    pub(super) line: usize,
    pub(super) conditional_depth: u32,
    pub(super) tokens: Vec<CToken>,
}

#[derive(Clone, Debug)]
pub(super) struct NamedFunctionBody {
    pub(super) name: String,
    pub(super) body: FunctionBody,
}

pub(super) fn lex_c(source: &str) -> Result<Vec<CToken>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1;
    let mut conditional_depth = 0_u32;
    let mut line_has_token = false;

    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' | b'\r' => index += 1,
            b'\n' => {
                index += 1;
                line += 1;
                line_has_token = false;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                let mut closed = false;
                while index < bytes.len() {
                    if bytes[index] == b'\n' {
                        line += 1;
                        line_has_token = false;
                    }
                    if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                        index += 2;
                        closed = true;
                        break;
                    }
                    index += 1;
                }
                anyhow::ensure!(closed, "unterminated C block comment");
            }
            b'"' | b'\'' => {
                let quote = bytes[index];
                line_has_token = true;
                index += 1;
                let mut closed = false;
                while index < bytes.len() {
                    match bytes[index] {
                        b'\\' if index + 1 < bytes.len() => {
                            if bytes[index + 1] == b'\n' {
                                line += 1;
                            }
                            index += 2;
                        }
                        byte if byte == quote => {
                            index += 1;
                            closed = true;
                            break;
                        }
                        b'\n' => {
                            line += 1;
                            index += 1;
                        }
                        _ => index += 1,
                    }
                }
                anyhow::ensure!(closed, "unterminated C string or character literal");
            }
            byte if is_identifier_start(byte) => {
                let start = index;
                index += 1;
                while index < bytes.len() && is_identifier_continue(bytes[index]) {
                    index += 1;
                }
                tokens.push(CToken {
                    text: String::from_utf8_lossy(&bytes[start..index]).into_owned(),
                    line,
                    conditional_depth,
                });
                line_has_token = true;
            }
            b'#' if !line_has_token => {
                let directive_line = line;
                let mut word_start = index + 1;
                while bytes.get(word_start).is_some_and(u8::is_ascii_whitespace)
                    && bytes[word_start] != b'\n'
                {
                    word_start += 1;
                }
                let mut word_end = word_start;
                while bytes.get(word_end).is_some_and(u8::is_ascii_alphabetic) {
                    word_end += 1;
                }
                let directive = String::from_utf8_lossy(&bytes[word_start..word_end]);
                match directive.as_ref() {
                    "if" | "ifdef" | "ifndef" => {
                        tokens.push(CToken {
                            text: format!("#{directive}"),
                            line: directive_line,
                            conditional_depth,
                        });
                        conditional_depth += 1;
                    }
                    "endif" => {
                        anyhow::ensure!(conditional_depth > 0, "unmatched #endif directive");
                        conditional_depth -= 1;
                        tokens.push(CToken {
                            text: "#endif".to_string(),
                            line: directive_line,
                            conditional_depth,
                        });
                    }
                    "else" | "elif" => tokens.push(CToken {
                        text: format!("#{directive}"),
                        line: directive_line,
                        conditional_depth,
                    }),
                    _ => {}
                }

                index = word_end;
                let mut escaped_newline = false;
                while index < bytes.len() {
                    if bytes[index] == b'\n' {
                        index += 1;
                        line += 1;
                        if escaped_newline {
                            escaped_newline = false;
                            continue;
                        }
                        line_has_token = false;
                        break;
                    }
                    escaped_newline = bytes[index] == b'\\';
                    index += 1;
                }
            }
            _ => {
                let start_line = line;
                let text = if let Some(operator) = two_character_operator(bytes, index) {
                    index += operator.len();
                    operator.to_string()
                } else {
                    let character = bytes[index] as char;
                    index += 1;
                    character.to_string()
                };
                tokens.push(CToken {
                    text,
                    line: start_line,
                    conditional_depth,
                });
                line_has_token = true;
            }
        }
    }

    anyhow::ensure!(
        conditional_depth == 0,
        "unterminated C preprocessor conditional"
    );

    Ok(tokens)
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn two_character_operator(bytes: &[u8], index: usize) -> Option<&'static str> {
    match bytes.get(index..index + 2)? {
        b"->" => Some("->"),
        b"+=" => Some("+="),
        b"-=" => Some("-="),
        b"==" => Some("=="),
        b"!=" => Some("!="),
        b">=" => Some(">="),
        b"<=" => Some("<="),
        b"&&" => Some("&&"),
        b"||" => Some("||"),
        b"++" => Some("++"),
        b"--" => Some("--"),
        _ => None,
    }
}

/// Extracts simple top-level C function definitions from a translation unit.
///
/// Function-like macros, definitions whose declarator is split by unusual
/// attributes, and preprocessor-dependent syntax are outside this bounded
/// parser. Callers must treat those cases as coverage limitations, never as
/// proof that a rule does not apply.
pub(super) fn extract_all_function_bodies(tokens: &[CToken]) -> Result<Vec<NamedFunctionBody>> {
    let mut functions = Vec::new();
    let mut index = 0;

    while index < tokens.len() {
        if tokens[index].text == "{" {
            let close = matching_delimiter(tokens, index, "{", "}")?;
            index = close + 1;
            continue;
        }

        if is_identifier(&tokens[index].text)
            && tokens.get(index + 1).is_some_and(|token| token.text == "(")
        {
            let close_parameters = matching_delimiter(tokens, index + 1, "(", ")")?;
            if tokens
                .get(close_parameters + 1)
                .is_some_and(|token| token.text == "{")
            {
                let open_body = close_parameters + 1;
                let close_body = matching_delimiter(tokens, open_body, "{", "}")?;
                functions.push(NamedFunctionBody {
                    name: tokens[index].text.clone(),
                    body: FunctionBody {
                        line: tokens[index].line,
                        conditional_depth: tokens[index].conditional_depth,
                        tokens: tokens[open_body + 1..close_body].to_vec(),
                    },
                });
                index = close_body + 1;
                continue;
            }
        }

        index += 1;
    }

    Ok(functions)
}

#[cfg(test)]
pub(super) fn extract_function_bodies(tokens: &[CToken], name: &str) -> Result<Vec<FunctionBody>> {
    Ok(extract_all_function_bodies(tokens)?
        .into_iter()
        .filter(|function| function.name == name)
        .map(|function| function.body)
        .collect())
}

fn is_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn matching_delimiter(tokens: &[CToken], open: usize, left: &str, right: &str) -> Result<usize> {
    anyhow::ensure!(
        tokens.get(open).is_some_and(|token| token.text == left),
        "expected {left}"
    );
    let mut depth = 0_u32;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        if token.text == left {
            depth += 1;
        } else if token.text == right {
            depth -= 1;
            if depth == 0 {
                return Ok(index);
            }
        }
    }
    anyhow::bail!("unmatched {left} delimiter")
}

#[path = "kernel_vuln_c_filters.rs"]
mod filters;
#[path = "kernel_vuln_c_rule_patterns.rs"]
mod rule_patterns;

pub(super) use self::filters::attribute_alloc_size_is_bounded;
pub(super) use self::filters::ea_name_length_is_bounded;
pub(super) use self::filters::perturb_period_conversion_is_bounded;
pub(super) use self::filters::perturb_period_tick_conversion_sites;
pub(super) use self::rule_patterns::cve_specific_filter_reason;
pub(super) use self::rule_patterns::cve_specific_rule_match;
