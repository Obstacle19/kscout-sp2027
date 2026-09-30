//! Exact, conservative C patterns used by the CVE-derived kernel rules.

use super::CToken;
use super::matching_delimiter;

/// Finds assignments whose `perturb_period` value is converted to timer ticks
/// with an unchecked `* HZ` operation. These are review candidates, not proof
/// that the input is attacker-controlled or that wraparound is exploitable.
pub fn perturb_period_tick_conversion_sites(tokens: &[CToken]) -> Vec<usize> {
    tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| {
            if token.text != "perturb_period" || !matches_at(tokens, index + 1, &["="]) {
                return None;
            }
            let statement_end = tokens[index + 2..]
                .iter()
                .position(|token| token.text == ";")
                .map(|offset| index + 2 + offset)?;
            tokens[index + 2..statement_end]
                .windows(2)
                .any(|window| window[0].text == "*" && window[1].text == "HZ")
                .then_some(index)
        })
        .collect()
}

/// Filters only the exact SFQ guard shape reviewed from CVE-2025-38193.
/// Unknown aliases, control flow, and equivalent-looking rewrites remain
/// candidates for semantic review.
pub fn perturb_period_conversion_is_bounded(tokens: &[CToken]) -> Option<&'static str> {
    let conversions = perturb_period_tick_conversion_sites(tokens);
    if conversions.is_empty() {
        return None;
    }

    let mut verified_guard_ends = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.text != "if"
            || !matches_at(tokens, index + 1, &["("])
            || !is_top_level(tokens, index)
            || !is_statement_boundary(tokens, index)
            || token.conditional_depth != 0
        {
            continue;
        }

        let Ok(condition_end) = matching_delimiter(tokens, index + 1, "(", ")") else {
            continue;
        };
        let condition = &tokens[index + 2..condition_end];
        let expected_condition = [
            "ctl",
            "->",
            "perturb_period",
            "<",
            "0",
            "||",
            "ctl",
            "->",
            "perturb_period",
            ">",
            "INT_MAX",
            "/",
            "HZ",
        ];
        if !condition
            .iter()
            .map(|token| token.text.as_str())
            .eq(expected_condition.iter().copied())
        {
            continue;
        }

        let body_open = condition_end + 1;
        if !matches_at(tokens, body_open, &["{"]) {
            continue;
        }
        let Ok(body_end) = matching_delimiter(tokens, body_open, "{", "}") else {
            continue;
        };
        let body = &tokens[body_open + 1..body_end];
        if !has_sequence(body, &["return", "-", "EINVAL", ";"])
            || ["if", "else", "switch", "case", "goto"]
                .iter()
                .any(|keyword| has_sequence(body, &[*keyword]))
            || tokens
                .get(body_end + 1)
                .is_some_and(|token| token.text == "else")
        {
            continue;
        }
        verified_guard_ends.push(body_end);
    }

    let every_conversion_guarded = conversions.iter().all(|conversion| {
        verified_guard_ends.iter().any(|guard_end| {
            *guard_end + 1 == *conversion
                && matches_at(
                    tokens,
                    *conversion,
                    &[
                        "perturb_period",
                        "=",
                        "ctl",
                        "->",
                        "perturb_period",
                        "*",
                        "HZ",
                    ],
                )
                && is_top_level(tokens, *conversion)
                && tokens[*conversion].conditional_depth == 0
                && !has_sequence(&tokens[..=*conversion], &["goto"])
        })
    });

    every_conversion_guarded.then_some(
        "The exact top-level negative and INT_MAX/HZ checks return -EINVAL before every perturb_period-to-HZ conversion.",
    )
}

fn is_top_level(tokens: &[CToken], position: usize) -> bool {
    let mut depth = 0_i32;
    for token in &tokens[..position] {
        match token.text.as_str() {
            "{" => depth += 1,
            "}" => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

fn is_statement_boundary(tokens: &[CToken], position: usize) -> bool {
    position == 0
        || tokens
            .get(position.wrapping_sub(1))
            .is_some_and(|token| matches!(token.text.as_str(), ";" | "}"))
}

fn matches_sequence(tokens: &[CToken], sequence: &[&str]) -> bool {
    tokens.windows(sequence.len()).any(|window| {
        window
            .iter()
            .map(|token| token.text.as_str())
            .eq(sequence.iter().copied())
    })
}

fn has_sequence(tokens: &[CToken], sequence: &[&str]) -> bool {
    matches_sequence(tokens, sequence)
}

pub fn ea_name_length_is_bounded(tokens: &[CToken]) -> Option<&'static str> {
    let conditions = [
        (
            &["if", "(", "ea", "->", "name_len", ">", "ea_size", ")"][..],
            false,
        ),
        (&["if", "(", "name_len", ">", "ea_size", ")"][..], true),
    ];
    for (condition, uses_local_name_len) in conditions {
        for index in matching_sequence_positions(tokens, condition) {
            if tokens[index].conditional_depth != 0 {
                continue;
            }
            let alias_binding_end = if uses_local_name_len {
                let Some(binding_end) = ea_name_len_alias_binding_end(tokens, index) else {
                    continue;
                };
                Some(binding_end)
            } else {
                None
            };
            let open = index + condition.len();
            let braced_guard_body = [
                "{",
                "ntfs_set_state",
                "(",
                "ni",
                "->",
                "mi",
                ".",
                "sbi",
                ",",
                "NTFS_DIRTY_ERROR",
                ")",
                ";",
                "err",
                "=",
                "-",
                "EINVAL",
                ";",
                "break",
                ";",
                "}",
            ];
            let guard_end = if matches_at(tokens, open, &["break", ";"]) {
                open + 2
            } else if matches_at(tokens, open, &["{", "break", ";", "}"]) {
                open + 4
            } else if matches_at(tokens, open, &braced_guard_body) {
                open + braced_guard_body.len()
            } else {
                continue;
            };

            let Some((loop_open, loop_close)) = enclosing_braced_loop(tokens, index) else {
                continue;
            };
            if !is_direct_child_statement(tokens, loop_open + 1, index) {
                continue;
            }
            let loop_body = &tokens[loop_open + 1..loop_close];
            if contains_goto(&tokens[loop_open + 1..index]) || contains_label(loop_body) {
                continue;
            }
            let ea_size_decodes = [
                &[
                    "int",
                    "ea_size",
                    "=",
                    "unpacked_ea_size",
                    "(",
                    "ea",
                    ")",
                    ";",
                ][..],
                &["ea_size", "=", "unpacked_ea_size", "(", "ea", ")", ";"][..],
            ];
            let ea_size_decode = ea_size_decodes
                .iter()
                .flat_map(|sequence| {
                    matching_sequence_positions(&tokens[..index], sequence)
                        .map(move |start| (start, sequence.len()))
                })
                .filter(|(start, length)| {
                    is_direct_child_statement(tokens, loop_open + 1, *start)
                        && !writes_identifier(&tokens[start + length..index], "ea_size")
                })
                .max_by_key(|(start, _)| *start);
            let Some((ea_size_decode_start, ea_size_decode_len)) = ea_size_decode else {
                continue;
            };
            let ea_size_decode_end = ea_size_decode_start + ea_size_decode_len;
            if writes_identifier(&tokens[ea_size_decode_end..loop_close], "ea_size")
                || writes_identifier(&tokens[ea_size_decode_end..loop_close], "ea")
            {
                continue;
            }
            if alias_binding_end.is_some_and(|binding_end| {
                writes_identifier(&tokens[binding_end..loop_close], "name_len")
            }) {
                continue;
            }
            let sinks = [
                &[
                    "memcpy", "(", "buffer", "+", "ret", ",", "ea", "->", "name", ",", "name_len",
                    ")",
                ][..],
                &[
                    "memcpy", "(", "buffer", "+", "ret", ",", "ea", "->", "name", ",", "ea", "->",
                    "name_len", ")",
                ][..],
            ];
            let size_updates = [
                &["ret", "+=", "name_len", "+", "1", ";"][..],
                &["ret", "+=", "ea", "->", "name_len", "+", "1", ";"][..],
            ];
            let has_no_prior_sink = sinks.iter().all(|sink| {
                matching_sequence_positions(&tokens[..index], sink)
                    .next()
                    .is_none()
            });
            let has_no_prior_size_update = size_updates.iter().all(|update| {
                matching_sequence_positions(&tokens[..index], update)
                    .next()
                    .is_none()
            });
            let has_later_sink = sinks.iter().any(|sink| {
                matching_sequence_positions(&tokens[guard_end..loop_close], sink)
                    .next()
                    .is_some()
            });
            let has_later_size_update = size_updates.iter().any(|update| {
                matching_sequence_positions(&tokens[guard_end..loop_close], update)
                    .next()
                    .is_some()
            });
            if has_no_prior_sink
                && has_no_prior_size_update
                && has_later_sink
                && has_later_size_update
            {
                return Some(
                    "Exact EA name-length guard exits the enclosing iteration before the name copy and output-size update.",
                );
            }
        }
    }
    None
}

fn ea_name_len_alias_binding_end(tokens: &[CToken], position: usize) -> Option<usize> {
    let binding = ["u8", "name_len", "=", "ea", "->", "name_len", ";"];
    matching_sequence_positions(&tokens[..position], &binding)
        .filter_map(|binding_start| {
            let binding_end = binding_start + binding.len();
            (!writes_identifier(&tokens[binding_end..position], "name_len")).then_some(binding_end)
        })
        .last()
}

fn writes_identifier(tokens: &[CToken], name: &str) -> bool {
    tokens.windows(2).any(|window| {
        window[0].text == name
            && matches!(
                window[1].text.as_str(),
                "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "++" | "--"
            )
    }) || tokens.windows(3).any(|window| {
        window[0].text == name
            && matches!(
                window[1].text.as_str(),
                "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "<" | ">"
            )
            && window[2].text == "="
    }) || tokens.windows(4).any(|window| {
        window[0].text == name
            && matches!(window[1].text.as_str(), "<" | ">")
            && window[1].text == window[2].text
            && window[3].text == "="
    }) || tokens
        .windows(2)
        .any(|window| matches!(window[0].text.as_str(), "++" | "--") && window[1].text == name)
        || tokens
            .windows(2)
            .any(|window| window[0].text == "&" && window[1].text == name)
}

fn contains_goto(tokens: &[CToken]) -> bool {
    matching_sequence_positions(tokens, &["goto"])
        .next()
        .is_some()
}

fn contains_label(tokens: &[CToken]) -> bool {
    tokens.windows(2).any(|window| window[1].text == ":")
}

fn enclosing_braced_loop(tokens: &[CToken], position: usize) -> Option<(usize, usize)> {
    let mut loops = Vec::new();
    for (index, token) in tokens.iter().enumerate().take(position) {
        if !matches!(token.text.as_str(), "for" | "while")
            || tokens.get(index + 1).is_none_or(|token| token.text != "(")
        {
            continue;
        }
        let Ok(close_parameters) = matching_delimiter(tokens, index + 1, "(", ")") else {
            continue;
        };
        let open_body = close_parameters + 1;
        if tokens.get(open_body).is_none_or(|token| token.text != "{") {
            continue;
        }
        let Ok(close_body) = matching_delimiter(tokens, open_body, "{", "}") else {
            continue;
        };
        if open_body < position && position < close_body {
            loops.push((open_body, close_body));
        }
    }

    loops.into_iter().min_by_key(|(open, close)| close - open)
}

/// True only when `position` begins a statement directly in a braced block.
/// This prevents a nested guard such as `if (x) if (len > bound) break;` from
/// suppressing the candidate when the outer condition is false.
fn is_direct_child_statement(tokens: &[CToken], block_start: usize, position: usize) -> bool {
    let mut cursor = block_start;
    while cursor < position {
        let Some(next) = statement_end(tokens, cursor) else {
            return false;
        };
        if next <= cursor || next > position {
            return false;
        }
        cursor = next;
    }
    cursor == position
}

/// Returns the first token after a bounded C statement shape. Unsupported or
/// malformed shapes return None, which keeps the rule hit for semantic review.
fn statement_end(tokens: &[CToken], start: usize) -> Option<usize> {
    let first = tokens.get(start)?.text.as_str();
    if first == "{" {
        return matching_delimiter(tokens, start, "{", "}")
            .ok()
            .map(|close| close + 1);
    }

    if matches!(first, "if" | "for" | "while" | "switch") {
        if tokens.get(start + 1)?.text != "(" {
            return None;
        }
        let condition_end = matching_delimiter(tokens, start + 1, "(", ")").ok()?;
        let mut next = statement_end(tokens, condition_end + 1)?;
        if first == "if" && tokens.get(next).is_some_and(|token| token.text == "else") {
            next = statement_end(tokens, next + 1)?;
        }
        return Some(next);
    }

    if first == "do" {
        let body_end = statement_end(tokens, start + 1)?;
        if tokens.get(body_end)?.text != "while" || tokens.get(body_end + 1)?.text != "(" {
            return None;
        }
        let condition_end = matching_delimiter(tokens, body_end + 1, "(", ")").ok()?;
        return (tokens.get(condition_end + 1)?.text == ";").then_some(condition_end + 2);
    }

    let mut paren_depth = 0_u32;
    let mut bracket_depth = 0_u32;
    let mut brace_depth = 0_u32;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token.text.as_str() {
            "(" => paren_depth += 1,
            ")" => paren_depth = paren_depth.checked_sub(1)?,
            "[" => bracket_depth += 1,
            "]" => bracket_depth = bracket_depth.checked_sub(1)?,
            "{" => brace_depth += 1,
            "}" => brace_depth = brace_depth.checked_sub(1)?,
            ";" if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                return Some(index + 1);
            }
            _ => {}
        }
    }
    None
}

pub fn attribute_alloc_size_is_bounded(tokens: &[CToken]) -> Option<&'static str> {
    let condition = [
        "if",
        "(",
        "alloc_size",
        ">",
        "mi",
        "->",
        "sbi",
        "->",
        "volume",
        ".",
        "size",
        ")",
    ];
    let alloc_size_decode = [
        "alloc_size",
        "=",
        "le64_to_cpu",
        "(",
        "attr",
        "->",
        "nres",
        ".",
        "alloc_size",
        ")",
        ";",
    ];
    let return_attr = ["return", "attr", ";"];
    for index in matching_sequence_positions(tokens, &condition) {
        if tokens[index].conditional_depth != 0 {
            continue;
        }
        if !is_direct_child_statement(tokens, 0, index) {
            continue;
        }
        if matching_sequence_positions(&tokens[..index], &["goto"])
            .next()
            .is_some()
        {
            continue;
        }
        if matching_sequence_positions(&tokens[..index], &["return"])
            .next()
            .is_some()
        {
            continue;
        }
        let Some(decode_start) =
            matching_sequence_positions(&tokens[..index], &alloc_size_decode).last()
        else {
            continue;
        };
        let decode_end = decode_start + alloc_size_decode.len();
        if !is_direct_child_statement(tokens, 0, decode_start)
            || writes_identifier(&tokens[decode_end..index], "alloc_size")
            || writes_identifier(&tokens[decode_end..index], "attr")
        {
            continue;
        }
        let statement = index + condition.len();
        let direct_return = ["return", "NULL", ";"];
        if matches_at(tokens, statement, &direct_return)
            && let Some(return_index) = matching_sequence_positions(
                &tokens[statement + direct_return.len()..],
                &return_attr,
            )
            .next()
        {
            let return_start = statement + direct_return.len() + return_index;
            if !writes_identifier(
                &tokens[statement + direct_return.len()..return_start],
                "alloc_size",
            ) && !writes_identifier(
                &tokens[statement + direct_return.len()..return_start],
                "attr",
            ) {
                return Some(
                    "Exact alloc_size-to-volume bound returns NULL before the parsed attribute can be accepted.",
                );
            }
        }

        let goto_out = ["goto", "out", ";"];
        if matches_at(tokens, statement, &goto_out) {
            let after_goto = statement + goto_out.len();
            let has_null_exit = matching_sequence_positions(&tokens[after_goto..], &["out", ":"])
                .any(|label| out_label_returns_null(&tokens[after_goto + label + 2..]));
            if has_null_exit
                && let Some(return_index) =
                    matching_sequence_positions(&tokens[after_goto..], &return_attr).next()
            {
                let return_start = after_goto + return_index;
                if !writes_identifier(&tokens[after_goto..return_start], "alloc_size")
                    && !writes_identifier(&tokens[after_goto..return_start], "attr")
                {
                    return Some(
                        "Exact alloc_size-to-volume bound jumps to the function's NULL exit before the parsed attribute can be accepted.",
                    );
                }
            }
        }
    }
    None
}

fn out_label_returns_null(tokens: &[CToken]) -> bool {
    let Some(return_index) = tokens.iter().position(|token| token.text == "return") else {
        return false;
    };
    let direct_null_return = ["return", "NULL", ";"];
    matches_at(tokens, return_index, &direct_null_return)
        && !tokens[..return_index].iter().any(|token| {
            matches!(
                token.text.as_str(),
                "if" | "switch" | "for" | "while" | "goto"
            )
        })
}

fn matching_sequence_positions<'a>(
    tokens: &'a [CToken],
    sequence: &'a [&'a str],
) -> impl Iterator<Item = usize> + 'a {
    tokens
        .windows(sequence.len())
        .enumerate()
        .filter_map(move |(index, window)| {
            window
                .iter()
                .map(|token| token.text.as_str())
                .eq(sequence.iter().copied())
                .then_some(index)
        })
}

fn matches_at(tokens: &[CToken], start: usize, sequence: &[&str]) -> bool {
    tokens
        .get(start..start.saturating_add(sequence.len()))
        .is_some_and(|window| {
            window
                .iter()
                .map(|token| token.text.as_str())
                .eq(sequence.iter().copied())
        })
}
