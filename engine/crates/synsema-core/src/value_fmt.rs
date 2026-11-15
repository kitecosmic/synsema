//! One output stream for a value's representation, with a bounded recursive prefix.
use std::fmt::{self, Display};

use crate::types::{ListRef, MapRef, Obj, ServerValue, SynValue};

const INLINE_DEPTH: usize = 32;

/// Logical row-major representation without creating a sub-view/string per axis.
/// The caller retains the existing summary for arrays with more than 100 elements.
pub(crate) fn array<T>(value: &ndarray::ArrayD<T>, elem: impl Fn(&T) -> String) -> String {
    if value.ndim() == 0 {
        return elem(value.first().expect("scalar array"));
    }
    let shape = value.shape();
    let mut values = value.iter();
    let mut frames = vec![(0usize, 0usize)];
    let mut output = String::from("[");
    while let Some(&(axis, index)) = frames.last() {
        if index == shape[axis] {
            output.push(']');
            frames.pop();
            continue;
        }
        if index != 0 {
            output.push_str(", ");
        }
        frames.last_mut().expect("current axis").1 += 1;
        if axis + 1 == shape.len() {
            output.push_str(&elem(values.next().expect("valid array shape")));
        } else {
            output.push('[');
            frames.push((axis + 1, 0));
        }
    }
    output
}

fn quoted(value: &str, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match serde_json::to_string(value) {
        Ok(value) => f.write_str(&value),
        Err(_) => write!(f, "{value:?}"),
    }
}

pub(crate) fn next(
    value: &SynValue,
    f: &mut fmt::Formatter<'_>,
    depth: usize,
    nested: bool,
) -> fmt::Result {
    if nested {
        if let SynValue::Text(value) = value {
            return quoted(value, f);
        }
    }
    if depth == INLINE_DEPTH
        && matches!(
            value,
            SynValue::List(_) | SynValue::Map(_) | SynValue::Server(_)
        )
    {
        return deep(value, f);
    }
    let depth = depth + 1;
    match value {
        SynValue::List(value) => list(value, f, depth),
        SynValue::Map(value) => map(value, f, depth),
        SynValue::Server(value) => match &**value {
            ServerValue::Envelope { status, value } => envelope(*status, value, f, depth),
            ServerValue::Node(value) => map(value, f, depth),
            ServerValue::Content(value) => next(value, f, depth, false),
            ServerValue::WithHeaders { inner, headers } => with_headers(inner, headers, f, depth),
            _ => value_as_leaf(value, f),
        },
        // Private/Secret are leaves here: their existing Display redacts them.
        _ => value.fmt(f),
    }
}

fn value_as_leaf(value: &Obj<ServerValue>, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    SynValue::Server(value.clone()).fmt(f)
}

pub(crate) fn list(value: &ListRef, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
    f.write_str("[")?;
    let value = value.borrow();
    if let Some(values) = value.as_values() {
        for (index, value) in values.iter().enumerate() {
            if index != 0 {
                f.write_str(", ")?;
            }
            next(value, f, depth, true)?;
        }
    } else {
        // Reading numbers by value does not box the whole list, even temporarily.
        for (index, value) in value.iter_owned().enumerate() {
            if index != 0 {
                f.write_str(", ")?;
            }
            next(&value, f, depth, true)?;
        }
    }
    f.write_str("]")
}

pub(crate) fn map(value: &MapRef, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
    f.write_str("{")?;
    for (index, (key, value)) in value.borrow().iter().enumerate() {
        if index != 0 {
            f.write_str(", ")?;
        }
        write!(f, "{key}: ")?;
        next(value, f, depth, true)?;
    }
    f.write_str("}")
}

pub(crate) fn envelope(
    status: i64,
    value: &SynValue,
    f: &mut fmt::Formatter<'_>,
    depth: usize,
) -> fmt::Result {
    write!(f, "{{status: {status}, value: ")?;
    next(value, f, depth, false)?;
    f.write_str("}")
}

fn headers(headers: &[(String, String)], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(", headers: {")?;
    for (index, (key, value)) in headers.iter().enumerate() {
        if index != 0 {
            f.write_str(", ")?;
        }
        write!(f, "{key}: {value}")?;
    }
    f.write_str("}}")
}

pub(crate) fn with_headers(
    value: &SynValue,
    values: &[(String, String)],
    f: &mut fmt::Formatter<'_>,
    depth: usize,
) -> fmt::Result {
    f.write_str("{value: ")?;
    next(value, f, depth, false)?;
    headers(values, f)
}

enum Frame {
    Value(SynValue, bool),
    List(ListRef, usize),
    Map(MapRef, usize),
    Close(&'static str),
    Headers(Obj<ServerValue>),
}

#[cold]
#[inline(never)]
fn deep(value: &SynValue, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut stack = vec![Frame::Value(value.clone(), false)];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Close(value) => f.write_str(value)?,
            Frame::Headers(server) => {
                let ServerValue::WithHeaders {
                    headers: values, ..
                } = &*server
                else {
                    unreachable!()
                };
                headers(values, f)?;
            }
            Frame::List(value, index) => {
                let next = value.borrow().get(index);
                if let Some(next) = next {
                    if index != 0 {
                        f.write_str(", ")?;
                    }
                    stack.push(Frame::List(value, index + 1));
                    stack.push(Frame::Value(next, true));
                } else {
                    f.write_str("]")?;
                }
            }
            Frame::Map(value, index) => {
                let next = value
                    .borrow()
                    .get_index(index)
                    .map(|(key, value)| (key.clone(), value.clone()));
                if let Some((key, next)) = next {
                    if index != 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{key}: ")?;
                    stack.push(Frame::Map(value, index + 1));
                    stack.push(Frame::Value(next, true));
                } else {
                    f.write_str("}")?;
                }
            }
            Frame::Value(value, nested) => match &value {
                SynValue::Text(value) if nested => quoted(value, f)?,
                SynValue::List(value) => {
                    f.write_str("[")?;
                    stack.push(Frame::List(value.clone(), 0));
                }
                SynValue::Map(value) => {
                    f.write_str("{")?;
                    stack.push(Frame::Map(value.clone(), 0));
                }
                SynValue::Server(server) => match &**server {
                    ServerValue::Envelope { status, value } => {
                        write!(f, "{{status: {status}, value: ")?;
                        stack.push(Frame::Close("}"));
                        stack.push(Frame::Value(value.clone(), false));
                    }
                    ServerValue::Node(value) => {
                        f.write_str("{")?;
                        stack.push(Frame::Map(value.clone(), 0));
                    }
                    ServerValue::Content(value) => {
                        stack.push(Frame::Value((**value).clone(), false))
                    }
                    ServerValue::WithHeaders { inner, .. } => {
                        f.write_str("{value: ")?;
                        stack.push(Frame::Headers(server.clone()));
                        stack.push(Frame::Value((**inner).clone(), false));
                    }
                    _ => value.fmt(f)?,
                },
                _ => value.fmt(f)?,
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{syn_int, syn_list, syn_map, syn_text, SynMap};

    fn nest(mut value: SynValue, n: usize, maps: bool) -> SynValue {
        for _ in 0..n {
            value = if maps {
                let mut map = SynMap::new();
                map.insert("x", value);
                syn_map(map)
            } else {
                syn_list(vec![value])
            };
        }
        value
    }

    #[test]
    fn nested_text_and_server_wrappers_keep_their_bytes() {
        let value = syn_list(vec![syn_text("a\n\"\\é"), syn_int(2)]);
        assert_eq!(value.to_string(), "[\"a\\n\\\"\\\\é\", 2]");
        let content = SynValue::Server(Obj::new(ServerValue::Content(Box::new(syn_text("raw")))));
        assert_eq!(syn_list(vec![content]).to_string(), "[raw]");
        let envelope = SynValue::Server(Obj::new(ServerValue::Envelope {
            status: 201,
            value: syn_text("raw"),
        }));
        let value = SynValue::Server(Obj::new(ServerValue::WithHeaders {
            inner: Box::new(envelope),
            headers: vec![
                ("Set-Cookie".into(), "x=1".into()),
                ("Set-Cookie".into(), "y=2".into()),
            ],
        }));
        assert_eq!(
            value.to_string(),
            "{value: {status: 201, value: raw}, headers: {Set-Cookie: x=1, Set-Cookie: y=2}}"
        );
    }

    #[test]
    fn a_million_levels_use_one_output_buffer() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                for maps in [false, true] {
                    for n in [0, 31, 32, 33, 1_000_000] {
                        let value = nest(syn_int(0), n, maps);
                        let output = value.to_string();
                        assert_eq!(output.len(), n * if maps { 5 } else { 2 } + 1);
                        assert_eq!(output.bytes().filter(|&c| c == b'0').count(), 1);
                    }
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn private_payload_is_a_redacted_leaf_even_in_the_fallback() {
        let value = crate::labels::mark(
            nest(syn_text("hidden payload"), 100_000, false),
            crate::labels::label_from(&["owner"]),
        );
        let redacted = value.to_string();
        let value = nest(value, 1000, false);
        let output = value.to_string();
        assert_eq!(output.len(), 2000 + redacted.len());
        assert!(!output.contains("hidden payload"));
    }

    #[test]
    fn a_failed_writer_releases_borrows_and_continuations() {
        use std::fmt::Write;
        struct Fails {
            left: usize,
            failed: bool,
        }
        impl fmt::Write for Fails {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                if !self.failed {
                    if s.len() > self.left {
                        self.failed = true;
                        return Err(fmt::Error);
                    }
                    self.left -= s.len();
                }
                Ok(())
            }
        }
        let value = nest(syn_int(0), 100_000, true);
        for left in [1024, 400_001] {
            assert!(write!(
                &mut Fails {
                    left,
                    failed: false
                },
                "{value}"
            )
            .is_err());
        }
        let SynValue::Map(map) = &value else {
            unreachable!()
        };
        assert_eq!(map.borrow_mut().len(), 1);
        assert_eq!(value.to_string().len(), 500_001);
    }

    #[test]
    fn array_rank_does_not_become_rust_stack_depth() {
        use ndarray::{ArrayD, IxDyn};
        let value = ArrayD::from_shape_vec(IxDyn(&vec![1; 50_000]), vec![1.0]).unwrap();
        let output = crate::types::array_display(&value);
        assert_eq!(output.len(), 100_001);
        let value = ArrayD::from_shape_vec(IxDyn(&[2, 3]), vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0])
            .unwrap()
            .reversed_axes();
        assert_eq!(
            crate::types::array_display(&value),
            "[[1, 4], [2, 5], [3, 6]]"
        );
        let empty = ArrayD::<f64>::from_shape_vec(IxDyn(&[2, 0, 100]), vec![]).unwrap();
        assert_eq!(crate::types::array_display(&empty), "[[], []]");
    }

    #[test]
    fn numeric_lists_keep_their_storage_and_float_representation() {
        let value =
            crate::types::syn_list_of(crate::synlist::SynList::from_floats(vec![1.0, -0.0, 2.5]));
        assert_eq!(value.to_string(), "[1.0, -0.0, 2.5]");
        let SynValue::List(list) = value else {
            unreachable!()
        };
        assert!(!list.borrow().is_values());
    }
}
