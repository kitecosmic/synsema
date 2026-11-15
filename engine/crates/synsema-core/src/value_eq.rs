//! Heap continuation for deep equality. Shallow comparisons allocate nothing.
//! Each container frame retains only the next index, not a copy of its children.

use crate::synlist::list_read;
use crate::types::{ListRef, MapRef, ServerValue, SynValue};

pub(crate) const INLINE_DEPTH: usize = 32;

enum Frame {
    Pair(SynValue, SynValue, bool),
    List(ListRef, ListRef, usize, bool),
    Map(MapRef, MapRef, usize, bool),
}

/// `strict` applies the language's pending decimal/float conflict only to lists
/// and maps. Server values retain their existing, non-strict structural equality.
#[cold]
#[inline(never)]
pub(crate) fn deep(a: &SynValue, b: &SynValue, strict: bool, clash: &mut bool) -> bool {
    let mut stack = vec![Frame::Pair(a.clone(), b.clone(), strict)];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::List(a, b, index, strict) => {
                let pair = {
                    let (a, b) = (list_read(&a), list_read(&b));
                    if index == a.len() {
                        continue;
                    }
                    (a[index].clone(), b[index].clone())
                };
                stack.push(Frame::List(a, b, index + 1, strict));
                stack.push(Frame::Pair(pair.0, pair.1, strict));
            }
            Frame::Map(a, b, index, strict) => {
                let pair = {
                    let (a, b) = (a.borrow(), b.borrow());
                    let Some((key, value)) = a.get_index(index) else {
                        continue;
                    };
                    let Some(other) = b.get(key.as_str()) else {
                        return false;
                    };
                    (value.clone(), other.clone())
                };
                stack.push(Frame::Map(a, b, index + 1, strict));
                stack.push(Frame::Pair(pair.0, pair.1, strict));
            }
            Frame::Pair(a, b, strict) => {
                let (a, b) = (crate::labels::unwrap(&a), crate::labels::unwrap(&b));
                match (a, b) {
                    (SynValue::List(a), SynValue::List(b)) => {
                        if list_read(a).len() != list_read(b).len() {
                            return false;
                        }
                        stack.push(Frame::List(a.clone(), b.clone(), 0, strict));
                    }
                    (SynValue::Map(a), SynValue::Map(b)) => {
                        if a.borrow().len() != b.borrow().len() {
                            return false;
                        }
                        stack.push(Frame::Map(a.clone(), b.clone(), 0, strict));
                    }
                    (SynValue::Server(a), SynValue::Server(b)) => match (&**a, &**b) {
                        (
                            ServerValue::Envelope {
                                status: sa,
                                value: va,
                            },
                            ServerValue::Envelope {
                                status: sb,
                                value: vb,
                            },
                        ) => {
                            if sa != sb {
                                return false;
                            }
                            stack.push(Frame::Pair(va.clone(), vb.clone(), false));
                        }
                        (ServerValue::Node(a), ServerValue::Node(b)) => {
                            if a.borrow().len() != b.borrow().len() {
                                return false;
                            }
                            stack.push(Frame::Map(a.clone(), b.clone(), 0, false));
                        }
                        (ServerValue::Content(a), ServerValue::Content(b)) => {
                            stack.push(Frame::Pair((**a).clone(), (**b).clone(), false));
                        }
                        (
                            ServerValue::WithHeaders {
                                inner: a,
                                headers: ha,
                            },
                            ServerValue::WithHeaders {
                                inner: b,
                                headers: hb,
                            },
                        ) => {
                            if ha != hb {
                                return false;
                            }
                            stack.push(Frame::Pair((**a).clone(), (**b).clone(), false));
                        }
                        // These variants have no SynValue descendants. In particular,
                        // Paged compares the callback's identity without fetching rows.
                        _ => {
                            if !SynValue::Server(a.clone()).syn_equals(&SynValue::Server(b.clone()))
                            {
                                return false;
                            }
                        }
                    },
                    _ if strict && crate::tabular::dec_float_clash(a, b) => *clash = true,
                    _ => {
                        if !a.syn_equals(b) {
                            return false;
                        }
                    }
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{syn_float, syn_int, syn_list, syn_map, Obj, SynMap};

    fn nested(mut value: SynValue, depth: usize, maps: bool) -> SynValue {
        for _ in 0..depth {
            value = if maps {
                let mut m = SynMap::new();
                m.insert("child", value);
                syn_map(m)
            } else {
                syn_list(vec![value])
            };
        }
        value
    }

    #[test]
    fn deep_lists_maps_and_private_preserve_equality() {
        for maps in [false, true] {
            for depth in [0, 31, 32, 33, 1000, 50000] {
                let a = nested(syn_int(1), depth, maps);
                let b = nested(syn_int(1), depth, maps);
                let c = nested(syn_int(2), depth, maps);
                assert!(a.syn_equals(&b));
                assert!(!a.syn_equals(&c));
                assert_eq!(crate::tabular::strict_equals(&a, &b), Ok(true));
                assert_eq!(crate::tabular::strict_equals(&a, &c), Ok(false));
                let private = crate::labels::mark(b, crate::labels::label_from(&["owner"]));
                assert!(a.syn_equals(&private));
            }
        }
    }

    #[test]
    fn million_levels_on_the_smallest_interpreter_stack() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let a = nested(syn_int(1), 1_000_000, false);
                let b = nested(syn_int(1), 1_000_000, false);
                let equal = a.syn_equals(&b);
                let strict = crate::tabular::strict_equals(&a, &b);
                drop((a, b));
                assert!(equal);
                assert_eq!(strict, Ok(true));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn deep_shared_nan_is_not_equal_to_itself() {
        let a = nested(syn_float(f64::NAN), 1000, false);
        assert!(!a.syn_equals(&a));
        assert_eq!(crate::tabular::strict_equals(&a, &a), Ok(false));
    }

    #[test]
    fn deep_strict_conflict_stays_pending_until_a_real_difference() {
        let decimal = SynValue::Number(crate::number::Number::Decimal(rust_decimal::Decimal::ONE));
        let a = nested(decimal, 1000, false);
        let b = nested(syn_float(1.0), 1000, false);
        assert_eq!(crate::tabular::strict_equals(&a, &b), Err(()));
        for reverse in [false, true] {
            let (a, b) = if reverse {
                (b.clone(), a.clone())
            } else {
                (a.clone(), b.clone())
            };
            let mut ma = SynMap::new();
            ma.insert("conflict", a);
            ma.insert("different", syn_int(1));
            let mut mb = SynMap::new();
            mb.insert("different", syn_int(2));
            mb.insert("conflict", b);
            assert_eq!(
                crate::tabular::strict_equals(
                    &nested(syn_map(ma), 40, false),
                    &nested(syn_map(mb), 40, false)
                ),
                Ok(false)
            );
        }
    }

    #[test]
    fn server_wrappers_continue_on_heap_without_changing_their_rules() {
        fn wrap(mut value: SynValue) -> SynValue {
            for _ in 0..1000 {
                value = SynValue::Server(Obj::new(ServerValue::Content(Box::new(value))));
            }
            value
        }
        let a = wrap(nested(syn_int(1), 1000, false));
        let b = wrap(nested(syn_int(1), 1000, false));
        assert!(a.syn_equals(&b));
        assert_eq!(crate::tabular::strict_equals(&a, &b), Ok(true));
    }
}
