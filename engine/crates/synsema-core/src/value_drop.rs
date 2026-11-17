//! Release compound values without using one Rust stack frame per data level.
//! No TLS or allocator changes: detach only the last owner's children. Flat
//! numeric lists keep their normal Vec destructor; continuation storage is inline.

use crate::types::{ListRef, MapRef, Obj, ServerValue, SynValue};
use smallvec::SmallVec;
use std::mem::ManuallyDrop;

// map_slot intentionally leaves these inline payloads alone in ManuallyDrop.
const _: () = assert!(!std::mem::needs_drop::<rust_decimal::Decimal>());
const _: () = assert!(!std::mem::needs_drop::<num_complex::Complex64>());

#[inline]
pub(crate) fn compound(value: &SynValue) -> bool {
    matches!(
        value,
        SynValue::List(_) | SynValue::Map(_) | SynValue::Private(_) | SynValue::Server(_)
    )
}

#[inline]
pub(crate) fn slot(value: &mut SynValue) {
    if compound(value) {
        drain(Frame::Value(std::mem::replace(value, SynValue::Nothing)));
    }
}

// One dispatch per value, like the compiler's drop glue. Maps/server values
// start their own continuation when needed; do not put flat records in frames.
#[inline]
pub(crate) fn list_value(value: SynValue) {
    match value {
        v @ (SynValue::List(_) | SynValue::Private(_)) => drain(Frame::Value(v)),
        SynValue::Map(v) => drop(v),
        SynValue::Server(v) => drop(v),
        SynValue::Number(v) => drop(v),
        SynValue::Text(v) => drop(v),
        SynValue::Task(v) => drop(v),
        SynValue::Builtin(v) => drop(v),
        SynValue::Secret(v) => drop(v),
        SynValue::Bytes(v) => drop(v),
        SynValue::Array(v) => drop(v),
        // La tabla suelta sus columnas `Value` por el destructor seguro de `ColumnData`
        // (`columns.rs`: `map_slots` iterativo por celda); los bloques primitivos no tienen
        // hijos. La tabla entera NUNCA necesita frame propio.
        SynValue::Table(v) => drop(v),
        SynValue::Time(v) => drop(v),
        SynValue::Bool(_) | SynValue::Nothing | SynValue::Complex(_) => {}
    }
}

#[inline(always)]
pub(crate) fn list_values(values: Vec<SynValue>) {
    // Vec's in-place collect reuses the allocation for this transparent wrapper.
    // Avoid moving inline text/scalars and avoid a second automatic drop pass.
    let mut values: Vec<ManuallyDrop<SynValue>> =
        values.into_iter().map(ManuallyDrop::new).collect();
    release_slots(&mut values);
}

trait ReleaseSlot {
    fn release(&mut self);
}

impl ReleaseSlot for SynValue {
    #[inline(always)]
    fn release(&mut self) {
        map_slot(self);
    }
}

impl ReleaseSlot for ManuallyDrop<SynValue> {
    #[inline(always)]
    fn release(&mut self) {
        list_slot(self);
    }
}

// Release is idempotent: completed resources are Nothing, trivial values own
// nothing. On unwind rescan the whole slice, avoiding a progress store per slot
// on the successful path. The guard owns only a borrow, so forget leaks nothing.
struct ReleaseSlots<'a, T: ReleaseSlot> {
    values: &'a mut [T],
}

impl<T: ReleaseSlot> ReleaseSlots<'_, T> {
    #[inline(always)]
    fn run(&mut self) {
        for value in self.values.iter_mut() {
            value.release();
        }
    }
}

impl<T: ReleaseSlot> Drop for ReleaseSlots<'_, T> {
    #[inline(always)]
    fn drop(&mut self) {
        self.run();
    }
}

#[inline(always)]
fn release_slots<T: ReleaseSlot>(values: &mut [T]) {
    let mut guard = ReleaseSlots { values };
    guard.run();
    std::mem::forget(guard);
}

#[inline(always)]
pub(crate) fn map_slots(values: &mut [SynValue]) {
    release_slots(values);
}

#[inline(always)]
fn list_slot(value: &mut SynValue) {
    use crate::number::Number;
    match value {
        SynValue::Number(Number::Int(_) | Number::Float(_) | Number::Decimal(_))
        | SynValue::Bool(_)
        | SynValue::Nothing
        | SynValue::Complex(_) => {}
        SynValue::Text(text) if text.is_inline() => {}
        SynValue::Map(_) | SynValue::Server(_) => {
            // These two payloads have their own safe compound-value destructor.
            // The known variants let LLVM move just their pointer, not the enum.
            match std::mem::replace(value, SynValue::Nothing) {
                SynValue::Map(value) => drop(value),
                SynValue::Server(value) => drop(value),
                _ => unreachable!(),
            }
        }
        _ => list_resource_slot(value),
    }
}

#[cold]
#[inline(never)]
fn list_resource_slot(value: &mut SynValue) {
    list_value(std::mem::replace(value, SynValue::Nothing));
}

#[inline(always)]
pub(crate) fn map_slot(value: &mut SynValue) {
    use crate::number::Number;
    // These representations own no resources. Leave their valid bits in the
    // ManuallyDrop tail instead of copying and clearing a whole SynValue.
    match value {
        SynValue::Number(Number::Int(_) | Number::Float(_) | Number::Decimal(_))
        | SynValue::Bool(_)
        | SynValue::Nothing
        | SynValue::Complex(_) => {}
        SynValue::Text(text) if text.is_inline() => {}
        _ => map_resource_slot(value),
    }
}

#[cold]
#[inline(never)]
fn map_resource_slot(value: &mut SynValue) {
    let value = std::mem::replace(value, SynValue::Nothing);
    match value {
        v @ (SynValue::Map(_) | SynValue::Server(_)) => drain(Frame::Value(v)),
        other => list_value(other),
    }
}

enum Frame {
    Value(SynValue),
    Values(std::vec::IntoIter<SynValue>),
    Map(MapRef, usize),
    Node(ServerValue, usize),
}

/// Take the next compound child, leaving scalar destruction to the normal drop.
fn next_child(map: &MapRef, index: &mut usize) -> Option<SynValue> {
    let mut map = map.borrow_mut();
    while *index < map.len() {
        let value = map.get_index_mut(*index).expect("existing map slot").1;
        *index += 1;
        if compound(value) {
            return Some(std::mem::replace(value, SynValue::Nothing));
        }
    }
    None
}

#[cold]
#[inline(never)]
fn drain(first: Frame) {
    let mut stack: SmallVec<[Frame; 32]> = SmallVec::new();
    stack.push(first);
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Values(mut values) => {
                if let Some(value) = values.next() {
                    if values.len() != 0 {
                        stack.push(Frame::Values(values));
                    }
                    stack.push(Frame::Value(value));
                }
            }
            Frame::Map(map, mut index) => {
                if let Some(value) = next_child(&map, &mut index) {
                    stack.push(Frame::Map(map, index));
                    stack.push(Frame::Value(value));
                }
            }
            Frame::Node(node, mut index) => {
                let ServerValue::Node(map) = &node else {
                    unreachable!()
                };
                if let Some(value) = next_child(map, &mut index) {
                    stack.push(Frame::Node(node, index));
                    stack.push(Frame::Value(value));
                }
            }
            Frame::Value(value) => match value {
                SynValue::List(list) => {
                    if !list.borrow().is_values() {
                        continue;
                    }
                    if let Ok(list) = ListRef::try_unwrap(list) {
                        stack.push(Frame::Values(list.into_vec().into_iter()));
                    }
                }
                SynValue::Map(map) => {
                    if MapRef::strong_count(&map) == 1 {
                        stack.push(Frame::Map(map, 0));
                    }
                }
                SynValue::Private(private) => {
                    if let Ok(private) = Obj::try_unwrap(private) {
                        stack.push(Frame::Value(private.value));
                    }
                }
                SynValue::Server(server) => {
                    if let Ok(mut server) = Obj::try_unwrap(server) {
                        match &mut server {
                            ServerValue::Envelope { value, .. } => {
                                stack.push(Frame::Value(std::mem::replace(
                                    value,
                                    SynValue::Nothing,
                                )));
                            }
                            ServerValue::Content(value)
                            | ServerValue::WithHeaders { inner: value, .. } => {
                                stack.push(Frame::Value(std::mem::replace(
                                    &mut **value,
                                    SynValue::Nothing,
                                )));
                            }
                            ServerValue::Node(map) if MapRef::strong_count(map) == 1 => {
                                stack.push(Frame::Node(server, 0));
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{syn_int, syn_list, syn_map, SynMap};

    #[test]
    fn million_lists_are_released_on_a_64_mib_stack() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let mut value = syn_list(vec![syn_int(0)]);
                let SynValue::List(leaf) = &value else {
                    unreachable!()
                };
                let weak = ListRef::downgrade(leaf);
                for _ in 0..1_000_000 {
                    value = syn_list(vec![value]);
                }
                drop(value);
                assert!(
                    weak.upgrade().is_none(),
                    "the deepest list must be released"
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn million_maps_are_released_on_a_64_mib_stack() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let mut value = syn_list(vec![syn_int(0)]);
                let SynValue::List(leaf) = &value else {
                    unreachable!()
                };
                let weak = ListRef::downgrade(leaf);
                for _ in 0..1_000_000 {
                    let mut map = SynMap::new();
                    map.insert("child", value);
                    value = syn_map(map);
                }
                drop(value);
                assert!(
                    weak.upgrade().is_none(),
                    "the deepest map child must be released"
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // A regressed destructor may abort instead of unwinding. Keep that failure
    // inside a child so mutation runs report an ordinary failed test assertion.
    #[test]
    fn deep_drop_children_exit_successfully() {
        for test in [
            "million_lists_are_released_on_a_64_mib_stack",
            "million_maps_are_released_on_a_64_mib_stack",
            "million_server_wrappers_are_released_on_a_64_mib_stack",
        ] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", &format!("value_drop::tests::{test}")]);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{test} aborted: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn million_server_wrappers_are_released_on_a_64_mib_stack() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let mut value = syn_int(0);
                for _ in 0..1_000_000 {
                    value = SynValue::Server(Obj::new(ServerValue::Content(Box::new(value))));
                }
                drop(value);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn deep_mixed_maps_nodes_headers_and_private_are_released() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let mut value = syn_int(0);
                for i in 0..200_000 {
                    value = match i % 5 {
                        0 => syn_list(vec![value]),
                        1 => crate::labels::mark(value, crate::labels::label_from(&["owner"])),
                        2 => SynValue::Server(Obj::new(ServerValue::Content(Box::new(value)))),
                        3 => SynValue::Server(Obj::new(ServerValue::WithHeaders {
                            inner: Box::new(value),
                            headers: vec![("x-test".into(), "1".into())],
                        })),
                        _ => {
                            let mut map = SynMap::new();
                            map.insert("child", value);
                            let SynValue::Map(map) = syn_map(map) else {
                                unreachable!()
                            };
                            SynValue::Server(Obj::new(ServerValue::Node(map)))
                        }
                    };
                }
                drop(value);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn dropping_a_parent_does_not_change_shared_children() {
        let mut child = syn_int(1);
        for _ in 0..100_000 {
            child = syn_list(vec![child]);
        }
        let alias = child.clone();
        drop(syn_list(vec![child]));
        let SynValue::List(list) = &alias else {
            unreachable!()
        };
        assert_eq!(list.borrow().len(), 1);
        drop(alias);

        let mut map = SynMap::new();
        map.insert("value", syn_int(3));
        let child = syn_map(map);
        let alias = child.clone();
        drop(syn_list(vec![child]));
        let SynValue::Map(map) = &alias else {
            unreachable!()
        };
        assert!(map.borrow().get("value").unwrap().syn_equals(&syn_int(3)));
    }

    #[test]
    fn dictionary_maps_and_envelopes_release_their_children() {
        let mut value = syn_int(1);
        for _ in 0..2000 {
            let mut map = SynMap::new();
            for i in 0..64 {
                map.insert(format!("k{i}"), syn_int(i));
            }
            map.insert("child", value);
            value = SynValue::Server(Obj::new(ServerValue::Envelope {
                status: 200,
                value: syn_map(map),
            }));
        }
        drop(value);
    }

    #[test]
    fn a_host_destructor_panic_still_releases_the_remaining_slots() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        use std::rc::Rc;
        struct Panics;
        impl Drop for Panics {
            fn drop(&mut self) {
                panic!("host payload drop");
            }
        }
        for maps in [false, true] {
            let panics = Panics;
            let func: crate::interpreter::BuiltinFn = Rc::new(move |_, _, _| {
                std::hint::black_box(&panics);
                Ok(SynValue::Nothing)
            });
            let builtin = SynValue::Builtin(Rc::new(crate::interpreter::BuiltinTask::new(
                "test_drop_payload",
                0,
                None,
                func,
            )));
            let leaf = syn_list(vec![syn_int(1)]);
            let SynValue::List(list) = &leaf else {
                unreachable!()
            };
            let weak = ListRef::downgrade(list);
            let before = syn_list(vec![syn_int(2)]);
            let SynValue::List(list) = &before else {
                unreachable!()
            };
            let before_weak = ListRef::downgrade(list);
            let root = if maps {
                let mut map = SynMap::new();
                map.insert("before", before);
                map.insert("panic", builtin);
                map.insert("remaining", leaf);
                syn_map(map)
            } else {
                syn_list(vec![before, builtin, leaf])
            };
            assert!(catch_unwind(AssertUnwindSafe(|| drop(root))).is_err());
            assert!(
                before_weak.upgrade().is_none(),
                "completed children stay released"
            );
            assert!(
                weak.upgrade().is_none(),
                "unwinding must release remaining children"
            );
        }
    }
}
