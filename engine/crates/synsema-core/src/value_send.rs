//! Heap continuations for the owned worker snapshot. Its policies remain distinct
//! from labels::deep_copy: server wrappers become maps and secrets stay redacted.
use crate::types::{self, SendValue, ServerValue, SynValue};
use smallvec::SmallVec;
use std::fmt;

fn syn_child<R>(v: &SynValue, i: usize, f: impl FnOnce(&SynValue) -> R) -> Option<R> {
    match v {
        SynValue::List(l) => l.borrow().get(i).as_ref().map(f),
        SynValue::Map(m) => m.borrow().get_index(i).map(|(_, v)| f(v)),
        SynValue::Private(p) if i == 0 => Some(f(&p.value)),
        SynValue::Server(s) => match &**s {
            ServerValue::Envelope { value, .. } if i == 0 => Some(f(value)),
            ServerValue::Node(m) => m.borrow().get_index(i).map(|(_, v)| f(v)),
            ServerValue::Content(v) | ServerValue::WithHeaders { inner: v, .. } if i == 0 => Some(f(v)),
            _ => None,
        },
        _ => None,
    }
}

fn syn_branch(v: &SynValue) -> bool {
    matches!(v, SynValue::List(_) | SynValue::Map(_) | SynValue::Private(_)) ||
        matches!(v, SynValue::Server(s) if matches!(&**s, ServerValue::Envelope { .. } | ServerValue::Node(_) | ServerValue::Content(_) | ServerValue::WithHeaders { .. }))
}

fn send_map(m: &types::MapRef, values: Vec<SendValue>) -> SendValue {
    let m = m.borrow();
    SendValue::Map(values.into_iter().enumerate().map(|(i, v)| (m.get_index(i).unwrap().0.to_string(), v)).collect())
}

fn to_rebuild(v: &SynValue, mut out: Vec<SendValue>) -> SendValue {
    match v {
        SynValue::List(_) => SendValue::List(out),
        SynValue::Map(m) => send_map(m, out),
        SynValue::Private(p) => SendValue::Private(p.label.iter().map(|s| s.to_string()).collect(), Box::new(out.pop().unwrap())),
        SynValue::Server(s) => match &**s {
            ServerValue::Node(m) => send_map(m, out),
            ServerValue::Envelope { status, .. } => SendValue::Map(vec![
                ("status".into(), SendValue::Number(crate::number::Number::Int(*status))),
                ("value".into(), out.pop().unwrap()),
            ]),
            ServerValue::Content(_) | ServerValue::WithHeaders { .. } => out.pop().unwrap(),
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

#[cold]
#[inline(never)]
pub(crate) fn to_deep(v: &SynValue) -> SendValue {
    if !syn_branch(v) { return types::to_send_at(v, 0); }
    let mut stack = vec![(v.clone(), Vec::new())];
    loop {
        let (v, out) = stack.last_mut().unwrap();
        match syn_child(v, out.len(), |v| if syn_branch(v) { Err(v.clone()) } else { Ok(types::to_send_at(v, 0)) }) {
            Some(Ok(v)) => out.push(v),
            Some(Err(v)) => stack.push((v, Vec::new())),
            None => {
                let (v, out) = stack.pop().unwrap();
                let v = to_rebuild(&v, out);
                if let Some((_, out)) = stack.last_mut() { out.push(v); } else { return v; }
            }
        }
    }
}

fn send_child(v: &SendValue, i: usize) -> Option<&SendValue> {
    match v {
        SendValue::List(v) => v.get(i),
        SendValue::Map(v) => v.get(i).map(|(_, v)| v),
        SendValue::Private(_, v) if i == 0 => Some(v),
        _ => None,
    }
}

fn send_branch(v: &SendValue) -> bool { matches!(v, SendValue::List(_) | SendValue::Map(_) | SendValue::Private(_, _)) }

// The input is an immutable owned tree: frames can borrow it directly, unlike
// a SynValue traversal whose list/map children live behind borrow guards.
fn map_send<T>(v: &SendValue, leaf: impl Fn(&SendValue) -> T, rebuild: impl Fn(&SendValue, Vec<T>) -> T) -> T {
    if !send_branch(v) { return leaf(v); }
    let mut stack = vec![(v, Vec::new())];
    loop {
        let (v, out) = stack.last_mut().unwrap();
        match send_child(v, out.len()) {
            Some(v) if send_branch(v) => stack.push((v, Vec::new())),
            Some(v) => out.push(leaf(v)),
            None => {
                let (v, out) = stack.pop().unwrap();
                let v = rebuild(v, out);
                if let Some((_, out)) = stack.last_mut() { out.push(v); } else { return v; }
            }
        }
    }
}

#[cold]
#[inline(never)]
pub(crate) fn from_deep(v: &SendValue) -> SynValue {
    map_send(v, |v| types::from_send_at(v, 0), |v, mut out| match v {
        SendValue::List(_) => types::syn_list(out),
        SendValue::Map(pairs) => {
            let mut m = types::SynMap::with_capacity(pairs.len());
            for ((k, _), value) in pairs.iter().zip(out) { m.insert(k.clone(), value); }
            types::syn_map(m)
        }
        SendValue::Private(principals, _) => crate::labels::mark(out.pop().unwrap(), crate::labels::label_from(principals)),
        _ => unreachable!(),
    })
}

fn clone_leaf(v: &SendValue) -> SendValue {
    match v {
        SendValue::Number(v) => SendValue::Number(v.clone()),
        SendValue::Text(v) => SendValue::Text(v.clone()),
        SendValue::Bool(v) => SendValue::Bool(*v),
        SendValue::Nothing => SendValue::Nothing,
        SendValue::Bytes(v) => SendValue::Bytes(v.clone()),
        SendValue::Complex(a, b) => SendValue::Complex(*a, *b),
        SendValue::Array(shape, data) => SendValue::Array(shape.clone(), data.clone()),
        SendValue::Time(v) => SendValue::Time(v.clone()),
        SendValue::Rng(v, name) => SendValue::Rng(v.clone(), name.clone()),
        // Hoja estructural propia: la tabla clona sus bloques (Vec de Send), sin recorrer
        // celdas.
        SendValue::Table { n_rows, cols } => SendValue::Table { n_rows: *n_rows, cols: cols.clone() },
        _ => unreachable!(),
    }
}

fn clone_rebuild(v: &SendValue, mut out: Vec<SendValue>) -> SendValue {
    match v {
        SendValue::List(_) => SendValue::List(out),
        SendValue::Map(pairs) => SendValue::Map(pairs.iter().map(|(k, _)| k.clone()).zip(out).collect()),
        SendValue::Private(p, _) => SendValue::Private(p.clone(), Box::new(out.pop().unwrap())),
        _ => unreachable!(),
    }
}

impl Clone for SendValue {
    fn clone(&self) -> Self { clone_at(self, 0) }
}

fn clone_at(v: &SendValue, depth: usize) -> SendValue {
    if !send_branch(v) { return clone_leaf(v); }
    if depth == 32 { return map_send(v, clone_leaf, clone_rebuild); }
    let mut out = Vec::new();
    while let Some(v) = send_child(v, out.len()) { out.push(clone_at(v, depth + 1)); }
    clone_rebuild(v, out)
}

pub(crate) fn display(v: &SendValue, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    enum Frame<'a> { Value(&'a SendValue), List(&'a [SendValue], usize), Map(&'a [(String, SendValue)], usize) }
    let mut stack: SmallVec<[Frame<'_>; 32]> = SmallVec::new();
    stack.push(Frame::Value(v));
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Value(SendValue::List(v)) => { f.write_str("[")?; stack.push(Frame::List(v, 0)); }
            Frame::Value(SendValue::Map(v)) => { f.write_str("{")?; stack.push(Frame::Map(v, 0)); }
            Frame::Value(v) => types::send_leaf_display(v, f)?,
            Frame::List(v, i) => {
                if i == v.len() { f.write_str("]")?; }
                else { if i > 0 { f.write_str(", ")?; } stack.push(Frame::List(v, i + 1)); stack.push(Frame::Value(&v[i])); }
            }
            Frame::Map(v, i) => {
                if i == v.len() { f.write_str("}")?; }
                else { if i > 0 { f.write_str(", ")?; } write!(f, "{}: ", v[i].0)?; stack.push(Frame::Map(v, i + 1)); stack.push(Frame::Value(&v[i].1)); }
            }
        }
    }
    Ok(())
}

enum DropFrame {
    List(std::vec::IntoIter<SendValue>),
    Map(std::vec::IntoIter<(String, SendValue)>),
    One(Option<SendValue>),
}

fn take_children(v: &mut SendValue) -> Option<DropFrame> {
    match v {
        SendValue::List(v) if !v.is_empty() => Some(DropFrame::List(std::mem::take(v).into_iter())),
        SendValue::Map(v) if !v.is_empty() => Some(DropFrame::Map(std::mem::take(v).into_iter())),
        // Las columnas `Value` de una tabla: sus celdas se aplanan en una sola lista (el
        // orden de la liberación no importa); los bloques primitivos sueltan solos sus Vec.
        SendValue::Table { cols, .. } => {
            let cells: Vec<SendValue> = std::mem::take(cols)
                .into_iter()
                .flat_map(|(_, col)| match col {
                    types::SendColumn::Value(cells) => cells,
                    _ => Vec::new(),
                })
                .collect();
            if cells.is_empty() { None } else { Some(DropFrame::List(cells.into_iter())) }
        }
        SendValue::Private(_, v) if !matches!(&**v, SendValue::Nothing) => Some(DropFrame::One(Some(std::mem::replace(&mut **v, SendValue::Nothing)))),
        _ => None,
    }
}

impl Drop for SendValue {
    fn drop(&mut self) {
        if let Some(frame) = take_children(self) { drop_children(frame); }
    }
}

#[inline(never)]
fn drop_children(frame: DropFrame) {
    let mut stack: SmallVec<[DropFrame; 32]> = SmallVec::new();
    stack.push(frame);
    while let Some(frame) = stack.last_mut() {
        let next = match frame {
            DropFrame::List(v) => v.next(),
            DropFrame::Map(v) => v.next().map(|(_, v)| v),
            DropFrame::One(v) => v.take(),
        };
        match next {
            Some(mut v) => if let Some(frame) = take_children(&mut v) { stack.push(frame); },
            None => { stack.pop(); },
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{labels, types::{syn_int, syn_list, syn_map, SynMap, Obj}};

    fn nested(mut v: SynValue, n: usize, maps: bool) -> SynValue {
        for _ in 0..n {
            v = if maps { let mut m = SynMap::new(); m.insert("k", v); syn_map(m) } else { syn_list(vec![v]) };
        }
        v
    }

    #[test]
    fn owned_snapshots_preserve_deep_values_labels_and_storage() {
        for maps in [false, true] {
            for depth in [0, 31, 32, 33, 1000, 50000] {
                let v = nested(labels::mark(syn_int(7), labels::label_from(&["p"])), depth, maps);
                let send = types::to_send(&v);
                let copy = send.clone();
                let restored = types::from_send(&copy);
                assert!(restored.syn_equals(&v));
                assert_eq!(labels::label_display_raw(&labels::label_deep(&restored)), "p");
                assert!(labels::check_flow(&restored, &[], "r").is_err());
                assert_eq!(send.to_string(), copy.to_string());
                assert!(send.to_string().ends_with(&if maps { "}" } else { "]" }.repeat(depth)));
            }
        }
        let numeric = types::syn_list_of(crate::synlist::SynList::from_ints(vec![1, 2]));
        assert_eq!(types::to_send(&numeric).to_string(), "[1, 2]");
        let SynValue::List(l) = numeric else { unreachable!() };
        assert!(l.borrow().as_values().is_none());
    }

    #[test]
    fn server_snapshot_contract_and_private_redaction() {
        let mut v = syn_int(7);
        for _ in 0..50000 { v = SynValue::Server(Obj::new(ServerValue::Content(Box::new(v)))); }
        assert_eq!(types::to_send(&v), SendValue::Number(crate::number::Number::Int(7)));
        let e = SynValue::Server(Obj::new(ServerValue::Envelope { status: 201, value: v }));
        assert_eq!(types::to_send(&e).to_string(), "{status: 201, value: 7}");
        let private = SendValue::Private(vec!["p".into()], Box::new(types::to_send(&nested(syn_int(7), 50000, false))));
        assert_eq!(private.to_string(), "private(p)");
        assert_eq!(private.clone().to_string(), "private(p)");
    }

    #[test]
    fn send_deep_children_exit_successfully() {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "value_send::tests::snapshot_million_clone_display_restore_and_drop"]);
        #[cfg(windows)]
        { use std::os::windows::process::CommandExt; command.creation_flags(0x08000000); }
        let result = command.output().unwrap();
        assert!(result.status.success(), "deep snapshot child aborted: {}", String::from_utf8_lossy(&result.stderr));
    }

    #[test]
    fn snapshot_million_clone_display_restore_and_drop() {
        std::thread::Builder::new().stack_size(64 * 1024 * 1024).spawn(|| {
            let v = nested(syn_int(7), 1_000_000, false);
            let send = types::to_send(&v);
            let copy = send.clone();
            assert_eq!(copy.to_string().len(), 2_000_001);
            let restored = types::from_send(&copy);
            assert!(restored.syn_equals(&v));
            drop(restored); drop(copy); drop(send); drop(v);
        }).unwrap().join().unwrap();
    }

    #[test]
    fn owned_display_propagates_writer_errors() {
        struct Limit(usize);
        impl fmt::Write for Limit {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                if text.len() > self.0 { return Err(fmt::Error); }
                self.0 -= text.len(); Ok(())
            }
        }
        let v = types::to_send(&nested(syn_int(7), 50000, true));
        for limit in [0, 31, 1000, 250000] {
            use std::fmt::Write;
            assert!(write!(&mut Limit(limit), "{}", v).is_err());
        }
    }
}
