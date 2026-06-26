//! API de manipulación de AST. Port de `synsema/core/ast_api.py`.
//!
//! Operaciones estructurales sobre el AST que un agente usa para modificar código
//! semánticamente (en vez de search-and-replace de texto): find_tasks, find_usages,
//! rename_task, add_parameter, extract_task, summarize, make_call/make_text, etc.

use crate::ast::{Arg, Node, NodeKind, Param, Program};
use crate::tokens::SourceLocation;

fn gen_loc() -> SourceLocation {
    SourceLocation { file: "<generated>".to_string(), line: 0, column: 0, offset: 0 }
}

// =========================================================
// Walker del AST (espeja _walk de Python: recorre todos los Node hijos)
// =========================================================

/// Nodos hijos directos de un nodo (todas las variantes con sub-Nodes).
fn children(n: &Node) -> Vec<&Node> {
    use NodeKind::*;
    match &n.kind {
        ListLiteral { elements } => elements.iter().collect(),
        MapLiteral { pairs } => pairs.iter().flat_map(|(k, v)| [k, v]).collect(),
        PropertyAccess { object, .. } => vec![object],
        IndexAccess { object, index } => vec![object, index],
        BinaryOp { left, right, .. } => vec![left, right],
        UnaryOp { operand, .. } => vec![operand],
        PipeExpression { value, transforms } => {
            let mut v = vec![value.as_ref()];
            v.extend(transforms.iter());
            v
        }
        LetBinding { value, .. } => vec![value],
        SetMutation { target, value } => vec![target, value],
        WhenStatement { condition, body, otherwise, otherwise_when } => {
            let mut v = vec![condition.as_ref()];
            v.extend(body.iter());
            if let Some(o) = otherwise {
                v.extend(o.iter());
            }
            if let Some(ow) = otherwise_when {
                v.push(ow);
            }
            v
        }
        EachStatement { collection, body, .. } => {
            let mut v = vec![collection.as_ref()];
            v.extend(body.iter());
            v
        }
        WhileStatement { condition, body } => {
            let mut v = vec![condition.as_ref()];
            v.extend(body.iter());
            v
        }
        MatchStatement { value, arms, otherwise } => {
            let mut v = vec![value.as_ref()];
            v.extend(arms.iter());
            if let Some(o) = otherwise {
                v.extend(o.iter());
            }
            v
        }
        MatchArm { pattern, guard, body } => {
            let mut v = vec![pattern.as_ref()];
            if let Some(g) = guard {
                v.push(g.as_ref());
            }
            v.extend(body.iter());
            v
        }
        // Patrones (Batch 2): descienden a sus sub-patrones; wildcard es hoja.
        WildcardPattern => Vec::new(),
        ListPattern { prefix, suffix, .. } => {
            let mut v: Vec<&Node> = prefix.iter().collect();
            v.extend(suffix.iter());
            v
        }
        MapPattern { fields } => fields.iter().filter_map(|(_, p)| p.as_ref()).collect(),
        StopStatement { value } => value.iter().map(|b| b.as_ref()).collect(),
        // Los defaults de params son sub-expresiones (Batch 2): se recorren.
        TaskDefinition { parameters, body, .. } => {
            let mut v: Vec<&Node> = parameters.iter().filter_map(|p| p.default.as_ref()).collect();
            v.extend(body.iter());
            v
        }
        TaskCall { name, arguments } => {
            let mut v = vec![name.as_ref()];
            v.extend(arguments.iter().map(|a| &a.value));
            v
        }
        GiveStatement { value } => value.iter().map(|b| b.as_ref()).collect(),
        AgentDefinition { capabilities, body, .. } => {
            let mut v: Vec<&Node> = capabilities.iter().collect();
            v.extend(body.iter());
            v
        }
        SpawnStatement { arguments, .. } => arguments.iter().map(|(_, node)| node).collect(),
        ShareStatement { value, key } => vec![value, key],
        ObserveStatement { key, .. } => vec![key],
        // El nombre del canal es una expresión (Batch 6) → se recorre (además del data/timeout).
        SignalStatement { name, data } => {
            let mut v: Vec<&Node> = vec![name.as_ref()];
            v.extend(data.iter().map(|b| b.as_ref()));
            v
        }
        WaitForStatement { signal_name, timeout, .. } => {
            let mut v: Vec<&Node> = vec![signal_name.as_ref()];
            v.extend(timeout.iter().map(|b| b.as_ref()));
            v
        }
        RequireStatement { scope, .. } => scope.iter().map(|b| b.as_ref()).collect(),
        SandboxBlock { body, .. } => body.iter().collect(),
        InvariantDeclaration { condition, .. } => vec![condition],
        ApproveStatement { message, context } => {
            let mut v = vec![message.as_ref()];
            if let Some(c) = context {
                v.push(c);
            }
            v
        }
        ShowStatement { value, .. } => vec![value],
        ConfirmStatement { message } => vec![message],
        AskExpression { prompt, options } => {
            let mut v = vec![prompt.as_ref()];
            if let Some(o) = options {
                v.push(o);
            }
            v
        }
        ReasonExpression { subject, context, body } => {
            let mut v: Vec<&Node> = Vec::new();
            if let Some(s) = subject {
                v.push(s);
            }
            v.extend(context.iter().map(|(_, node)| node));
            v.extend(body.iter());
            v
        }
        DecideExpression { options, given, .. } => {
            let mut v = Vec::new();
            if let Some(o) = options {
                v.push(o.as_ref());
            }
            if let Some(g) = given {
                v.push(g.as_ref());
            }
            v
        }
        AnalyzeExpression { data, .. } => vec![data],
        GenerateExpression { given, parameters, .. } => {
            let mut v = Vec::new();
            if let Some(g) = given {
                v.push(g.as_ref());
            }
            v.extend(parameters.iter().map(|(_, node)| node));
            v
        }
        TraceBlock { body, .. } => body.iter().collect(),
        TestBlock { body, .. } => body.iter().collect(),
        LogStatement { message, .. } => vec![message],
        MeasureBlock { body, .. } => body.iter().collect(),
        TryRecover { try_body, recover_body, .. } => {
            let mut v: Vec<&Node> = try_body.iter().collect();
            v.extend(recover_body.iter());
            v
        }
        RouteDefinition { rate_limit, body, .. } => {
            let mut v: Vec<&Node> = rate_limit.iter().map(|b| b.as_ref()).collect();
            v.extend(body.iter());
            v
        }
        ServeBlock {
            port,
            auth_handler,
            max_body,
            max_streams,
            rate_limit,
            static_mounts,
            cors,
            describe,
            routes,
            tls_cert,
            tls_key,
            tls_auto_email,
            domain,
            hosts,
            ..
        } => {
            let mut v = vec![port.as_ref()];
            for opt in [auth_handler, max_body, max_streams, rate_limit, cors, describe, tls_cert, tls_key, tls_auto_email, domain] {
                if let Some(b) = opt {
                    v.push(b);
                }
            }
            v.extend(static_mounts.iter());
            v.extend(routes.iter());
            v.extend(hosts.iter());
            v
        }
        HostBlock { pattern, auth_handler, static_mounts, routes, tls_cert, tls_key } => {
            let mut v = vec![pattern.as_ref()];
            for opt in [auth_handler, tls_cert, tls_key] {
                if let Some(b) = opt {
                    v.push(b);
                }
            }
            v.extend(static_mounts.iter());
            v.extend(routes.iter());
            v
        }
        StreamBlock { body } => body.iter().collect(),
        ProxyStatement { target } => vec![target.as_ref()],
        SendStatement { value, .. } => vec![value],
        RateLimitClause { count, .. } => count.iter().map(|b| b.as_ref()).collect(),
        StaticMount { directory, prefix } => {
            let mut v = vec![directory.as_ref()];
            if let Some(p) = prefix {
                v.push(p);
            }
            v
        }
        DescribeClause { about, api } => {
            let mut v = Vec::new();
            if let Some(a) = about {
                v.push(a.as_ref());
            }
            if let Some(a) = api {
                v.push(a.as_ref());
            }
            v
        }
        CheckpointStatement { name } => vec![name.as_ref()],
        // Hojas (sin sub-Nodes): literales, Identifier, TypeDefinition, IntentDeclaration,
        // StateTransition, ExpectStatement, NothingLiteral, etc.
        _ => Vec::new(),
    }
}

/// Recorre el AST (pre-orden), llamando `visitor` en cada nodo.
pub fn walk<'a>(node: &'a Node, visitor: &mut dyn FnMut(&'a Node)) {
    visitor(node);
    for child in children(node) {
        walk(child, visitor);
    }
}

// =========================================================
// Query
// =========================================================

pub fn find_tasks(program: &Program) -> Vec<&Node> {
    let mut out = Vec::new();
    for stmt in &program.statements {
        walk(stmt, &mut |n| {
            if matches!(n.kind, NodeKind::TaskDefinition { .. }) {
                out.push(n);
            }
        });
    }
    out
}

pub fn find_task_by_name<'a>(program: &'a Program, name: &str) -> Option<&'a Node> {
    find_tasks(program).into_iter().find(|t| {
        matches!(&t.kind, NodeKind::TaskDefinition { name: n, .. } if n == name)
    })
}

pub fn find_invariants(program: &Program) -> Vec<&Node> {
    let mut out = Vec::new();
    for stmt in &program.statements {
        walk(stmt, &mut |n| {
            if matches!(n.kind, NodeKind::InvariantDeclaration { .. }) {
                out.push(n);
            }
        });
    }
    out
}

pub fn find_types(program: &Program) -> Vec<&Node> {
    let mut out = Vec::new();
    for stmt in &program.statements {
        walk(stmt, &mut |n| {
            if matches!(n.kind, NodeKind::TypeDefinition { .. }) {
                out.push(n);
            }
        });
    }
    out
}

pub fn find_usages<'a>(program: &'a Program, name: &str) -> Vec<&'a Node> {
    let mut out = Vec::new();
    for stmt in &program.statements {
        walk(stmt, &mut |n| {
            if matches!(&n.kind, NodeKind::Identifier { name: id } if id == name) {
                out.push(n);
            }
        });
    }
    out
}

pub fn get_task_dependencies(program: &Program, task_name: &str) -> Vec<String> {
    let task = match find_task_by_name(program, task_name) {
        Some(t) => t,
        None => return Vec::new(),
    };
    let body = match &task.kind {
        NodeKind::TaskDefinition { body, .. } => body,
        _ => return Vec::new(),
    };
    let mut calls: Vec<String> = Vec::new();
    for stmt in body {
        walk(stmt, &mut |n| {
            if let NodeKind::TaskCall { name, .. } = &n.kind {
                if let NodeKind::Identifier { name: id } = &name.kind {
                    if !calls.contains(id) {
                        calls.push(id.clone());
                    }
                }
            }
        });
    }
    calls
}

/// Grafo de dependencias de todas las tasks (name → tasks llamadas).
pub fn get_dependency_graph(program: &Program) -> indexmap::IndexMap<String, Vec<String>> {
    let mut graph = indexmap::IndexMap::new();
    for task in find_tasks(program) {
        if let NodeKind::TaskDefinition { name, .. } = &task.kind {
            graph.insert(name.clone(), get_task_dependencies(program, name));
        }
    }
    graph
}

// =========================================================
// Mutación
// =========================================================

/// Renombra una task y todos sus usos (definición + identificadores). Devuelve el
/// número de cambios.
pub fn rename_task(program: &mut Program, old_name: &str, new_name: &str) -> usize {
    let mut changes = 0;
    for stmt in &mut program.statements {
        walk_mut(stmt, &mut |n| match &mut n.kind {
            NodeKind::TaskDefinition { name, .. } if name == old_name => {
                *name = new_name.to_string();
                changes += 1;
            }
            NodeKind::Identifier { name } if name == old_name => {
                *name = new_name.to_string();
                changes += 1;
            }
            _ => {}
        });
    }
    changes
}

/// Agrega un parámetro a una definición de task (si no está ya).
pub fn add_parameter(task: &mut Node, param_name: &str) {
    if let NodeKind::TaskDefinition { parameters, .. } = &mut task.kind {
        if !parameters.iter().any(|p| p.name == param_name) {
            parameters.push(Param { name: param_name.to_string(), default: None });
        }
    }
}

/// Extrae los statements [start, end) a una nueva task, los reemplaza por una
/// llamada a ella, e inserta la definición. Devuelve la nueva task.
pub fn extract_task(
    program: &mut Program,
    start: usize,
    end: usize,
    task_name: &str,
    params: &[String],
) -> Node {
    let extracted: Vec<Node> = program.statements.drain(start..end).collect();
    let task = Node {
        location: gen_loc(),
        kind: NodeKind::TaskDefinition {
            name: task_name.to_string(),
            parameters: params
                .iter()
                .map(|n| Param { name: n.clone(), default: None })
                .collect(),
            body: extracted,
            return_type: None,
            capabilities: Vec::new(),
        },
    };
    program.statements.insert(start, task.clone());
    let call = make_call(
        task_name,
        params.iter().map(|p| make_identifier(p)).collect(),
    );
    program.statements.insert(start + 1, call);
    task
}

// =========================================================
// Generación de nodos
// =========================================================

pub fn make_text(value: &str) -> Node {
    Node { location: gen_loc(), kind: NodeKind::TextLiteral { value: value.to_string() } }
}

pub fn make_identifier(name: &str) -> Node {
    Node { location: gen_loc(), kind: NodeKind::Identifier { name: name.to_string() } }
}

pub fn make_call(task_name: &str, args: Vec<Node>) -> Node {
    Node {
        location: gen_loc(),
        kind: NodeKind::TaskCall {
            name: Box::new(make_identifier(task_name)),
            arguments: args.into_iter().map(|value| Arg { name: None, value }).collect(),
        },
    }
}

// =========================================================
// Resumen
// =========================================================

#[derive(Debug, Default)]
pub struct TaskInfo {
    pub name: String,
    pub params: Vec<String>,
    pub line: usize,
}

#[derive(Debug, Default)]
pub struct TypeInfo {
    pub name: String,
    pub fields: Vec<(String, String)>,
    pub line: usize,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub tasks: Vec<TaskInfo>,
    pub types: Vec<TypeInfo>,
    pub agents: Vec<String>,
    pub invariants: Vec<Option<String>>,
    pub intents: Vec<String>,
    pub capabilities: Vec<String>,
    pub variables: Vec<String>,
}

/// Resumen compacto de la estructura de un programa (firmas, no cuerpos).
pub fn summarize(program: &Program) -> Summary {
    let mut s = Summary::default();
    for stmt in &program.statements {
        match &stmt.kind {
            NodeKind::TaskDefinition { name, parameters, .. } => s.tasks.push(TaskInfo {
                name: name.clone(),
                params: parameters.iter().map(|p| p.name.clone()).collect(),
                line: stmt.location.line,
            }),
            NodeKind::TypeDefinition { name, fields } => s.types.push(TypeInfo {
                name: name.clone(),
                fields: fields.clone(),
                line: stmt.location.line,
            }),
            NodeKind::AgentDefinition { name, .. } => s.agents.push(name.clone()),
            NodeKind::InvariantDeclaration { description, .. } => {
                s.invariants.push(description.clone())
            }
            NodeKind::IntentDeclaration { description } => s.intents.push(description.clone()),
            NodeKind::RequireStatement { capability, .. } => s.capabilities.push(capability.clone()),
            NodeKind::LetBinding { name, .. } => s.variables.push(name.clone()),
            _ => {}
        }
    }
    s
}

// =========================================================
// Walker mutable (para rename)
// =========================================================

fn children_mut(n: &mut Node) -> Vec<&mut Node> {
    use NodeKind::*;
    match &mut n.kind {
        ListLiteral { elements } => elements.iter_mut().collect(),
        MapLiteral { pairs } => pairs.iter_mut().flat_map(|(k, v)| [k, v]).collect(),
        PropertyAccess { object, .. } => vec![object.as_mut()],
        IndexAccess { object, index } => vec![object.as_mut(), index.as_mut()],
        BinaryOp { left, right, .. } => vec![left.as_mut(), right.as_mut()],
        UnaryOp { operand, .. } => vec![operand.as_mut()],
        PipeExpression { value, transforms } => {
            let mut v = vec![value.as_mut()];
            v.extend(transforms.iter_mut());
            v
        }
        LetBinding { value, .. } => vec![value.as_mut()],
        SetMutation { target, value } => vec![target.as_mut(), value.as_mut()],
        WhenStatement { condition, body, otherwise, otherwise_when } => {
            let mut v = vec![condition.as_mut()];
            v.extend(body.iter_mut());
            if let Some(o) = otherwise {
                v.extend(o.iter_mut());
            }
            if let Some(ow) = otherwise_when {
                v.push(ow.as_mut());
            }
            v
        }
        EachStatement { collection, body, .. } => {
            let mut v = vec![collection.as_mut()];
            v.extend(body.iter_mut());
            v
        }
        WhileStatement { condition, body } => {
            let mut v = vec![condition.as_mut()];
            v.extend(body.iter_mut());
            v
        }
        MatchStatement { value, arms, otherwise } => {
            let mut v = vec![value.as_mut()];
            v.extend(arms.iter_mut());
            if let Some(o) = otherwise {
                v.extend(o.iter_mut());
            }
            v
        }
        MatchArm { pattern, guard, body } => {
            let mut v = vec![pattern.as_mut()];
            if let Some(g) = guard {
                v.push(g.as_mut());
            }
            v.extend(body.iter_mut());
            v
        }
        // Patrones (Batch 2): descienden a sus sub-patrones; wildcard es hoja.
        WildcardPattern => Vec::new(),
        ListPattern { prefix, suffix, .. } => {
            let mut v: Vec<&mut Node> = prefix.iter_mut().collect();
            v.extend(suffix.iter_mut());
            v
        }
        MapPattern { fields } => fields.iter_mut().filter_map(|(_, p)| p.as_mut()).collect(),
        StopStatement { value } => value.iter_mut().map(|b| b.as_mut()).collect(),
        TaskDefinition { parameters, body, .. } => {
            let mut v: Vec<&mut Node> =
                parameters.iter_mut().filter_map(|p| p.default.as_mut()).collect();
            v.extend(body.iter_mut());
            v
        }
        TaskCall { name, arguments } => {
            let mut v = vec![name.as_mut()];
            v.extend(arguments.iter_mut().map(|a| &mut a.value));
            v
        }
        GiveStatement { value } => value.iter_mut().map(|b| b.as_mut()).collect(),
        AgentDefinition { capabilities, body, .. } => {
            let mut v: Vec<&mut Node> = capabilities.iter_mut().collect();
            v.extend(body.iter_mut());
            v
        }
        SpawnStatement { arguments, .. } => arguments.iter_mut().map(|(_, node)| node).collect(),
        ShareStatement { value, key } => vec![value.as_mut(), key.as_mut()],
        ObserveStatement { key, .. } => vec![key.as_mut()],
        SignalStatement { name, data } => {
            let mut v: Vec<&mut Node> = vec![name.as_mut()];
            v.extend(data.iter_mut().map(|b| b.as_mut()));
            v
        }
        WaitForStatement { signal_name, timeout, .. } => {
            let mut v: Vec<&mut Node> = vec![signal_name.as_mut()];
            v.extend(timeout.iter_mut().map(|b| b.as_mut()));
            v
        }
        RequireStatement { scope, .. } => scope.iter_mut().map(|b| b.as_mut()).collect(),
        SandboxBlock { body, .. } => body.iter_mut().collect(),
        InvariantDeclaration { condition, .. } => vec![condition.as_mut()],
        ApproveStatement { message, context } => {
            let mut v = vec![message.as_mut()];
            if let Some(c) = context {
                v.push(c.as_mut());
            }
            v
        }
        ShowStatement { value, .. } => vec![value.as_mut()],
        ConfirmStatement { message } => vec![message.as_mut()],
        AskExpression { prompt, options } => {
            let mut v = vec![prompt.as_mut()];
            if let Some(o) = options {
                v.push(o.as_mut());
            }
            v
        }
        ReasonExpression { subject, context, body } => {
            let mut v: Vec<&mut Node> = Vec::new();
            if let Some(s) = subject {
                v.push(s.as_mut());
            }
            v.extend(context.iter_mut().map(|(_, node)| node));
            v.extend(body.iter_mut());
            v
        }
        DecideExpression { options, given, .. } => {
            let mut v = Vec::new();
            if let Some(o) = options {
                v.push(o.as_mut());
            }
            if let Some(g) = given {
                v.push(g.as_mut());
            }
            v
        }
        AnalyzeExpression { data, .. } => vec![data.as_mut()],
        GenerateExpression { given, parameters, .. } => {
            let mut v = Vec::new();
            if let Some(g) = given {
                v.push(g.as_mut());
            }
            v.extend(parameters.iter_mut().map(|(_, node)| node));
            v
        }
        TraceBlock { body, .. } => body.iter_mut().collect(),
        TestBlock { body, .. } => body.iter_mut().collect(),
        LogStatement { message, .. } => vec![message.as_mut()],
        MeasureBlock { body, .. } => body.iter_mut().collect(),
        TryRecover { try_body, recover_body, .. } => {
            let mut v: Vec<&mut Node> = try_body.iter_mut().collect();
            v.extend(recover_body.iter_mut());
            v
        }
        RouteDefinition { rate_limit, body, .. } => {
            let mut v: Vec<&mut Node> = rate_limit.iter_mut().map(|b| b.as_mut()).collect();
            v.extend(body.iter_mut());
            v
        }
        ServeBlock {
            port,
            auth_handler,
            max_body,
            max_streams,
            rate_limit,
            static_mounts,
            cors,
            describe,
            routes,
            tls_cert,
            tls_key,
            tls_auto_email,
            domain,
            hosts,
            ..
        } => {
            let mut v = vec![port.as_mut()];
            for opt in [auth_handler, max_body, max_streams, rate_limit, cors, describe, tls_cert, tls_key, tls_auto_email, domain] {
                if let Some(b) = opt {
                    v.push(b.as_mut());
                }
            }
            v.extend(static_mounts.iter_mut());
            v.extend(routes.iter_mut());
            v.extend(hosts.iter_mut());
            v
        }
        HostBlock { pattern, auth_handler, static_mounts, routes, tls_cert, tls_key } => {
            let mut v = vec![pattern.as_mut()];
            for opt in [auth_handler, tls_cert, tls_key] {
                if let Some(b) = opt {
                    v.push(b.as_mut());
                }
            }
            v.extend(static_mounts.iter_mut());
            v.extend(routes.iter_mut());
            v
        }
        StreamBlock { body } => body.iter_mut().collect(),
        ProxyStatement { target } => vec![target.as_mut()],
        SendStatement { value, .. } => vec![value.as_mut()],
        RateLimitClause { count, .. } => count.iter_mut().map(|b| b.as_mut()).collect(),
        StaticMount { directory, prefix } => {
            let mut v = vec![directory.as_mut()];
            if let Some(p) = prefix {
                v.push(p.as_mut());
            }
            v
        }
        DescribeClause { about, api } => {
            let mut v = Vec::new();
            if let Some(a) = about {
                v.push(a.as_mut());
            }
            if let Some(a) = api {
                v.push(a.as_mut());
            }
            v
        }
        _ => Vec::new(),
    }
}

fn walk_mut(node: &mut Node, visitor: &mut dyn FnMut(&mut Node)) {
    visitor(node);
    for child in children_mut(node) {
        walk_mut(child, visitor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_source;

    const SAMPLE: &str = "\ntask add(a, b)\n    give a + b\n\ntask multiply(a, b)\n    give a * b\n\ntask compute(x)\n    let doubled be add(x, x)\n    give multiply(doubled, 3)\n\ntype Point\n    x: number\n    y: number\n\nlet result be compute(5)\n";

    fn prog(src: &str) -> Program {
        parse_source(src, "<t>").unwrap()
    }

    fn tname(n: &Node) -> String {
        match &n.kind {
            NodeKind::TaskDefinition { name, .. } => name.clone(),
            _ => String::new(),
        }
    }

    #[test]
    fn find_tasks_works() {
        let p = prog(SAMPLE);
        let names: Vec<String> = find_tasks(&p).iter().map(|t| tname(t)).collect();
        assert!(names.contains(&"add".to_string()));
        assert!(names.contains(&"multiply".to_string()));
        assert!(names.contains(&"compute".to_string()));
    }

    #[test]
    fn find_task_by_name_params() {
        let p = prog(SAMPLE);
        let task = find_task_by_name(&p, "add").unwrap();
        if let NodeKind::TaskDefinition { parameters, .. } = &task.kind {
            let names: Vec<String> = parameters.iter().map(|p| p.name.clone()).collect();
            assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
        } else {
            panic!("not a task");
        }
    }

    #[test]
    fn find_types_works() {
        let p = prog(SAMPLE);
        let types = find_types(&p);
        assert_eq!(types.len(), 1);
        assert!(matches!(&types[0].kind, NodeKind::TypeDefinition { name, .. } if name == "Point"));
    }

    #[test]
    fn find_usages_works() {
        let p = prog(SAMPLE);
        assert!(!find_usages(&p, "compute").is_empty());
    }

    #[test]
    fn dependency_graph_works() {
        let p = prog(SAMPLE);
        let g = get_dependency_graph(&p);
        let compute = g.get("compute").unwrap();
        assert!(compute.contains(&"add".to_string()));
        assert!(compute.contains(&"multiply".to_string()));
    }

    #[test]
    fn rename_task_works() {
        let mut p = prog(SAMPLE);
        let changes = rename_task(&mut p, "add", "sum");
        assert!(changes >= 2);
    }

    #[test]
    fn add_parameter_works() {
        let mut p = prog(SAMPLE);
        let task = p
            .statements
            .iter_mut()
            .find(|s| matches!(&s.kind, NodeKind::TaskDefinition { name, .. } if name == "add"))
            .unwrap();
        add_parameter(task, "c");
        if let NodeKind::TaskDefinition { parameters, .. } = &task.kind {
            assert!(parameters.iter().any(|p| p.name == "c"));
        }
    }

    #[test]
    fn summarize_works() {
        let p = prog(SAMPLE);
        let s = summarize(&p);
        assert_eq!(s.tasks.len(), 3);
        assert_eq!(s.types.len(), 1);
    }

    #[test]
    fn make_helpers_work() {
        let node = make_call("print", vec![make_text("hello")]);
        if let NodeKind::TaskCall { name, .. } = &node.kind {
            assert!(matches!(&name.kind, NodeKind::Identifier { name } if name == "print"));
        } else {
            panic!("not a call");
        }
    }

    #[test]
    fn extract_task_works() {
        let mut p = prog("let a be 1\nlet b be 2\nlet c be a + b\nprint(text(c))");
        let task = extract_task(&mut p, 0, 2, "setup", &[]);
        assert_eq!(tname(&task), "setup");
    }
}
