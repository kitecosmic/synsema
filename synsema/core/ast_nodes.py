"""
Synsema AST (Abstract Syntax Tree) Node Definitions.

Every node in the AST carries its source location for full traceability.
The AST is designed to be inspectable by agents — each node type
clearly represents the programmer's intent, not just syntax.

The node hierarchy:
    Node (base)
    ├── Program
    ├── Expression nodes (produce values)
    │   ├── NumberLiteral, TextLiteral, BoolLiteral, NothingLiteral
    │   ├── ListLiteral, MapLiteral
    │   ├── Identifier
    │   ├── BinaryOp, UnaryOp
    │   ├── PropertyAccess (name of person)
    │   ├── TaskCall (function invocation)
    │   ├── LambdaExpression ((params) => expr)
    │   ├── PipeExpression (x |> transform)
    │   ├── ReasonExpression (LLM reasoning)
    │   ├── DecideExpression (LLM decision)
    │   ├── AnalyzeExpression (LLM analysis)
    │   ├── GenerateExpression (LLM generation)
    │   └── AskExpression (human input)
    └── Statement nodes (perform actions)
        ├── LetBinding (let x be value)
        ├── SetMutation (set x to value)
        ├── WhenStatement (conditional)
        ├── EachStatement (iteration)
        ├── WhileStatement (loop)
        ├── MatchStatement (pattern matching)
        ├── TaskDefinition (function definition)
        ├── GiveStatement (return)
        ├── AgentDefinition
        ├── SpawnStatement
        ├── ShareStatement, ObserveStatement
        ├── SignalStatement, WaitForStatement
        ├── RequireStatement (capability)
        ├── SandboxBlock
        ├── InvariantDeclaration
        ├── IntentDeclaration
        ├── ApproveStatement, ShowStatement, ConfirmStatement
        ├── TraceBlock, LogStatement, MeasureBlock, CheckpointStatement
        ├── TypeDefinition
        └── StopStatement
"""

from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict
from .tokens import SourceLocation


# -- Base --

@dataclass
class Node:
    """Base AST node. All nodes carry location for observability."""
    location: SourceLocation


# -- Program --

@dataclass
class Program(Node):
    """Root node: a sequence of statements."""
    statements: List[Node] = field(default_factory=list)


# -- Literals --

@dataclass
class NumberLiteral(Node):
    value: float | int = 0

@dataclass
class TextLiteral(Node):
    value: str = ""

@dataclass
class BoolLiteral(Node):
    value: bool = True

@dataclass
class NothingLiteral(Node):
    pass

@dataclass
class ListLiteral(Node):
    elements: List[Node] = field(default_factory=list)

@dataclass
class MapLiteral(Node):
    pairs: List[tuple] = field(default_factory=list)  # list of (key_node, value_node)


# -- Identifiers & Access --

@dataclass
class Identifier(Node):
    name: str = ""

@dataclass
class PropertyAccess(Node):
    """'name of person' or 'person.name'"""
    property_name: str = ""
    object: Node = None

@dataclass
class IndexAccess(Node):
    """list[0] or map["key"]"""
    object: Node = None
    index: Node = None


# -- Operators --

@dataclass
class BinaryOp(Node):
    left: Node = None
    operator: str = ""
    right: Node = None

@dataclass
class UnaryOp(Node):
    operator: str = ""
    operand: Node = None

@dataclass
class PipeExpression(Node):
    """value |> transform — chains operations naturally."""
    value: Node = None
    transforms: List[Node] = field(default_factory=list)


# -- Bindings & Mutation --

@dataclass
class LetBinding(Node):
    """let name be value"""
    name: str = ""
    value: Node = None
    type_annotation: Optional[str] = None

@dataclass
class SetMutation(Node):
    """set name to value"""
    target: Node = None
    value: Node = None


# -- Flow Control --

@dataclass
class WhenStatement(Node):
    """
    when condition
        body
    otherwise
        alternative
    """
    condition: Node = None
    body: List[Node] = field(default_factory=list)
    otherwise: Optional[List[Node]] = None
    otherwise_when: Optional['WhenStatement'] = None  # chained: otherwise when ...

@dataclass
class EachStatement(Node):
    """each item in collection\n        body"""
    variable: str = ""
    collection: Node = None
    body: List[Node] = field(default_factory=list)

@dataclass
class WhileStatement(Node):
    """while condition\n        body"""
    condition: Node = None
    body: List[Node] = field(default_factory=list)

@dataclass
class MatchStatement(Node):
    """match value\n    is pattern then action"""
    value: Node = None
    arms: List['MatchArm'] = field(default_factory=list)

@dataclass
class MatchArm(Node):
    pattern: Node = None
    body: List[Node] = field(default_factory=list)

@dataclass
class StopStatement(Node):
    """Early exit from a loop or task."""
    value: Optional[Node] = None


# -- Task (Function) Definition --

@dataclass
class TaskDefinition(Node):
    """
    task greet(name)
        give "Hello, " + name
    """
    name: str = ""
    parameters: List[str] = field(default_factory=list)
    body: List[Node] = field(default_factory=list)
    return_type: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)  # required capabilities

@dataclass
class TaskCall(Node):
    """greet("world") or process(data)"""
    name: Node = None  # can be Identifier or PropertyAccess
    arguments: List[Node] = field(default_factory=list)

@dataclass
class LambdaExpression(Node):
    """
    Anonymous single-expression function: (params) => expr

    Evaluates to a function value (type "task"), capturing the
    enclosing scope as its closure. The body is exactly one expression.
    """
    parameters: List[str] = field(default_factory=list)
    body: Node = None

@dataclass
class GiveStatement(Node):
    """give value — return from task."""
    value: Optional[Node] = None


# -- Type Definition --

@dataclass
class TypeDefinition(Node):
    """
    type Person
        name: text
        age: number
    """
    name: str = ""
    fields: List[tuple] = field(default_factory=list)  # (name, type_str)


# -- Agent System --

@dataclass
class AgentDefinition(Node):
    """
    agent Researcher
        state: idle
        require net("*.wikipedia.org")

        task search(query)
            ...
    """
    name: str = ""
    initial_state: Optional[str] = None
    capabilities: List[Node] = field(default_factory=list)
    body: List[Node] = field(default_factory=list)

@dataclass
class SpawnStatement(Node):
    """spawn Researcher with query = "AI safety" """
    agent_name: str = ""
    arguments: Dict[str, Node] = field(default_factory=dict)

@dataclass
class ShareStatement(Node):
    """share results as "search_results" or share results as key_expr"""
    value: Node = None
    key: Node = None  # expression, evaluated at runtime to get key string

@dataclass
class ObserveStatement(Node):
    """observe "search_results" as data — or observe key_expr as data"""
    key: Node = None  # expression, evaluated at runtime
    variable: str = ""

@dataclass
class SignalStatement(Node):
    """signal "done" """
    name: str = ""
    data: Optional[Node] = None

@dataclass
class WaitForStatement(Node):
    """wait_for "done" as result"""
    signal_name: str = ""
    variable: Optional[str] = None
    timeout: Optional[Node] = None

@dataclass
class StateTransition(Node):
    """set state to "processing" """
    new_state: str = ""


# -- Capability & Security --

@dataclass
class RequireStatement(Node):
    """require net("api.example.com"), file("/data/*")"""
    capability: str = ""
    scope: Optional[Node] = None

@dataclass
class SandboxBlock(Node):
    """sandbox\n        untrusted_operation()"""
    body: List[Node] = field(default_factory=list)
    allowed_capabilities: List[str] = field(default_factory=list)

@dataclass
class InvariantDeclaration(Node):
    """invariant: response_time < 200"""
    condition: Node = None
    description: Optional[str] = None

@dataclass
class IntentDeclaration(Node):
    """intent: "Process user payment for order #123" """
    description: str = ""


# -- Human Interaction --

@dataclass
class ApproveStatement(Node):
    """approve "Send email to {recipient}?" """
    message: Node = None
    context: Optional[Node] = None

@dataclass
class ShowStatement(Node):
    """show preview to human"""
    value: Node = None
    label: Optional[str] = None

@dataclass
class ConfirmStatement(Node):
    """confirm "Deploy to production?" """
    message: Node = None

@dataclass
class AskExpression(Node):
    """let choice be ask "Which option?" with ["A", "B", "C"]"""
    prompt: Node = None
    options: Optional[Node] = None


# -- LLM / Reasoning --

@dataclass
class ReasonExpression(Node):
    """
    reason about customer_complaint
        with context = order_history
        give summary
    """
    subject: Node = None
    context: Dict[str, Node] = field(default_factory=dict)
    body: List[Node] = field(default_factory=list)

@dataclass
class DecideExpression(Node):
    """decide between ["approve", "reject", "escalate"] given application_data"""
    options: Node = None
    given: Node = None
    criteria: Optional[str] = None

@dataclass
class AnalyzeExpression(Node):
    """analyze sales_data for "trends and anomalies" """
    data: Node = None
    objective: str = ""

@dataclass
class GenerateExpression(Node):
    """generate "email response" given complaint with tone = "professional" """
    target: str = ""
    given: Optional[Node] = None
    parameters: Dict[str, Node] = field(default_factory=dict)


# -- Observability --

@dataclass
class TraceBlock(Node):
    """trace "payment_processing"\n        process_payment(order)"""
    name: str = ""
    body: List[Node] = field(default_factory=list)

@dataclass
class LogStatement(Node):
    """log "Order processed: {order_id}" """
    message: Node = None
    level: str = "info"

@dataclass
class MeasureBlock(Node):
    """measure "query_time"\n        run_query(sql)"""
    name: str = ""
    body: List[Node] = field(default_factory=list)

@dataclass
class CheckpointStatement(Node):
    """checkpoint "before_payment" """
    name: str = ""


# -- Error handling --

@dataclass
class TryRecover(Node):
    """
    try
        risky_operation()
    recover error
        handle_error(error)
    """
    try_body: List[Node] = field(default_factory=list)
    error_variable: str = "error"  # variable name for the error
    recover_body: List[Node] = field(default_factory=list)


# -- HTTP Server --

@dataclass
class RouteDefinition(Node):
    """
    route "GET /products/:id" requires auth
        let p be find_product(params.id)
        give p
    """
    method: str = "GET"
    path: str = "/"                      # pattern, may contain :params
    param_names: List[str] = field(default_factory=list)  # named path params
    requires_auth: bool = False
    streaming: bool = False              # True when the body streams (SSE) instead of give
    rate_limit: Optional['RateLimitClause'] = None  # per-route override
    body: List[Node] = field(default_factory=list)

@dataclass
class StreamBlock(Node):
    """
    stream
        each tick in range(10)
            send {"count": tick}
    A route body that emits Server-Sent Events over time instead of one give.
    """
    body: List[Node] = field(default_factory=list)

@dataclass
class SendStatement(Node):
    """send <value> [as "event"] — emit one SSE event inside a stream block."""
    value: Node = None
    event_name: Optional[str] = None

@dataclass
class RateLimitClause(Node):
    """
    rate_limit 100 per minute   — a request rate limit (token bucket).
    rate_limit none             — disable an inherited default (unlimited=True).
    Declared on a serve block (default) or a route (override).
    """
    count: Optional[Node] = None         # expression → tokens per window
    window: str = "minute"               # second | minute | hour
    unlimited: bool = False              # `rate_limit none` / `unlimited`

@dataclass
class StaticMount(Node):
    """
    A static-file mount inside a serve block:
        static "./public"               -- prefix is None → mounted at "/"
        static "/assets" from "./assets" -- mounted under the "/assets" prefix
    """
    directory: Node = None               # expression: directory to serve from
    prefix: Optional[Node] = None        # expression: URL prefix, or None for "/"

@dataclass
class DescribeClause(Node):
    """
    Enriches the auto-generated /llms.txt:
        describe
            about: "Blog and waitlist"
            api: ["GET /blog/:slug — article", "POST /api/signup — join"]
    """
    about: Optional[Node] = None         # expression → text (site summary)
    api: Optional[Node] = None           # expression → list of endpoint descriptions

@dataclass
class ServeBlock(Node):
    """
    serve on 8080
        auth with check_token
        route "GET /products"
            give all_products()
    """
    port: Node = None                    # expression evaluating to the port number
    auth_handler: Optional[Node] = None  # expression resolving to the auth task
    max_body: Optional[Node] = None      # expression: max request body ("10mb"/bytes/"unlimited")
    max_streams: Optional[Node] = None   # expression: max concurrent SSE streams
    rate_limit: Optional['RateLimitClause'] = None  # default rate limit for all routes
    static_mounts: List['StaticMount'] = field(default_factory=list)  # static file mounts
    cors: Optional[Node] = None          # expression: CORS origin ("*" or "https://app.com")
    describe: Optional['DescribeClause'] = None  # enriches /llms.txt
    private: bool = False                # opt-out of agent discoverability (/llms.txt)
    routes: List[RouteDefinition] = field(default_factory=list)

@dataclass
class ExpectStatement(Node):
    """
    expect body {name: text, age: number}
    Validates the request's parsed JSON body against the declared shape.
    """
    target: str = "body"                 # what to validate (currently: body)
    shape: List[tuple] = field(default_factory=list)  # [(field_name, type_name)]
