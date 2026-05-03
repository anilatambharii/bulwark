# API Reference

Every public surface in Bulwark, with signatures and examples. For deep
implementation context see [ARCHITECTURE.md](ARCHITECTURE.md).

## `bulwark.guard`

```python
def guard(
    executors: dict[str, ToolExecutor],
    config: BulwarkConfig | None = None,
    outbound_tools: list[str] | None = None,
    *,
    audit: AuditTrail | None = None,
    gate: HumanGate | None = None,
) -> dict[str, BulwarkSecuredExecutor]
```

Wraps each executor with the five-layer pipeline. Pass shared `audit` and
`gate` instances when you want a single forensic timeline across multiple
`guard()` calls.

**Raises:** `ConfigurationError` on empty input or non-callable values.

## `BulwarkConfig`

```python
class BulwarkConfig(BaseModel):
    alert_mode: Literal["log", "alert", "interrupt"] = "interrupt"
    threshold: float = 0.7
    compliance: list[str] = []
    agent_role: AgentRole = AgentRole.RESEARCH
    agent_id: str = "default"
    user_id: str = "default"
    sanitizer_config: SanitizerConfig
    detector_config: DetectorConfig | None = None  # filled from threshold
    rbac_config: RBACConfig
    audit_config: AuditConfig
    gate_config: GateConfig
```

* `alert_mode="interrupt"` — raise `InjectionDetectedError` on injection (production default).
* `alert_mode="alert"` — log a warning and continue (canary mode).
* `alert_mode="log"` — record but do not warn.

## `BulwarkSecuredExecutor`

The dataclass returned from `guard()`. Call it like the original executor;
introspect its `metrics` for observability.

```python
@dataclass
class BulwarkSecuredExecutor:
    tool_name: str
    original: ToolExecutor
    config: BulwarkConfig
    sanitizer: InputSanitizer
    detector: InjectionDetector
    rbac: RBACEnforcer
    audit: AuditTrail
    gate: HumanGate
    is_outbound: bool = False
    metrics: dict[str, int]    # calls, approved, blocked, escalated, denied
```

## Layer 1 — Sanitizer

```python
class SanitizerConfig(BaseModel):
    model_name: str = "distilbert-base-uncased"
    max_length: int = 8192
    enable_ml: bool = False
    strip_html: bool = True
    strip_zero_width: bool = True
    strip_bidi: bool = True
    normalize_unicode: bool = True
    decode_html_entities: bool = True
    device: Literal["cpu", "cuda", "mps", "auto"] = "cpu"

class SanitizerResult(BaseModel):     # frozen
    filtered_text: str
    risk_score: float                  # 0.0 (safe) → 1.0 (high risk)
    detected_patterns: list[str]
    bytes_removed: int
    truncated: bool
    is_safe: bool

class InputSanitizer:
    async def sanitize(self, untrusted_input: str) -> SanitizerResult: ...
    def sanitize_sync(self, untrusted_input: str) -> SanitizerResult: ...
```

## Layer 2 — Detector

```python
class DetectorConfig(BaseModel):
    model_path: str = "bulwark/models/injection_classifier"
    threshold: float = 0.7
    enable_ml: bool = False
    pattern_matching: bool = True
    ml_weight: float = 0.6
    pattern_weight: float = 0.4
    device: Literal["cpu", "cuda", "mps", "auto"] = "cpu"

class DetectionResult(BaseModel):     # frozen
    score: float
    ml_score: float
    pattern_score: float
    patterns: list[str]
    severities: dict[str, str]         # name -> "LOW"/"MEDIUM"/"HIGH"/"CRITICAL"
    confidence: float
    is_injection: bool
    explanation: str

class InjectionDetector:
    async def detect(self, text: str) -> DetectionResult: ...
    def detect_sync(self, text: str) -> DetectionResult: ...
```

## Layer 3 — RBAC

```python
class AgentRole(str, Enum):
    RESEARCH = "research"
    WRITE = "write"
    EMAIL = "email"
    FINANCIAL = "financial"
    ADMIN = "admin"

class ToolPermission(BaseModel):       # frozen
    tool_name: str
    allowed_roles: set[AgentRole]
    requires_confirmation: bool = False
    description: str = ""

class RBACConfig(BaseModel):
    default_role: AgentRole = AgentRole.RESEARCH
    permissions: list[ToolPermission]   # defaults from defaults.py
    deny_unknown_tools: bool = True

class RBACEnforcer:
    def check_permission(self, role: AgentRole | str, tool_name: str) -> bool: ...
    def requires_confirmation(self, tool_name: str) -> bool: ...
    def authorized_tools(self, role: AgentRole | str) -> list[str]: ...
    def grant(self, tool_name: str, roles: Iterable[AgentRole], *,
              confirmation: bool = False) -> None: ...
    def revoke(self, tool_name: str) -> None: ...
```

## Layer 4 — Gate

```python
class GateConfig(BaseModel):
    financial_threshold: float = 100.0
    data_deletion_threshold: int = 1
    credential_change: bool = True
    timeout_minutes: float = 5.0
    auto_approve_low_risk: bool = False
    low_risk_threshold: float = 0.2

class ConfirmationRequest(BaseModel):
    request_id: str
    agent_id: str
    action: str
    parameters: dict[str, Any]
    risk_score: float
    reason: str
    created_at: datetime
    expires_at: datetime
    status: ConfirmationStatus

class ConfirmationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    EXPIRED = "expired"

class ConfirmationDecision(BaseModel):
    request_id: str
    status: ConfirmationStatus
    approver: str | None
    note: str | None
    resolved_at: datetime
    @property
    def approved(self) -> bool: ...

class HumanGate:
    def add_channel(self, callback: NotificationCallback) -> None: ...
    def needs_confirmation(self, action: str,
                           parameters: dict[str, Any] | None = None) -> bool: ...
    async def request_confirmation(self, agent_id: str, action: str,
                                   parameters: dict | None = None,
                                   risk_score: float = 0.0,
                                   reason: str = "",
                                   timeout_minutes: float | None = None
                                   ) -> ConfirmationDecision: ...
    async def approve(self, request_id: str, *, approver: str,
                      note: str | None = None) -> bool: ...
    async def deny(self, request_id: str, *, approver: str,
                   note: str | None = None) -> bool: ...
    async def list_pending(self) -> list[ConfirmationRequest]: ...
```

## Layer 5 — Audit

```python
class AuditConfig(BaseModel):
    encryption_key: str | None = None
    encryption_keys: list[str] | None = None    # rotation
    retention_days: int = 2555
    compliance_mode: list[str] = ["HIPAA", "SOC2"]
    storage_path: str | None = None
    redact_fields: list[str] = ["password", "ssn", "api_key", "token", "secret"]

class AuditEntry(BaseModel):
    audit_id: str
    timestamp: datetime
    agent_id: str
    user_id: str
    tool_called: str
    input_data: dict[str, Any]
    output_data: dict[str, Any]
    risk_score: float
    decision: str            # 'approved' | 'blocked' | 'escalated' | 'denied' | 'error'
    source_data: list[str]
    reasoning_chain: str | None
    compliance_tags: list[str]
    layer: str | None
    duration_ms: float

class AuditTrail:
    def __init__(self, config: AuditConfig | None = None, *,
                 storage: AuditStorage | None = None) -> None: ...

    @property
    def encrypted(self) -> bool: ...

    async def log(self, entry: AuditEntry) -> str: ...
    async def get(self, audit_id: str) -> AuditEntry | None: ...
    async def query(self, *,
                    agent_id: str | None = None,
                    user_id: str | None = None,
                    tool_called: str | None = None,
                    decision: str | None = None,
                    start_time: datetime | None = None,
                    end_time: datetime | None = None,
                    min_risk: float | None = None,
                    compliance_tag: str | None = None,
                    limit: int | None = None,
                    ) -> list[AuditEntry]: ...
    async def purge_expired(self, *, now: datetime | None = None) -> int: ...
```

### Storage backends

```python
class AuditStorage(Protocol):
    async def append(self, audit_id: str, payload: bytes) -> None: ...
    async def read(self, audit_id: str) -> bytes | None: ...
    async def scan(self) -> AsyncIterator[tuple[str, bytes]]: ...

class InMemoryAuditStorage: ...     # default
class FileAuditStorage:             # one file per record
    def __init__(self, base_path: str | Path) -> None: ...
```

## Crypto helpers

```python
def generate_audit_key() -> str: ...

class AuditCipher:
    def __init__(self, keys: str | Sequence[str]) -> None: ...
    def encrypt(self, plaintext: str | bytes) -> bytes: ...
    def decrypt(self, token: bytes | str) -> bytes: ...
    def decrypt_text(self, token: bytes | str) -> str: ...
```

## Exceptions

```python
BulwarkError                # base
├── SecurityError           # base for policy denials
│   ├── InjectionDetectedError(score, patterns)
│   ├── PermissionDeniedError(role, tool)
│   └── ConfirmationDeniedError(action, reason)
├── ConfigurationError
└── AuditError
```

## Integrations

```python
# bulwark.integrations.mcp
def secure_tools(handlers, config=None, *, outbound_tools=None,
                 audit=None, gate=None) -> dict[str, BulwarkSecuredExecutor]: ...

class BulwarkMCPProxy:
    def __init__(self, server, config=None, *, outbound_tools=None) -> None: ...
    def register(self, name, handler) -> BulwarkSecuredExecutor: ...
    async def call_tool(self, name, arguments) -> Any: ...

# bulwark.integrations.anthropic
class BulwarkAnthropic:
    def __init__(self, client, config=None) -> None: ...
    # passes through .messages.create() with sanitization + detection

# bulwark.integrations.openai
class BulwarkOpenAI:
    def __init__(self, client, config=None) -> None: ...
    # wraps .chat.completions.create()

# bulwark.integrations.langchain
def secure_tool(name, func, config=None, *, is_outbound=False,
                audit=None, gate=None) -> BulwarkSecuredExecutor: ...
def secure_toolkit(tools, config=None, *, outbound_tools=None,
                   audit=None, gate=None) -> dict[str, BulwarkSecuredExecutor]: ...
```

## CLI

```
bulwark scan [--threshold 0.7] [--json] [TEXT]
bulwark sanitize [--json] [TEXT]
bulwark genkey
```
