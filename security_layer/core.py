"""
AgentShield - Real AI Agent Security Middleware
A working security layer you wrap around ANY AI agent.
"""

import re
import time
import hashlib
import json
import logging
from typing import Callable, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from .llama_guard import LlamaGuard
from .ssrf_guard import ssrf_guard


logger = logging.getLogger("agentshield")

# ─────────────────────────────────────────────
#  EXCEPTIONS
# ─────────────────────────────────────────────

class SecurityViolation(Exception):
    """Raised when a real security threat is detected and blocked."""
    def __init__(self, layer: str, reason: str, severity: str = "HIGH"):
        self.layer = layer
        self.reason = reason
        self.severity = severity
        super().__init__(f"[AgentShield:{layer}] {reason}")


class RateLimitExceeded(SecurityViolation):
    def __init__(self, user_id: str, calls: int, limit: int):
        super().__init__("RATE_LIMITER", f"User '{user_id}' made {calls} calls, limit is {limit}/min", "MEDIUM")


# ─────────────────────────────────────────────
#  AUDIT LOG — real persistent log of all events
# ─────────────────────────────────────────────

@dataclass
class AuditEvent:
    timestamp: str
    layer: str
    action: str          # BLOCKED | ALLOWED | REDACTED | WARNED
    user_id: str
    detail: str
    severity: str = "INFO"

class AuditLogger:
    def __init__(self, log_file: Optional[str] = None):
        self.events: list[AuditEvent] = []
        self.log_file = log_file

    def record(self, layer: str, action: str, user_id: str, detail: str, severity: str = "INFO"):
        evt = AuditEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            layer=layer,
            action=action,
            user_id=user_id,
            detail=detail,
            severity=severity,
        )
        self.events.append(evt)
        log_fn = logger.warning if severity in ("HIGH", "CRITICAL") else logger.info
        log_fn(f"[{action}] [{layer}] user={user_id} | {detail}")
        if self.log_file:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(evt.__dict__) + "\n")
        return evt

    def summary(self) -> dict:
        blocked = [e for e in self.events if e.action == "BLOCKED"]
        return {
            "total_events": len(self.events),
            "blocked": len(blocked),
            "allowed": len([e for e in self.events if e.action == "ALLOWED"]),
            "redacted": len([e for e in self.events if e.action == "REDACTED"]),
            "by_layer": {
                layer: len([e for e in self.events if e.layer == layer])
                for layer in set(e.layer for e in self.events)
            }
        }


# ─────────────────────────────────────────────
#  LAYER 1 — INPUT GUARD (real pattern matching)
# ─────────────────────────────────────────────

# Real prompt injection and jailbreak patterns sourced from security research
INJECTION_PATTERNS = [
    # Direct instruction override
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|prior)\s+instructions?",
    r"forget\s+(everything|all|your\s+instructions?)",
    r"override\s+(your\s+)?(instructions?|rules?|guidelines?)",
    r"bypass\s+(your\s+)?(safety|security|restrictions?)",

    # Role/identity hijacking
    r"you\s+are\s+now\s+(a\s+)?(different|new|evil|unrestricted)",
    r"pretend\s+(you\s+are|to\s+be)\s+.{0,40}(no\s+restrictions?|unrestricted|without\s+rules?)",
    r"act\s+as\s+(if\s+you\s+(are|have|were)\s+)?.{0,30}(no\s+restrictions?|unrestricted)",
    r"your\s+(new|real|true)\s+(identity|name|purpose|role)\s+is",
    r"DAN\s+mode|jailbreak\s+mode|developer\s+mode",

    # System prompt extraction
    r"(print|show|reveal|tell\s+me|output|repeat|display)\s+(your\s+)?(system\s+prompt|instructions?|rules?|guidelines?)",
    r"what\s+(are\s+)?(your\s+)?(instructions?|system\s+prompt|rules?)",

    # Encoding attacks (base64 / hex obfuscation attempts)
    r"base64\s*:\s*[A-Za-z0-9+/]{20,}",
    r"decode\s+this\s+and\s+(follow|execute|run)",

    # Indirect injection via fake context
    r"<\s*system\s*>",
    r"\[INST\]|\[\/INST\]",
    r"###\s*(instruction|system|prompt|override)",
]

COMPILED_INJECTION = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in INJECTION_PATTERNS]

# Real PII patterns
PII_PATTERNS = {
    "EMAIL":        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'),
    "PHONE_US":     re.compile(r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "SSN":          re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "CREDIT_CARD":  re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'),
    "IP_ADDRESS":   re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "API_KEY":      re.compile(r'\b(sk-[A-Za-z0-9]{32,}|AIza[A-Za-z0-9_\-]{35}|[A-Za-z0-9]{32,40})\b'),
    "AWS_KEY":      re.compile(r'\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b'),
    "JWT":          re.compile(r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b'),
}

class InputGuard:
    """
    LAYER 1 — Real input validation.
    Scans every prompt before it reaches the LLM.
    """
    def __init__(self, max_length: int = 8000, sensitivity: float = 0.75):
        self.max_length = max_length
        self.sensitivity = sensitivity  # 0.0 to 1.0

    def scan(self, text: str, user_id: str, audit: AuditLogger) -> str:
        # 1. Length check
        if len(text) > self.max_length:
            audit.record("INPUT_GUARD", "BLOCKED", user_id,
                         f"Input length {len(text)} exceeds limit {self.max_length}", "MEDIUM")
            raise SecurityViolation("INPUT_GUARD", f"Input too long ({len(text)} chars, max {self.max_length})", "MEDIUM")

        # 2. Injection/jailbreak scan
        for pattern in COMPILED_INJECTION:
            match = pattern.search(text)
            if match:
                snippet = match.group(0)[:80]
                audit.record("INPUT_GUARD", "BLOCKED", user_id,
                             f"Injection pattern matched: '{snippet}'", "HIGH")
                raise SecurityViolation(
                    "INPUT_GUARD",
                    f"Prompt injection detected: '{snippet}'",
                    "HIGH"
                )

        # 3. Scan input for PII being sent in (warn, don't block)
        found_pii = self._find_pii(text)
        if found_pii:
            audit.record("INPUT_GUARD", "WARNED", user_id,
                         f"PII types detected in input: {list(found_pii.keys())}", "LOW")

        audit.record("INPUT_GUARD", "ALLOWED", user_id, f"Input passed ({len(text)} chars)")
        return text

    def _find_pii(self, text: str) -> dict:
        found = {}
        for name, pattern in PII_PATTERNS.items():
            if pattern.search(text):
                found[name] = True
        return found


# ─────────────────────────────────────────────
#  LAYER 2 — RATE LIMITER (real sliding window)
# ─────────────────────────────────────────────

class RateLimiter:
    """
    LAYER 2 — Sliding window rate limiter.
    Prevents tool flooding and denial-of-service from runaway agents.
    """
    def __init__(self, max_calls: int = 60, window_seconds: int = 60):
        self.max_calls = max_calls
        self.window = window_seconds
        self._windows: dict[str, deque] = defaultdict(deque)

    def check(self, user_id: str, audit: AuditLogger) -> int:
        """Returns current call count. Raises RateLimitExceeded if over limit."""
        now = time.time()
        window = self._windows[user_id]

        # Drop calls outside sliding window
        while window and window[0] < now - self.window:
            window.popleft()

        if len(window) >= self.max_calls:
            audit.record("RATE_LIMITER", "BLOCKED", user_id,
                         f"Rate limit hit: {len(window)}/{self.max_calls} calls in {self.window}s", "MEDIUM")
            raise RateLimitExceeded(user_id, len(window), self.max_calls)

        window.append(now)
        return len(window)


# ─────────────────────────────────────────────
#  LAYER 3 — TOOL FIREWALL (real allowlist + scope check)
# ─────────────────────────────────────────────

# Default destructive tools that require human approval
DESTRUCTIVE_TOOLS = {
    "delete_file", "drop_table", "send_email", "post_message",
    "execute_code", "run_shell", "write_file", "make_payment",
    "delete_record", "publish", "deploy", "terminate_instance",
}

class ToolFirewall:
    """
    LAYER 3 — Real tool execution firewall.
    Checks allowlists and blocks destructive actions.
    """
    def __init__(
        self,
        allowed_tools: Optional[set] = None,
        require_approval_fn: Optional[Callable] = None,
    ):
        self.allowed_tools = allowed_tools  # None = allow all (minus destructive)
        self.require_approval_fn = require_approval_fn  # callback for human approval

    def check(self, tool_name: str, tool_args: dict, user_id: str, audit: AuditLogger) -> bool:
        # 1. Allowlist check
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            audit.record("TOOL_FIREWALL", "BLOCKED", user_id,
                         f"Tool '{tool_name}' not in allowlist", "HIGH")
            raise SecurityViolation("TOOL_FIREWALL", f"Tool '{tool_name}' is not permitted", "HIGH")

        # 2. Destructive action gate
        if tool_name in DESTRUCTIVE_TOOLS:
            if self.require_approval_fn is not None:
                approved = self.require_approval_fn(tool_name, tool_args, user_id)
                if not approved:
                    audit.record("TOOL_FIREWALL", "BLOCKED", user_id,
                                 f"Destructive tool '{tool_name}' rejected by human reviewer", "HIGH")
                    raise SecurityViolation("TOOL_FIREWALL", f"Human reviewer rejected '{tool_name}'", "HIGH")
                audit.record("TOOL_FIREWALL", "ALLOWED", user_id,
                             f"Destructive tool '{tool_name}' approved by human reviewer")
            else:
                # No approval function — block all destructive tools by default
                audit.record("TOOL_FIREWALL", "BLOCKED", user_id,
                             f"Destructive tool '{tool_name}' blocked (no approval handler)", "HIGH")
                raise SecurityViolation(
                    "TOOL_FIREWALL",
                    f"Tool '{tool_name}' is destructive and no approval handler is configured",
                    "HIGH"
                )

        audit.record("TOOL_FIREWALL", "ALLOWED", user_id, f"Tool '{tool_name}' cleared")
        return True


# ─────────────────────────────────────────────
#  LAYER 4 — OUTPUT FILTER (real PII redaction)
# ─────────────────────────────────────────────

class OutputFilter:
    """
    LAYER 4 — Real output scanning.
    Redacts PII, blocks secret leakage, prevents system prompt echo.
    """
    def __init__(self, system_prompt: Optional[str] = None):
        self._prompt_hash = hashlib.sha256(system_prompt.encode()).hexdigest() if system_prompt else None
        self._prompt_phrases = self._extract_phrases(system_prompt) if system_prompt else []

    def _extract_phrases(self, text: str) -> list[str]:
        """Extract unique phrases from system prompt for leakage detection."""
        sentences = re.split(r'[.!?\n]', text)
        phrases = [s.strip() for s in sentences if len(s.strip()) > 20]
        # Also add sliding 6-word windows for partial leakage
        words = text.split()
        for i in range(len(words) - 5):
            chunk = " ".join(words[i:i+6])
            if len(chunk) > 20:
                phrases.append(chunk)
        return phrases

    def scan(self, text: str, user_id: str, audit: AuditLogger) -> str:
        redacted = text
        redaction_log = []

        # 1. Redact PII
        for pii_type, pattern in PII_PATTERNS.items():
            matches = pattern.findall(redacted)
            if matches:
                redacted = pattern.sub(f"[REDACTED:{pii_type}]", redacted)
                redaction_log.append(f"{pii_type}({len(matches)})")

        if redaction_log:
            audit.record("OUTPUT_FILTER", "REDACTED", user_id,
                         f"PII redacted from output: {', '.join(redaction_log)}", "MEDIUM")

        # 2. System prompt leakage detection
        if self._prompt_phrases:
            for phrase in self._prompt_phrases:
                if phrase.lower() in redacted.lower():
                    audit.record("OUTPUT_FILTER", "BLOCKED", user_id,
                                 "System prompt content detected in output", "CRITICAL")
                    raise SecurityViolation(
                        "OUTPUT_FILTER",
                        "Output contains system prompt content — response blocked",
                        "CRITICAL"
                    )

        if not redaction_log:
            audit.record("OUTPUT_FILTER", "ALLOWED", user_id, "Output clean — no PII/secrets found")

        return redacted


# ─────────────────────────────────────────────
#  LAYER 5 — MEMORY GUARD (context isolation)
# ─────────────────────────────────────────────

class MemoryGuard:
    """
    LAYER 5 — Per-session memory isolation.
    Prevents cross-user memory bleed, validates injected context.
    """
    def __init__(self, ttl_seconds: int = 3600):
        self._store: dict[str, dict] = {}
        self._timestamps: dict[str, float] = {}
        self.ttl = ttl_seconds

    def store(self, user_id: str, key: str, value: Any, audit: AuditLogger):
        if user_id not in self._store:
            self._store[user_id] = {}
        # Scan stored value for injection attempts
        if isinstance(value, str):
            for pattern in COMPILED_INJECTION:
                if pattern.search(value):
                    audit.record("MEMORY_GUARD", "BLOCKED", user_id,
                                 f"Injection pattern in memory value for key '{key}'", "HIGH")
                    raise SecurityViolation("MEMORY_GUARD", f"Memory value for '{key}' contains injection pattern")
        self._store[user_id][key] = value
        self._timestamps[user_id] = time.time()
        audit.record("MEMORY_GUARD", "ALLOWED", user_id, f"Stored key '{key}'")

    def retrieve(self, user_id: str, key: str, audit: AuditLogger) -> Optional[Any]:
        # TTL check
        ts = self._timestamps.get(user_id, 0)
        if time.time() - ts > self.ttl:
            if user_id in self._store:
                del self._store[user_id]
                audit.record("MEMORY_GUARD", "ALLOWED", user_id, "Session expired — memory cleared")
            return None
        return self._store.get(user_id, {}).get(key)

    def clear(self, user_id: str):
        self._store.pop(user_id, None)
        self._timestamps.pop(user_id, None)


# ─────────────────────────────────────────────
#  SHIELD CONFIG
# ─────────────────────────────────────────────

@dataclass
class ShieldConfig:
    # Input
    max_input_length: int = 8000
    sensitivity: float = 0.75

    # Rate limiting
    max_calls_per_minute: int = 60

    # Tools
    allowed_tools: Optional[set] = None          # None = allow all safe tools
    require_approval_fn: Optional[Callable] = None  # For destructive tools

    # Output
    system_prompt: Optional[str] = None           # Used for leakage detection

    # Memory
    memory_ttl_seconds: int = 3600

    # Audit
    audit_log_file: Optional[str] = None          # Path to write JSONL audit log


# ─────────────────────────────────────────────
#  AGENTSHIELD — THE MAIN CLASS
# ─────────────────────────────────────────────

class AgentShield:
    """
    The real AgentShield security layer.

    Wraps ANY callable AI agent with:
    - Prompt injection / jailbreak detection
    - Rate limiting
    - Tool allowlist + destructive action gating
    - Output PII redaction + system prompt leakage detection
    - Per-user memory isolation

    Usage:
        shield = AgentShield(config=ShieldConfig(...))

        # Option A: use as a wrapper
        safe_response = shield.run(
            user_input="...",
            user_id="user_123",
            agent_fn=my_agent.invoke
        )

        # Option B: call layers manually
        safe_input = shield.check_input(text, user_id)
        shield.check_tool("delete_file", args, user_id)
        safe_output = shield.filter_output(raw_output, user_id)
    """

    def __init__(self, config: Optional[ShieldConfig] = None):
        self.config = config or ShieldConfig()
        self.audit = AuditLogger(log_file=self.config.audit_log_file)
        self.input_guard = InputGuard(
            max_length=self.config.max_input_length,
            sensitivity=self.config.sensitivity,
        )
        self.rate_limiter = RateLimiter(max_calls=self.config.max_calls_per_minute)
        self.tool_firewall = ToolFirewall(
            allowed_tools=self.config.allowed_tools,
            require_approval_fn=self.config.require_approval_fn,
        )
        self.output_filter = OutputFilter(system_prompt=self.config.system_prompt)
        self.memory = MemoryGuard(ttl_seconds=self.config.memory_ttl_seconds)
        self._active = True
        self.llama_guard = LlamaGuard()
        self.ssrf_guard = ssrf_guard
        logger.info("AgentShield initialized — all 5 layers active + SSRFGuard")

    # ── Full lifecycle wrapper ──

    def run(
        self,
        user_input: str,
        user_id: str,
        agent_fn: Callable[[str], str],
        timeout_seconds: int = 60,
    ) -> str:
        """
        Run an agent call through the full security lifecycle.
        Raises SecurityViolation if any layer blocks the request.
        Returns the sanitized output.
        """
        import signal

        # 1. Input scan
        # LlamaGuard moderation before input_guard
        moderation_result = self.llama_guard.moderate_input(user_input)
        if not moderation_result.safe:
            self.audit.record("LLAMA_GUARD", "BLOCKED", user_id, moderation_result.blocked_message, "HIGH")
            raise SecurityViolation("LLAMA_GUARD", moderation_result.blocked_message, "HIGH")
        safe_input = self.check_input(user_input, user_id)

        # 2. Rate limit
        self.rate_limiter.check(user_id, self.audit)

        # 3. Run agent with timeout
        def _timeout_handler(signum, frame):
            raise SecurityViolation("TIMEOUT", f"Agent exceeded {timeout_seconds}s execution limit", "HIGH")

        old = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(timeout_seconds)
        try:
            raw_output = agent_fn(safe_input)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)

        # 4. LlamaGuard moderation on output
        moderation_result_out = self.llama_guard.moderate_output(user_input, raw_output)
        if not moderation_result_out.safe:
            self.audit.record("LLAMA_GUARD", "BLOCKED", user_id, moderation_result_out.blocked_message, "HIGH")
            raise SecurityViolation("LLAMA_GUARD", moderation_result_out.blocked_message, "HIGH")

        # 5. Filter output
        safe_output = self.filter_output(raw_output, user_id)

        return safe_output

    # ── Individual layer methods ──

    def check_input(self, text: str, user_id: str) -> str:
        """Layer 1: Validate and scan input. Returns cleaned input or raises."""
        return self.input_guard.scan(text, user_id, self.audit)

    def check_rate_limit(self, user_id: str) -> int:
        """Layer 2: Check rate limit. Returns call count or raises."""
        return self.rate_limiter.check(user_id, self.audit)

    def check_tool(self, tool_name: str, tool_args: dict, user_id: str) -> bool:
        """Layer 3: Validate tool call. Returns True or raises."""
        # SSRFGuard: Validate URLs in tool arguments before tool firewall
        urls_to_check = []
        for k, v in tool_args.items():
            if isinstance(v, str):
                all_safe, violations = self.ssrf_guard.validate_urls_in_text(v)
                if not all_safe:
                    self.audit.record("SSRF_GUARD", "BLOCKED", user_id, f"Blocked URLs: {violations}", "HIGH")
                    raise SecurityViolation("SSRF_GUARD", f"Blocked URLs: {violations}", "HIGH")
        return self.tool_firewall.check(tool_name, tool_args, user_id, self.audit)

    def filter_output(self, text: str, user_id: str) -> str:
        """Layer 4: Redact PII and check for leakage. Returns sanitized text."""
        return self.output_filter.scan(text, user_id, self.audit)

    def store_memory(self, user_id: str, key: str, value: Any):
        """Layer 5: Safely store to isolated user memory."""
        return self.memory.store(user_id, key, value, self.audit)

    def get_memory(self, user_id: str, key: str) -> Optional[Any]:
        """Layer 5: Retrieve from isolated user memory (respects TTL)."""
        return self.memory.retrieve(user_id, key, self.audit)

    def get_audit_summary(self) -> dict:
        """Returns a summary of all security events this session."""
        return self.audit.summary()

    def get_audit_log(self) -> list[AuditEvent]:
        """Returns the full audit log."""
        return self.audit.events
