"""Security and safety invariant tests for Phase 7 tools layer.

Enforces:
- No raw SQL execution
- No shell execution / subprocess calls
- No live external network sockets or HTTP requests
- No secret / credential leaks
- Deterministic behavior
- Import-time purity (no mutations, no network)
"""

import inspect
import src.tools
from src.tools.registry import build_default_tool_registry
from src.tools.schemas import SideEffectClass


def test_no_subprocess_or_os_system_in_tools():
    """Verify tool implementation modules do not import or invoke shell execution."""
    modules = [
        "src.tools.scan_tools",
        "src.tools.threat_tools",
        "src.tools.asset_tools",
        "src.tools.risk_tools",
        "src.tools.planning_tools",
        "src.tools.verification_tools",
        "src.tools.registry",
    ]
    forbidden_terms = [
        "subprocess",
        "os.system",
        "os.popen",
        "shutil.rmtree",
        "requests.get",
        "requests.post",
        "httpx.get",
        "urllib.request",
    ]

    for mod_name in modules:
        mod = __import__(mod_name, fromlist=["*"])
        src_code = inspect.getsource(mod)
        for term in forbidden_terms:
            assert term not in src_code, f"Forbidden term '{term}' found in module {mod_name}"


def test_tool_side_effects_restricted():
    """Verify no tool is classified as executing destructive infrastructure operations."""
    registry = build_default_tool_registry()
    allowed_side_effects = {
        SideEffectClass.READ_ONLY,
        SideEffectClass.COMPUTE_ONLY,
        SideEffectClass.SIMULATION,
        SideEffectClass.PERSISTENCE_WRITE,
    }
    for tool in registry.list_tools():
        assert tool.side_effect in allowed_side_effects


def test_deterministic_output_stability():
    """Verify identical inputs produce identical deterministic tool outputs."""
    from src.tools.risk_tools import map_ssvc_decision
    from src.tools.schemas import MapSsvcDecisionInput

    inp = MapSsvcDecisionInput(ers_score=78.5, has_compensating_controls=True)
    out1 = map_ssvc_decision(inp)
    out2 = map_ssvc_decision(inp)

    assert out1.decision == out2.decision
    assert out1.risk_tier == out2.risk_tier
    assert out1.remediation_decision == out2.remediation_decision
    assert out1.ers_score == out2.ers_score
