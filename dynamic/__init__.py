from .execute import DLLExecutor, ExecuteResult, BufferResult

try:
    from .runtime_probe import Tier3Result, run_tier3, TIER3_THRESHOLD
except NotImplementedError:
    pass  # Windows-only module; silently absent on other platforms
