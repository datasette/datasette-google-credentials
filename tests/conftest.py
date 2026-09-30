# Shared fixtures. The mock Google fixtures live in fixtures_google.py so
# later tickets can add theirs here without conflicts. The default suite must
# never contact real Google: _block_network (autouse) enforces it.
#
# The otel_* names are Datasette's OpenTelemetry test kit (ticket 20):
# importing them registers session-scoped autouse tracer/meter providers
# with in-memory synchronous export (skipped when the SDK isn't installed)
# and a per-test reset.
from datasette.telemetry_testing import (  # noqa: F401
    otel_meter_provider,
    otel_metrics,
    otel_provider,
    otel_reset,
    otel_spans,
)
from fixtures_google import (  # noqa: F401
    _block_network,
    mock_google,
    service_account_keys,
)


def pytest_collection_modifyitems(items):
    # assert_package_never_imports_sdk shells out to a fresh interpreter, and
    # its docstring documents a macOS/CPython 3.13 fork+exec crash (SIGBUS)
    # when subprocess-spawning tests run late in a thread-heavy process, so
    # run it first (as datasette-cron and core do).
    front = [
        item for item in items if item.name == "test_package_never_imports_the_sdk"
    ]
    for item in front:
        items.insert(0, items.pop(items.index(item)))
