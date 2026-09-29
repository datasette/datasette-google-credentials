# Shared fixtures. The mock Google fixtures live in fixtures_google.py so
# later tickets can add theirs here without conflicts. The default suite must
# never contact real Google: _block_network (autouse) enforces it.
from fixtures_google import (  # noqa: F401
    _block_network,
    mock_google,
    service_account_keys,
)
