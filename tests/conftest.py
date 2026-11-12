import pytest


@pytest.fixture(autouse=True)
def _isolated_config(tmp_path_factory, monkeypatch):
    """Never read or write the developer's real ~/.config/icp during tests."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path_factory.mktemp("xdg")))
    for var in ("ICP_ANISETTE_URL", "ICP_ANISETTE_PROTOCOL", "ICP_CLIENT_INFO", "ICP_2FA_METHOD"):
        monkeypatch.delenv(var, raising=False)
