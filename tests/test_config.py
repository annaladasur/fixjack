from verify.inputs import GITHUB_API, Inputs, allowed_hosts_from_env, github_api


def test_github_api_defaults_to_github_com(monkeypatch):
    monkeypatch.delenv("FIXJACK_GITHUB_API", raising=False)
    assert github_api() == GITHUB_API


def test_github_api_follows_enterprise_server(monkeypatch):
    monkeypatch.setenv("FIXJACK_GITHUB_API", "https://ghe.example.internal/api/v3/")
    assert github_api() == "https://ghe.example.internal/api/v3"


def test_allow_hosts_env_unset_or_empty_means_default(monkeypatch):
    monkeypatch.delenv("FIXJACK_ALLOW_HOSTS", raising=False)
    assert allowed_hosts_from_env() == ()
    monkeypatch.setenv("FIXJACK_ALLOW_HOSTS", "")
    assert allowed_hosts_from_env() == ()
    assert "registry.npmjs.org" in Inputs.allowed_hosts


def test_allow_hosts_env_lists_an_internal_mirror(monkeypatch):
    monkeypatch.setenv("FIXJACK_ALLOW_HOSTS", " Artifacts.example.internal , registry.npmjs.org,")
    assert allowed_hosts_from_env() == ("artifacts.example.internal", "registry.npmjs.org")
