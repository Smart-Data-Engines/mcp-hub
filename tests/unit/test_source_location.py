import pytest

from mcp_hub.registry import source_location


@pytest.mark.parametrize(
    "remote,provider,url",
    [
        (
            "git@bitbucket.org:team/registry.git",
            "Bitbucket",
            "https://bitbucket.org/team/registry/src/feature%2Fnew/alice/alpha",
        ),
        (
            "ssh://git@github.com/team/registry.git",
            "GitHub",
            "https://github.com/team/registry/tree/feature%2Fnew/alice/alpha",
        ),
        (
            "https://user:password@gitlab.com/team/registry.git?access_token=secret",
            "GitLab",
            "https://gitlab.com/team/registry/-/tree/feature%2Fnew/alice/alpha",
        ),
    ],
)
def test_web_locations_strip_authentication_and_encode_refs(settings, remote, provider, url):
    settings.registry_backend = "git"
    settings.registry_git_remote = remote
    info = source_location(settings, "alice/alpha", "feature/new")
    assert info["provider"] == provider and info["folder_url"] == url
    assert info["pinned"]


@pytest.mark.parametrize(
    "remote", ["file:///private/checkout", "javascript:alert(1)", "https://[invalid", ""]
)
def test_non_web_sources_never_become_links(settings, remote):
    settings.registry_backend = "git"
    settings.registry_git_remote = remote
    info = source_location(settings, "alice/alpha")
    assert info["repository_url"] is None and info["folder_url"] is None
    assert "private/checkout" not in info["repository"]
