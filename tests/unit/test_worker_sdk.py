import pytest

from mcp_hub.models import HubError
from mcp_hub.runtime import validate_worker_sdk


@pytest.mark.parametrize(
    "requirement",
    [
        "mcp>=1.30,<2",
        "mcp==1.30.0",
        "mcp==2.3.0",
        "mcp[cli]==2.3.0",
    ],
)
def test_worker_sdk_accepts_bounded_v1_or_exact_v2(requirement):
    validate_worker_sdk(requirement + "\nhttpx>=0.28\n")


@pytest.mark.parametrize(
    "requirement",
    [
        "mcp>=1.30",
        "mcp>=2",
        "mcp>=2.3,<3",
        "mcp==2.*",
        "mcp==3.0.0",
        "mcp==2.3.0,!=2.3.0",
        "mcp @ https://example.test/sdk.whl",
    ],
)
def test_unbounded_or_unsupported_worker_sdk_is_rejected(requirement):
    with pytest.raises(HubError) as error:
        validate_worker_sdk(requirement)
    assert error.value.status == 422
