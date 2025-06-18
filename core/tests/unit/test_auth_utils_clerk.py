import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException, Header
from typing import Optional

from core.auth_utils import verify_token, settings as auth_settings # Import settings used by auth_utils
from core.models.auth import AuthContext, EntityType
from clerk_sdk import ClerkAPIException # Assuming this is the correct exception
from clerk_sdk.jwt import JWT # Not directly used by verify_token but good for context

# Fixture for common mock settings if needed, though individual patching might be clearer
@pytest.fixture(autouse=True)
def reset_settings_mocks():
    # Ensure each test gets a fresh settings mock if settings are modified by tests
    # This might be an overkill if settings are only read, but good practice.
    # If auth_settings is a module-level variable from get_settings(), we might need to patch get_settings()
    # For now, assuming auth_settings can be patched directly on the module if it's a simple object
    # or we patch its attributes if it's a Pydantic model.
    pass

@pytest.mark.asyncio
async def test_verify_token_successful():
    """Test successful token verification with organization_id."""
    mock_clerk_claims = {
        "sub": "user_test_id_123",
        "org_id": "org_test_id_456",
        # Add other claims Clerk might return, e.g., "iss", "exp", "iat", "sid"
        "iss": "https://clerk.your-domain.com",
        "exp": 9999999999, # A future timestamp
        "iat": 1600000000,
        "sid": "sess_test_id"
    }

    with patch('core.auth_utils.clerk_client.verify_token', return_value=mock_clerk_claims) as mock_verify, \
         patch('core.auth_utils.settings.dev_mode', False): # Ensure dev_mode is off

        auth_context = await verify_token(authorization="Bearer valid_token")

        mock_verify.assert_called_once_with(token="valid_token")
        assert isinstance(auth_context, AuthContext)
        assert auth_context.user_id == "user_test_id_123"
        assert auth_context.entity_id == "user_test_id_123" # entity_id should map to user_id
        assert auth_context.organization_id == "org_test_id_456"
        assert auth_context.entity_type == EntityType.USER
        assert auth_context.permissions == {"read", "write"} # Default permissions for Clerk users

@pytest.mark.asyncio
async def test_verify_token_successful_no_org_id():
    """Test successful token verification when org_id is missing."""
    mock_clerk_claims = {
        "sub": "user_test_id_789",
        "iss": "https://clerk.your-domain.com",
        "exp": 9999999999,
        "iat": 1600000000,
        "sid": "sess_test_id_abc"
    } # org_id is intentionally missing

    with patch('core.auth_utils.clerk_client.verify_token', return_value=mock_clerk_claims) as mock_verify, \
         patch('core.auth_utils.settings.dev_mode', False):

        auth_context = await verify_token(authorization="Bearer valid_token_no_org")

        mock_verify.assert_called_once_with(token="valid_token_no_org")
        assert auth_context.user_id == "user_test_id_789"
        assert auth_context.entity_id == "user_test_id_789"
        assert auth_context.organization_id is None
        assert auth_context.entity_type == EntityType.USER
        assert auth_context.permissions == {"read", "write"}

@pytest.mark.asyncio
async def test_verify_token_missing_authorization_header():
    """Test missing authorization header."""
    with patch('core.auth_utils.settings.dev_mode', False):
        with pytest.raises(HTTPException) as exc_info:
            # Call verify_token with authorization=None, which is the default for Header(None)
            await verify_token(authorization=None)
        assert exc_info.value.status_code == 401
        assert "Missing authorization header" in exc_info.value.detail

@pytest.mark.asyncio
async def test_verify_token_invalid_bearer_format():
    """Test invalid bearer token format."""
    with patch('core.auth_utils.settings.dev_mode', False):
        with pytest.raises(HTTPException) as exc_info:
            await verify_token(authorization="InvalidFormat token")
        assert exc_info.value.status_code == 401
        assert "Invalid authorization header" in exc_info.value.detail

@pytest.mark.asyncio
async def test_verify_token_clerk_api_exception():
    """Test ClerkAPIException handling."""
    # Example error structure from Clerk, may vary
    clerk_error = [{"message": "Token is invalid", "long_message": "The token signature is invalid.", "code": "token_invalid"}]

    with patch('core.auth_utils.clerk_client.verify_token', side_effect=ClerkAPIException("Clerk Error", errors=clerk_error)) as mock_verify, \
         patch('core.auth_utils.settings.dev_mode', False):

        with pytest.raises(HTTPException) as exc_info:
            await verify_token(authorization="Bearer problematic_token")

        mock_verify.assert_called_once_with(token="problematic_token")
        assert exc_info.value.status_code == 401
        assert "Invalid token: The token signature is invalid." in exc_info.value.detail

@pytest.mark.asyncio
async def test_verify_token_clerk_api_exception_no_errors_list():
    """Test ClerkAPIException handling when errors list is empty or not present."""
    with patch('core.auth_utils.clerk_client.verify_token', side_effect=ClerkAPIException("Clerk Error With No Detailed Errors", errors=[])) as mock_verify, \
         patch('core.auth_utils.settings.dev_mode', False):

        with pytest.raises(HTTPException) as exc_info:
            await verify_token(authorization="Bearer another_problem_token")

        mock_verify.assert_called_once_with(token="another_problem_token")
        assert exc_info.value.status_code == 401
        assert "Invalid token: Clerk Error With No Detailed Errors" in exc_info.value.detail


@pytest.mark.asyncio
async def test_verify_token_dev_mode_enabled():
    """Test dev_mode behavior."""
    # Mock the settings directly as they are imported at module level in auth_utils
    # We need to patch where 'settings' is looked up, which is 'core.auth_utils.settings'
    with patch('core.auth_utils.settings.dev_mode', True), \
         patch('core.auth_utils.settings.dev_entity_type', "developer") as mock_dev_type, \
         patch('core.auth_utils.settings.dev_entity_id', "dev_user_1") as mock_dev_id, \
         patch('core.auth_utils.settings.dev_permissions', ["dev_read", "dev_write"]) as mock_dev_perms, \
         patch('core.auth_utils.clerk_client.verify_token') as mock_clerk_verify: # Ensure Clerk is not called

        auth_context = await verify_token(authorization="Bearer any_token_dev_mode")

        mock_clerk_verify.assert_not_called() # Clerk verification should be bypassed
        assert isinstance(auth_context, AuthContext)
        assert auth_context.entity_type == EntityType("developer")
        assert auth_context.entity_id == "dev_user_1"
        assert auth_context.user_id == "dev_user_1" # In dev mode, user_id == entity_id
        assert auth_context.permissions == {"dev_read", "dev_write"}
        assert auth_context.organization_id is None # As per current verify_token logic for dev_mode

@pytest.mark.asyncio
async def test_verify_token_missing_sub_claim():
    """Test token verification when 'sub' claim is missing."""
    mock_clerk_claims_no_sub = {
        # "sub" is missing
        "org_id": "org_test_id_456",
        "iss": "https://clerk.your-domain.com",
        "exp": 9999999999,
        "iat": 1600000000,
        "sid": "sess_test_id"
    }

    with patch('core.auth_utils.clerk_client.verify_token', return_value=mock_clerk_claims_no_sub) as mock_verify, \
         patch('core.auth_utils.settings.dev_mode', False):

        with pytest.raises(HTTPException) as exc_info:
            await verify_token(authorization="Bearer token_missing_sub")

        mock_verify.assert_called_once_with(token="token_missing_sub")
        assert exc_info.value.status_code == 401
        assert "Invalid token: Missing user identifier" in exc_info.value.detail

@pytest.mark.asyncio
async def test_verify_token_unexpected_exception():
    """Test handling of unexpected exceptions during token verification."""
    with patch('core.auth_utils.clerk_client.verify_token', side_effect=RuntimeError("Unexpected internal error")) as mock_verify, \
         patch('core.auth_utils.settings.dev_mode', False):

        with pytest.raises(HTTPException) as exc_info:
            await verify_token(authorization="Bearer some_token")

        mock_verify.assert_called_once_with(token="some_token")
        assert exc_info.value.status_code == 500
        assert "Token processing error" in exc_info.value.detail

# Example of how to run tests with pytest:
# Ensure pytest and pytest-asyncio are installed:
# pip install pytest pytest-asyncio
# Then run from the root of your project:
# pytest core/tests/unit/test_auth_utils_clerk.py
