# Clerk Authentication for Morphik-Core

Morphik-Core can be configured to use [Clerk](https://clerk.com/) for robust and flexible user authentication. This document outlines how to set up Clerk and configure Morphik-Core to use it.

## Why Clerk?

Clerk provides a comprehensive suite of tools for user management, authentication, and authorization, allowing for features like:
- Social sign-on (Google, GitHub, etc.)
- Multi-factor authentication (MFA)
- Organization management
- Customizable UI components (though Morphik-Core primarily uses it for backend token verification)

When Morphik-Core is integrated with Clerk, it verifies JWTs issued by Clerk, enabling secure access to its APIs. The `organization_id` from the Clerk token is used for data scoping, ensuring that users within an organization can only access data pertinent to their organization.

## Setting up Clerk

1.  **Create a Clerk Application:**
    *   Sign up or log in to your [Clerk Dashboard](https://dashboard.clerk.com/).
    *   Create a new application. Give it a name relevant to your Morphik-Core deployment.
    *   Choose your preferred authentication methods (e.g., Email/Password, Google, GitHub).

2.  **Find Your Secret Key:**
    *   In your Clerk application dashboard, navigate to **API Keys**.
    *   You will find several keys. The key you need for Morphik-Core is the **Secret Key**. It typically starts with `sk_live_` or `sk_test_`.
    *   Keep this key secure, as it allows bypassing Clerk's frontend validation.

## Configuring Morphik-Core

Once you have your Clerk Secret Key, you need to configure Morphik-Core to use it.

1.  **Set `CLERK_SECRET_KEY`:**
    This key can be set either in your `.env` file or in the `morphik.toml` configuration file.

    *   **Using `.env` file (recommended for sensitive keys):**
        Add the following line to your `.env` file at the root of your Morphik-Core project:
        ```env
        CLERK_SECRET_KEY="your_clerk_secret_key_here"
        ```

    *   **Using `morphik.toml`:**
        Under the `[auth]` section of your `morphik.toml` file, add:
        ```toml
        [auth]
        # ... other auth settings ...
        clerk_secret_key = "your_clerk_secret_key_here"
        # Note: Environment variable takes precedence if both are set.
        ```
    **Important:** If `dev_mode = true` in `morphik.toml` (under `[auth]`), Clerk authentication will be bypassed, and the dev user credentials will be used instead. Ensure `dev_mode` is `false` or commented out for Clerk authentication to be active.

2.  **Restart Morphik-Core:**
    After setting the `CLERK_SECRET_KEY`, restart your Morphik-Core application for the changes to take effect.

## Data Scoping with Organization ID

When a user authenticates via a Clerk-issued token, Morphik-Core can extract the `organization_id` (`org_id` claim in the JWT) if the user belongs to an organization within your Clerk application.

This `organization_id` is then used by Morphik-Core to scope data access:
-   **Folders, Documents, and Graphs** created by a user within an organization context will be associated with that `organization_id`.
-   Users will only be able to list, view, modify, or delete resources that are associated with their current active `organization_id` from the token.
-   This ensures data isolation between different organizations using the same Morphik-Core instance.

If a user is not part of any organization in Clerk, or if the `org_id` claim is not present in their token, they will typically access non-organization-scoped data (e.g., their personal data or data not explicitly tied to an organization).

## Generating Tokens for Testing

To interact with Morphik-Core APIs when Clerk authentication is enabled, you need a valid JWT issued by your Clerk application.

1.  **From Clerk's Test Environment:**
    *   In your Clerk application dashboard, navigate to **Sessions**. You can often find active session tokens here, or use the "JWT Templates" section to create test tokens with specific claims (like `org_id`).
    *   Remember to use a **Session token**, not an API key, for emulating user requests.

2.  **Using a Frontend Application with Clerk SDK:**
    *   If you have a frontend application integrated with the Clerk SDK (e.g., `@clerk/clerk-react`, `@clerk/nextjs`), the SDK handles token generation and refresh automatically.
    *   You can obtain the current session token from the SDK. For example, in JavaScript:
        ```javascript
        // Using Clerk's frontend SDK
        const { getToken } = useAuth(); // Example for React
        const token = await getToken();
        // or for Next.js App Router
        // import { auth } from "@clerk/nextjs/server";
        // const { getToken } = auth();
        // const token = await getToken();
        ```
    *   This token can then be used in the `Authorization: Bearer <token>` header when making requests to Morphik-Core.

3.  **Clerk Backend SDK (for server-to-server or testing scripts):**
    *   Clerk's backend SDKs can also be used to mint tokens, but this is typically for backend services acting on behalf of users or for specific testing scenarios. Refer to the official [Clerk Documentation](https://clerk.com/docs) for details on your specific language/SDK.

Always ensure your tokens have the necessary claims (like `sub` for user ID and optionally `org_id` for organization ID) for Morphik-Core to correctly identify the user and their organizational context.
