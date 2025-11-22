# Authentik Setup Guide

This guide will help you configure the local Authentik instance to work with the VNC Manager.

## 1. Initial Setup

1.  **Start the containers**:
    ```bash
    docker-compose up -d
    ```
    *Wait for a few minutes for Authentik to initialize.*

2.  **Access the Admin Interface**:
    - Go to `http://localhost:9000/if/flow/initial-setup/`.
    - Set the password for the `akadmin` user.

## 2. Create a Provider

1.  Log in to the Admin Interface (`http://localhost:9000/if/admin/`).
2.  Go to **Applications** -> **Providers**.
3.  Click **Create**.
4.  Select **OAuth2/OpenID Provider**.
5.  **Name**: `VNC Manager Provider`
6.  **Authentication Flow**: `default-authentication-flow` (or similar default).
7.  **Authorization Flow**: `default-provider-authorization-implicit-consent` (to skip the consent screen) or `default-provider-authorization-explicit-consent`.
8.  **Client Type**: `Confidential`.
9.  **Redirect URIs**:
    ```
    http://localhost:8080/api/auth/callback/authentik
    ```
    *(Note: We are using port 8080 because that is where Nginx is listening and proxying to the backend)*
10. Click **Finish**.
11. **IMPORTANT**: Note down the **Client ID** and **Client Secret** from the provider details page.

## 3. Create an Application

1.  Go to **Applications** -> **Applications**.
2.  Click **Create**.
3.  **Name**: `VNC Manager`
4.  **Slug**: `vnc-manager`
5.  **Provider**: Select `VNC Manager Provider` (created in step 2).
6.  Click **Create**.

## 4. Configure Backend

1.  Create or update the `.env` file in `e:\workspaces\vnc2.0\backend\.env` (or the root `.env` if you prefer, but docker-compose expects it).
2.  Add the following variables:

    ```env
    AUTHENTIK_CLIENT_ID=your_client_id_here
    AUTHENTIK_CLIENT_SECRET=your_client_secret_here
    AUTHENTIK_SERVER_URL=http://authentik-server:9000
    SESSION_SECRET_KEY=some-random-string-for-sessions
    ```

3.  **Restart the backend**:
    ```bash
    docker-compose restart backend
    ```

## 5. Verify

1.  Go to `http://localhost:8080`.
2.  You should see the login page.
3.  (Once the frontend button is added) Click "Login with Authentik".
