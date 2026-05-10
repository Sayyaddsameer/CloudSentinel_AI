/**
 * auth.js -- Amazon Cognito authentication
 *
 * Requires window.ENV_COGNITO_POOL_ID, window.ENV_COGNITO_CLIENT_ID,
 * and window.ENV_API_URL to be set by js/env.js before this script loads.
 *
 * All auth flows use the Cognito USER_PASSWORD_AUTH flow directly
 * from the browser (public client -- no client secret).
 */

(function () {
  'use strict';

  const REGION    = window.ENV_REGION             || 'us-east-1';
  const CLIENT_ID = window.ENV_COGNITO_CLIENT_ID  || '';
  const POOL_ID   = window.ENV_COGNITO_POOL_ID     || '';

  const COGNITO_URL = `https://cognito-idp.${REGION}.amazonaws.com/`;

  /* ── Validation guard ─────────────────────────────────────── */
  function _assertConfigured() {
    if (!CLIENT_ID || !POOL_ID ||
        CLIENT_ID.startsWith('%%') || POOL_ID.startsWith('%%')) {
      throw new Error(
        'Cognito is not configured. ' +
        'Set COGNITO_POOL_ID, COGNITO_CLIENT_ID, and REGION in your deployment environment.'
      );
    }
  }

  /* ── Session helpers ──────────────────────────────────────── */
  function setSession(data) {
    localStorage.setItem('cs_user', JSON.stringify(data));
  }

  function getSession() {
    try { return JSON.parse(localStorage.getItem('cs_user') || 'null'); }
    catch { return null; }
  }

  function clearSession() {
    localStorage.removeItem('cs_user');
  }

  function getUser() {
    return getSession();
  }

  function requireAuth() {
    const u = getSession();
    if (!u) {
      window.location.href = 'index.html';
      return null;
    }
    return u;
  }

  function getToken() {
    const u = getSession();
    // API Gateway COGNITO_USER_POOLS authorizer validates the IdToken, NOT the AccessToken.
    return u ? (u.idToken || u.accessToken) : null;
  }

  /* ── Login ────────────────────────────────────────────────── */
  async function login(email, password) {
    _assertConfigured();

    const res = await fetch(COGNITO_URL, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.InitiateAuth',
      },
      body: JSON.stringify({
        AuthFlow:       'USER_PASSWORD_AUTH',
        ClientId:       CLIENT_ID,
        AuthParameters: { USERNAME: email, PASSWORD: password },
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const msg = err.message || err.__type || 'Authentication failed.';
      throw new Error(msg);
    }

    const data   = await res.json();
    const tokens = data.AuthenticationResult;

    /* Decode user attributes from the ID token (JWT payload) */
    const payload  = JSON.parse(atob(tokens.IdToken.split('.')[1]));
    const rawName  = payload.name || payload['cognito:username'] || email.split('@')[0];
    const name     = rawName
      .replace(/[._]/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());
    const initials = name.split(' ').map(p => p[0]).join('').slice(0, 2).toUpperCase();

    const user = {
      email:       payload.email || email,
      name,
      initials,
      sub:         payload.sub,
      accessToken: tokens.AccessToken,
      idToken:     tokens.IdToken,
      refreshToken: tokens.RefreshToken || '',
      expiresIn:   tokens.ExpiresIn     || 3600,
      issuedAt:    Date.now(),
    };

    setSession(user);
    return user;
  }

  /* ── Register ─────────────────────────────────────────────── */
  async function register(name, email, password) {
    _assertConfigured();

    const res = await fetch(COGNITO_URL, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.SignUp',
      },
      body: JSON.stringify({
        ClientId: CLIENT_ID,
        Username: email,
        Password: password,
        UserAttributes: [
          { Name: 'email', Value: email },
          { Name: 'name',  Value: name  },
        ],
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const msg = err.message || err.__type || 'Registration failed.';
      throw new Error(msg);
    }

    /* User must confirm email -- return email so the UI can show the code step. */
    const body = await res.json();
    return { pending: true, email };
  }

  /* ── Confirm sign-up (email verification code) ───────────── */
  async function confirmSignUp(email, code) {
    _assertConfigured();

    const res = await fetch(COGNITO_URL, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.ConfirmSignUp',
      },
      body: JSON.stringify({
        ClientId:         CLIENT_ID,
        Username:         email,
        ConfirmationCode: code,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const msg = err.message || err.__type || 'Confirmation failed.';
      throw new Error(msg);
    }

    return true;
  }

  /* ── Refresh access token ─────────────────────────────────── */
  async function refreshSession() {
    const u = getSession();
    if (!u || !u.refreshToken) return null;
    _assertConfigured();

    const res = await fetch(COGNITO_URL, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.InitiateAuth',
      },
      body: JSON.stringify({
        AuthFlow:       'REFRESH_TOKEN_AUTH',
        ClientId:       CLIENT_ID,
        AuthParameters: { REFRESH_TOKEN: u.refreshToken },
      }),
    });

    if (!res.ok) { clearSession(); return null; }

    const data   = await res.json();
    const tokens = data.AuthenticationResult;

    const updated = {
      ...u,
      accessToken: tokens.AccessToken,
      idToken:     tokens.IdToken,
      expiresIn:   tokens.ExpiresIn || 3600,
      issuedAt:    Date.now(),
    };
    setSession(updated);
    return updated;
  }

  /* ── Logout ───────────────────────────────────────────────── */
  async function logout() {
    /* Step 1: Revoke all cloud connections + delete stacks BEFORE clearing session */
    if (typeof autoDisconnectAll === 'function') {
      try { await autoDisconnectAll(); } catch (e) { /* non-blocking */ }
    }
    /* Step 2: Clear local session */
    clearSession();
    localStorage.removeItem('cs_last_activity');
    window.location.href = 'index.html';
  }

  /* ── Forgot Password -- sends code to email ───────────────── */
  async function forgotPassword(email) {
    _assertConfigured();
    const res = await fetch(COGNITO_URL, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.ForgotPassword',
      },
      body: JSON.stringify({ ClientId: CLIENT_ID, Username: email }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || err.__type || 'Failed to send reset code.');
    }
    return true;
  }

  /* ── Confirm Forgot Password -- verifies code + sets new pw ─ */
  async function confirmForgotPassword(email, code, newPassword) {
    _assertConfigured();
    const res = await fetch(COGNITO_URL, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.ConfirmForgotPassword',
      },
      body: JSON.stringify({
        ClientId:         CLIENT_ID,
        Username:         email,
        ConfirmationCode: code,
        Password:         newPassword,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || err.__type || 'Password reset failed.');
    }
    return true;
  }

  /* ── Expose globally ──────────────────────────────────────── */
  window.setSession              = setSession;
  window.getSession              = getSession;
  window.clearSession            = clearSession;
  window.getUser                 = getUser;
  window.requireAuth             = requireAuth;
  window.getToken                = getToken;
  window.login                   = login;
  window.register                = register;
  window.confirmSignUp           = confirmSignUp;
  window.refreshSession          = refreshSession;
  window.logout                  = logout;
  window.forgotPassword          = forgotPassword;
  window.confirmForgotPassword   = confirmForgotPassword;
})();
