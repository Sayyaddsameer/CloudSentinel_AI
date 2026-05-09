# Frontend Portal -- Architecture

## Overview

The CloudSentinel frontend is a static multi-page application hosted on
AWS S3 with static website hosting. It uses vanilla HTML, CSS, and JavaScript
with no frontend framework dependency, keeping bundle size minimal and
deployment straightforward.

---

## Pages

| File | Route | Auth Required |
|------|-------|---------------|
| `landing.html` | / | No -- public marketing page |
| `index.html` | /index.html | No -- sign-in page |
| `signup.html` | /signup.html | No -- account registration |
| `dashboard.html` | /dashboard.html | Yes |
| `cloud.html` | /cloud.html | Yes |
| `devops.html` | /devops.html | Yes |
| `fullstack.html` | /fullstack.html | Yes |
| `data.html` | /data.html | Yes |
| `mobile.html` | /mobile.html | Yes |
| `history.html` | /history.html | Yes |
| `terms.html` | /terms.html | No |
| `privacy.html` | /privacy.html | No |

---

## JavaScript Modules

| File | Purpose |
|------|---------|
| `js/env.js` | Runtime config: API URL, Cognito Pool ID, Client ID, Region |
| `js/auth.js` | Cognito sign-in, sign-up, sign-out, forgot password, get/clear session |
| `js/session.js` | Login-time countdown timer, auto-logout, credential revocation |
| `js/app.js` | Shared utilities: API calls, risk rendering, chatbot, disconnect API |
| `js/theme.js` | Dark/light mode toggle with localStorage persistence |
| `js/cloud.js` | Cloud Infrastructure module logic |
| `js/devops.js` | DevOps Intelligence module logic |
| `js/fullstack.js` | Full-Stack Intelligence module logic |
| `js/data.js` | Data Engineering module logic |
| `js/mobile.js` | Mobile Backend Intelligence module logic |
| `js/dashboard.js` | Dashboard overview with platform-wide chatbot |
| `js/chatbot.js` | Chatbot UI: open/close, message rendering, Markdown support |

---

## Authentication Flow

```
landing.html  -->  index.html (Sign In)
                         |
                   auth.js: cognitoSignIn()
                         |
                   Cognito returns IdToken, AccessToken, RefreshToken
                         |
                   Stored in localStorage: cs_user = { name, email, token, issuedAt }
                         |
                   requireAuth() called on every protected page
                         |
                   getToken() sends IdToken as Authorization header
```

### Forgot Password Flow (3 steps)

```
1. User enters email -> auth.js: forgotPassword()
   -> Cognito ForgotPassword API -> sends verification code to email

2. User enters code + new password -> auth.js: confirmForgotPassword()
   -> Cognito ConfirmForgotPassword API -> password updated

3. Redirect to sign-in
```

---

## Session Timer

The session timer is based on **login time** (stored in `cs_user.issuedAt`),
NOT on mouse/keyboard activity. This means:

- The timer counts down steadily regardless of user activity
- Switching tabs or navigating between module pages does NOT reset the timer
- On expiry: `autoDisconnectAll()` is called before redirect

```
initSessionTimer()
  --> _computeRemaining() = timeout - (now - session.issuedAt)
  --> _startInterval() recalculates every second from issuedAt
  --> At 5 min: warning toast
  --> At 1 min: modal with "Extend Session" button
  --> At 0:   _doAutoLogout()
                  --> autoDisconnectAll() [calls POST /disconnect for each module]
                  --> clearSession()
                  --> redirect to index.html?reason=timeout
```

---

## Automated Disconnect (Credential Revocation)

When a user clicks **Disconnect** on any module page, or when their session expires:

```
performDisconnect() / autoDisconnectAll()
  --> callDisconnectApi(module, provider)
        --> POST /disconnect { module, provider, roleArn, stackName }
        --> disconnect_handler Lambda:
              AWS: STS AssumeRole --> cloudformation:DeleteStack
              GCP: secretsmanager:DeleteSecret (ForceDeleteWithoutRecovery)
              DynamoDB: batch delete all risk records for module
  --> localStorage cleared: cs_conn_*, cs_scan_*, cs_history_*
```

---

## Chatbot Architecture

The chatbot appears as a floating action button (FAB) on all module pages
and on the main dashboard.

**Module pages** (cloud, devops, fullstack, data, mobile):
- Initialized by `initChatbot(module)` in `app.js`
- Chips: "Highest risk right now?", "How do I fix this?", "Compare priorities", "Best security practice?"
- Sends question + module context to POST /chat

**Dashboard page**:
- Initialized by `initDashboardChatbot()` in `dashboard.js`
- Chips: "What does CloudSentinel do?", "Which module first?", "How to connect AWS?", "What risks detected?"
- Platform-level Q&A + fallback to risk-specific answers

**Message rendering** (in `appendBotMessage()`):
- `**text**` -> bold
- `` `code` `` -> inline code
- `\n` -> line break
- Numbered lists preserved

---

## Dark / Light Mode

Landing page: standalone toggle with `localStorage` key `cs_landing_theme`.
Dashboard and module pages: `theme.js` with `localStorage` key `cs_theme`.
Default: dark mode.

---

## Deployment

```bash
# Sync all frontend files to S3
python sync_frontend.py

# Live URLs
Landing: http://cloudsentinel-frontend-<accountid>.s3-website-us-east-1.amazonaws.com/landing.html
Sign In: http://cloudsentinel-frontend-<accountid>.s3-website-us-east-1.amazonaws.com/index.html
```
