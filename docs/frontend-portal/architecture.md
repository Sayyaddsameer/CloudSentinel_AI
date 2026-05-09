# Architecture — Frontend Portal
## Bogavalli Akash

How the portal is structured, how it connects to the backend, and what I added in v2.

---

## Overall flow

```mermaid
flowchart TD
    User([User]) --> Amplify[AWS Amplify\nStatic hosting]

    subgraph Portal pages
        Amplify --> Login[index.html\nLogin]
        Amplify --> Dash[dashboard.html\nMain Hub]
        Amplify --> Signup[signup.html\nRegister]
        Amplify --> History[history.html\nRisk History]
        Amplify --> Modules[cloud/devops/fullstack/data/mobile\nModule pages]
    end

    Login --> Cognito[Amazon Cognito]
    Signup --> Cognito
    Cognito -->|returns JWT tokens| Dash

    Dash --> API[API Gateway\nGET /risks?module=...]
    Dash --> Scan[POST /scan-*]
    Modules --> ChatAPI[POST /chat]

    API --> Cards[Risk cards rendered in UI]
    ChatAPI --> Bubble[Chat response bubble]

    style Cognito fill:#D13212,color:#fff
    style Amplify fill:#1A9C3E,color:#fff
    style API fill:#8C4FFF,color:#fff
```

---

## Login flow in detail

```mermaid
sequenceDiagram
    participant U as User
    participant FE as index.html + auth.js
    participant Cognito as Amazon Cognito
    participant LS as localStorage

    U->>FE: enters email + password, clicks Sign In
    FE->>Cognito: POST InitiateAuth\n{ AuthFlow: USER_PASSWORD_AUTH }
    Cognito-->>FE: AccessToken + IdToken + RefreshToken

    FE->>LS: store tokens
    FE->>FE: redirect to dashboard.html

    Note over FE: On every API call,\nread token from localStorage\nand put in Authorization header
```

---

## Dashboard tab state

```mermaid
stateDiagram-v2
    [*] --> CheckAuth
    CheckAuth --> LoginPage: no token
    CheckAuth --> DefaultTab: token found

    DefaultTab --> FetchRisks: load cloud-infra tab
    FetchRisks --> ShowCards: API returns data
    FetchRisks --> ShowEmpty: API returns empty
    FetchRisks --> ShowError: API or network error

    ShowCards --> ClickTab: user switches module
    ClickTab --> FetchRisks

    ShowCards --> ScanNow: user clicks Scan button
    ScanNow --> Loading: POST to /scan-*
    Loading --> FetchRisks: scan done
```

---

## File structure

```mermaid
flowchart LR
    FE[modules/frontend] --> Pages
    FE --> CSS[css/styles.css]
    FE --> Scripts[js/]
    FE --> Config[amplify.yml]

    Pages --> I[index.html - login]
    Pages --> D[dashboard.html - main hub]
    Pages --> S[signup.html - registration]
    Pages --> H[history.html - scan history]
    Pages --> M[cloud, devops, fullstack, data, mobile html]

    Scripts --> Auth[auth.js - Cognito and demo mode]
    Scripts --> App[app.js - shared utilities, risk rendering]
    Scripts --> Theme[theme.js - light/dark mode, anti-flash]
    Scripts --> Session[session.js - idle timeout, countdown, modal]
    Scripts --> ModJS[cloud, devops, fullstack, data, mobile js]
```

---

## Amplify build pipeline

```mermaid
flowchart LR
    Push([git push feature/frontend]) --> GH[GitHub]
    GH --> Amplify[Amplify auto-build]

    subgraph Build steps
        Amplify --> P[Provision]
        P --> B[Build - echo static]
        B --> Dep[Deploy modules/frontend]
        Dep --> V[URL live]
    end

    style GH fill:#24292e,color:#fff
    style Amplify fill:#1A9C3E,color:#fff
```

No npm build step needed since it's pure HTML/CSS/JS. Amplify just copies the files.

---

## Session management and security (v2)

I added a proper session timeout system because leaving the dashboard open indefinitely is a security risk, especially since the module connections give read access to the user's AWS account.

How the session timer works:
- session.js starts a 30-minute idle timer on login
- Any activity (mouse, keyboard, scroll) resets the timer
- At 5 minutes remaining, a toast notification appears
- At 60 seconds, a modal pops up with a Stay Logged In button
- If no action, auto-logout fires and redirects to login with reason=timeout in the URL
- Users can adjust the timeout from 15 minutes up to 8 hours by clicking the timer pill in the navbar

Login rate limiting:
- After 3 failed attempts the account locks for 60 seconds
- 5 attempts locks for 5 minutes, 10 attempts locks for 30 minutes
- Live countdown shows in a banner during lockout
- After the second fail an attempt counter warns the user before the threshold

Password strength meter on signup:
- Four-level meter based on length, uppercase, number, symbol presence
- Each requirement shows as a chip that turns green when met
- Weak passwords are blocked at submission before the API is called

Light and dark mode:
- theme.js runs in the head before the body renders so there is no flash of the wrong theme on load
- Toggle button in the navbar persists preference to localStorage

Scan history (history.html):
- Shows all past scans with trend indicators (more/fewer/same vs previous scan)
- Filter by module, export as JSON, or clear all
- Dashboard shows the 10 most recent scans in a Recent Activity feed at the bottom
