# Tech Specs — Frontend Module
## Bogavalli Akash

Reference notes for the portal.

---

## Stack

| Thing | What I'm using |
|-------|---------------|
| HTML | HTML5 semantic tags |
| CSS | Vanilla CSS, custom properties, no frameworks |
| JavaScript | ES6+, Fetch API, no jQuery |
| Auth | Amazon Cognito direct API call |
| Hosting | AWS Amplify static site |
| Local dev | VS Code + Live Server extension |

---

## Config values I need from Sameer

I put these at the top of `auth.js` and `dashboard.js`:

```javascript
// auth.js
const COGNITO_CONFIG = {
  UserPoolId: "us-east-1_XXXXXXXXX",  // from Sameer
  ClientId:   "XXXXXXXXXXXXXXXXX",    // from Sameer
  Region:     "us-east-1"
};

// dashboard.js
const API_BASE_URL = "https://xxx.execute-api.us-east-1.amazonaws.com/dev";
```

---

## auth.js — what it does

`login(email, password)`:
- Sends `InitiateAuth` to Cognito
- On success: stores `AccessToken` and `IdToken` in localStorage, redirects to dashboard
- On failure: shows error message in `#error-msg` div

`logout()`:
- Clears localStorage
- Redirects to index.html

`getToken()`:
- Returns `localStorage.getItem('accessToken')`
- Used by every API call in dashboard.js

Auth check on dashboard load: if no token in localStorage, redirect straight back to login.

---

## dashboard.js — what it does

`fetchRisks(module)`:
```javascript
fetch(`${API_BASE_URL}/risks?module=${module}`, {
  headers: { Authorization: getToken() }
})
```

`renderRiskCard(risk)`:
- Priority badge colored by `riskPriority`
- `riskType` as card title
- `resourceName` below title
- `riskReason` paragraph
- Expandable section: `remediationSteps` as list
- `aiExplanation` paragraph (may be empty initially)

`triggerScan(module)`:
```javascript
fetch(`${API_BASE_URL}/scan-${module}`, {
  method: "POST",
  headers: { Authorization: getToken() }
})
```

---

## CSS variables (themes)

```css
:root {
  --bg-primary:    #0d1117;
  --bg-card:       #21262d;
  --accent:        #58a6ff;
  --text-primary:  #c9d1d9;
  --high:          #f85149;
  --medium:        #e3b341;
  --low:           #3fb950;
  --border:        #30363d;
}
```

---

## amplify.yml

```yaml
version: 1
frontend:
  phases:
    build:
      commands:
        - echo "Static site"
  artifacts:
    baseDirectory: modules/frontend
    files:
      - '**/*'
```

No build command needed — just serving static files.

---

## Testing checklist I run before each PR

- [ ] Login with test Cognito user → redirects to dashboard
- [ ] Wrong password → shows error message (no redirect)
- [ ] Each module tab → risk cards appear (or empty state message)
- [ ] Chatbot → enter a question → response appears
- [ ] F12 Console → zero red CORS errors
- [ ] Logout → redirected to login page, can't navigate back to dashboard
