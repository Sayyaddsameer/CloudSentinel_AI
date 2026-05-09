# Research Notes — Frontend
## Bogavalli Akash

Why I made the design and tech decisions I did.

---

## Why plain HTML/CSS/JS and not React or Vue

Honest answer: the portal doesn't need a framework. It's a dashboard that:
- Shows a login page
- Fetches a list of risks from an API
- Renders them as cards
- Has a chat interface

All of that is 100% doable with vanilla JS and `fetch()`. Adding React would mean a build step, a node_modules folder, Webpack or Vite config, and extra complexity for no real benefit at our project scale.

Amplify's static hosting also works better with plain HTML — no build configuration needed, just upload files.

---

## Cognito integration — why I implemented it manually instead of using Amplify Auth

The Amplify Auth SDK is designed for React/Vue apps. Since I'm using vanilla JS, integrating it would mean loading the entire Amplify JS library just to make one API call.

Instead I call the Cognito API directly with `fetch()` using the `InitiateAuth` action. It's just an HTTP POST with the username, password, and client ID. The response gives back the access token, ID token, and refresh token. I store those in localStorage.

This approach is:
- Simpler — no SDK dependency
- Transparent — easy to read and debug
- Sufficient for the project scope

---

## Design choices

Dark theme — I went dark because that's what most developer tools (GitHub, VS Code, AWS console itself) use. It also makes the color-coded risk badges (red/amber/green) stand out more clearly.

Color system: High = red (#f85149), Medium = amber (#e3b341), Low = green (#3fb950). These match the standard traffic light mental model that anyone in tech will immediately understand.

I wrote the base CSS as custom properties (CSS variables) so anyone on the team can change the color scheme by editing the `:root` block in `styles.css` without touching any HTML.

---

## CORS — what I learned the hard way

First time I deployed and tried to fetch from the API, the browser blocked every request with a CORS error. Spent about 30 minutes debugging before realizing the issue: API Gateway didn't have CORS enabled on the `/risks` route.

The fix is on Sameer's side (enable CORS on API Gateway and redeploy the stage), but from the frontend I also make sure my `fetch()` calls don't include custom headers that trigger a preflight unless absolutely necessary.

Good to know for future: CORS errors appear in browser DevTools under the Console tab, usually as `Access to fetch at '...' from origin '...' has been blocked by CORS policy`.

---

## Why Amplify over GitHub Pages or Netlify

I actually considered GitHub Pages first since we're already on GitHub. But:
- GitHub Pages doesn't support environment variables or build-time config
- We might need backend integrations in the future
- Amplify is part of the AWS ecosystem so it integrates cleanly with Cognito and API Gateway

Netlify would also work but introduces another platform account to manage.
