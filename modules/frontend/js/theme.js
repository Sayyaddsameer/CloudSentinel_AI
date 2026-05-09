/**
 * theme.js -- Light / Dark mode
 * Load this in <head> with a <script> tag so it runs before body paint.
 * Prevents flash-of-wrong-theme.
 */

const THEME_KEY = 'cs_theme';

function getTheme() {
  const stored = localStorage.getItem(THEME_KEY);
  if (stored === 'light' || stored === 'dark') return stored;
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem(THEME_KEY, theme);
  /* Update all toggle buttons on the page */
  document.querySelectorAll('.theme-toggle-btn').forEach(btn => {
    btn.textContent = theme === 'dark' ? 'Light' : 'Dark';
    btn.title = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
  });
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  setTheme(current === 'dark' ? 'light' : 'dark');
}

/* Apply immediately -- must run before DOM renders */
(function() { setTheme(getTheme()); })();
