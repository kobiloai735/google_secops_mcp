// ============================================================
// הרץ את הקוד הזה ב-DevTools Console של secops-lab
// (F12 → Console → הדבק ולחץ Enter)
// ============================================================

(async () => {
  // נסה לשלוף token מתוך בקשות רשת פעילות
  const entries = performance.getEntriesByType('resource');
  const apiCalls = entries.filter(e => e.name.includes('chronicle') || e.name.includes('backstory'));

  if (apiCalls.length > 0) {
    console.log('Found API calls to Chronicle:');
    apiCalls.slice(0,3).forEach(e => console.log(' -', e.name));
  }

  // בקש token חדש דרך Google Identity
  try {
    const tokenResp = await fetch('/api/v1/auth/token').catch(() => null) ||
                      await fetch('/_ah/api/auth/v1/token').catch(() => null);
    if (tokenResp && tokenResp.ok) {
      const data = await tokenResp.json();
      console.log('Token from API:', data);
    }
  } catch(e) {}

  // הדפס הוראה לחלץ token מה-Network tab
  console.log(`
=== HOW TO GET YOUR TOKEN ===

1. Click the "Network" tab in DevTools
2. Reload the page (Ctrl+R)
3. In the filter box type: backstory OR chronicle
4. Click on any request
5. Go to "Headers" tab
6. Find: Authorization: Bearer <TOKEN>
7. Copy everything after "Bearer "

OR use this shortcut — type in Console:
  copy_token()

`);

  // הגדר helper function
  window.copy_token = function() {
    const allXhr = performance.getEntriesByType('resource')
      .filter(e => e.name.match(/backstory|chronicle/i))
      .map(e => e.name);
    console.log('Recent API URLs:', allXhr.slice(0,5));
    console.log('Open Network tab, reload, filter by "backstory", check Authorization header');
  };
})();
