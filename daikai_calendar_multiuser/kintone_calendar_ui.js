/* Calendar integration pilot; install separately in App 1675 PC customization. */
(function () {
  'use strict';
  var APP_ID = 1675;
  var BACKEND = 'http://localhost:8080'; // Change to your HTTPS hostname after deployment.
  var PILOT_EMAIL = 'hc_wong@daikai.com'; // Hide the pilot from everyone else.
  var PANEL_ID = 'gc-pilot-v2';

  kintone.events.on('app.record.index.show', function (event) {
    if (kintone.app.getId() !== APP_ID) return event;
    var user = kintone.getLoginUser();
    if (!user || String(user.email).toLowerCase() !== PILOT_EMAIL) return event;
    var space = kintone.app.getHeaderSpaceElement();
    if (!space) return event;
    var old = document.getElementById(PANEL_ID);
    if (old) old.remove();

    var panel = document.createElement('div');
    panel.id = PANEL_ID;
    panel.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap;box-sizing:border-box;width:100%;padding:10px 16px;margin:0;background:#f7f9fc;border-bottom:1px solid #ddd;position:relative;z-index:1';
    var heading = document.createElement('strong');
    heading.textContent = 'Google Calendar — Pilot';
    panel.appendChild(heading);

    function button(text, path) {
      var item = document.createElement('button');
      item.type = 'button';
      item.textContent = text;
      item.style.cssText = 'padding:8px 12px;border:1px solid #ccc;background:white;border-radius:5px;cursor:pointer;font-size:13px';
      item.onclick = function () { window.open(BACKEND + path, '_blank', 'noopener,noreferrer'); };
      panel.appendChild(item);
    }
    button('Connect Google Calendar', '/google/connect');
    button('Sync Now', '/sync/preview');
    button('Manage / Disconnect', '/');
    space.appendChild(panel);
    return event;
  });
})();
