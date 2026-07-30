// Aethersea GvG Stats — Discord OAuth + Role Gate
// Deploy: wrangler deploy
// Secrets: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, SESSION_SECRET, BASE_URL
// Vars: GUILD_ID, REQUIRED_ROLE_ID, SHEET_EMBED_URL

async function signCookie(value, secret) {
  var key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  var sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  var sigStr = btoa(String.fromCharCode.apply(null, new Uint8Array(sig))).replace(/=/g, '');
  return value + '.' + sigStr;
}

async function unsignCookie(signed, secret) {
  var dot = signed.lastIndexOf('.');
  if (dot === -1) return null;
  var value = signed.substring(0, dot);
  var sig = signed.substring(dot + 1);
  var key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  var expectedSig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  var expectedStr = btoa(String.fromCharCode.apply(null, new Uint8Array(expectedSig))).replace(/=/g, '');
  return sig === expectedStr ? value : null;
}

function htmlPage(body, title) {
  title = title || 'Aethersea GvG Stats';
  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n<title>' + title + '</title>\n<style>\n*{margin:0;padding:0;box-sizing:border-box}\nbody{font-family:\'Comic Sans MS\',\'Chalkboard SE\',cursive;background-color:#0a0a2e;background-image:radial-gradient(ellipse at 20% 50%,rgba(0,50,120,0.4) 0%,transparent 60%),radial-gradient(ellipse at 80% 50%,rgba(0,40,100,0.3) 0%,transparent 60%);color:#ccddff;min-height:100vh;cursor:url(\'https://lorddlazaro.github.io/media/momonga.gif\') 31 31,auto}\n.header{background:linear-gradient(180deg,#000d1a 0%,#002244 30%,#003d6b 60%,#002244 100%);border:4px outset #3399cc;margin:10px;padding:20px;text-align:center}\n.header h1{font-size:28px;color:#66ccff;text-shadow:2px 2px 0 #003366,0 0 15px #3399cc;letter-spacing:4px}\n.content{max-width:1200px;margin:10px auto;padding:0 10px;text-align:center}\n.sheet-wrap{width:100%;height:calc(100vh - 200px);min-height:500px;border:3px outset #3399cc;margin:10px 0;background:#fff}\n.sheet-wrap iframe{width:100%;height:100%;border:none}\n.access-denied{background:linear-gradient(180deg,rgba(100,0,0,0.4)0%,rgba(50,0,0,0.3)100%);border:3px outset #cc3333;padding:40px 20px;margin:40px auto;max-width:500px;text-align:center}\n.access-denied h2{color:#ff6666;font-size:24px;margin-bottom:15px}\n.access-denied p{color:#cc9999;font-size:14px;margin-bottom:10px;line-height:1.5}\n.login-btn{display:inline-block;background:linear-gradient(180deg,#1a1a44 0%,#0a0a2e 100%);border:3px outset #445577;color:#88aacc;font-family:\'Comic Sans MS\',\'Chalkboard SE\',cursive;font-size:16px;font-weight:bold;padding:12px 30px;cursor:pointer;text-decoration:none;margin-top:10px}\n.login-btn:hover{background:linear-gradient(180deg,#222266 0%,#111144 100%);color:#aaccdd}\n.loading{color:#66ccff;font-size:18px;margin:40px}\n.footer{text-align:center;padding:20px;color:#446688;font-size:12px;margin-top:20px}\n</style>\n</head>\n<body>\n<div class="header"><h1>\u{1F30A} AETHERSEA GvG STATS \u{1F30A}</h1></div>\n<div class="content">' + body + '</div>\n<div class="footer">AETHERSEA \u2014 Where Winds Meet &nbsp;|&nbsp; Est. 2025</div>\n</body>\n</html>';
}

function embedPage(env) {
  var sheetUrl = env.SHEET_EMBED_URL || 'https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID/pubhtml';
  return htmlPage(
    '<div class="sheet-wrap"><iframe src="' + sheetUrl + '" frameborder="0" allowfullscreen></iframe></div>' +
    '<p style="color:#88aacc;font-size:12px;">Data refreshes from Google Sheets automatically.</p>' +
    '<a class="login-btn" href="' + env.BASE_URL + '/logout" style="margin-top:5px;font-size:12px;padding:6px 15px;">Logout</a>'
  );
}

function deniedPage(env) {
  var loginUrl = 'https://discord.com/api/oauth2/authorize' +
    '?client_id=' + env.DISCORD_CLIENT_ID +
    '&redirect_uri=' + encodeURIComponent(env.BASE_URL + '/callback') +
    '&response_type=code' +
    '&scope=identify%20guilds%20guilds.members.read';
  return htmlPage(
    '<div class="access-denied">' +
    '<h2>\u26D4 Access Denied</h2>' +
    '<p>You must be a member of the Aethersea guild with the required role to view this page.</p>' +
    '<p>If you believe this is a mistake, please contact an officer in the guild Discord.</p>' +
    '<a class="login-btn" href="' + loginUrl + '">Try Again</a>' +
    '</div>',
    'Access Denied \u2014 Aethersea GvG Stats'
  );
}

async function exchangeCode(code, env) {
  var resp = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: env.BASE_URL + '/callback',
      scope: 'identify guilds guilds.members.read'
    })
  });
  return resp.ok ? await resp.json() : null;
}

async function verifyAccess(token, env) {
  if (!token) return false;

  var resp = await fetch('https://discord.com/api/users/@me/guilds', {
    headers: { Authorization: 'Bearer ' + token }
  });
  if (!resp.ok) return false;
  var guilds = await resp.json();
  var inGuild = guilds.some(function(g) { return g.id === env.GUILD_ID; });
  if (!inGuild) return false;

  var memResp = await fetch('https://discord.com/api/users/@me/guilds/' + env.GUILD_ID + '/member', {
    headers: { Authorization: 'Bearer ' + token }
  });
  if (!memResp.ok) return false;
  var member = await memResp.json();
  return member.roles && member.roles.indexOf(env.REQUIRED_ROLE_ID) !== -1;
}

function getSessionCookie(request) {
  var cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  var cookies = cookieHeader.split(';').map(function(c) { return c.trim(); });
  for (var i = 0; i < cookies.length; i++) {
    var pair = cookies[i].split('=');
    if (pair[0] === 'session') return pair[1];
  }
  return null;
}

export default {
  async fetch(request, env) {
    var url = new URL(request.url);
    var path = url.pathname;

    if (path === '/callback') {
      var code = url.searchParams.get('code');
      if (!code) return new Response('Missing code', { status: 400 });

      var tokens = await exchangeCode(code, env);
      if (!tokens) return new Response('Failed to exchange code', { status: 400 });

      var authorized = await verifyAccess(tokens.access_token, env);
      if (!authorized) {
        return new Response(deniedPage(env), {
          headers: { 'Content-Type': 'text/html;charset=utf-8' }
        });
      }

      var signed = await signCookie(tokens.access_token, env.SESSION_SECRET);
      return new Response(null, {
        status: 302,
        headers: {
          Location: env.BASE_URL + '/',
          'Set-Cookie': 'session=' + signed + '; HttpOnly; Secure; SameSite=Lax; Max-Age=86400; Path=/'
        }
      });
    }

    if (path === '/logout') {
      return new Response(null, {
        status: 302,
        headers: {
          Location: env.BASE_URL + '/',
          'Set-Cookie': 'session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/'
        }
      });
    }

    // Check session
    var rawCookie = getSessionCookie(request);
    var token = rawCookie ? await unsignCookie(rawCookie, env.SESSION_SECRET) : null;
    if (token) {
      var valid = await verifyAccess(token, env);
      if (valid) {
        return new Response(embedPage(env), {
          headers: { 'Content-Type': 'text/html;charset=utf-8' }
        });
      }
    }

    // Not authed — redirect to Discord
    var loginUrl = 'https://discord.com/api/oauth2/authorize' +
      '?client_id=' + env.DISCORD_CLIENT_ID +
      '&redirect_uri=' + encodeURIComponent(env.BASE_URL + '/callback') +
      '&response_type=code' +
      '&scope=identify%20guilds%20guilds.members.read';
    return new Response(null, {
      status: 302,
      headers: { Location: loginUrl }
    });
  }
};
