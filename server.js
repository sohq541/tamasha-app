const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { Readable } = require('stream');
const zlib = require('zlib');
const crypto = require('crypto');
const ffmpeg = require('fluent-ffmpeg');
ffmpeg.setFfmpegPath(require('ffmpeg-static'));
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const webpush = require('web-push');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme123';



const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || 'BOHLvhXAVxUKM5vGFbzlZ12dgf_yXLpGOrRlcLgEZ5tQrQwqCaFAEovjZXH5B1HDZ-B_Os5s90j_vuF_dWglHug';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '8FwcswgdL8jv1VNwCWZgfIsZcYJgiucD7-RjlBPYTMc';
webpush.setVapidDetails('mailto:sohailp541@gmail.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

app.use(cookieParser());
app.use(express.json());
// Render's free plan includes only 5 GB of outbound traffic a month, so JSON responses are gzip-compressed.
app.use((req, res, next) => {
  const orig = res.json.bind(res);
  res.json = (obj) => {
    if (!/\bgzip\b/.test(req.headers['accept-encoding'] || '') || res.headersSent) return orig(obj);
    const body = JSON.stringify(obj);
    if (body === undefined || body.length < 1024) return orig(obj);
    zlib.gzip(body, (err, buf) => {
      if (err) return orig(obj);
      res.set({ 'Content-Type': 'application/json; charset=utf-8', 'Content-Encoding': 'gzip', 'Vary': 'Accept-Encoding', 'Content-Length': buf.length });
      res.end(buf);
    });
    return res;
  };
  next();
});

// Suspended accounts: their login is blocked, and any session they already had (30-day token) stops working too.
const suspendedIds = new Set();
async function refreshSuspendedIds() {
  try {
    const users = await readUsers();
    suspendedIds.clear();
    users.forEach(u => { if (u && u.suspended) suspendedIds.add(u.id); });
  } catch (e) { /* storage hiccup: keep the previous list */ }
}

function getUserFromReq(req) {
  const token = req.cookies.token;
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload && suspendedIds.has(payload.id)) return null;
    return payload;
  } catch (e) { return null; }
}

const ADMIN_COOKIE = 'admin_token';
function safeEq(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function isAdminBasicAuth(req) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.split(' ')[1], 'base64').toString();
    const idx = decoded.indexOf(':');
    const user = decoded.slice(0, idx), pass = decoded.slice(idx + 1);
    if (idx > -1 && safeEq(user, ADMIN_USER) && safeEq(pass, ADMIN_PASS)) return true;
  }
  const tok = req.cookies && req.cookies[ADMIN_COOKIE];      // login form on the dashboard sets this cookie
  if (tok) { try { const p = jwt.verify(tok, JWT_SECRET); return !!(p && p.role === 'admin'); } catch (e) {} }
  return false;
}

function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}

function toBool(v) { return v === true || v === 'true'; }
function extractHashtags(text) {
  const matches = String(text || '').match(/#(\w+)/g) || [];
  const tags = matches.map(t => t.slice(1).toLowerCase());
  return [...new Set(tags)].slice(0, 30);
}
function escapeRegex(str) { return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function findMentionedUsers(text, users) {
  const src = String(text || '');
  if (!src.includes('@')) return [];
  const found = [];
  const sorted = users.filter(u => u.username).slice().sort((a, b) => b.username.length - a.username.length);
  for (const u of sorted) {
    const re = new RegExp('@' + escapeRegex(u.username) + '(?![\\w])', 'i');
    if (re.test(src)) found.push({ id: u.id, username: u.username });
    if (found.length >= 10) break;
  }
  return found;
}
async function notifyMentions(text, fromUser, context) {
  const users = await readUsers();
  const mentioned = findMentionedUsers(text, users);
  for (const m of mentioned) {
    if (m.id === fromUser.id) continue;
    const target = users.find(u => u.id === m.id);
    if (target && (target.blockedUsers || []).includes(fromUser.id)) continue;
    await notify(m.id, {
      type: 'mention', fromUserId: fromUser.id, fromUsername: fromUser.username,
      filmId: context.filmId || null,
      message: `@${fromUser.username} mentioned you ${context.label || ''}`
    });
  }
  return mentioned;
}

// Collab: resolve "@username" (or plain username) to an existing user, and invite them
async function decorateNewFilm(newFilm, body, currentUser) {
  const users = await readUsers();
  newFilm.mentions = findMentionedUsers((newFilm.title || '') + ' ' + (newFilm.description || ''), users);
  const raw = String((body && body.collabUsername) || '').trim().replace(/^@/, '');
  if (raw && currentUser) {
    const target = users.find(u => (u.username || '').toLowerCase() === raw.toLowerCase());
    if (target && target.id !== currentUser.id && !(target.blockedUsers || []).includes(currentUser.id)) {
      newFilm.collaboratorId = target.id;
      newFilm.collaboratorUsername = target.username;
      newFilm.collabStatus = 'pending';
    }
  }
}
function getFilmHashtags(f) {
  const base = (f.hashtags && f.hashtags.length) ? f.hashtags : extractHashtags((f.title || '') + ' ' + (f.description || ''));
  const commentText = (f.comments || []).map(c => c.text || '').join(' ');
  if (!commentText.includes('#')) return base;
  return [...new Set([...base, ...extractHashtags(commentText)])];
}
function isFilmOwnerOrCollab(f, userId) {
  return !!(userId && (f.ownerId === userId || (f.collabStatus === 'accepted' && f.collaboratorId === userId)));
}
async function notifyCollabInvite(newFilm, currentUser) {
  if (newFilm.collabStatus !== 'pending' || !currentUser) return;
  await notify(newFilm.collaboratorId, {
    type: 'collab_invite', fromUserId: currentUser.id, fromUsername: currentUser.username,
    filmId: newFilm.id, message: `@${currentUser.username} ne tumhe "${newFilm.title}" pe collab ke liye invite kiya`
  });
}

// ---------------- File storage: Google Drive only ----------------
// Every file (videos, photos, avatars, stories, chat media) and the JSON "database" files live in one Google Drive folder.
// Each Drive file is named by its key (e.g. "videos/abc.mp4", "films.json"). See the Google Drive section below.
const gdReady = () => gdEnabled();
function storeNeedsDrive() {
  if (!gdReady()) { const e = new Error('Google Drive is not configured (GDRIVE_CLIENT_ID / GDRIVE_CLIENT_SECRET / GDRIVE_REFRESH_TOKEN)'); e.status = 503; throw e; }
}
async function storePutBuffer(buffer, key, contentType) { storeNeedsDrive(); await gdPutByKey(key, buffer, contentType); }
async function storeCopy(sourceKey, destKey) {
  storeNeedsDrive();
  const srcId = typeof sourceKey === 'string' && sourceKey.startsWith('gd:') ? sourceKey.slice(3) : await gdResolve(sourceKey);
  if (!srcId) { const e = new Error('Original file not found on Drive'); e.status = 404; throw e; }
  // Drive copies the file on its own side: no bytes pass through this server, so no Render bandwidth is used
  const r = await fetch(`${GD.apiBase}/files/${srcId}/copy?fields=id`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + await gdAccessToken(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: destKey, parents: [await gdFolderId()] })
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.id) throw new Error('Drive copy failed (' + r.status + ')');
  gdIdx.set(destKey, j.id);
  await gdMakePublic(j.id);
  gdIdxShared.set(destKey, true);
}
async function storeDelete(key) {
  if (typeof key === 'string' && key.startsWith('gd:')) { await gdDelete(key.slice(3)); return; }
  try { const id = await gdResolve(key); if (id) { await gdDelete(id); gdIdx.delete(key); } } catch (e) {}
}
async function storeUrl(key) {                                   // a link the browser can open (direct Google link or our /media route)
  storeNeedsDrive();
  const id = typeof key === 'string' && key.startsWith('gd:') ? key.slice(3) : await gdResolve(key);
  if (!id) throw new Error('File not found');
  return gdMediaUrl(id);
}
async function storeStream(key, req, res) {                      // serve a stored file through this server (used by old-style routes)
  const id = typeof key === 'string' && key.startsWith('gd:') ? key.slice(3) : await gdResolve(key).catch(() => null);
  if (!id) return res.status(404).send('Not found');
  return gdServe(id, req, res);
}
// one place that turns a stored key into a URL for the browser; never throws
function makeDirectUrlCache() {
  const cache = {};
  return async function directUrl(key) {
    if (!key) return null;
    if (cache[key]) return cache[key];
    try { const url = await storeUrl(key); cache[key] = url; return url; } catch (e) { return null; }
  };
}

// ---- Usage tracking (shown in the admin dashboard) ----
// Usage counters shown on the dashboard: JSON reads from Drive (exact), media served through this server (exact).
const STORAGE_LIMIT_BYTES = (parseFloat(process.env.STORAGE_LIMIT_GB) || 10) * 1024 * 1024 * 1024;
const usage = { month: new Date().toISOString().slice(0, 7), jsonBytes: 0, mediaBytes: 0, proxyBytes: 0, views: 0, dirty: false };
function usageRoll() {
  const m = new Date().toISOString().slice(0, 7);
  if (usage.month !== m) { usage.month = m; usage.jsonBytes = 0; usage.mediaBytes = 0; usage.proxyBytes = 0; usage.views = 0; usage.dirty = true; }
}
function usageAdd(field, n) { usageRoll(); usage[field] += n || 0; usage.dirty = true; }

// The JSON "database" files are cached in memory (this server is the only writer), so Drive is read once per
// JSON_CACHE_SECONDS instead of on every request. Writes update the cache straight away.
const JSON_CACHE_MS = (parseInt(process.env.JSON_CACHE_SECONDS, 10) || 3600) * 1000;
const jsonCache = new Map();
async function storeReadJSON(key) {
  const hit = jsonCache.get(key);
  if (hit && Date.now() - hit.at < JSON_CACHE_MS) return JSON.parse(hit.raw);
  const pend = gdPending.get(key);                               // a write that has not reached Drive yet is the newest truth
  if (pend) return JSON.parse(pend.raw);
  const buf = await gdGetByKey(key);
  usageAdd('jsonBytes', buf.length);
  const raw = buf.toString('utf-8');
  jsonCache.set(key, { at: Date.now(), raw });
  return JSON.parse(raw);
}

async function storeTryReadJSON(key) {
  try { return await storeReadJSON(key); } catch (e) { return null; }
}

async function storeWriteJSON(key, data) {
  const raw = JSON.stringify(data, null, 2);
  jsonCache.set(key, { at: Date.now(), raw });
  gdQueueJSON(key, raw);                                          // write-behind: memory now, Drive within a few seconds
}







// ---------------- Notifications ----------------
async function notify(toUserId, { type, fromUserId, fromUsername, filmId, storyId, conversationId, message }) {
  if (!toUserId || toUserId === fromUserId) return;
  try {
    const notifications = await storeTryReadJSON('notifications.json') || [];
    notifications.push({
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      userId: toUserId, type, fromUserId, fromUsername,
      filmId: filmId || null, storyId: storyId || null, conversationId: conversationId || null,
      message, read: false, createdAt: new Date().toISOString()
    });
    await storeWriteJSON('notifications.json', notifications.slice(-500));
  } catch (e) { console.error('notify failed:', e.message); }
  sendPushToUser(toUserId, { title: 'YouSeries', body: message, filmId, storyId, conversationId, fromUserId, fromUsername }).catch(() => {});
}

async function sendPushToUser(userId, payload) {
  const subs = await storeTryReadJSON('push-subscriptions.json') || [];
  const mine = subs.filter(s => s.userId === userId);
  if (!mine.length) return;
  let changed = false;
  for (const s of mine) {
    try {
      await webpush.sendNotification(s.subscription, JSON.stringify(payload));
    } catch (err) {
      if (err.statusCode === 404 || err.statusCode === 410) {
        const idx = subs.indexOf(s);
        if (idx !== -1) { subs.splice(idx, 1); changed = true; }
      }
    }
  }
  if (changed) await storeWriteJSON('push-subscriptions.json', subs);
}

function generateThumbnail(videoBuffer, ext) {
  return new Promise((resolve, reject) => {
    const tmpDir = os.tmpdir();
    const uniq = Date.now() + '-' + Math.random().toString(36).slice(2);
    const inputPath = path.join(tmpDir, `in-${uniq}${ext || '.mp4'}`);
    const outputName = `thumb-${uniq}.jpg`;
    const outputPath = path.join(tmpDir, outputName);
    fs.writeFileSync(inputPath, videoBuffer);
    ffmpeg(inputPath)
      .on('end', () => {
        try {
          const buf = fs.readFileSync(outputPath);
          fs.unlinkSync(inputPath);
          fs.unlinkSync(outputPath);
          resolve(buf);
        } catch (err) { reject(err); }
      })
      .on('error', (err) => {
        try { fs.unlinkSync(inputPath); } catch (e) {}
        reject(err);
      })
      .screenshots({ count: 1, timemarks: ['2'], filename: outputName, folder: tmpDir, size: '640x?' });
  });
}

// ---------------- Films "database" ----------------
let filmsCache = { data: null, expiresAt: 0 };
const FILMS_CACHE_MS = 15000;

async function readFilms() {
  if (filmsCache.data && Date.now() < filmsCache.expiresAt) return filmsCache.data;
  const films = await storeTryReadJSON('films.json') || [];
  filmsCache = { data: films, expiresAt: Date.now() + FILMS_CACHE_MS };
  return films;
}

async function writeFilms(films) {
  await storeWriteJSON('films.json', films);
  filmsCache = { data: films, expiresAt: Date.now() + FILMS_CACHE_MS };
}

// ---------------- Users "database" ----------------
async function readUsers() {
  return await storeTryReadJSON('users.json') || [];
}
async function writeUsers(users) {
  await storeWriteJSON('users.json', users);
}

// ---------------- Express setup ----------------
const uploadTmpDir = path.join(os.tmpdir(), 'uploads');
if (!fs.existsSync(uploadTmpDir)) fs.mkdirSync(uploadTmpDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadTmpDir,
    filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + path.extname(file.originalname))
  }),
  limits: { fileSize: 500 * 1024 * 1024 }
});

function readFileAsBuffer(filePath) {
  const buf = fs.readFileSync(filePath);
  fs.unlink(filePath, () => {});
  return buf;
}

app.get('/moderation.html', (req, res) => {
  if (!isAdminBasicAuth(req)) {
    res.set('WWW-Authenticate', 'Basic realm="Moderation"');
    return res.status(401).send('Admin login required');
  }
  res.sendFile(path.join(__dirname, 'public', 'moderation.html'));
});

const gzStatic = new Map();
app.use((req, res, next) => {
  if (req.method !== 'GET' || !/\bgzip\b/.test(req.headers['accept-encoding'] || '')) return next();
  const rel = req.path === '/' ? '/index.html' : req.path;
  if (!/\.(html|js|css|svg|json|txt)$/i.test(rel) || rel.includes('..')) return next();
  const file = path.join(__dirname, 'public', rel);
  if (!file.startsWith(path.join(__dirname, 'public'))) return next();
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return next();
    const cached = gzStatic.get(file);
    const send = buf => {
      res.type(path.extname(file));
      res.set({ 'Content-Encoding': 'gzip', 'Vary': 'Accept-Encoding', 'Cache-Control': 'no-cache', 'Content-Length': buf.length });
      res.end(buf);
    };
    if (cached && cached.mtime === st.mtimeMs) return send(cached.buf);
    fs.readFile(file, (e2, data) => {
      if (e2) return next();
      zlib.gzip(data, { level: 9 }, (e3, buf) => {
        if (e3) return next();
        gzStatic.set(file, { mtime: st.mtimeMs, buf });
        send(buf);
      });
    });
  });
});
app.use(express.static(path.join(__dirname, 'public')));

// ===================== AUTH ROUTES =====================

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, username, ageConfirm, securityQuestion, securityAnswer } = req.body;
    if (!email || !password || !username) return res.status(400).json({ error: 'Email, password and username are required' });
    if (!ageConfirm) return res.status(400).json({ error: 'You must confirm that you will not upload 18+ content' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (!securityQuestion || !securityAnswer || !securityAnswer.trim()) return res.status(400).json({ error: 'A security question and answer are required' });

    const users = await readUsers();
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) return res.status(400).json({ error: 'This email is already registered' });
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(400).json({ error: 'This username is already taken' });

    const passwordHash = await bcrypt.hash(password, 10);
    const securityAnswerHash = await bcrypt.hash(securityAnswer.trim().toLowerCase(), 10);
    const newUser = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
      email, username, passwordHash, securityQuestion, securityAnswerHash,
      usernameChanges: [], bio: '', website: '', following: [],
      createdAt: new Date().toISOString()
    };
    users.push(newUser);
    await writeUsers(users);

    const token = signToken(newUser);
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ id: newUser.id, email: newUser.email, username: newUser.username });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const users = await readUsers();
    const user = users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
    if (!user) return res.status(401).json({ error: 'Incorrect email or password' });
    if (!user.passwordHash) return res.status(401).json({ error: 'This account was created with Google. Please use "Continue with Google" below to log in.' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Incorrect email or password' });
    if (user.suspended) return res.status(403).json({ error: 'Ye account suspend kar diya gaya hai community guidelines violate karne ki wajah se.' });
    const token = signToken(user);
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ id: user.id, email: user.email, username: user.username });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ success: true }); });

// ---------------- Google OAuth ----------------
function googleRedirectUri(req) {
  return `${req.protocol}://${req.get('host')}/api/auth/google/callback`;
}

app.get('/api/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.redirect('/login.html?error=google_not_configured');
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: googleRedirectUri(req),
    response_type: 'code',
    scope: 'openid email profile',
    prompt: 'select_account'
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code || !GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) throw new Error('Google login setup incomplete');

    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: googleRedirectUri(req),
        grant_type: 'authorization_code'
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('Google token exchange failed: ' + JSON.stringify(tokenData));

    const profileRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const profile = await profileRes.json();
    if (!profile.email) throw new Error('Could not get email from Google');

    const users = await readUsers();
    let user = users.find(u => u.email.toLowerCase() === profile.email.toLowerCase());

    if (!user) {
      let baseUsername = (profile.name || profile.email.split('@')[0]).replace(/[^a-zA-Z0-9_]/g, '').toLowerCase() || 'user';
      let username = baseUsername, suffix = 1;
      while (users.find(u => u.username.toLowerCase() === username.toLowerCase())) { username = baseUsername + suffix; suffix++; }

      user = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
        email: profile.email, username, passwordHash: null,
        authProvider: 'google', profileImage: null,
        securityQuestion: '', securityAnswerHash: '',
        usernameChanges: [], bio: '', website: '', following: [],
        createdAt: new Date().toISOString()
      };
      users.push(user);
      await writeUsers(users);
    }
    if (user.suspended) { res.redirect('/login.html?error=suspended'); return; }

    const token = signToken(user);
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.redirect('/');
  } catch (err) {
    console.error('Google auth error:', err);
    res.redirect('/login.html?error=google_failed');
  }
});

app.get('/api/me', (req, res) => { res.json(getUserFromReq(req)); });

app.get('/api/users/by-username/:username', async (req, res) => {
  try {
    const uname = String(req.params.username || '').toLowerCase();
    const users = await readUsers();
    const user = users.find(u => (u.username || '').toLowerCase() === uname);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const directUrl = makeDirectUrlCache();
    res.json({
      id: user.id, username: user.username,
      profileImage: user.profileImage ? await directUrl(user.profileImage, user.avatarStorageProvider) : null
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users/:id/public', async (req, res) => {
  try {
    const users = await readUsers();
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const currentUser = getUserFromReq(req);
    const me = currentUser ? users.find(u => u.id === currentUser.id) : null;
    const isFollowing = me && me.following ? me.following.includes(user.id) : false;
    const followersCount = users.filter(u => u.following && u.following.includes(user.id)).length;
    const followingCount = user.following ? user.following.length : 0;

    res.json({
      id: user.id, username: user.username, bio: user.bio || '', website: user.website || '',
      verified: !!user.verified,
      note: activeNote(user),
      pinnedFilmIds: Array.isArray(user.pinnedFilmIds) ? user.pinnedFilmIds : [],
      profileImage: user.profileImage ? await makeDirectUrlCache()(user.profileImage, user.avatarStorageProvider) : null,
      followersCount, followingCount, isFollowing,
      hideSensitiveContent: !!user.hideSensitiveContent,
      online: isUserOnline(user),
      blocked: !!(me && me.blockedUsers && me.blockedUsers.includes(user.id)),
      restricted: !!(me && me.restrictedUsers && me.restrictedUsers.includes(user.id)),
      hasBlockedMe: !!(currentUser && user.blockedUsers && user.blockedUsers.includes(currentUser.id))
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/me/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    if (!req.file) return res.status(400).json({ error: 'A photo file is required' });

    const key = `profiles/${currentUser.id}${path.extname(req.file.originalname) || '.jpg'}`;
    await storePutBuffer(readFileAsBuffer(req.file.path), key, req.file.mimetype);

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.profileImage = key;
    user.avatarStorageProvider = 'gdrive';
    await writeUsers(users);

    res.json({ profileImage: '/media/avatar/' + currentUser.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/media/avatar/:id', async (req, res) => {
  try {
    const users = await readUsers();
    const user = users.find(u => u.id === req.params.id);
    if (!user || !user.profileImage) return res.status(404).send('Not found');
    return storeStream(user.profileImage, req, res);
  } catch (err) { res.status(500).send(err.message); }
});

app.put('/api/me/username', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const { username } = req.body;
    if (!username || !username.trim()) return res.status(400).json({ error: 'Username is required' });

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (users.find(u => u.id !== user.id && u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(400).json({ error: 'This username is already taken' });
    }

    if (!user.usernameChanges) user.usernameChanges = [];
    const oneYearAgo = Date.now() - 365 * 24 * 60 * 60 * 1000;
    const changesThisYear = user.usernameChanges.filter(t => new Date(t).getTime() > oneYearAgo);
    if (changesThisYear.length >= 3) return res.status(400).json({ error: 'You can only change your username 3 times a year. Limit reached.' });

    const newUsername = username.trim();
    user.username = newUsername;
    user.usernameChanges.push(new Date().toISOString());
    await writeUsers(users);

    const films = await readFilms();
    let updated = false;
    films.forEach(f => { if (f.ownerId === user.id) { f.ownerUsername = newUsername; updated = true; } });
    if (updated) await writeFilms(films);

    const token = signToken(user);
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ username: user.username, changesLeft: 3 - changesThisYear.length - 1 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/me/password', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both password fields are required' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Naya password kam se kam 6 characters ka ho' });

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const ok = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await writeUsers(users);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/me/security-question', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const { securityQuestion, securityAnswer } = req.body;
    if (!securityQuestion || !securityAnswer || !securityAnswer.trim()) return res.status(400).json({ error: 'Both the question and answer are required' });

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.securityQuestion = securityQuestion;
    user.securityAnswerHash = await bcrypt.hash(securityAnswer.trim().toLowerCase(), 10);
    await writeUsers(users);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/me/bio', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const { bio, website } = req.body;

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.bio = (bio || '').slice(0, 150);
    user.website = (website || '').slice(0, 100);
    await writeUsers(users);
    res.json({ bio: user.bio, website: user.website });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users/:id/follow', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    if (currentUser.id === req.params.id) return res.status(400).json({ error: 'You can\'t follow yourself' });

    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    const target = users.find(u => u.id === req.params.id);
    if (!me || !target) return res.status(404).json({ error: 'User not found' });

    if (!me.following) me.following = [];
    const idx = me.following.indexOf(target.id);
    let nowFollowing;
    if (idx === -1) {
      me.following.push(target.id); nowFollowing = true;
      await notify(target.id, { type: 'follow', fromUserId: me.id, fromUsername: me.username, message: `@${me.username} started following you` });
    }
    else { me.following.splice(idx, 1); nowFollowing = false; }
    await writeUsers(users);

    const followersCount = users.filter(u => u.following && u.following.includes(target.id)).length;
    res.json({ following: nowFollowing, followersCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users/:id/block', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    if (currentUser.id === req.params.id) return res.status(400).json({ error: 'You can\'t block yourself' });

    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    const target = users.find(u => u.id === req.params.id);
    if (!me || !target) return res.status(404).json({ error: 'User not found' });

    if (!me.blockedUsers) me.blockedUsers = [];
    const idx = me.blockedUsers.indexOf(target.id);
    let blocked;
    if (idx === -1) {
      me.blockedUsers.push(target.id); blocked = true;
      if (me.following) me.following = me.following.filter(id => id !== target.id);
      if (target.following) target.following = target.following.filter(id => id !== me.id);
    } else {
      me.blockedUsers.splice(idx, 1); blocked = false;
    }
    await writeUsers(users);
    res.json({ blocked });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users/:id/restrict', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    if (currentUser.id === req.params.id) return res.status(400).json({ error: 'You can\'t restrict yourself' });

    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    const target = users.find(u => u.id === req.params.id);
    if (!me || !target) return res.status(404).json({ error: 'User not found' });

    if (!me.restrictedUsers) me.restrictedUsers = [];
    const idx = me.restrictedUsers.indexOf(target.id);
    let restricted;
    if (idx === -1) { me.restrictedUsers.push(target.id); restricted = true; }
    else { me.restrictedUsers.splice(idx, 1); restricted = false; }
    await writeUsers(users);
    res.json({ restricted });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users/:id/following', async (req, res) => {
  try {
    const users = await readUsers();
    const target = users.find(u => u.id === req.params.id);
    if (!target) return res.status(404).json({ error: 'User not found' });
    const currentUser = getUserFromReq(req);
    const me = currentUser ? users.find(u => u.id === currentUser.id) : null;
    const directUrl = makeDirectUrlCache();
    const list = await Promise.all((target.following || []).slice().reverse().map(async uid => {
      const u = users.find(x => x.id === uid);
      if (!u) return null;
      return {
        id: u.id, username: u.username,
        profileImage: u.profileImage ? await directUrl(u.profileImage, u.avatarStorageProvider) : null,
        isFollowing: !!(me && me.following && me.following.includes(u.id)),
        isMe: !!(currentUser && currentUser.id === u.id)
      };
    }));
    res.json({ users: list.filter(Boolean) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users/:id/followers', async (req, res) => {
  try {
    const users = await readUsers();
    const target = users.find(u => u.id === req.params.id);
    if (!target) return res.status(404).json({ error: 'User not found' });
    const currentUser = getUserFromReq(req);
    const me = currentUser ? users.find(u => u.id === currentUser.id) : null;
    const directUrl = makeDirectUrlCache();
    const followers = users.filter(u => u.following && u.following.includes(target.id));
    const list = await Promise.all(followers.slice().reverse().map(async u => ({
      id: u.id, username: u.username,
      profileImage: u.profileImage ? await directUrl(u.profileImage, u.avatarStorageProvider) : null,
      isFollowing: !!(me && me.following && me.following.includes(u.id)),
      isMe: !!(currentUser && currentUser.id === u.id)
    })));
    res.json({ users: list });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/forgot-password/question', async (req, res) => {
  try {
    const { email } = req.body;
    const users = await readUsers();
    const user = users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
    if (!user) return res.status(404).json({ error: 'This email is not registered' });
    res.json({ securityQuestion: user.securityQuestion });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/forgot-password/reset', async (req, res) => {
  try {
    const { email, securityAnswer, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Naya password kam se kam 6 characters ka ho' });
    const users = await readUsers();
    const user = users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
    if (!user) return res.status(404).json({ error: 'This email is not registered' });

    const ok = await bcrypt.compare((securityAnswer || '').trim().toLowerCase(), user.securityAnswerHash);
    if (!ok) return res.status(401).json({ error: 'Security answer is incorrect' });

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await writeUsers(users);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/claim-existing-films', async (req, res) => {
  try {
    const user = getUserFromReq(req);
    if (!user) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    let count = 0;
    films.forEach(f => { if (!f.ownerId) { f.ownerId = user.id; f.ownerUsername = user.username; count++; } });
    await writeFilms(films);
    res.json({ claimed: count });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===================== FILMS ROUTES =====================

app.get('/api/films', async (req, res) => {
  try {
    const films = await readFilms();
    const users = await readUsers();
    const currentUser = getUserFromReq(req);
    const me = currentUser ? users.find(u => u.id === currentUser.id) : null;
    const hideSensitive = me ? !!me.hideSensitiveContent : false;
    const myBlocked = (me && me.blockedUsers) || [];
    const directUrl = makeDirectUrlCache();

    const out = await Promise.all(films
      .filter(f => !(hideSensitive && f.isSensitive))
      .filter(f => !myBlocked.includes(f.ownerId))
      .filter(f => {
        const owner = users.find(u => u.id === f.ownerId);
        return !(owner && owner.blockedUsers && me && owner.blockedUsers.includes(me.id));
      })
      .map(async f => {
        const owner = users.find(u => u.id === f.ownerId);
        const ownerAvatarUrl = owner && owner.profileImage ? await directUrl(owner.profileImage, owner.avatarStorageProvider) : null;
        const ownerRestricted = (owner && owner.restrictedUsers) || [];
        const isThisFilmOwner = isFilmOwnerOrCollab(f, me && me.id);
        const visibleComments = (f.comments || []).filter(c => {
          if (c.hidden && !isThisFilmOwner) return false;
          if (!isThisFilmOwner && ownerRestricted.includes(c.userId) && !(me && me.id === c.userId)) return false;
          return true;
        });
        const enrichedComments = await Promise.all(visibleComments.map(async c => {
          const cUser = users.find(u => u.id === c.userId);
          const cAvatarUrl = cUser && cUser.profileImage ? await directUrl(cUser.profileImage, cUser.avatarStorageProvider) : null;
          return { ...c, name: cUser ? cUser.username : c.name, profileImage: cAvatarUrl, verified: !!(cUser && cUser.verified) };
        }));
        const videoUrl = f.type !== 'photo' && f.videoFile ? await directUrl(f.videoFile, f.storageProvider) : null;
        const posterUrl = f.posterFile ? await directUrl(f.posterFile, f.storageProvider) : null;
        return {
          ...f, comments: enrichedComments,
          videoUrl, posterUrl,
          slideUrls: await buildSlideUrls(f, directUrl),
          ownerVerified: !!(owner && owner.verified),
          ownerProfileImage: ownerAvatarUrl,
          isFollowing: !!(me && me.following && me.following.includes(f.ownerId))
        };
      }));
    res.json(out);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/collab/accept', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || f.collaboratorId !== currentUser.id || f.collabStatus !== 'pending') return res.status(404).json({ error: 'Invite nahi mila' });
    f.collabStatus = 'accepted';
    await writeFilms(films);
    await notify(f.ownerId, { type: 'collab_accepted', fromUserId: currentUser.id, fromUsername: currentUser.username, filmId: f.id, message: `@${currentUser.username} ne "${f.title}" ka collab accept kar liya` });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/collab/decline', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || !f.collaboratorId) return res.status(404).json({ error: 'Collab nahi mila' });
    if (f.collaboratorId !== currentUser.id && f.ownerId !== currentUser.id) return res.status(403).json({ error: 'You don\'t have permission' });
    delete f.collaboratorId; delete f.collaboratorUsername; delete f.collabStatus;
    await writeFilms(films);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users/search', async (req, res) => {
  try {
    const q = String(req.query.q || '').trim().replace(/^@/, '').toLowerCase();
    if (!q) return res.json({ users: [] });
    const currentUser = getUserFromReq(req);
    const users = await readUsers();
    const me = currentUser ? users.find(u => u.id === currentUser.id) : null;
    const directUrl = makeDirectUrlCache();
    const hits = users
      .filter(u => u.username && u.username.toLowerCase().includes(q))
      .filter(u => !(me && (me.blockedUsers || []).includes(u.id)) && !(me && (u.blockedUsers || []).includes(me.id)))
      .sort((a, b) => (a.username.toLowerCase().startsWith(q) ? 0 : 1) - (b.username.toLowerCase().startsWith(q) ? 0 : 1))
      .slice(0, 10);
    const out = await Promise.all(hits.map(async u => ({
      id: u.id, username: u.username, verified: !!u.verified,
      profileImage: u.profileImage ? await directUrl(u.profileImage, u.avatarStorageProvider) : null
    })));
    res.json({ users: out });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/collab', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Post nahi mili' });
    if (f.ownerId !== currentUser.id) return res.status(403).json({ error: 'Sirf post ka owner collab set kar sakta hai' });

    const raw = String(req.body.username || '').trim().replace(/^@/, '');
    if (!raw) {
      delete f.collaboratorId; delete f.collaboratorUsername; delete f.collabStatus;
      await writeFilms(films);
      return res.json({ collabStatus: null });
    }
    const users = await readUsers();
    const target = users.find(u => (u.username || '').toLowerCase() === raw.toLowerCase());
    if (!target) return res.status(404).json({ error: 'Ye username nahi mila' });
    if (target.id === currentUser.id) return res.status(400).json({ error: 'Apne aap ke saath collab nahi ho sakta' });
    if ((target.blockedUsers || []).includes(currentUser.id)) return res.status(403).json({ error: 'Is user ko invite nahi kar sakte' });

    f.collaboratorId = target.id; f.collaboratorUsername = target.username; f.collabStatus = 'pending';
    await writeFilms(films);
    await notifyCollabInvite(f, currentUser);
    res.json({ collabStatus: 'pending', collaboratorId: target.id, collaboratorUsername: target.username });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users/lookup/:username', async (req, res) => {
  try {
    const uname = String(req.params.username || '').replace(/^@/, '').toLowerCase();
    const u = (await readUsers()).find(x => (x.username || '').toLowerCase() === uname);
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json({ id: u.id, username: u.username });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/hashtags/:tag', async (req, res) => {
  try {
    const tag = String(req.params.tag || '').toLowerCase().replace(/^#/, '');
    const films = await readFilms();
    const users = await readUsers();
    const currentUser = getUserFromReq(req);
    const me = currentUser ? users.find(u => u.id === currentUser.id) : null;
    const myBlocked = (me && me.blockedUsers) || [];
    const directUrl = makeDirectUrlCache();

    const matches = films.filter(f => getFilmHashtags(f).includes(tag) && !myBlocked.includes(f.ownerId));
    const out = await Promise.all(matches.map(async f => ({
      id: f.id, title: f.title, type: f.type,
      posterUrl: f.posterFile ? await directUrl(f.posterFile, f.storageProvider) : null,
      isCarousel: Array.isArray(f.slides) && f.slides.length > 1,
      views: f.views || 0, likes: f.likes || 0
    })));
    res.json({ tag, count: out.length, films: out });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/films/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });
    const currentUser = getUserFromReq(req);
    const isFilmOwner = isFilmOwnerOrCollab(f, currentUser && currentUser.id);
    const users = await readUsers();
    const owner = users.find(u => u.id === f.ownerId);
    const ownerRestricted = (owner && owner.restrictedUsers) || [];
    const directUrl = makeDirectUrlCache();
    const ownerAvatarUrl = owner && owner.profileImage ? await directUrl(owner.profileImage, owner.avatarStorageProvider) : null;
    const visibleComments = (f.comments || []).filter(c => {
      if (c.hidden && !isFilmOwner) return false;
      if (!isFilmOwner && ownerRestricted.includes(c.userId) && !(currentUser && currentUser.id === c.userId)) return false;
      return true;
    });
    const enrichedComments = await Promise.all(visibleComments.map(async c => {
      const cUser = users.find(u => u.id === c.userId);
      const cAvatarUrl = cUser && cUser.profileImage ? await directUrl(cUser.profileImage, cUser.avatarStorageProvider) : null;
      return { ...c, name: cUser ? cUser.username : c.name, profileImage: cAvatarUrl, verified: !!(cUser && cUser.verified) };
    }));
    res.json({
      ...f, comments: enrichedComments,
      videoUrl: f.type !== 'photo' && f.videoFile ? await directUrl(f.videoFile, f.storageProvider) : null,
      posterUrl: f.posterFile ? await directUrl(f.posterFile, f.storageProvider) : null,
      slideUrls: await buildSlideUrls(f, directUrl),
      ownerVerified: !!(owner && owner.verified),
      ownerProfileImage: ownerAvatarUrl
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/media/video/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || !f.videoFile) return res.status(404).send('Not found');
    return storeStream(f.videoFile, req, res);
  } catch (err) { res.status(500).send(err.message); }
});

app.get('/media/poster/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || !f.posterFile) return res.status(404).send('Not found');
    return storeStream(f.posterFile, req, res);
  } catch (err) { res.status(500).send(err.message); }
});

app.post('/api/films', (req, res, next) => {
  req.currentUser = getUserFromReq(req);
  if (!req.currentUser && !isAdminBasicAuth(req)) return res.status(401).json({ error: 'Please log in to upload' });
  next();
}, upload.fields([{ name: 'video', maxCount: 1 }, { name: 'poster', maxCount: 1 }, { name: 'photo', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, year, language, genre, description, type, isSensitive } = req.body;
    if (!title) return res.status(400).json({ error: 'A title is required' });
    if (!isAdminBasicAuth(req) && await findBannedWord((title || '') + ' ' + (description || ''))) return res.status(400).json({ error: 'Title ya description me aisa shabd hai jo allowed nahi hai' });

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

    if (type === 'photo') {
      if (!req.files || !req.files.photo) return res.status(400).json({ error: 'A photo file is required' });
      const photoFile = req.files.photo[0];
      const photoKey = `posters/${id}${path.extname(photoFile.originalname)}`;
      await storePutBuffer(readFileAsBuffer(photoFile.path), photoKey, photoFile.mimetype);

      const films = await readFilms();
      const newFilm = {
        id, title, year: year || '', language: language || '', genre: genre || '',
        description: description || '', videoFile: null, posterFile: photoKey, type: 'photo',
        isSensitive: toBool(isSensitive),
        hashtags: extractHashtags(title + ' ' + (description || '')),
        storageProvider: 'gdrive',
        ownerId: req.currentUser ? req.currentUser.id : 'admin',
        ownerUsername: req.currentUser ? req.currentUser.username : 'YouSeries',
        views: 0, likes: 0, comments: [], uploadedAt: new Date().toISOString()
      };
      await decorateNewFilm(newFilm, req.body, req.currentUser);
      films.unshift(newFilm);
      await writeFilms(films);
      await notifyCollabInvite(newFilm, req.currentUser);
      return res.status(201).json(newFilm);
    }

    if (!req.files || !req.files.video) return res.status(400).json({ error: 'A video file is required' });

    const videoFile = req.files.video[0];
    const videoKey = `videos/${id}${path.extname(videoFile.originalname)}`;
    await storePutBuffer(fs.readFileSync(videoFile.path), videoKey, videoFile.mimetype);

    let posterKey = null;
    if (req.files.poster) {
      const posterFile = req.files.poster[0];
      posterKey = `posters/${id}${path.extname(posterFile.originalname)}`;
      await storePutBuffer(readFileAsBuffer(posterFile.path), posterKey, posterFile.mimetype);
    }

    const films = await readFilms();
    const newFilm = {
      id, title, year: year || '', language: language || '', genre: genre || '',
      description: description || '', videoFile: videoKey, posterFile: posterKey,
      type: type === 'short' ? 'short' : 'film',
      isSensitive: toBool(isSensitive),
      hashtags: extractHashtags(title + ' ' + (description || '')),
      storageProvider: 'gdrive',
      ownerId: req.currentUser ? req.currentUser.id : 'admin',
      ownerUsername: req.currentUser ? req.currentUser.username : 'YouSeries',
      views: 0, likes: 0, comments: [], uploadedAt: new Date().toISOString()
    };
    await decorateNewFilm(newFilm, req.body, req.currentUser);
    films.unshift(newFilm);
    await writeFilms(films);
    await notifyCollabInvite(newFilm, req.currentUser);
    res.status(201).json(newFilm);

    // Generate thumbnail in the background so the upload response returns faster
    if (!posterKey) {
      const videoPathForThumb = videoFile.path;
      generateThumbnail(fs.readFileSync(videoPathForThumb), path.extname(videoFile.originalname))
        .then(async (thumbBuffer) => {
          fs.unlink(videoPathForThumb, () => {});
          const genPosterKey = `posters/${id}.jpg`;
          await storePutBuffer(thumbBuffer, genPosterKey, 'image/jpeg');
          const latestFilms = await readFilms();
          const f = latestFilms.find(x => x.id === id);
          if (f) { f.posterFile = genPosterKey; await writeFilms(latestFilms); }
        })
        .catch(err => { console.error('Background thumbnail failed:', err.message); fs.unlink(videoPathForThumb, () => {}); });
    }
    return;
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/upload/presign-url', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser && !isAdminBasicAuth(req)) return res.status(401).json({ error: 'Please log in' });
    const { fileName, contentType, folder } = req.body;
    if (!fileName || !folder) return res.status(400).json({ error: 'A file name and folder are required' });
    const safeFolder = ['videos', 'posters', 'photos'].includes(folder) ? folder : 'videos';
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const key = `${safeFolder}/${id}${path.extname(fileName)}`;
    return res.status(501).json({ error: 'Use the resumable upload route' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------- Google Drive (the only storage) ----------------
// Videos / photos of posts are stored in the owner's Google Drive (e.g. a Google One plan) and streamed through this server
// at /media/gd/<fileId>. Only the "drive.file" scope is needed, so the app can see just the files it created.
// Needs GDRIVE_CLIENT_ID, GDRIVE_CLIENT_SECRET and GDRIVE_REFRESH_TOKEN.
const GD = {
  clientId: process.env.GDRIVE_CLIENT_ID, clientSecret: process.env.GDRIVE_CLIENT_SECRET, refreshToken: process.env.GDRIVE_REFRESH_TOKEN,
  apiKey: process.env.GDRIVE_API_KEY || null,   // optional: files become public-by-link and the browser loads them straight from Google (no Render bandwidth)
  folderId: process.env.GDRIVE_FOLDER_ID || null, folderName: process.env.GDRIVE_FOLDER_NAME || 'YouSeries Media',
  tokenUrl: process.env.GDRIVE_TOKEN_URL || 'https://oauth2.googleapis.com/token',
  apiBase: process.env.GDRIVE_API_BASE || 'https://www.googleapis.com/drive/v3',
  uploadBase: process.env.GDRIVE_UPLOAD_BASE || 'https://www.googleapis.com/upload/drive/v3'
};
const GD_MONTH_CAP = (parseFloat(process.env.GD_MONTHLY_CAP_GB) || 4) * 1024 * 1024 * 1024;   // Render free = 5 GB/month outbound; keep ~1 GB for pages and API
const GD_PART = 8 * 1024 * 1024;               // must match the browser's PART_SIZE (and be a multiple of 256 KiB)
const gdMediaUrl = id => GD.apiKey ? `https://www.googleapis.com/drive/v3/files/${id}?alt=media&key=${GD.apiKey}` : '/media/gd/' + id;
async function gdMakePublic(id) {
  if (!GD.apiKey) return;
  try {
    await fetch(`${GD.apiBase}/files/${id}/permissions`, {
      method: 'POST', headers: { Authorization: 'Bearer ' + await gdAccessToken(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'reader', type: 'anyone' })
    });
  } catch (e) { /* best effort */ }
}
const gdEnabled = () => !!(GD.clientId && GD.clientSecret && GD.refreshToken);
const isGdSession = s => typeof s === 'string' && s.startsWith(GD.uploadBase + '/files');
const GD_KEY_RE = /^gd:[A-Za-z0-9_-]{8,100}$/;
let gdToken = { value: null, exp: 0 };
async function gdAccessToken() {
  if (gdToken.value && Date.now() < gdToken.exp - 60000) return gdToken.value;
  const res = await fetch(GD.tokenUrl, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: GD.clientId, client_secret: GD.clientSecret, refresh_token: GD.refreshToken, grant_type: 'refresh_token' })
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok || !j.access_token) throw new Error('Google login failed: ' + (j.error_description || j.error || res.status));
  gdToken = { value: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return gdToken.value;
}
async function gdFolderId() {
  if (GD.folderId) return GD.folderId;
  const token = await gdAccessToken();
  const q = encodeURIComponent(`name='${GD.folderName.replace(/'/g, "\\'")}' and mimeType='application/vnd.google-apps.folder' and trashed=false`);
  const found = await (await fetch(`${GD.apiBase}/files?q=${q}&fields=files(id)&spaces=drive`, { headers: { Authorization: 'Bearer ' + token } })).json();
  if (found.files && found.files[0]) { GD.folderId = found.files[0].id; return GD.folderId; }
  const made = await (await fetch(`${GD.apiBase}/files?fields=id`, {
    method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: GD.folderName, mimeType: 'application/vnd.google-apps.folder' })
  })).json();
  if (!made.id) throw new Error('Could not create the Drive folder');
  GD.folderId = made.id;
  return GD.folderId;
}
async function gdCreateSession(name, mime, size) {
  const token = await gdAccessToken();
  const folder = await gdFolderId();
  const res = await fetch(`${GD.uploadBase}/files?uploadType=resumable&fields=id`, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json; charset=UTF-8', 'X-Upload-Content-Type': mime || 'application/octet-stream', 'X-Upload-Content-Length': String(size) },
    body: JSON.stringify({ name, parents: [folder] })
  });
  const loc = res.headers.get('location');
  if (!res.ok || !loc) throw new Error('Drive refused the upload (' + res.status + ')');
  return loc;
}
async function gdSessionStatus(session, size) {
  const r = await fetch(session, { method: 'PUT', headers: { 'Content-Range': `bytes */${size}` } });
  if (r.status === 200 || r.status === 201) { const j = await r.json().catch(() => ({})); return { done: true, id: j.id }; }
  if (r.status === 308) { const m = /bytes=0-(\d+)/.exec(r.headers.get('range') || ''); return { done: false, received: m ? Number(m[1]) + 1 : 0 }; }
  if (r.status === 404 || r.status === 410) return { expired: true };
  throw new Error('Drive status check failed (' + r.status + ')');
}
async function gdPutPart(session, buf, offset, size) {
  const st = await gdSessionStatus(session, size);
  if (st.expired) { const e = new Error('Upload session expired'); e.expired = true; throw e; }
  if (st.done) return { done: true, id: st.id };
  let data = buf, start = offset;
  if (st.received > offset) {                    // part was partly received before a refresh: send only the missing tail
    const skip = st.received - offset;
    if (skip >= buf.length) return { done: false };
    data = buf.subarray(skip); start = offset + skip;
  } else if (st.received < offset) { const e = new Error('Part out of order'); e.status = 409; throw e; }
  usageAdd('proxyBytes', data.length);
  const r = await fetch(session, { method: 'PUT', headers: { 'Content-Range': `bytes ${start}-${start + data.length - 1}/${size}` }, body: data });
  if (r.status === 200 || r.status === 201) { const j = await r.json().catch(() => ({})); return { done: true, id: j.id }; }
  if (r.status === 308) return { done: false };
  if (r.status === 404 || r.status === 410) { const e = new Error('Upload session expired'); e.expired = true; throw e; }
  throw new Error('Drive upload failed (' + r.status + ')');
}
async function gdDelete(id) {
  try {
    if (!gdEnabled() || !/^[A-Za-z0-9_-]{8,100}$/.test(id)) return;
    await fetch(`${GD.apiBase}/files/${id}`, { method: 'DELETE', headers: { Authorization: 'Bearer ' + await gdAccessToken() } });
  } catch (e) { /* best effort */ }
}
let gdAboutCache = { at: 0, data: null };
async function gdAbout() {
  if (!gdEnabled()) return { enabled: false };
  if (gdAboutCache.data && Date.now() - gdAboutCache.at < 10 * 60 * 1000) return gdAboutCache.data;
  try {
    const r = await fetch(`${GD.apiBase}/about?fields=storageQuota`, { headers: { Authorization: 'Bearer ' + await gdAccessToken() } });
    const j = await r.json();
    if (!r.ok) throw new Error((j.error && j.error.message) || r.status);
    const q = j.storageQuota || {};
    gdAboutCache = { at: Date.now(), data: { enabled: true, usedBytes: Number(q.usage) || 0, limitBytes: Number(q.limit) || null } };
  } catch (e) { gdAboutCache = { at: Date.now(), data: { enabled: true, error: e.message } }; }
  return gdAboutCache.data;
}

// Small files (thumbnails, avatars) are kept in memory so feeds do not hit Drive for every card.
const gdSmall = new Map(); let gdSmallBytes = 0;
const GD_SMALL_MAX_FILE = 1024 * 1024, GD_SMALL_CAP = 64 * 1024 * 1024;
function gdSmallPut(id, buf, type) {
  if (buf.length > GD_SMALL_MAX_FILE || gdSmall.has(id)) return;
  gdSmall.set(id, { buf, type }); gdSmallBytes += buf.length;
  for (const [k, v] of gdSmall) { if (gdSmallBytes <= GD_SMALL_CAP) break; gdSmall.delete(k); gdSmallBytes -= v.buf.length; }
}

// ---- Key based object store on Drive: a Drive file is named exactly like its storage key (e.g. videos/abc.mp4) ----
const gdIdx = new Map();                // key (file name) -> Drive file id
let gdIdxAt = 0, gdIdxSizes = new Map(), gdIdxShared = new Map();
async function gdIndexRefresh(force) {
  if (!force && Date.now() - gdIdxAt < 20000) return;
  gdIdxAt = Date.now();
  const token = await gdAccessToken();
  const folder = await gdFolderId();
  let pageToken = '';
  const seen = new Map(), sizes = new Map();
  gdIdxShared = new Map();
  do {
    const q = encodeURIComponent(`'${folder}' in parents and trashed=false`);
    const r = await fetch(`${GD.apiBase}/files?q=${q}&pageSize=1000&fields=nextPageToken,files(id,name,size,shared)${pageToken ? '&pageToken=' + encodeURIComponent(pageToken) : ''}`, { headers: { Authorization: 'Bearer ' + token } });
    const j = await r.json();
    if (!r.ok) throw new Error('Drive listing failed: ' + ((j.error && j.error.message) || r.status));
    (j.files || []).forEach(f => { if (!seen.has(f.name)) { seen.set(f.name, f.id); sizes.set(f.name, Number(f.size) || 0); gdIdxShared.set(f.name, !!f.shared); } });
    pageToken = j.nextPageToken || '';
  } while (pageToken);
  seen.forEach((id, name) => gdIdx.set(name, id));
  gdIdxSizes = sizes;
}
let gdLastMissRefresh = 0;
async function gdResolve(key) {
  if (gdIdx.has(key)) return gdIdx.get(key);
  // a key we do not know yet: look at Drive again, but at most once every 2 seconds
  if (Date.now() - gdLastMissRefresh > 2000) { gdLastMissRefresh = Date.now(); try { await gdIndexRefresh(true); } catch (e) {} }
  return gdIdx.get(key) || null;
}
const gdKeyLocks = new Map();
async function gdEnsurePublic() {                       // files uploaded before GDRIVE_API_KEY was set
  if (!GD.apiKey) return;
  let n = 0;
  for (const [name, id] of gdIdx) {
    if (/\.json$/i.test(name) || gdIdxShared.get(name) === true) continue;
    await gdMakePublic(id); gdIdxShared.set(name, true);
    if (++n >= 300) break;
    await new Promise(r => setTimeout(r, 120));
  }
  if (n) console.log(`Drive: made ${n} existing media files viewable by link`);
}
function gdWithLock(key, fn) {                      // one write at a time per key, so a key never gets two Drive files
  const prev = gdKeyLocks.get(key) || Promise.resolve();
  const next = prev.catch(() => {}).then(fn);
  gdKeyLocks.set(key, next);
  next.finally(() => { if (gdKeyLocks.get(key) === next) gdKeyLocks.delete(key); }).catch(() => {});
  return next;
}
function gdPutByKey(key, buf, contentType) {
  return gdWithLock(key, async () => {
    const ct = contentType || 'application/octet-stream';
    let id = await gdResolve(key);
    if (id) {
      const r = await fetch(`${GD.uploadBase}/files/${id}?uploadType=media`, { method: 'PATCH', headers: { Authorization: 'Bearer ' + await gdAccessToken(), 'Content-Type': ct }, body: buf });
      if (r.ok) return id;
      if (r.status !== 404) throw new Error('Drive update failed (' + r.status + ')');
      gdIdx.delete(key);                              // file was removed behind our back: create it again
    }
    if (!buf.length) { const e = new Error('Empty file'); throw e; }
    const session = await gdCreateSession(key, ct, buf.length);
    usageAdd('proxyBytes', buf.length);
    const r = await fetch(session, { method: 'PUT', headers: { 'Content-Range': `bytes 0-${buf.length - 1}/${buf.length}` }, body: buf });
    if (r.status !== 200 && r.status !== 201) throw new Error('Drive upload failed (' + r.status + ')');
    const j = await r.json();
    gdIdx.set(key, j.id);
    gdIdxSizes.set(key, buf.length);
    if (!/\.json$/i.test(key)) { await gdMakePublic(j.id); gdIdxShared.set(key, true); }
    return j.id;
  });
}
async function gdGetByKey(key) {
  const id = await gdResolve(key);
  const miss = () => { const e = new Error('NoSuchKey'); e.name = 'NoSuchKey'; return e; };
  if (!id) throw miss();
  const r = await fetch(`${GD.apiBase}/files/${id}?alt=media`, { headers: { Authorization: 'Bearer ' + await gdAccessToken() } });
  if (r.status === 404) { gdIdx.delete(key); throw miss(); }
  if (!r.ok) throw new Error('Drive download failed (' + r.status + ')');
  return Buffer.from(await r.arrayBuffer());
}
// JSON "database" writes are batched: memory is updated immediately, Drive gets the newest copy of each file every few seconds.
const gdPending = new Map();
let gdFlushTimer = null;
function gdQueueJSON(key, raw) {
  gdPending.set(key, { raw });
  if (!gdFlushTimer) gdFlushTimer = setTimeout(() => { gdFlushTimer = null; gdFlushAll().catch(() => {}); }, 5000);
}
async function gdFlushAll() {
  const items = Array.from(gdPending.entries());
  await Promise.all(items.map(async ([key, v]) => {
    try {
      await gdPutByKey(key, Buffer.from(v.raw), 'application/json');
      if (gdPending.get(key) === v) gdPending.delete(key);
    } catch (e) {
      console.error(`Drive save of ${key} failed (will retry):`, e.message);
      if (!gdFlushTimer) gdFlushTimer = setTimeout(() => { gdFlushTimer = null; gdFlushAll().catch(() => {}); }, 15000);
    }
  }));
}

async function gdServe(id, req, res) {
  if (!gdEnabled() || !/^[A-Za-z0-9_-]{8,100}$/.test(id)) return res.status(404).end();
  const range = req.headers.range;
  // Render's free plan only includes 5 GB of outbound traffic a month (more is billed at $0.15/GB), so media streaming
  // stops at GD_MONTHLY_CAP_GB (default 4) instead of letting the whole site run into overage.
  usageRoll();
  if (usage.proxyBytes >= GD_MONTH_CAP && !gdSmall.has(id)) {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Retry-After', '86400');
    return res.status(503).end('Is mahine ki bandwidth limit poori ho gayi — media agle mahine se chalega');
  }
  res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  res.setHeader('Accept-Ranges', 'bytes');
  res.setHeader('Content-Disposition', 'inline');
  try {
    const hit = !range && gdSmall.get(id);
    if (hit) { res.setHeader('Content-Type', hit.type); res.setHeader('Content-Length', hit.buf.length); usageAdd('proxyBytes', hit.buf.length); return res.end(hit.buf); }
    const ctrl = new AbortController();
    res.on('close', () => ctrl.abort());
    const r = await fetch(`${GD.apiBase}/files/${id}?alt=media`, { headers: { Authorization: 'Bearer ' + await gdAccessToken(), ...(range ? { Range: range } : {}) }, signal: ctrl.signal });
    if (r.status === 404) return res.status(404).end();
    if (r.status === 403 || r.status === 429) { res.setHeader('Cache-Control', 'no-store'); res.setHeader('Retry-After', '3600'); return res.status(503).end('Drive ki download limit — thodi der baad try karo'); }
    if (!r.ok && r.status !== 206) { res.setHeader('Cache-Control', 'no-store'); return res.status(502).end(); }
    ['content-type', 'content-length', 'content-range', 'etag', 'last-modified'].forEach(h => { const v = r.headers.get(h); if (v) res.setHeader(h, v); });
    res.status(r.status);
    const len = parseInt(r.headers.get('content-length') || '0', 10);
    if (!range && len && len <= GD_SMALL_MAX_FILE) {
      const buf = Buffer.from(await r.arrayBuffer());
      gdSmallPut(id, buf, r.headers.get('content-type') || 'application/octet-stream');
      usageAdd('proxyBytes', buf.length);
      return res.end(buf);
    }
    const stream = Readable.fromWeb(r.body);
    let sent = 0;
    stream.on('data', c => { sent += c.length; });
    stream.on('close', () => usageAdd('proxyBytes', sent));
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  } catch (e) {
    if (e.name === 'AbortError') return;
    if (!res.headersSent) { res.setHeader('Cache-Control', 'no-store'); res.status(502).end(); } else res.destroy();
  }
}
app.get('/media/gd/:id', (req, res) => gdServe(req.params.id, req, res));

// ---------------- Resumable uploads (Google Drive) ----------------
// The browser cuts a file into 8 MB parts and sends them here. Drive keeps the upload session, so after a refresh the
// browser asks which parts arrived and continues. Finished files are named "gd:<fileId>".
const keyOk = k => typeof k === 'string' && GD_KEY_RE.test(k);
function mpAuth(req, res) {
  const currentUser = getUserFromReq(req);
  if (!currentUser && !isAdminBasicAuth(req)) { res.status(401).json({ error: 'Please log in' }); return null; }
  return currentUser || { id: 'admin' };
}

app.post('/api/upload/mp/create', async (req, res) => {
  try {
    if (!mpAuth(req, res)) return;
    const { fileName, contentType, folder, size: sizeRaw } = req.body || {};
    if (!fileName || !folder) return res.status(400).json({ error: 'A file name and folder are required' });
    storeNeedsDrive();
    const safeFolder = ['videos', 'posters', 'photos'].includes(folder) ? folder : 'videos';
    const size = Number(sizeRaw);
    if (!(size > 0)) return res.status(400).json({ error: 'File size is required' });
    usageRoll();
    if (usage.proxyBytes + size >= GD_MONTH_CAP) return res.status(503).json({ error: 'Is mahine ki server bandwidth limit poori ho gayi — upload agle mahine se chalega' });
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const ext = (path.extname(String(fileName)) || '').replace(/[^A-Za-z0-9.]/g, '').slice(0, 8);
    const session = await gdCreateSession(`${safeFolder}/${id}${ext}`, contentType, size);
    res.json({ key: 'gd:pending', uploadId: session, provider: 'gdrive' });
  } catch (err) { res.status(err.status || 500).json({ error: err.message }); }
});

app.put('/api/upload/mp/part', express.raw({ type: () => true, limit: '16mb' }), async (req, res) => {
  try {
    if (!mpAuth(req, res)) return;
    const { uploadId } = req.query;
    if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'Empty part' });
    if (!isGdSession(uploadId)) return res.status(400).json({ error: 'Bad part request' });
    const size = Number(req.query.size), offset = Number(req.query.offset);
    if (!(size > 0) || !(offset >= 0) || offset % 262144 !== 0 || offset + req.body.length > size) return res.status(400).json({ error: 'Bad part request' });
    usageRoll();
    if (usage.proxyBytes >= GD_MONTH_CAP) return res.status(503).json({ error: 'Is mahine ki server bandwidth limit poori ho gayi — upload agle mahine se chalega' });
    const out = await gdPutPart(uploadId, req.body, offset, size);
    if (out.done && out.id) await gdMakePublic(out.id);
    res.json({ ok: true, done: !!out.done, key: out.done && out.id ? 'gd:' + out.id : undefined });
  } catch (err) {
    if (err.expired) return res.status(404).json({ error: err.message, expired: true });
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.get('/api/upload/mp/parts', async (req, res) => {
  try {
    if (!mpAuth(req, res)) return;
    const { uploadId } = req.query;
    const size = Number(req.query.size);
    if (!isGdSession(uploadId) || !(size > 0)) return res.status(400).json({ error: 'Bad request' });
    const st = await gdSessionStatus(uploadId, size);
    if (st.expired) return res.status(404).json({ error: 'Upload session expired', expired: true });
    const total = Math.max(1, Math.ceil(size / GD_PART));
    const have = st.done ? total : Math.floor(st.received / GD_PART);
    res.json({ parts: Array.from({ length: have }, (_, i) => ({ n: i + 1 })) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/upload/mp/complete', async (req, res) => {
  try {
    if (!mpAuth(req, res)) return;
    const { uploadId } = req.body || {};
    const size = Number((req.body || {}).size);
    if (!isGdSession(uploadId) || !(size > 0)) return res.status(400).json({ error: 'Bad request' });
    const st = await gdSessionStatus(uploadId, size);
    if (st.expired) return res.status(404).json({ error: 'Upload session expired', expired: true });
    if (!st.done || !st.id) return res.status(409).json({ error: 'Some parts are still missing' });
    await gdMakePublic(st.id);
    res.json({ ok: true, key: 'gd:' + st.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/upload/mp/abort', async (req, res) => {
  try {
    if (!mpAuth(req, res)) return;
    const { uploadId } = req.body || {};
    if (isGdSession(uploadId)) fetch(uploadId, { method: 'DELETE' }).catch(() => {});
    res.json({ ok: true });
  } catch (err) { res.json({ ok: true }); }
});

app.post('/api/films/finalize', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser && !isAdminBasicAuth(req)) return res.status(401).json({ error: 'Please log in' });
    const { title, year, language, genre, description, type, mediaKey, posterKey, isSensitive, clientUploadId } = req.body;
    if (!title) return res.status(400).json({ error: 'A title is required' });
    if (!mediaKey) return res.status(400).json({ error: 'Could not find a reference to the uploaded file' });
    if (!isAdminBasicAuth(req) && await findBannedWord((title || '') + ' ' + (description || ''))) return res.status(400).json({ error: 'Title ya description me aisa shabd hai jo allowed nahi hai' });
    // Carousel: several photos/videos in one post (slides[0] is also mediaKey)
    let slides = [];
    if (type === 'photo' && Array.isArray(req.body.slides)) {
      slides = req.body.slides.slice(0, 10)
        .filter(sl => sl && keyOk(sl.key) && (sl.mediaType === 'photo' || sl.mediaType === 'video'))
        .map(sl => ({ key: sl.key, mediaType: sl.mediaType }));
    }

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const films = await readFilms();

    // A resumed/retried upload must never create the same post twice.
    if (clientUploadId) {
      const ownerKey = currentUser ? currentUser.id : 'admin';
      const dup = films.find(x => x.clientUploadId === clientUploadId && x.ownerId === ownerKey);
      if (dup) return res.status(200).json(dup);
    }

    const newFilm = type === 'photo'
      ? {
          id, title, year: year || '', language: language || '', genre: genre || '',
          description: description || '', videoFile: null, posterFile: mediaKey, type: 'photo',
          isSensitive: toBool(isSensitive),
          hashtags: extractHashtags(title + ' ' + (description || '')),
          storageProvider: 'gdrive',
          ownerId: currentUser ? currentUser.id : 'admin',
          ownerUsername: currentUser ? currentUser.username : 'YouSeries',
          views: 0, likes: 0, comments: [], uploadedAt: new Date().toISOString()
        }
      : {
          id, title, year: year || '', language: language || '', genre: genre || '',
          description: description || '', videoFile: mediaKey, posterFile: posterKey || null,
          type: type === 'short' ? 'short' : 'film',
          isSensitive: toBool(isSensitive),
          hashtags: extractHashtags(title + ' ' + (description || '')),
          storageProvider: 'gdrive',
          ownerId: currentUser ? currentUser.id : 'admin',
          ownerUsername: currentUser ? currentUser.username : 'YouSeries',
          views: 0, likes: 0, comments: [], uploadedAt: new Date().toISOString()
        };

    if (clientUploadId) newFilm.clientUploadId = String(clientUploadId).slice(0, 64);
    if (newFilm.type === 'photo' && slides.length >= 2) {
      newFilm.slides = slides;
      newFilm.posterFile = posterKey || (slides[0].mediaType === 'photo' ? slides[0].key : null);
    }
    await decorateNewFilm(newFilm, req.body, currentUser);
    films.unshift(newFilm);
    await writeFilms(films);
    await notifyCollabInvite(newFilm, currentUser);
    if (currentUser) await notifyMentions(newFilm.title + ' ' + newFilm.description, currentUser, { filmId: newFilm.id, label: `in "${newFilm.title}"` });
    res.status(201).json(newFilm);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/view', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });
    f.views = (f.views || 0) + 1;
    await writeFilms(films);
    try {
      const sz = k => (k && storageStats.sizes.get(k)) || 0;
      usageAdd('mediaBytes', f.type === 'photo' ? ((f.slides && f.slides.length > 1) ? f.slides.reduce((a, sl) => a + sz(sl.key), 0) : sz(f.posterFile)) : sz(f.videoFile));
      usage.views++;
    } catch (e) {}

    const currentUser = getUserFromReq(req);
    if (currentUser) {
      const history = await readWatchHistory();
      const idx = history.findIndex(h => h.userId === currentUser.id && h.filmId === f.id);
      if (idx !== -1) history.splice(idx, 1);
      history.push({ userId: currentUser.id, filmId: f.id, viewedAt: new Date().toISOString() });
      await writeWatchHistory(history);
    }

    res.json({ views: f.views });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/like', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Please log in to like' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });

    if (!f.likedBy) { f.likedBy = []; f.likesBaseline = f.likes || 0; }
    if (!f.likedAt) f.likedAt = {};
    const idx = f.likedBy.indexOf(currentUser.id);
    let liked;
    if (idx === -1) {
      f.likedBy.push(currentUser.id);
      f.likedAt[currentUser.id] = new Date().toISOString();
      liked = true;
    } else {
      f.likedBy.splice(idx, 1);
      delete f.likedAt[currentUser.id];
      liked = false;
    }
    f.likes = (f.likesBaseline || 0) + f.likedBy.length;

    await writeFilms(films);
    res.json({ likes: f.likes, liked });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/save', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Please log in to save' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });

    if (!f.savedBy) f.savedBy = [];
    const idx = f.savedBy.indexOf(currentUser.id);
    let saved;
    if (idx === -1) { f.savedBy.push(currentUser.id); saved = true; }
    else { f.savedBy.splice(idx, 1); saved = false; }

    await writeFilms(films);
    res.json({ saved });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/share', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });
    f.shares = (f.shares || 0) + 1;
    await writeFilms(films);
    res.json({ shares: f.shares });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/watch-time', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });
    const seconds = Math.max(0, Math.min(parseFloat(req.body.seconds) || 0, 6 * 60 * 60));
    if (seconds > 0) {
      f.watchSeconds = (f.watchSeconds || 0) + seconds;
      f.watchSamples = (f.watchSamples || 0) + 1;
      await writeFilms(films);
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/films/:id/insights', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });
    if (!isFilmOwnerOrCollab(f, currentUser.id)) return res.status(403).json({ error: 'You don\'t have permission' });
    const views = f.views || 0;
    const likes = f.likes || 0;
    const shares = f.shares || 0;
    const avgWatchSeconds = f.watchSamples ? Math.round((f.watchSeconds || 0) / f.watchSamples) : 0;
    const likeRate = views ? Math.round((likes / views) * 1000) / 10 : 0;
    res.json({ views, likes, likeRate, shares, avgWatchSeconds, commentCount: (f.comments || []).length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/comments', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Please log in to comment' });

    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Please write a comment' });
    if (await findBannedWord(text)) return res.status(400).json({ error: 'Is comment me aisa shabd hai jo allowed nahi hai' });

    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });

    if (!f.comments) f.comments = [];
    const comment = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      userId: currentUser.id,
      name: currentUser.username,
      text: text.trim().slice(0, 500),
      createdAt: new Date().toISOString()
    };
    comment.mentions = findMentionedUsers(comment.text, await readUsers());
    f.comments.push(comment);
    await writeFilms(films);
    if (checkSpamAndRecord(currentUser.id, comment.text)) {
      const reports = await readReports();
      const already = reports.some(r => r.reason === 'auto-spam' && r.status === 'pending' && r.targetOwnerId === currentUser.id
        && r.targetPreview === comment.text && Date.now() - new Date(r.createdAt).getTime() < 10 * 60 * 1000);
      if (!already) reports.push({
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        type: 'comment', targetId: `${f.id}:${comment.id}`, filmId: f.id,
        targetOwnerId: currentUser.id, targetPreview: comment.text,
        reporterId: 'system', reporterUsername: 'Spam Detection',
        reason: 'auto-spam', note: 'Automatically flagged for repeated/link-heavy content',
        status: 'pending', createdAt: new Date().toISOString()
      });
      if (!already) {
        await writeReports(reports);
        alertAdminOfReport(reports[reports.length - 1]).catch(() => {});
      }
    }
    if (f.ownerId) {
      await notify(f.ownerId, { type: 'film_comment', fromUserId: currentUser.id, fromUsername: currentUser.username, filmId: f.id, message: `@${currentUser.username} commented on your "${f.title}"` });
    }
    await notifyMentions(comment.text, currentUser, { filmId: f.id, label: `in a comment on "${f.title}"` });
    res.status(201).json(comment);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:filmId/comments/:commentId/delete', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });

    const films = await readFilms();
    const f = films.find(x => x.id === req.params.filmId);
    if (!f || !f.comments) return res.status(404).json({ error: 'Not found' });

    const comment = f.comments.find(c => c.id === req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });

    const isCommentOwner = comment.userId === currentUser.id;
    const isFilmOwner = f.ownerId === currentUser.id;
    if (!isCommentOwner && !isFilmOwner) return res.status(403).json({ error: 'You don\'t have permission' });

    f.comments = f.comments.filter(c => c.id !== req.params.commentId);
    await writeFilms(films);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:filmId/comments/:commentId/hide', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });

    const films = await readFilms();
    const f = films.find(x => x.id === req.params.filmId);
    if (!f || !f.comments) return res.status(404).json({ error: 'Not found' });
    if (!isFilmOwnerOrCollab(f, currentUser.id)) return res.status(403).json({ error: 'You don\'t have permission' });

    const comment = f.comments.find(c => c.id === req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });

    comment.hidden = !comment.hidden;
    await writeFilms(films);
    res.json({ hidden: comment.hidden });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:filmId/comments/:commentId/pin', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });

    const films = await readFilms();
    const f = films.find(x => x.id === req.params.filmId);
    if (!f || !f.comments) return res.status(404).json({ error: 'Not found' });
    if (!isFilmOwnerOrCollab(f, currentUser.id)) return res.status(403).json({ error: 'Sirf post owner pin kar sakta hai' });

    const comment = f.comments.find(c => c.id === req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    if (comment.hidden) return res.status(400).json({ error: 'Hidden comment pin nahi ho sakta' });

    const willPin = !comment.pinned;
    f.comments.forEach(c => { c.pinned = false; });   // only one pinned comment per post
    comment.pinned = willPin;
    await writeFilms(films);

    if (willPin && comment.userId && comment.userId !== currentUser.id) {
      notify(comment.userId, {
        type: 'comment_pin', fromUserId: currentUser.id, fromUsername: currentUser.username,
        filmId: f.id, message: `@${currentUser.username} pinned your comment`
      }).catch(() => {});
    }
    res.json({ pinned: willPin, commentId: comment.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:filmId/comments/:commentId/edit', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });

    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Comment can\'t be empty' });

    const films = await readFilms();
    const f = films.find(x => x.id === req.params.filmId);
    if (!f || !f.comments) return res.status(404).json({ error: 'Not found' });

    const comment = f.comments.find(c => c.id === req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });

    if (comment.userId !== currentUser.id) return res.status(403).json({ error: 'You can only edit your own comment' });

    const ageMs = Date.now() - new Date(comment.createdAt).getTime();
    if (ageMs > 24 * 60 * 60 * 1000) return res.status(400).json({ error: 'Comments can\'t be edited after 24 hours' });

    comment.text = text.trim().slice(0, 500);
    comment.edited = true;
    await writeFilms(films);
    res.json(comment);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/films/:id', (req, res, next) => {
  req.currentUser = getUserFromReq(req);
  next();
}, upload.fields([{ name: 'poster', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, year, language, genre, description, type } = req.body;
    if (!isAdminBasicAuth(req) && (title !== undefined || description !== undefined) && await findBannedWord((title || '') + ' ' + (description || ''))) return res.status(400).json({ error: 'Title ya description me aisa shabd hai jo allowed nahi hai' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });

    const isOwner = req.currentUser && f.ownerId === req.currentUser.id;
    if (!isOwner && !isAdminBasicAuth(req)) return res.status(403).json({ error: 'This isn\'t your content' });

    if (title !== undefined) f.title = title;
    if (year !== undefined) f.year = year;
    if (language !== undefined) f.language = language;
    if (genre !== undefined) f.genre = genre;
    if (description !== undefined) f.description = description;
    if (type !== undefined) f.type = type === 'short' ? 'short' : 'film';
    if (title !== undefined || description !== undefined) {
      f.hashtags = extractHashtags((f.title || '') + ' ' + (f.description || ''));
      f.mentions = findMentionedUsers((f.title || '') + ' ' + (f.description || ''), await readUsers());
    }
    if (req.body.collabUsername !== undefined && isOwner) {
      const rawCollab = String(req.body.collabUsername || '').trim().replace(/^@/, '');
      if (!rawCollab) { delete f.collaboratorId; delete f.collaboratorUsername; delete f.collabStatus; }
      else {
        const allUsers = await readUsers();
        const target = allUsers.find(u => (u.username || '').toLowerCase() === rawCollab.toLowerCase());
        if (target && target.id !== req.currentUser.id && target.id !== f.collaboratorId && !(target.blockedUsers || []).includes(req.currentUser.id)) {
          f.collaboratorId = target.id; f.collaboratorUsername = target.username; f.collabStatus = 'pending';
          await notifyCollabInvite(f, req.currentUser);
        }
      }
    }

    if (req.files && req.files.poster) {
      const posterFile = req.files.poster[0];
      const newPosterKey = `posters/${f.id}-edit${Date.now()}${path.extname(posterFile.originalname)}`;
      await storePutBuffer(readFileAsBuffer(posterFile.path), newPosterKey, posterFile.mimetype);
      const oldPoster = f.posterFile;
      f.posterFile = newPosterKey;
      f.storageProvider = 'gdrive';
      if (oldPoster) storeDelete(oldPoster).catch(() => {});
    }

    await writeFilms(films);
    res.json(f);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/films/:id', (req, res, next) => {
  req.currentUser = getUserFromReq(req);
  next();
}, async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });

    const isOwner = req.currentUser && f.ownerId === req.currentUser.id;
    if (!isOwner && !isAdminBasicAuth(req)) return res.status(403).json({ error: 'This isn\'t your content' });

    // Storage cleanup is best-effort: a storage hiccup must never leave the owner unable to delete their own post.
    try { await storeDelete(f.videoFile); } catch (e) {}
    try { await storeDelete(f.posterFile); } catch (e) {}
    for (const sl of (f.slides || [])) { try { await storeDelete(sl.key); } catch (e) {} }

    const remaining = films.filter(x => x.id !== req.params.id);
    await writeFilms(remaining);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------- Stories "database" ----------------
let storiesCache = { data: null, expiresAt: 0 };
const STORIES_CACHE_MS = 10000;
const STORY_TTL_MS = 24 * 60 * 60 * 1000;

// ---------------- Watch history ----------------
async function readWatchHistory() {
  return await storeTryReadJSON('watch-history.json') || [];
}
async function writeWatchHistory(list) {
  await storeWriteJSON('watch-history.json', list.slice(-3000));
}

async function readStories() {
  if (storiesCache.data && Date.now() < storiesCache.expiresAt) return storiesCache.data;
  let stories = await storeTryReadJSON('stories.json') || [];

  storiesCache = { data: stories, expiresAt: Date.now() + STORIES_CACHE_MS };
  return stories;
}

async function writeStories(stories) {
  await storeWriteJSON('stories.json', stories);
  storiesCache = { data: stories, expiresAt: Date.now() + STORIES_CACHE_MS };
}

function isStoryActive(s) {
  return (Date.now() - new Date(s.createdAt).getTime()) < STORY_TTL_MS;
}
const STORY_ARCHIVE_MS = 90 * 24 * 60 * 60 * 1000;
function isStoryArchivable(s) {
  if (s.highlightId) return true;
  return (Date.now() - new Date(s.createdAt).getTime()) < STORY_ARCHIVE_MS;
}

// ---------------- Highlights "database" ----------------
async function readHighlights() {
  return await storeTryReadJSON('highlights.json') || [];
}
async function writeHighlights(list) {
  await storeWriteJSON('highlights.json', list);
}

// ===================== STORY ROUTES =====================

app.post('/api/stories', (req, res, next) => {
  req.currentUser = getUserFromReq(req);
  if (!req.currentUser) return res.status(401).json({ error: 'Please log in to post a story' });
  next();
}, upload.fields([{ name: 'media', maxCount: 1 }]), async (req, res) => {
  try {
    if (!req.files || !req.files.media) return res.status(400).json({ error: 'A photo or video is required' });
    const mediaFile = req.files.media[0];
    const isVideo = mediaFile.mimetype.startsWith('video');
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const mediaKey = `stories/${id}${path.extname(mediaFile.originalname)}`;
    await storePutBuffer(fs.readFileSync(mediaFile.path), mediaKey, mediaFile.mimetype);
    fs.unlink(mediaFile.path, () => {});

    let stories = await readStories();
    stories = stories.filter(isStoryArchivable);
    const newStory = {
      id,
      ownerId: req.currentUser.id,
      ownerUsername: req.currentUser.username,
      mediaFile: mediaKey,
      mediaType: isVideo ? 'video' : 'photo',
      storageProvider: 'gdrive',
      textOverlay: (req.body.textOverlay || '').slice(0, 200),
      createdAt: new Date().toISOString(),
      views: [],
      comments: []
    };
    stories.unshift(newStory);
    await writeStories(stories);
    res.status(201).json(newStory);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/stories/from-film', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Please log in to post a story' });
    const { filmId } = req.body;
    const films = await readFilms();
    const film = films.find(f => f.id === filmId);
    if (!film) return res.status(404).json({ error: 'Ye video/photo ab available nahi hai' });

    const sourceKey = film.type === 'photo' ? (film.posterFile || film.videoFile) : (film.videoFile || film.posterFile);
    if (!sourceKey) return res.status(400).json({ error: 'Story me daalne layak media nahi mila' });
    const isVideo = film.type !== 'photo';

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const ext = path.extname(sourceKey) || (isVideo ? '.mp4' : '.jpg');
    const mediaKey = `stories/${id}${ext}`;
    await storeCopy(sourceKey, mediaKey);

    let stories = await readStories();
    stories = stories.filter(isStoryArchivable);
    const newStory = {
      id, ownerId: currentUser.id, ownerUsername: currentUser.username,
      mediaFile: mediaKey, mediaType: isVideo ? 'video' : 'photo', storageProvider: 'gdrive',
      textOverlay: '', createdAt: new Date().toISOString(), views: [], comments: []
    };
    stories.unshift(newStory);
    await writeStories(stories);
    res.status(201).json(newStory);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stories', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    const stories = (await readStories()).filter(isStoryActive);
    const users = await readUsers();
    const directUrl = makeDirectUrlCache();

    const byUser = {};
    stories.forEach(s => {
      if (!byUser[s.ownerId]) byUser[s.ownerId] = [];
      byUser[s.ownerId].push(s);
    });

    const groups = await Promise.all(Object.keys(byUser).map(async ownerId => {
      const owner = users.find(u => u.id === ownerId);
      const ownerAvatarUrl = owner && owner.profileImage ? await directUrl(owner.profileImage, owner.avatarStorageProvider) : null;
      const userStories = await Promise.all(byUser[ownerId].slice().reverse().map(async s => ({
        id: s.id, ownerId: s.ownerId, ownerUsername: s.ownerUsername,
        mediaType: s.mediaType, textOverlay: s.textOverlay, createdAt: s.createdAt,
        mediaUrl: await directUrl(s.mediaFile, s.storageProvider),
        viewCount: (s.views || []).length,
        commentCount: (s.comments || []).length,
        viewedByMe: !!(currentUser && (s.views || []).some(v => v.userId === currentUser.id))
      })));
      return {
        ownerId,
        ownerUsername: owner ? owner.username : userStories[0].ownerUsername,
        ownerProfileImage: ownerAvatarUrl,
        stories: userStories,
        allViewed: userStories.every(s => s.viewedByMe)
      };
    }));

    res.json({ groups });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stories/:id', async (req, res) => {
  try {
    const stories = await readStories();
    const s = stories.find(x => x.id === req.params.id);
    if (!s || !isStoryActive(s)) return res.status(404).json({ error: 'Story not found or expired' });
    const users = await readUsers();
    const owner = users.find(u => u.id === s.ownerId);
    const directUrl = makeDirectUrlCache();
    const ownerAvatarUrl = owner && owner.profileImage ? await directUrl(owner.profileImage, owner.avatarStorageProvider) : null;
    const enrichedComments = await Promise.all((s.comments || []).map(async c => {
      const cUser = users.find(u => u.id === c.userId);
      const cAvatarUrl = cUser && cUser.profileImage ? await directUrl(cUser.profileImage, cUser.avatarStorageProvider) : null;
      return {
        ...c, likes: c.likes || [],
        name: cUser ? cUser.username : c.name,
        profileImage: cAvatarUrl
      };
    }));
    res.json({
      ...s, comments: enrichedComments,
      mediaUrl: await directUrl(s.mediaFile, s.storageProvider),
      viewCount: (s.views || []).length,
      ownerProfileImage: ownerAvatarUrl
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/media/story/:id', async (req, res) => {
  try {
    const stories = await readStories();
    const s = stories.find(x => x.id === req.params.id);
    if (!s || !s.mediaFile) return res.status(404).send('Not found');
    return storeStream(s.mediaFile, req, res);
  } catch (err) { res.status(500).send(err.message); }
});

app.post('/api/stories/:id/view', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    const stories = await readStories();
    const s = stories.find(x => x.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Story not found' });
    if (currentUser && !(s.views || []).some(v => v.userId === currentUser.id)) {
      if (!s.views) s.views = [];
      s.views.push({ userId: currentUser.id, username: currentUser.username, viewedAt: new Date().toISOString() });
      await writeStories(stories);
    }
    res.json({ viewCount: (s.views || []).length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/stories/:id/views', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const stories = await readStories();
    const s = stories.find(x => x.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Story not found' });
    if (s.ownerId !== currentUser.id) return res.status(403).json({ error: 'Only the story owner can view this' });
    const users = await readUsers();
    const viewers = (s.views || []).slice().reverse().map(v => {
      const u = users.find(x => x.id === v.userId);
      return { userId: v.userId, username: u ? u.username : v.username, profileImage: u && u.profileImage ? '/media/avatar/' + u.id : null, viewedAt: v.viewedAt };
    });
    res.json({ viewCount: viewers.length, viewers });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/stories/:id/comments', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Please log in to comment' });
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Please write a comment' });

    const stories = await readStories();
    const s = stories.find(x => x.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Story not found' });

    if (!s.comments) s.comments = [];
    const comment = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      userId: currentUser.id, name: currentUser.username,
      text: text.trim().slice(0, 500), likes: [], createdAt: new Date().toISOString()
    };
    s.comments.push(comment);
    await writeStories(stories);
    await notify(s.ownerId, { type: 'story_comment', fromUserId: currentUser.id, fromUsername: currentUser.username, storyId: s.id, message: `@${currentUser.username} commented on your story` });
    const cUser = currentUser;
    res.status(201).json({ ...comment, profileImage: null });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/stories/:storyId/comments/:commentId/like', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const stories = await readStories();
    const s = stories.find(x => x.id === req.params.storyId);
    if (!s || !s.comments) return res.status(404).json({ error: 'Not found' });
    const c = s.comments.find(x => x.id === req.params.commentId);
    if (!c) return res.status(404).json({ error: 'Comment not found' });
    if (!c.likes) c.likes = [];
    const idx = c.likes.indexOf(currentUser.id);
    if (idx === -1) {
      c.likes.push(currentUser.id);
      await notify(c.userId, { type: 'comment_like', fromUserId: currentUser.id, fromUsername: currentUser.username, storyId: s.id, message: `@${currentUser.username} liked your comment` });
    } else c.likes.splice(idx, 1);
    await writeStories(stories);
    res.json({ likes: c.likes.length, liked: idx === -1 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/stories/:storyId/comments/:commentId/delete', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const stories = await readStories();
    const s = stories.find(x => x.id === req.params.storyId);
    if (!s || !s.comments) return res.status(404).json({ error: 'Not found' });
    const comment = s.comments.find(c => c.id === req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    const isCommentOwner = comment.userId === currentUser.id;
    const isStoryOwner = s.ownerId === currentUser.id;
    if (!isCommentOwner && !isStoryOwner) return res.status(403).json({ error: 'You don\'t have permission' });
    s.comments = s.comments.filter(c => c.id !== req.params.commentId);
    await writeStories(stories);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/stories/:id/delete', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    let stories = await readStories();
    const s = stories.find(x => x.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Story not found' });
    if (s.ownerId !== currentUser.id) return res.status(403).json({ error: 'You don\'t have permission' });
    await storeDelete(s.mediaFile);
    stories = stories.filter(x => x.id !== req.params.id);
    await writeStories(stories);

    if (s.highlightId) {
      let highlights = await readHighlights();
      const h = highlights.find(x => x.id === s.highlightId);
      if (h) {
        h.storyIds = (h.storyIds || []).filter(id => id !== s.id);
        if (!h.storyIds.length) highlights = highlights.filter(x => x.id !== h.id);
        await writeHighlights(highlights);
      }
    }

    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===================== STORY HIGHLIGHTS =====================

app.get('/api/me/stories', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const stories = (await readStories()).filter(s => s.ownerId === currentUser.id);
    const directUrl = makeDirectUrlCache();
    const out = await Promise.all(stories.slice().reverse().map(async s => ({
      id: s.id, mediaType: s.mediaType, textOverlay: s.textOverlay, createdAt: s.createdAt,
      mediaUrl: await directUrl(s.mediaFile, s.storageProvider),
      active: isStoryActive(s), highlightId: s.highlightId || null
    })));
    res.json({ stories: out });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/highlights', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const title = (req.body.title || '').trim().slice(0, 30);
    const storyIds = Array.isArray(req.body.storyIds) ? req.body.storyIds.slice(0, 50) : [];
    if (!title) return res.status(400).json({ error: 'Highlight ko ek title do' });
    if (!storyIds.length) return res.status(400).json({ error: 'Kam se kam ek story chuno' });

    const stories = await readStories();
    const mine = storyIds.map(id => stories.find(s => s.id === id && s.ownerId === currentUser.id)).filter(Boolean);
    if (!mine.length) return res.status(404).json({ error: 'Stories nahi mili' });

    const highlight = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      ownerId: currentUser.id, ownerUsername: currentUser.username,
      title, storyIds: mine.map(s => s.id), createdAt: new Date().toISOString()
    };
    mine.forEach(s => { s.highlightId = highlight.id; });
    await writeStories(stories);

    const highlights = await readHighlights();
    highlights.push(highlight);
    await writeHighlights(highlights);
    res.status(201).json(highlight);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/highlights/:id', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const highlights = await readHighlights();
    const h = highlights.find(x => x.id === req.params.id);
    if (!h) return res.status(404).json({ error: 'Highlight not found' });
    if (h.ownerId !== currentUser.id) return res.status(403).json({ error: 'You don\'t have permission' });
    const title = (req.body.title || '').trim().slice(0, 30);
    if (title) h.title = title;
    await writeHighlights(highlights);
    res.json(h);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/highlights/:id/delete', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    let highlights = await readHighlights();
    const h = highlights.find(x => x.id === req.params.id);
    if (!h) return res.status(404).json({ error: 'Highlight not found' });
    if (h.ownerId !== currentUser.id) return res.status(403).json({ error: 'You don\'t have permission' });
    highlights = highlights.filter(x => x.id !== req.params.id);
    await writeHighlights(highlights);

    const stories = await readStories();
    let changed = false;
    stories.forEach(s => { if (s.highlightId === req.params.id) { delete s.highlightId; changed = true; } });
    if (changed) await writeStories(stories);

    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/users/:id/highlights', async (req, res) => {
  try {
    const highlights = (await readHighlights()).filter(h => h.ownerId === req.params.id);
    const stories = await readStories();
    const directUrl = makeDirectUrlCache();
    const out = await Promise.all(highlights.map(async h => {
      const cover = stories.find(s => s.id === h.storyIds[0]);
      return {
        id: h.id, title: h.title, storyCount: h.storyIds.length,
        coverUrl: cover ? await directUrl(cover.mediaFile, cover.storageProvider) : null
      };
    }));
    res.json({ highlights: out });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/highlights/:id', async (req, res) => {
  try {
    const highlights = await readHighlights();
    const h = highlights.find(x => x.id === req.params.id);
    if (!h) return res.status(404).json({ error: 'Highlight not found' });
    const stories = await readStories();
    const users = await readUsers();
    const owner = users.find(u => u.id === h.ownerId);
    const directUrl = makeDirectUrlCache();
    const ownerAvatarUrl = owner && owner.profileImage ? await directUrl(owner.profileImage, owner.avatarStorageProvider) : null;
    const enrichedStories = await Promise.all(h.storyIds.map(async id => {
      const s = stories.find(x => x.id === id);
      if (!s) return null;
      return {
        id: s.id, ownerId: s.ownerId, ownerUsername: s.ownerUsername,
        mediaType: s.mediaType, textOverlay: s.textOverlay, createdAt: s.createdAt,
        mediaUrl: await directUrl(s.mediaFile, s.storageProvider),
        viewCount: (s.views || []).length, commentCount: (s.comments || []).length
      };
    }));
    res.json({
      id: h.id, title: h.title, ownerId: h.ownerId,
      ownerUsername: owner ? owner.username : h.ownerUsername,
      ownerProfileImage: ownerAvatarUrl,
      stories: enrichedStories.filter(Boolean)
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


app.get('/api/notifications', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const all = await storeTryReadJSON('notifications.json') || [];
    const mine = all.filter(n => n.userId === currentUser.id).slice().reverse().slice(0, 50);
    const unreadCount = mine.filter(n => !n.read).length;
    res.json({ notifications: mine, unreadCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/notifications/unread-count', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.json({ unreadCount: 0 });
    const all = await storeTryReadJSON('notifications.json') || [];
    const unreadCount = all.filter(n => n.userId === currentUser.id && !n.read).length;
    res.json({ unreadCount });
  } catch (err) { res.json({ unreadCount: 0 }); }
});

app.post('/api/notifications/mark-read', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const all = await storeTryReadJSON('notifications.json') || [];
    let changed = false;
    all.forEach(n => { if (n.userId === currentUser.id && !n.read) { n.read = true; changed = true; } });
    if (changed) await storeWriteJSON('notifications.json', all);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------- Presence: typing + online status ----------------
const typingState = {}; // key: conversationId+':'+userId -> last-typed timestamp (ms)
const TYPING_TTL_MS = 4000;
const ONLINE_THRESHOLD_MS = 70 * 1000;
function isUserOnline(u) {
  return !!(u && u.lastActiveAt && (Date.now() - new Date(u.lastActiveAt).getTime()) < ONLINE_THRESHOLD_MS);
}
function isOtherTyping(conversationId, otherUserId) {
  const ts = typingState[conversationId + ':' + otherUserId];
  return !!(ts && (Date.now() - ts) < TYPING_TTL_MS);
}

// ---------------- Chat / DM "database" ----------------
async function readConversations() {
  return await storeTryReadJSON('conversations.json') || [];
}
async function writeConversations(list) {
  await storeWriteJSON('conversations.json', list);
}
function conversationIdFor(a, b) {
  return [a, b].sort().join('_');
}
async function readChatMessages(conversationId) {
  return await storeTryReadJSON(`chats/${conversationId}.json`) || [];
}
async function writeChatMessages(conversationId, messages) {
  await storeWriteJSON(`chats/${conversationId}.json`, messages);
}
async function getConversationForUsers(userA, userB, createIfMissing) {
  const list = await readConversations();
  const id = conversationIdFor(userA, userB);
  let convo = list.find(c => c.id === id);
  if (!convo && createIfMissing) {
    convo = { id, participants: [userA, userB], updatedAt: new Date().toISOString(), lastMessage: null };
    list.push(convo);
    await writeConversations(list);
  }
  return convo || null;
}
const MSG_EDIT_WINDOW_MS = 24 * 60 * 60 * 1000;
function previewForMessage(m) {
  if (m.unsent) return 'Message unsent';
  if (m.type === 'photo') return '📷 Photo';
  if (m.type === 'video') return '🎬 Video';
  if (m.type === 'voice') return '🎤 Voice message';
  if (m.type === 'short') return '🎬 Shared a short';
  return (m.text || '').slice(0, 80);
}
async function enrichMessage(m, directUrl) {
  const out = {
    id: m.id, conversationId: m.conversationId, senderId: m.senderId,
    type: m.type, text: m.unsent ? null : (m.text || null),
    createdAt: m.createdAt, editedAt: m.editedAt || null,
    unsent: !!m.unsent, readBy: m.readBy || [],
    mediaUrl: null, duration: m.duration || null,
    shortId: null, shortTitle: null, shortThumb: null, shortOwnerUsername: null,
    reactions: m.reactions || {}
  };
  if (!m.unsent && m.mediaKey && (m.type === 'photo' || m.type === 'video' || m.type === 'voice')) {
    out.mediaUrl = await directUrl(m.mediaKey, m.storageProvider || 'gdrive');
  }
  if (!m.unsent && m.type === 'short') {
    out.shortId = m.shortId;
    out.shortTitle = m.shortTitle || null;
    out.shortOwnerUsername = m.shortOwnerUsername || null;
    out.shortThumb = m.shortId ? `/media/poster/${m.shortId}` : null;
  }
  return out;
}

// ---------------- Ask AI: Groq + Tavily Integration ----------------
const AI_ASSISTANT_ID = 'ai-assistant';
const AI_ASSISTANT_USERNAME = 'Ask AI';
const AI_ASSISTANT_USER = { id: AI_ASSISTANT_ID, username: AI_ASSISTANT_USERNAME, profileImage: null };

const GROQ_API_KEY = process.env.GROQ_API_KEY;
const TAVILY_API_KEY = process.env.TAVILY_API_KEY;

const AI_SYSTEM_PROMPT = `Tum "Ask AI" ho — TAMASHA (YouSeries) streaming app ke andar built-in ek general-purpose AI assistant.
Agar tumhe [Live Web Context] diya jaye, to usi ko real-time/current info ka source maano aur usी ke basis par jawab do.
Agar [Live Web Context] NAHI diya gaya (ya usme kaam ka kuch na mile), aur sawaal aisi cheez ke baare me hai jo waqt ke saath badalti hai (jaise aaj ki tareekh/score/news/price), to saaf bol do ke ye abhi pata nahi — bana ke mat batao.
Baaki sab general knowledge, advice, explanations ke sawaalon ka apni knowledge se best-effort jawab do, aur TAMASHA app (upload, DM, follow, stories, settings) se judi problems me bhi madad karo.
Hinglish me chhota, to-the-point jawab do — chat bubble me padhna hai, essay nahi.`;

// Only spend a Tavily search credit when the question actually looks time-sensitive.
const REALTIME_HINT = /\b(today|now|current|latest|recent|live|score|news|price|weather|stock|update|kal|aaj|abhi|latest|mausam|taaza|score|kitna hai|kya hai)\b/i;

async function getLiveWebContext(query) {
  if (!TAVILY_API_KEY || !REALTIME_HINT.test(query)) return null;
  try {
    const res = await fetch('https://api.tavily.com/search', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${TAVILY_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        query: query,
        search_depth: 'basic',
        include_answer: true,
        max_results: 5
      })
    });
    if (!res.ok) { console.error('Tavily API error:', await res.text()); return null; }
    const data = await res.json();
    let result = '';
    if (data.answer) result += `Summary: ${data.answer}\n`;
    if (data.results && data.results.length > 0) {
      result += data.results.map(item => `- ${item.title}: ${item.content}`).join('\n');
    }
    return result.trim() || null;
  } catch (err) {
    console.error('Tavily search error:', err.message);
    return null;
  }
}

let cachedGroqModel = { id: null, resolvedAt: 0 };

async function resolveGroqModel() {
  if (cachedGroqModel.id && Date.now() - cachedGroqModel.resolvedAt < 6 * 60 * 60 * 1000) {
    return cachedGroqModel.id;
  }
  try {
    const res = await fetch('https://api.groq.com/openai/v1/models', {
      headers: { 'Authorization': `Bearer ${GROQ_API_KEY}` }
    });
    const data = await res.json();
    const ids = (data.data || []).map(m => m.id);
    const bad = /guard|whisper|tts|orpheus|prompt-guard|safeguard|embed/i;
    const candidates = ids.filter(id => !bad.test(id));
    const pick = candidates.find(id => /70b|120b/i.test(id)) ||
                 candidates.find(id => /llama/i.test(id)) ||
                 candidates[0];
    if (pick) { cachedGroqModel = { id: pick, resolvedAt: Date.now() }; return pick; }
  } catch (err) { console.error('Model resolution failed:', err.message); }
  return 'llama-3.3-70b-versatile';
}

async function callGroqChat(model, messages) {
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${GROQ_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ model, messages, max_tokens: 600 })
  });
  const data = await res.json();
  return { ok: res.ok, data };
}

async function callAiAssistant(recentMessages, currentUserId) {
  if (!GROQ_API_KEY) {
    return "Groq API Key set nahi hai, please GROQ_API_KEY add karein.";
  }

  const history = recentMessages
    .filter(m => !m.unsent && (m.text || '').trim())
    .slice(-16)
    .map(m => ({
      role: m.senderId === AI_ASSISTANT_ID ? 'assistant' : 'user',
      content: m.text
    }));

  // Keep the conversation starting on a real user turn (our seeded welcome message is 'assistant').
  while (history.length && history[0].role === 'assistant') history.shift();
  if (!history.length) return "Hi! Main Ask AI hoon. Kuch bhi pooch sakte hain aap.";

  const latestUserText = history[history.length - 1].content;
  const webData = await getLiveWebContext(latestUserText);

  const messages = [{ role: 'system', content: AI_SYSTEM_PROMPT }];
  if (webData) {
    messages.push({
      role: 'system',
      content: `[Live Web Context]:\n${webData}`
    });
  }
  messages.push(...history);

  try {
    const model = await resolveGroqModel();
    let { ok, data } = await callGroqChat(model, messages);

    if (!ok && /does not exist|decommissioned|not found/i.test((data.error && data.error.message) || '')) {
      // Cached model just went stale — force a fresh lookup and retry once.
      cachedGroqModel = { id: null, resolvedAt: 0 };
      const freshModel = await resolveGroqModel();
      ({ ok, data } = await callGroqChat(freshModel, messages));
    }

    if (!ok) {
      console.error('Groq API Error:', JSON.stringify(data));
      return "Abhi jawab nahi de paya (error: " + (data.error && data.error.message || 'unknown') + ")";
    }
    return (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || "Mujhe samajh nahi aaya, dobara poochein.";
  } catch (err) {
    console.error('Ask AI error:', err.message);
    return "Error: Thodi der baad try karein.";
  }
}
async function ensureAiConversation(userId){
  const convos = await readConversations();
  const id = conversationIdFor(userId, AI_ASSISTANT_ID);
  let convo = convos.find(c => c.id === id);
  if (convo) return convo;
  convo = { id, participants: [userId, AI_ASSISTANT_ID], updatedAt: new Date().toISOString(), lastMessage: null };
  convos.push(convo);
  await writeConversations(convos);

  const welcomeMsg = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
    conversationId: id, senderId: AI_ASSISTANT_ID,
    type: 'text', text: "Hi! Main Ask AI hoon 🤖 — TAMASHA use karne me koi bhi problem ho (account, upload, follow, kuch bhi), yahan pooch lo.",
    mediaKey: null, mediaType: null, storageProvider: null, duration: null,
    shortId: null, shortTitle: null, shortOwnerUsername: null,
    createdAt: new Date().toISOString(), editedAt: null,
    deletedFor: [], unsent: false, readBy: [AI_ASSISTANT_ID]
  };
  await writeChatMessages(id, [welcomeMsg]);
  convo.updatedAt = welcomeMsg.createdAt;
  convo.lastMessage = { senderId: AI_ASSISTANT_ID, preview: previewForMessage(welcomeMsg), createdAt: welcomeMsg.createdAt };
  await writeConversations(convos);
  return convo;
}

async function triggerAiReply(conversationId, currentUserId){
  try {
    const messages = await readChatMessages(conversationId);
    const replyText = await callAiAssistant(messages, currentUserId);
    const aiMsg = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
      conversationId, senderId: AI_ASSISTANT_ID,
      type: 'text', text: replyText,
      mediaKey: null, mediaType: null, storageProvider: null, duration: null,
      shortId: null, shortTitle: null, shortOwnerUsername: null,
      createdAt: new Date().toISOString(), editedAt: null,
      deletedFor: [], unsent: false, readBy: [AI_ASSISTANT_ID]
    };
    const all = await readChatMessages(conversationId);
    all.push(aiMsg);
    await writeChatMessages(conversationId, all);

    const convos = await readConversations();
    const convo = convos.find(c => c.id === conversationId);
    if (convo) {
      convo.updatedAt = aiMsg.createdAt;
      convo.lastMessage = { senderId: AI_ASSISTANT_ID, preview: previewForMessage(aiMsg), createdAt: aiMsg.createdAt };
      await writeConversations(convos);
    }
    // Notify ONLY if the user has left the Ask AI chat (closed it / switched app / locked phone).
    // If they are still looking at the chat, the reply just appears in the bubble list — no bell, no push.
    if (!isViewingAiChat(currentUserId)) {
      await notify(currentUserId, {
        type: 'message', fromUserId: AI_ASSISTANT_ID, fromUsername: AI_ASSISTANT_USERNAME,
        conversationId, message: '@Ask AI replied to you'
      });
    }
  } catch (err) { console.error('triggerAiReply failed:', err.message); }
}

// In-memory presence for the Ask AI chat (no storage reads/writes; resets on restart, which is fine).
// The client pings every few seconds while the AI chat is open AND the page is visible, and sends
// active:false the moment the chat is closed / page hidden. The TTL is the fallback if the app is killed.
const AI_VIEW_TTL_MS = 9000;
const aiViewing = new Map(); // userId -> last ping timestamp
function isViewingAiChat(userId) {
  const ts = aiViewing.get(userId);
  if (!ts) return false;
  if (Date.now() - ts > AI_VIEW_TTL_MS) { aiViewing.delete(userId); return false; }
  return true;
}
app.post('/api/ai/viewing', (req, res) => {
  const currentUser = getUserFromReq(req);
  if (!currentUser) return res.status(401).json({ error: 'Login required' });
  if (req.body && req.body.active) aiViewing.set(currentUser.id, Date.now());
  else aiViewing.delete(currentUser.id);
  res.json({ ok: true });
});

// ===================== CHAT / DM ROUTES =====================

app.get('/api/conversations', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    await ensureAiConversation(currentUser.id);
    const list = (await readConversations()).filter(c => c.participants.includes(currentUser.id));
    const users = await readUsers();
    const directUrl = makeDirectUrlCache();

    const out = await Promise.all(list
      .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
      .map(async c => {
        const otherId = c.participants.find(p => p !== currentUser.id);
        if (otherId === AI_ASSISTANT_ID) {
          const messages = await readChatMessages(c.id);
          const unreadCount = messages.filter(m => m.senderId !== currentUser.id && !m.unsent &&
            !(m.deletedFor || []).includes(currentUser.id) && !(m.readBy || []).includes(currentUser.id)).length;
          return { id: c.id, otherUser: AI_ASSISTANT_USER, lastMessage: c.lastMessage, updatedAt: c.updatedAt, unreadCount };
        }
        const other = users.find(u => u.id === otherId);
        const messages = await readChatMessages(c.id);
        const unreadCount = messages.filter(m => m.senderId !== currentUser.id && !m.unsent &&
          !(m.deletedFor || []).includes(currentUser.id) && !(m.readBy || []).includes(currentUser.id)).length;
        return {
          id: c.id,
          otherUser: other ? {
            id: other.id, username: other.username,
            profileImage: other.profileImage ? await directUrl(other.profileImage, other.avatarStorageProvider) : null,
            online: isUserOnline(other)
          } : { id: otherId, username: 'Unknown user', profileImage: null, online: false },
          lastMessage: c.lastMessage,
          updatedAt: c.updatedAt,
          unreadCount
        };
      }));
    res.json({ conversations: out });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/conversations/unread-count', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.json({ unreadCount: 0 });
    const list = (await readConversations()).filter(c => c.participants.includes(currentUser.id));
    let total = 0;
    for (const c of list) {
      const messages = await readChatMessages(c.id);
      total += messages.filter(m => m.senderId !== currentUser.id && !m.unsent &&
        !(m.deletedFor || []).includes(currentUser.id) && !(m.readBy || []).includes(currentUser.id)).length;
    }
    res.json({ unreadCount: total });
  } catch (err) { res.json({ unreadCount: 0 }); }
});

app.get('/api/conversations/with/:userId', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    if (currentUser.id === req.params.userId) return res.status(400).json({ error: "You can't message yourself" });

    const directUrl = makeDirectUrlCache();

    if (req.params.userId === AI_ASSISTANT_ID) {
      const convo = await ensureAiConversation(currentUser.id);
      const rawMessages = (await readChatMessages(convo.id)).filter(m => !(m.deletedFor || []).includes(currentUser.id));
      const messages = await Promise.all(rawMessages.slice(-100).map(m => enrichMessage(m, directUrl)));
      return res.json({ id: convo.id, otherUser: AI_ASSISTANT_USER, messages });
    }

    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    const target = users.find(u => u.id === req.params.userId);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if ((me.blockedUsers || []).includes(target.id) || (target.blockedUsers || []).includes(me.id)) {
      return res.status(403).json({ error: 'You can\'t message this user' });
    }

    let convo = await getConversationForUsers(currentUser.id, target.id, false);
    if (!convo) {
      const iFollowThem = me && me.following && me.following.includes(target.id);
      if (!iFollowThem) return res.status(403).json({ error: 'Message karne ke liye pehle is user ko follow karo' });
      convo = await getConversationForUsers(currentUser.id, target.id, true);
    }

    const rawMessages = (await readChatMessages(convo.id)).filter(m => !(m.deletedFor || []).includes(currentUser.id));
    const messages = await Promise.all(rawMessages.slice(-100).map(m => enrichMessage(m, directUrl)));

    res.json({
      id: convo.id,
      otherUser: {
        id: target.id, username: target.username,
        profileImage: target.profileImage ? await directUrl(target.profileImage, target.avatarStorageProvider) : null,
        online: isUserOnline(target)
      },
      messages
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/conversations/:id/messages', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const convo = convos.find(c => c.id === req.params.id);
    if (!convo || !convo.participants.includes(currentUser.id)) return res.status(403).json({ error: 'Not allowed' });

    const since = req.query.since ? new Date(req.query.since).getTime() : 0;
    const directUrl = makeDirectUrlCache();
    let raw = (await readChatMessages(convo.id)).filter(m => !(m.deletedFor || []).includes(currentUser.id));
    if (since) raw = raw.filter(m => new Date(m.createdAt).getTime() > since || (m.editedAt && new Date(m.editedAt).getTime() > since) || (m.reactedAt && new Date(m.reactedAt).getTime() > since));
    const messages = await Promise.all(raw.map(m => enrichMessage(m, directUrl)));

    const otherId = convo.participants.find(p => p !== currentUser.id);
    let otherOnline = false;
    if (otherId && otherId !== AI_ASSISTANT_ID) {
      const users = await readUsers();
      otherOnline = isUserOnline(users.find(u => u.id === otherId));
    }
    res.json({ messages, otherTyping: otherId ? isOtherTyping(convo.id, otherId) : false, otherOnline });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/conversations/:id/messages', (req, res, next) => {
  req.currentUser = getUserFromReq(req);
  if (!req.currentUser) return res.status(401).json({ error: 'Login required' });
  next();
}, upload.fields([{ name: 'media', maxCount: 1 }]), async (req, res) => {
  try {
    const convos = await readConversations();
    const convo = convos.find(c => c.id === req.params.id);
    if (!convo || !convo.participants.includes(req.currentUser.id)) return res.status(403).json({ error: 'Not allowed' });

    const otherParticipantId = convo.participants.find(p => p !== req.currentUser.id);
    if (otherParticipantId && otherParticipantId !== AI_ASSISTANT_ID) {
      const users = await readUsers();
      const me = users.find(u => u.id === req.currentUser.id);
      const other = users.find(u => u.id === otherParticipantId);
      if ((me && me.blockedUsers && me.blockedUsers.includes(otherParticipantId)) || (other && other.blockedUsers && other.blockedUsers.includes(req.currentUser.id))) {
        return res.status(403).json({ error: 'You can\'t message this user' });
      }
    }

    const text = (req.body.text || '').trim().slice(0, 2000);
    const shortId = req.body.shortId || null;
    const isVoice = toBool(req.body.isVoice);
    const mediaFile = req.files && req.files.media && req.files.media[0];

    if (!text && !mediaFile && !shortId) return res.status(400).json({ error: 'Kuch to bhejo — message, photo, video ya short' });

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    let type = 'text', mediaKey = null, mediaType = null, duration = null;
    let shortTitle = null, shortOwnerUsername = null;

    if (mediaFile) {
      const isVideo = mediaFile.mimetype.startsWith('video');
      const isAudio = mediaFile.mimetype.startsWith('audio') || isVoice;
      type = isAudio ? 'voice' : (isVideo ? 'video' : 'photo');
      mediaKey = `chats/${convo.id}/${id}${path.extname(mediaFile.originalname) || (isAudio ? '.webm' : '')}`;
      await storePutBuffer(readFileAsBuffer(mediaFile.path), mediaKey, mediaFile.mimetype);
      mediaType = type;
      if (isAudio && req.body.duration) duration = parseFloat(req.body.duration) || null;
    } else if (shortId) {
      const films = await readFilms();
      const film = films.find(f => f.id === shortId);
      if (!film) return res.status(404).json({ error: 'Ye short ab available nahi hai' });
      type = 'short';
      shortTitle = film.title;
      shortOwnerUsername = film.ownerUsername;
    }

    const newMessage = {
      id, conversationId: convo.id, senderId: req.currentUser.id,
      type, text: text || null,
      mediaKey, mediaType, storageProvider: 'gdrive', duration,
      shortId: type === 'short' ? shortId : null, shortTitle, shortOwnerUsername,
      createdAt: new Date().toISOString(), editedAt: null,
      deletedFor: [], unsent: false, readBy: [req.currentUser.id]
    };

    const messages = await readChatMessages(convo.id);
    messages.push(newMessage);
    await writeChatMessages(convo.id, messages);

    convo.updatedAt = newMessage.createdAt;
    convo.lastMessage = { senderId: req.currentUser.id, preview: previewForMessage(newMessage), createdAt: newMessage.createdAt };
    await writeConversations(convos);

    const otherId = convo.participants.find(p => p !== req.currentUser.id);
    if (otherId === AI_ASSISTANT_ID) {
      triggerAiReply(convo.id, req.currentUser.id).catch(() => {});
    } else {
      await notify(otherId, {
        type: 'message', fromUserId: req.currentUser.id, fromUsername: req.currentUser.username,
        conversationId: convo.id, message: `@${req.currentUser.username} sent you a message`
      });
    }

    const directUrl = makeDirectUrlCache();
    res.status(201).json(await enrichMessage(newMessage, directUrl));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/conversations/:id/messages/:messageId', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const convo = convos.find(c => c.id === req.params.id);
    if (!convo || !convo.participants.includes(currentUser.id)) return res.status(403).json({ error: 'Not allowed' });

    const messages = await readChatMessages(convo.id);
    const m = messages.find(x => x.id === req.params.messageId);
    if (!m) return res.status(404).json({ error: 'Message not found' });
    if (m.senderId !== currentUser.id) return res.status(403).json({ error: 'You can only edit your own messages' });
    if (m.unsent) return res.status(400).json({ error: 'This message was unsent' });
    if (m.type !== 'text') return res.status(400).json({ error: 'Only text messages can be edited' });
    if (Date.now() - new Date(m.createdAt).getTime() > MSG_EDIT_WINDOW_MS) return res.status(400).json({ error: 'Edit window (24h) has expired' });

    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Message khali nahi ho sakta' });
    m.text = text.trim().slice(0, 2000);
    m.editedAt = new Date().toISOString();
    await writeChatMessages(convo.id, messages);

    if (convo.lastMessage && convo.lastMessage.createdAt === m.createdAt) {
      convo.lastMessage.preview = previewForMessage(m);
      await writeConversations(convos);
    }

    const directUrl = makeDirectUrlCache();
    res.json(await enrichMessage(m, directUrl));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/conversations/:id/messages/:messageId/delete', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const convo = convos.find(c => c.id === req.params.id);
    if (!convo || !convo.participants.includes(currentUser.id)) return res.status(403).json({ error: 'Not allowed' });

    const messages = await readChatMessages(convo.id);
    const m = messages.find(x => x.id === req.params.messageId);
    if (!m) return res.status(404).json({ error: 'Message not found' });

    const scope = req.body.scope === 'everyone' ? 'everyone' : 'me';
    if (scope === 'everyone') {
      if (m.senderId !== currentUser.id) return res.status(403).json({ error: 'You can only delete your own messages for everyone' });
      if (m.mediaKey) { await storeDelete(m.mediaKey); m.mediaKey = null; }
      m.unsent = true;
      m.text = null;
      m.editedAt = new Date().toISOString(); // so live polling (since=editedAt) picks up the unsend immediately
    } else {
      if (!m.deletedFor) m.deletedFor = [];
      if (!m.deletedFor.includes(currentUser.id)) m.deletedFor.push(currentUser.id);
    }
    await writeChatMessages(convo.id, messages);

    if (convo.lastMessage && convo.lastMessage.createdAt === m.createdAt) {
      convo.lastMessage.preview = previewForMessage(m);
      await writeConversations(convos);
    }
    res.json({ success: true, scope });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const REACTION_EMOJIS = ['❤️', '😂', '😮', '😢', '👍'];
app.post('/api/conversations/:id/messages/:messageId/react', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const convo = convos.find(c => c.id === req.params.id);
    if (!convo || !convo.participants.includes(currentUser.id)) return res.status(403).json({ error: 'Not allowed' });

    const messages = await readChatMessages(convo.id);
    const m = messages.find(x => x.id === req.params.messageId);
    if (!m) return res.status(404).json({ error: 'Message not found' });

    const emoji = req.body.emoji;
    if (!m.reactions) m.reactions = {};
    if (!emoji || !REACTION_EMOJIS.includes(emoji)) {
      delete m.reactions[currentUser.id];
    } else if (m.reactions[currentUser.id] === emoji) {
      delete m.reactions[currentUser.id];
    } else {
      m.reactions[currentUser.id] = emoji;
      if (m.senderId && m.senderId !== currentUser.id && m.senderId !== AI_ASSISTANT_ID) {
        await notify(m.senderId, {
          type: 'message_reaction', fromUserId: currentUser.id, fromUsername: currentUser.username,
          conversationId: convo.id, message: `@${currentUser.username} reacted ${emoji} to your message`
        });
      }
    }
    m.reactedAt = new Date().toISOString();
    await writeChatMessages(convo.id, messages);
    res.json({ reactions: m.reactions });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/conversations/:id/read', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const convo = convos.find(c => c.id === req.params.id);
    if (!convo || !convo.participants.includes(currentUser.id)) return res.status(403).json({ error: 'Not allowed' });

    const messages = await readChatMessages(convo.id);
    let changed = false;
    messages.forEach(m => {
      if (m.senderId !== currentUser.id) {
        if (!m.readBy) m.readBy = [];
        if (!m.readBy.includes(currentUser.id)) { m.readBy.push(currentUser.id); changed = true; }
      }
    });
    if (changed) await writeChatMessages(convo.id, messages);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/me/watch-history', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const history = await readWatchHistory();
    const films = await readFilms();
    const directUrl = makeDirectUrlCache();
    const mine = history.filter(h => h.userId === currentUser.id).slice().reverse().slice(0, 100);
    const out = await Promise.all(mine.map(async h => {
      const f = films.find(x => x.id === h.filmId);
      if (!f) return null;
      return {
        filmId: f.id, title: f.title, type: f.type,
        posterUrl: f.posterFile ? await directUrl(f.posterFile, f.storageProvider) : null,
        viewedAt: h.viewedAt
      };
    }));
    res.json({ history: out.filter(Boolean) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/me/liked', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const directUrl = makeDirectUrlCache();
    const out = await Promise.all(films
      .filter(f => f.likedBy && f.likedBy.includes(currentUser.id))
      .map(async f => ({
        filmId: f.id, title: f.title, type: f.type,
        posterUrl: f.posterFile ? await directUrl(f.posterFile, f.storageProvider) : null,
        likedAt: (f.likedAt && f.likedAt[currentUser.id]) || null
      })));
    out.sort((a, b) => new Date(b.likedAt || 0) - new Date(a.likedAt || 0));
    res.json({ liked: out });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/me/saved', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const directUrl = makeDirectUrlCache();
    const mine = films.filter(f => f.savedBy && f.savedBy.includes(currentUser.id));
    const out = await Promise.all(mine.map(async f => ({
      id: f.id, filmId: f.id, title: f.title, type: f.type,
      posterUrl: f.posterFile ? await directUrl(f.posterFile, f.storageProvider) : null
    })));
    res.json({ saved: out.reverse() });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/me/comments', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const directUrl = makeDirectUrlCache();
    const out = [];
    for (const f of films) {
      for (const c of (f.comments || [])) {
        if (c.userId === currentUser.id) {
          out.push({
            filmId: f.id, filmTitle: f.title,
            posterUrl: f.posterFile ? await directUrl(f.posterFile, f.storageProvider) : null,
            commentId: c.id, text: c.text, createdAt: c.createdAt
          });
        }
      }
    }
    out.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ comments: out.slice(0, 100) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/me/heartbeat', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    if (!me) return res.status(404).json({ error: 'User not found' });
    me.lastActiveAt = new Date().toISOString();
    await writeUsers(users);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/conversations/:id/typing', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const convo = convos.find(c => c.id === req.params.id);
    if (!convo || !convo.participants.includes(currentUser.id)) return res.status(403).json({ error: 'Not allowed' });
    typingState[convo.id + ':' + currentUser.id] = Date.now();
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/me/settings', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (typeof req.body.hideSensitiveContent === 'boolean') user.hideSensitiveContent = req.body.hideSensitiveContent;
    await writeUsers(users);
    res.json({ hideSensitiveContent: !!user.hideSensitiveContent });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/me/delete', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });

    const films = await readFilms();
    const myFilms = films.filter(f => f.ownerId === currentUser.id);
    for (const f of myFilms) {
      await storeDelete(f.videoFile);
      await storeDelete(f.posterFile);
    }
    const remainingFilms = films.filter(f => f.ownerId !== currentUser.id);
    await writeFilms(remainingFilms);

    let stories = await readStories();
    const myStories = stories.filter(s => s.ownerId === currentUser.id);
    for (const s of myStories) {
      await storeDelete(s.mediaFile);
    }
    await writeStories(stories.filter(s => s.ownerId !== currentUser.id));

    const conversations = await readConversations();
    const myConversations = conversations.filter(c => c.participants.includes(currentUser.id));
    for (const c of myConversations) {
      const messages = await readChatMessages(c.id);
      for (const m of messages) { if (m.mediaKey) await storeDelete(m.mediaKey); }
      await storeDelete(`chats/${c.id}.json`);
    }
    await writeConversations(conversations.filter(c => !c.participants.includes(currentUser.id)));

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (user && user.profileImage) await storeDelete(user.profileImage);
    users.forEach(u => { if (u.following) u.following = u.following.filter(id => id !== currentUser.id); });
    const remainingUsers = users.filter(u => u.id !== currentUser.id);
    await writeUsers(remainingUsers);

    res.clearCookie('token');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const RESEND_API_KEY = process.env.RESEND_API_KEY;

// ---------------- Help desk: tickets stored for the dashboard (with email), admin replies shown back to the user ----------------
async function readHelpdesk() { return (await storeTryReadJSON('helpdesk.json')) || []; }
async function writeHelpdesk(list) { await storeWriteJSON('helpdesk.json', list); }
const helpRate = new Map();
function helpRateOk(key) {
  const now = Date.now();
  const arr = (helpRate.get(key) || []).filter(t => now - t < 60 * 60 * 1000);
  if (arr.length >= 5) { helpRate.set(key, arr); return false; }
  arr.push(now); helpRate.set(key, arr); return true;
}
const looksLikeEmail = e => typeof e === 'string' && e.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
async function sendResendMail(to, subject, text) {
  if (!RESEND_API_KEY) return false;
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: 'YouSeries Help Desk <onboarding@resend.dev>', to: [to], subject, text })
    });
    return r.ok;
  } catch (e) { return false; }
}
function ticketView(t) {
  return { id: t.id, problem: t.problem, status: t.status, createdAt: t.createdAt, replies: t.replies || [], hasNewReply: !!t.hasNewReply };
}

app.post('/api/help-desk', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    const { name, problem, email } = req.body || {};
    const text = String(problem || '').trim().slice(0, 2000);
    if (!text) return res.status(400).json({ error: 'Please describe your problem' });
    const contact = String(email || (currentUser && currentUser.email) || '').trim();
    if (contact && !looksLikeEmail(contact)) return res.status(400).json({ error: 'Email sahi nahi lag raha' });
    if (!helpRateOk(currentUser ? 'u:' + currentUser.id : 'ip:' + req.ip)) return res.status(429).json({ error: 'Bahut zyada messages — thodi der baad try karo' });

    const list = await readHelpdesk();
    const ticket = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      userId: currentUser ? currentUser.id : null,
      username: currentUser ? currentUser.username : null,
      name: String(name || (currentUser && currentUser.username) || 'User').slice(0, 60),
      email: contact || null,
      problem: text, status: 'open', createdAt: new Date().toISOString(), replies: []
    };
    list.push(ticket);
    await writeHelpdesk(list.slice(-1000));
    // tell the owner: in-app notification (+ email through Resend if configured) — never blocks the ticket itself
    alertAdminText(`📩 Naya Help Desk message: ${ticket.name}${ticket.email ? ' (' + ticket.email + ')' : ''} — "${text.slice(0, 80)}"`).catch(() => {});
    sendResendMail('sohailp541@gmail.com', 'YouSeries Help Desk - ' + ticket.name,
      `Name: ${ticket.name}\nEmail: ${ticket.email || '-'}\nUser ID: ${ticket.userId || '-'}\n\nProblem:\n${text}\n\nDashboard → Help Desk me jawab de sakte ho.`).catch(() => {});
    res.status(201).json({ success: true, id: ticket.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/help-desk/mine', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const list = await readHelpdesk();
    const mine = list.filter(t => t.userId === currentUser.id);
    const out = mine.slice().reverse().map(ticketView);
    let changed = false;
    mine.forEach(t => { if (t.hasNewReply) { t.hasNewReply = false; changed = true; } });
    if (changed) await writeHelpdesk(list);
    res.json({ tickets: out });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/help-desk/:id/reply', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const text = String((req.body && req.body.message) || '').trim().slice(0, 1000);
    if (!text) return res.status(400).json({ error: 'Message likho' });
    const list = await readHelpdesk();
    const t = list.find(x => x.id === req.params.id && x.userId === currentUser.id);
    if (!t) return res.status(404).json({ error: 'Ticket nahi mila' });
    if (!helpRateOk('u:' + currentUser.id)) return res.status(429).json({ error: 'Bahut zyada messages — thodi der baad try karo' });
    t.replies = t.replies || [];
    t.replies.push({ from: 'user', text, at: new Date().toISOString() });
    t.status = 'open'; t.adminSeen = false;
    await writeHelpdesk(list);
    alertAdminText(`💬 Help Desk follow-up: ${t.name} — "${text.slice(0, 80)}"`).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/helpdesk', requireAdmin, async (req, res) => {
  try {
    const list = await readHelpdesk();
    res.json({ tickets: list.slice().reverse().sort((a, b) => (a.status === 'open' ? 0 : 1) - (b.status === 'open' ? 0 : 1)) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/helpdesk/:id/reply', requireAdmin, async (req, res) => {
  try {
    const text = String((req.body && req.body.message) || '').trim().slice(0, 1500);
    if (!text) return res.status(400).json({ error: 'Jawab likho' });
    const list = await readHelpdesk();
    const t = list.find(x => x.id === req.params.id);
    if (!t) return res.status(404).json({ error: 'Ticket nahi mila' });
    t.replies = t.replies || [];
    t.replies.push({ from: 'admin', text, at: new Date().toISOString() });
    t.hasNewReply = true; t.adminSeen = true; t.status = 'answered';
    await writeHelpdesk(list);
    if (t.userId) await notify(t.userId, { type: 'helpdesk_reply', fromUserId: 'system', fromUsername: 'Help Desk', message: '🆘 Help Desk ne tumhare sawal ka jawab diya' });
    let emailed = false;
    if (t.email) emailed = await sendResendMail(t.email, 'YouSeries Help Desk — tumhare sawal ka jawab', `Hi ${t.name},\n\n${text}\n\n— YouSeries Help Desk\n\n(Tumhara sawal: ${t.problem.slice(0, 200)})`);
    res.json({ success: true, emailed });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/helpdesk/:id/status', requireAdmin, async (req, res) => {
  try {
    const status = (req.body && req.body.status) === 'closed' ? 'closed' : 'open';
    const list = await readHelpdesk();
    const t = list.find(x => x.id === req.params.id);
    if (!t) return res.status(404).json({ error: 'Ticket nahi mila' });
    t.status = status; await writeHelpdesk(list);
    res.json({ success: true, status });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/push/vapid-public-key', (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC_KEY });
});

app.post('/api/push/subscribe', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Please log in' });
    const { subscription } = req.body;
    if (!subscription || !subscription.endpoint) return res.status(400).json({ error: 'Invalid subscription' });

    const subs = await storeTryReadJSON('push-subscriptions.json') || [];
    const existingIdx = subs.findIndex(s => s.subscription.endpoint === subscription.endpoint);
    const entry = { userId: currentUser.id, subscription, createdAt: new Date().toISOString() };
    if (existingIdx !== -1) subs[existingIdx] = entry; else subs.push(entry);
    await storeWriteJSON('push-subscriptions.json', subs);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/push/unsubscribe', async (req, res) => {
  try {
    const { endpoint } = req.body;
    if (!endpoint) return res.status(400).json({ error: 'Endpoint required' });
    const subs = await storeTryReadJSON('push-subscriptions.json') || [];
    const filtered = subs.filter(s => s.subscription.endpoint !== endpoint);
    await storeWriteJSON('push-subscriptions.json', filtered);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===================== SAFETY / MODERATION =====================
async function readReports() {
  return await storeTryReadJSON('reports.json') || [];
}
async function writeReports(list) {
  await storeWriteJSON('reports.json', list);
}

const recentCommentsByUser = {};
function checkSpamAndRecord(userId, text) {
  const now = Date.now();
  if (!recentCommentsByUser[userId]) recentCommentsByUser[userId] = [];
  recentCommentsByUser[userId] = recentCommentsByUser[userId].filter(e => now - e.ts < 10 * 60 * 1000);
  recentCommentsByUser[userId].push({ text, ts: now });
  const sameTextCount = recentCommentsByUser[userId].filter(e => e.text === text).length;
  const linkCount = (text.match(/https?:\/\//g) || []).length;
  return sameTextCount >= 3 || linkCount >= 3;
}

app.post('/api/reports', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const { type, targetId, reason, note } = req.body;
    if (!['post', 'user', 'comment'].includes(type)) return res.status(400).json({ error: 'Invalid report type' });
    if (!targetId) return res.status(400).json({ error: 'Missing target' });

    let targetOwnerId = null, targetPreview = null, filmId = null;
    if (type === 'post') {
      const films = await readFilms();
      const f = films.find(x => x.id === targetId);
      if (!f) return res.status(404).json({ error: 'Post not found' });
      targetOwnerId = f.ownerId; targetPreview = f.title; filmId = f.id;
    } else if (type === 'user') {
      const users = await readUsers();
      const u = users.find(x => x.id === targetId);
      if (!u) return res.status(404).json({ error: 'User not found' });
      targetOwnerId = u.id; targetPreview = u.username;
    } else if (type === 'comment') {
      const [fId, cId] = String(targetId).split(':');
      const films = await readFilms();
      const f = films.find(x => x.id === fId);
      const c = f && (f.comments || []).find(x => x.id === cId);
      if (!f || !c) return res.status(404).json({ error: 'Comment not found' });
      targetOwnerId = c.userId; targetPreview = c.text; filmId = f.id;
    }

    const reports = await readReports();
    const report = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      type, targetId, filmId, targetOwnerId, targetPreview,
      reporterId: currentUser.id, reporterUsername: currentUser.username,
      reason: reason || 'other', note: (note || '').slice(0, 500),
      status: 'pending', createdAt: new Date().toISOString()
    };
    reports.push(report);
    await writeReports(reports);
    alertAdminOfReport(report).catch(() => {});
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

function requireAdmin(req, res, next) {
  if (!isAdminBasicAuth(req)) {
    if (!req.headers['x-no-prompt']) res.set('WWW-Authenticate', 'Basic realm="Moderation"');   // dashboard has its own login form
    return res.status(401).json({ error: 'Admin login required' });
  }
  next();
}

app.get('/api/admin/reports', requireAdmin, async (req, res) => {
  try {
    const reports = await readReports();
    res.json({ reports: reports.slice().reverse() });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/reports/:id/dismiss', requireAdmin, async (req, res) => {
  try {
    const reports = await readReports();
    const r = reports.find(x => x.id === req.params.id);
    if (!r) return res.status(404).json({ error: 'Not found' });
    r.status = 'dismissed';
    await writeReports(reports);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/reports/:id/remove-content', requireAdmin, async (req, res) => {
  try {
    const reports = await readReports();
    const r = reports.find(x => x.id === req.params.id);
    if (!r) return res.status(404).json({ error: 'Not found' });

    if (r.type === 'post' && r.filmId) {
      let films = await readFilms();
      const f = films.find(x => x.id === r.filmId);
      if (f) {
        await storeDelete(f.videoFile);
        await storeDelete(f.posterFile);
        films = films.filter(x => x.id !== r.filmId);
        await writeFilms(films);
      }
    } else if (r.type === 'comment' && r.filmId) {
      const films = await readFilms();
      const f = films.find(x => x.id === r.filmId);
      if (f && f.comments) {
        const [, cId] = String(r.targetId).split(':');
        f.comments = f.comments.filter(c => c.id !== cId);
        await writeFilms(films);
      }
    }
    r.status = 'resolved';
    await writeReports(reports);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/users/:id/suspend', requireAdmin, async (req, res) => {
  try {
    const users = await readUsers();
    const u = users.find(x => x.id === req.params.id);
    if (!u) return res.status(404).json({ error: 'User not found' });
    u.suspended = !u.suspended;
    await writeUsers(users);
    if (u.suspended) suspendedIds.add(u.id); else suspendedIds.delete(u.id);
    res.json({ suspended: u.suspended });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------- Admin dashboard (owner-only, same ADMIN_USER / ADMIN_PASS login as the moderation panel) ----------------
// Shows public activity + account stats. Private messages are deliberately NOT part of this.
app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  try {
    const [users, films, stories, reports] = await Promise.all([readUsers(), readFilms(), readStories(), readReports()]);
    const now = Date.now(), DAY = 24 * 60 * 60 * 1000;
    const ts = x => (x ? new Date(x).getTime() || 0 : 0);
    const postCount = {}, commentCount = {}, followers = {}, reportsAgainst = {};
    let events = [];
    let uploads24h = 0, comments24h = 0;
    const byType = { film: 0, short: 0, photo: 0 };

    films.forEach(f => {
      const type = f.type === 'photo' ? 'photo' : f.type === 'short' ? 'short' : 'film';
      byType[type]++;
      if (f.ownerId && f.ownerId !== 'admin') postCount[f.ownerId] = (postCount[f.ownerId] || 0) + 1;
      if (now - ts(f.uploadedAt) < DAY) uploads24h++;
      events.push({ type: 'upload', at: f.uploadedAt, userId: f.ownerId, username: f.ownerUsername, text: type + ': ' + (f.title || '') });
      (f.comments || []).forEach(c => {
        if (c.userId) commentCount[c.userId] = (commentCount[c.userId] || 0) + 1;
        if (now - ts(c.createdAt) < DAY) comments24h++;
        events.push({ type: 'comment', at: c.createdAt, userId: c.userId, username: c.name,
          text: String(c.text || '').slice(0, 140) + '  →  ' + (f.title || '') });
      });
    });
    let stories24h = 0;
    stories.forEach(st => {
      if (now - ts(st.createdAt) < DAY) stories24h++;
      events.push({ type: 'story', at: st.createdAt, userId: st.ownerId, username: st.ownerUsername, text: st.mediaType === 'video' ? 'video story' : 'photo story' });
    });
    users.forEach(u => {
      (u.following || []).forEach(id => { followers[id] = (followers[id] || 0) + 1; });
      events.push({ type: 'signup', at: u.createdAt, userId: u.id, username: u.username, text: 'naya account bana' });
    });
    reports.forEach(r => { if (r.targetOwnerId && r.status !== 'dismissed') reportsAgainst[r.targetOwnerId] = (reportsAgainst[r.targetOwnerId] || 0) + 1; });

    events.sort((a, b) => ts(b.at) - ts(a.at));
    events = events.slice(0, 100);

    // Trending: top posts, hashtags (last 14 days) and creators
    const commentsOf = f => (f.comments || []).length;
    const scoreOf = f => (f.views || 0) + (f.likes || 0) * 3 + commentsOf(f) * 2;
    const trendingPosts = films.slice().sort((a, b) => scoreOf(b) - scoreOf(a)).slice(0, 8).map(f => ({
      id: f.id, title: f.title, type: f.type === 'photo' ? ((f.slides && f.slides.length > 1) ? 'carousel' : 'photo') : (f.type === 'short' ? 'short' : 'film'),
      owner: f.ownerUsername, views: f.views || 0, likes: f.likes || 0, comments: commentsOf(f), score: scoreOf(f)
    }));
    const tagCount = {};
    films.forEach(f => { if (now - ts(f.uploadedAt) < 14 * DAY) getFilmHashtags(f).forEach(t => { tagCount[t] = (tagCount[t] || 0) + 1; }); });
    const trendingTags = Object.entries(tagCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([tag, count]) => ({ tag, count }));
    const creatorAgg = {};
    films.forEach(f => { if (!f.ownerId || f.ownerId === 'admin') return; const c = creatorAgg[f.ownerId] || (creatorAgg[f.ownerId] = { username: f.ownerUsername, posts: 0, score: 0 }); c.posts++; c.score += scoreOf(f); });
    const trendingCreators = Object.values(creatorAgg).sort((a, b) => b.score - a.score).slice(0, 5);

    // Storage + egress
    const st = await refreshStorageStats();
    usageRoll();

    const rows = users.map(u => ({
      id: u.id, username: u.username, email: u.email, createdAt: u.createdAt || null, lastActiveAt: u.lastActiveAt || null,
      online: isUserOnline(u), suspended: !!u.suspended, verified: !!u.verified, google: !u.passwordHash,
      posts: postCount[u.id] || 0, comments: commentCount[u.id] || 0, followers: followers[u.id] || 0, reports: reportsAgainst[u.id] || 0
    })).sort((a, b) => ts(b.lastActiveAt) - ts(a.lastActiveAt) || ts(b.createdAt) - ts(a.createdAt));

    res.json({
      overview: {
        totalUsers: users.length,
        newToday: users.filter(u => now - ts(u.createdAt) < DAY).length,
        new7d: users.filter(u => now - ts(u.createdAt) < 7 * DAY).length,
        onlineNow: rows.filter(r => r.online).length,
        activeToday: users.filter(u => now - ts(u.lastActiveAt) < DAY).length,
        suspended: users.filter(u => u.suspended).length,
        posts: byType, uploads24h, comments24h, stories24h,
        pendingReports: reports.filter(r => r.status === 'pending').length
      },
      trending: { posts: trendingPosts, hashtags: trendingTags, creators: trendingCreators },
      storage: { ok: st.ok, error: st.error, usedBytes: st.usedBytes, limitBytes: st.accountLimit || STORAGE_LIMIT_BYTES, objects: st.objects, byFolder: st.byFolder, listedAt: st.at ? new Date(st.at).toISOString() : null },
      egress: { mode: 'render', month: usage.month, jsonBytes: usage.jsonBytes, mediaBytes: 0, proxyBytes: usage.proxyBytes, totalBytes: usage.proxyBytes, allowedBytes: GD_MONTH_CAP, views: usage.views },
      drive: Object.assign({ direct: !!GD.apiKey }, await gdAbout()),
      users: rows,
      activity: events
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------- Storage stats ----------------
let storageStats = { at: 0, usedBytes: 0, objects: 0, byFolder: {}, sizes: new Map(), ok: false, error: null };
async function refreshStorageStats(force) {
  if (!force && storageStats.at && Date.now() - storageStats.at < 10 * 60 * 1000) return storageStats;
  try {
    await gdIndexRefresh(true);
    const about = await gdAbout();
    const by = {}; let total = 0;
    for (const [name, size] of gdIdxSizes) { const nm = String(name); const f = nm.includes('/') ? nm.split('/')[0] : 'data (json)'; by[f] = (by[f] || 0) + (Number(size) || 0); total += Number(size) || 0; }
    storageStats = { at: Date.now(), usedBytes: total, objects: gdIdx.size, byFolder: by, sizes: gdIdxSizes, ok: true, error: null, accountUsed: about.usedBytes, accountLimit: about.limitBytes };
  } catch (e) { storageStats = { ...storageStats, at: Date.now(), ok: false, error: e.message }; }
  return storageStats;
}
async function usageLoad() {
  try {
    const saved = await storeTryReadJSON('usage-stats.json');
    if (saved && saved.month === new Date().toISOString().slice(0, 7)) { usage.jsonBytes += saved.jsonBytes || 0; usage.mediaBytes += saved.mediaBytes || 0; usage.proxyBytes += saved.proxyBytes || 0; usage.views += saved.views || 0; }
  } catch (e) {}
}
async function usageFlush() {
  if (!usage.dirty) return;
  usage.dirty = false;
  try { await storeWriteJSON('usage-stats.json', { month: usage.month, jsonBytes: usage.jsonBytes, mediaBytes: usage.mediaBytes, proxyBytes: usage.proxyBytes, views: usage.views }); }
  catch (e) { usage.dirty = true; }
}

// ---------------- Banned words ----------------
let bannedCache = { words: null, at: 0 };
async function getBannedWords() {
  if (bannedCache.words && Date.now() - bannedCache.at < 60 * 1000) return bannedCache.words;
  let list = bannedCache.words || [];
  try { const saved = await storeTryReadJSON('banned-words.json'); if (Array.isArray(saved)) list = saved; } catch (e) {}
  bannedCache = { words: list, at: Date.now() };
  return list;
}
const escRe = str => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
async function findBannedWord(text) {
  const words = await getBannedWords();
  if (!words.length) return null;
  const t = String(text || '').toLowerCase();
  for (const w of words) {
    const ww = String(w || '').toLowerCase().trim();
    if (!ww) continue;
    if (new RegExp('(^|[^\\p{L}\\p{N}])' + escRe(ww) + '($|[^\\p{L}\\p{N}])', 'u').test(t)) return ww;
  }
  return null;
}

// ---------------- Carousel / notes helpers ----------------
async function buildSlideUrls(f, directUrl) {
  if (!Array.isArray(f.slides) || f.slides.length < 2) return null;
  return Promise.all(f.slides.map(async sl => ({ url: await directUrl(sl.key, f.storageProvider), mediaType: sl.mediaType })));
}
function activeNote(u) {
  if (!u || !u.note || !u.note.text) return null;
  if (Date.now() - new Date(u.note.createdAt).getTime() > 24 * 60 * 60 * 1000) return null;
  return { text: u.note.text, createdAt: u.note.createdAt };
}

// ---------------- Report alerts (in-app + push to the owner's account, optional email through Resend) ----------------
// Render's free plan blocks SMTP, so email goes over HTTPS. Set RESEND_API_KEY (+ optionally ALERT_EMAIL_TO) in Render to enable it.
const ALERT_EMAIL_TO = process.env.ALERT_EMAIL_TO || 'sohailp541@gmail.com';
async function alertAdminOfReport(r) {
  try {
    const label = `${r.type} report (${r.reason || 'other'})`;
    const preview = r.targetPreview ? `: "${String(r.targetPreview).slice(0, 60)}"` : '';
    const users = await readUsers();
    const owners = users.filter(u => (u.email || '').toLowerCase() === ALERT_EMAIL_TO.toLowerCase());
    for (const o of owners) {
      await notify(o.id, { type: 'report_alert', fromUserId: 'system', fromUsername: 'Reports', message: `🚨 Naya ${label}${preview}` });
    }
    if (process.env.RESEND_API_KEY) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: 'YouSeries <onboarding@resend.dev>', to: [ALERT_EMAIL_TO], subject: '🚨 Naya report — ' + label,
          text: `Naya ${label}\nReporter: ${r.reporterUsername || 'unknown'}\nNote: ${r.note || '-'}\n${r.targetPreview ? 'Content: ' + r.targetPreview + '\n' : ''}\nDashboard: /dashboard.html (Reports tab)` })
      });
    }
  } catch (e) { console.error('report alert failed:', e.message); }
}

// ---------------- Pin posts to profile + Notes ----------------
app.post('/api/films/:id/pin-profile', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const [users, films] = await Promise.all([readUsers(), readFilms()]);
    const me = users.find(u => u.id === currentUser.id);
    const f = films.find(x => x.id === req.params.id);
    if (!me || !f) return res.status(404).json({ error: 'Post nahi mili' });
    if (!isFilmOwnerOrCollab(f, me.id)) return res.status(403).json({ error: 'Sirf apni post pin kar sakte ho' });
    const live = new Set(films.map(x => x.id));
    let pins = (me.pinnedFilmIds || []).filter(id => live.has(id));
    const has = pins.includes(f.id);
    if (has) pins = pins.filter(id => id !== f.id);
    else { if (pins.length >= 3) return res.status(400).json({ error: 'Sirf 3 posts pin ho sakti hain — pehle koi unpin karo' }); pins.push(f.id); }
    me.pinnedFilmIds = pins;
    await writeUsers(users);
    res.json({ pinned: !has, pinnedFilmIds: pins });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/me/note', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const text = String((req.body && req.body.text) || '').trim().slice(0, 60);
    if (text && await findBannedWord(text)) return res.status(400).json({ error: 'Is note me aisa shabd hai jo allowed nahi hai' });
    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    if (!me) return res.status(404).json({ error: 'User not found' });
    if (text) me.note = { text, createdAt: new Date().toISOString() }; else delete me.note;
    await writeUsers(users);
    res.json({ note: activeNote(me) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/notes', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.json({ notes: [] });
    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    if (!me) return res.json({ notes: [] });
    const directUrl = makeDirectUrlCache();
    const list = users.filter(u => (u.id === me.id || (me.following || []).includes(u.id)) && activeNote(u)
      && !(me.blockedUsers || []).includes(u.id) && !(u.blockedUsers || []).includes(me.id));
    const notes = await Promise.all(list.map(async u => ({
      userId: u.id, username: u.username, verified: !!u.verified, mine: u.id === me.id,
      profileImage: u.profileImage ? await directUrl(u.profileImage, u.avatarStorageProvider) : null,
      text: u.note.text, createdAt: u.note.createdAt
    })));
    notes.sort((a, b) => (b.mine ? 1 : 0) - (a.mine ? 1 : 0) || new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ notes });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------- Announcements ----------------
async function readAnnouncements() { return (await storeTryReadJSON('announcements.json')) || []; }
async function pushToAll(payload) {
  const subs = await storeTryReadJSON('push-subscriptions.json') || [];
  let changed = false;
  await Promise.allSettled(subs.map(async s => {
    try { await webpush.sendNotification(s.subscription, JSON.stringify(payload)); }
    catch (err) { if (err.statusCode === 404 || err.statusCode === 410) { s._dead = true; changed = true; } }
  }));
  if (changed) await storeWriteJSON('push-subscriptions.json', subs.filter(s => !s._dead));
}
app.get('/api/announcements', async (req, res) => {
  try { const list = await readAnnouncements(); res.json({ announcements: list.slice(-5).reverse() }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/admin/announcements', requireAdmin, async (req, res) => {
  try { res.json({ announcements: (await readAnnouncements()).slice().reverse() }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/announce', requireAdmin, async (req, res) => {
  try {
    const message = String((req.body && req.body.message) || '').trim().slice(0, 300);
    if (!message) return res.status(400).json({ error: 'Message likho' });
    const list = await readAnnouncements();
    const a = { id: Date.now().toString(36) + Math.random().toString(36).slice(2, 5), message, createdAt: new Date().toISOString() };
    list.push(a);
    await storeWriteJSON('announcements.json', list.slice(-30));
    pushToAll({ title: '📢 YouSeries', body: message }).catch(() => {});
    res.json({ success: true, announcement: a });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/announcements/:id/delete', requireAdmin, async (req, res) => {
  try {
    const list = (await readAnnouncements()).filter(a => a.id !== req.params.id);
    await storeWriteJSON('announcements.json', list);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------- Admin tools: verify, banned words, delete user, CSV ----------------
app.post('/api/admin/users/:id/verify', requireAdmin, async (req, res) => {
  try {
    const users = await readUsers();
    const u = users.find(x => x.id === req.params.id);
    if (!u) return res.status(404).json({ error: 'User nahi mila' });
    u.verified = !u.verified;
    await writeUsers(users);
    res.json({ verified: u.verified });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/banned-words', requireAdmin, async (req, res) => {
  try { bannedCache.at = 0; res.json({ words: await getBannedWords() }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/banned-words', requireAdmin, async (req, res) => {
  try {
    const raw = Array.isArray(req.body && req.body.words) ? req.body.words : String((req.body && req.body.words) || '').split(/[\n,]/);
    const words = [...new Set(raw.map(w => String(w).trim().toLowerCase()).filter(w => w && w.length <= 40))].slice(0, 300);
    await storeWriteJSON('banned-words.json', words);
    bannedCache = { words, at: Date.now() };
    res.json({ words });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/users/:id/delete', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    let users = await readUsers();
    const u = users.find(x => x.id === id);
    if (!u) return res.status(404).json({ error: 'User nahi mila' });
    const delFile = async (key, provider) => { if (!key) return; try { await storeDelete(key); } catch (e) {} };

    let films = await readFilms();
    for (const f of films.filter(x => x.ownerId === id)) {
      await delFile(f.videoFile, f.storageProvider); await delFile(f.posterFile, f.storageProvider);
      for (const sl of (f.slides || [])) await delFile(sl.key, f.storageProvider);
    }
    films = films.filter(f => f.ownerId !== id);
    films.forEach(f => {
      if (Array.isArray(f.comments)) f.comments = f.comments.filter(c => c.userId !== id);
      if (f.collaboratorId === id) { delete f.collaboratorId; delete f.collaboratorUsername; delete f.collabStatus; }
    });
    await writeFilms(films);

    try {
      let stories = await readStories();
      for (const st of stories.filter(x => x.ownerId === id)) await delFile(st.mediaFile || st.videoFile || st.posterFile, st.storageProvider || 'gdrive');
      stories = stories.filter(x => x.ownerId !== id);
      await writeStories(stories);
    } catch (e) {}

    await delFile(u.profileImage, u.avatarStorageProvider);
    users = users.filter(x => x.id !== id);
    users.forEach(x => {
      ['following', 'blockedUsers', 'restrictedUsers', 'pinnedFilmIds'].forEach(k => { if (Array.isArray(x[k])) x[k] = x[k].filter(v => v !== id); });
    });
    await writeUsers(users);
    suspendedIds.delete(id);

    try {
      const notifs = (await storeTryReadJSON('notifications.json')) || [];
      await storeWriteJSON('notifications.json', notifs.filter(n => n.userId !== id && n.fromUserId !== id));
    } catch (e) {}
    try {
      const convos = await readConversations();
      const gone = convos.filter(c => (c.participants || []).includes(id));
      for (const c of gone) await storeDelete(`chats/${c.id}.json`).catch(() => {});
      await writeConversations(convos.filter(c => !(c.participants || []).includes(id)));
    } catch (e) {}
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/users.csv', requireAdmin, async (req, res) => {
  try {
    const [users, films] = await Promise.all([readUsers(), readFilms()]);
    const posts = {}, comments = {}, followers = {};
    films.forEach(f => { posts[f.ownerId] = (posts[f.ownerId] || 0) + 1; (f.comments || []).forEach(c => { comments[c.userId] = (comments[c.userId] || 0) + 1; }); });
    users.forEach(u => (u.following || []).forEach(i => { followers[i] = (followers[i] || 0) + 1; }));
    const q = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
    const lines = ['username,email,joined,last_active,suspended,verified,posts,comments,followers'];
    users.forEach(u => lines.push([u.username, u.email, u.createdAt || '', u.lastActiveAt || '', !!u.suspended, !!u.verified, posts[u.id] || 0, comments[u.id] || 0, followers[u.id] || 0].map(q).join(',')));
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="youseries-users.csv"');
    res.send('\ufeff' + lines.join('\n'));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------- Admin diagnostic: what Google says about a playable file (no secrets are shown) ----------------
app.get('/api/admin/drive-test', requireAdmin, async (req, res) => {
  const out = { apiKeySet: !!GD.apiKey, steps: [] };
  try {
    let id = String(req.query.id || '').replace(/[^A-Za-z0-9_-]/g, '');
    if (!id) {
      const media = [...gdIdx.entries()].filter(([name]) => !/\.json$/i.test(name) && /^(videos|posters|photos|stories)\//.test(name));
      if (!media.length) return res.json({ ...out, error: 'Drive me koi media file nahi mili' });
      id = media[media.length - 1][1];
    }
    out.fileId = id;
    // 1) does the owner's Drive say the file is shared "anyone with link"?
    const meta = await fetch(`${GD.apiBase}/files/${id}?fields=id,name,mimeType,size,shared,permissions(type,role)`, { headers: { Authorization: 'Bearer ' + await gdAccessToken() } });
    const mj = await meta.json().catch(() => ({}));
    out.steps.push({ step: 'owner check (OAuth)', status: meta.status, name: mj.name, size: mj.size, shared: mj.shared, permissions: mj.permissions, error: mj.error && mj.error.message });
    // 2) can the browser's way (API key, no login) read it?
    if (GD.apiKey) {
      const r = await fetch(`${GD.apiBase}/files/${id}?alt=media&key=${GD.apiKey}`, { headers: { Range: 'bytes=0-15' } });
      const body = await r.text().catch(() => '');
      out.steps.push({ step: 'public playback check (API key)', status: r.status, contentType: r.headers.get('content-type'), error: r.ok ? null : body.slice(0, 400) });
    } else {
      out.steps.push({ step: 'public playback check (API key)', skipped: 'GDRIVE_API_KEY is not set' });
    }
    res.json(out);
  } catch (e) { res.status(500).json({ ...out, error: e.message }); }
});

// ---------------- Blue tick (verified badge), paid by UPI, approved by the owner ----------------
const BT_MIN_FOLLOWERS = 10, BT_MIN_VIEWS = 150, BT_DAYS = 30;
const BT_KEY_QR = 'bluetick/qr.png';
async function readBlueSettings() { return (await storeTryReadJSON('bluetick-settings.json')) || { price: 49, upi: '', qrUrl: null }; }
async function writeBlueSettings(x) { await storeWriteJSON('bluetick-settings.json', x); }
async function readBlueRequests() { return (await storeTryReadJSON('bluetick.json')) || []; }
async function writeBlueRequests(x) { await storeWriteJSON('bluetick.json', x.slice(-2000)); }
// Criteria met -> permanent free blue tick (no payment, never removed later)
function grantFreeBlueTicks(users, films) {
  let changed = false;
  users.forEach(u => {
    if (u.blueFree) return;
    const st = blueStats(u, users, films);
    if (st.eligible) { u.verified = true; u.blueFree = true; delete u.blueUntil; changed = true; }
  });
  return changed;
}
function blueStats(user, users, films) {
  const followers = users.filter(u => (u.following || []).includes(user.id)).length;
  const views = films.filter(f => f.ownerId === user.id).reduce((a, f) => a + (f.views || 0), 0);
  return { followers, views, minFollowers: BT_MIN_FOLLOWERS, minViews: BT_MIN_VIEWS, eligible: followers >= BT_MIN_FOLLOWERS && views >= BT_MIN_VIEWS };
}

app.get('/api/bluetick/status', async (req, res) => {
  try {
    const cu = getUserFromReq(req);
    if (!cu) return res.status(401).json({ error: 'Login required' });
    const [users, films, reqs, st] = await Promise.all([readUsers(), readFilms(), readBlueRequests(), readBlueSettings()]);
    const me = users.find(u => u.id === cu.id);
    if (!me) return res.status(404).json({ error: 'User not found' });
    if (grantFreeBlueTicks(users, films)) await writeUsers(users);
    const mine = reqs.filter(r => r.userId === me.id).slice(-1)[0] || null;
    const qrUrl = st.qrUrl ? await storeUrl(st.qrUrl).catch(() => null) : null;
    res.json({
      ...blueStats(me, users, films),
      verified: !!me.verified, verifiedUntil: me.blueUntil || null, free: !!me.blueFree,
      price: st.price, upi: st.upi || '', qrUrl,
      pending: !!reqs.find(r => r.userId === me.id && r.status === 'pending'),
      latest: mine ? { status: mine.status, createdAt: mine.createdAt, reason: mine.reason || null } : null
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/bluetick/request', async (req, res) => {
  try {
    const cu = getUserFromReq(req);
    if (!cu) return res.status(401).json({ error: 'Login required' });
    const utr = String((req.body && req.body.utr) || '').replace(/\s/g, '');
    if (!/^\d{12}$/.test(utr)) return res.status(400).json({ error: 'UPI transaction ID (UTR) 12 digits ka hona chahiye' });
    const [users, films, reqs, st] = await Promise.all([readUsers(), readFilms(), readBlueRequests(), readBlueSettings()]);
    const me = users.find(u => u.id === cu.id);
    if (!me) return res.status(404).json({ error: 'User not found' });
    if (me.blueFree) return res.status(409).json({ error: 'Tumhara blue tick permanent hai, payment ki zaroorat nahi' });
    if (reqs.some(r => r.utr === utr)) return res.status(409).json({ error: 'Ye UTR pehle use ho chuka hai' });
    if (reqs.some(r => r.userId === me.id && r.status === 'pending')) return res.status(409).json({ error: 'Tumhari ek request pehle se pending hai' });
    reqs.push({ id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), userId: me.id, username: me.username, utr, amount: st.price, status: 'pending', createdAt: new Date().toISOString() });
    await writeBlueRequests(reqs);
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/bluetick', requireAdmin, async (req, res) => {
  try {
    const [reqs, st] = await Promise.all([readBlueRequests(), readBlueSettings()]);
    res.json({ requests: reqs.slice().reverse(), settings: st });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/bluetick/:id/decide', requireAdmin, async (req, res) => {
  try {
    const approve = !!(req.body && req.body.approve);
    const reason = String((req.body && req.body.reason) || '').slice(0, 200);
    const reqs = await readBlueRequests();
    const r = reqs.find(x => x.id === req.params.id);
    if (!r || r.status !== 'pending') return res.status(404).json({ error: 'Pending request nahi mili' });
    const users = await readUsers();
    const u = users.find(x => x.id === r.userId);
    r.status = approve ? 'approved' : 'rejected';
    r.decidedAt = new Date().toISOString();
    if (!approve) r.reason = reason || null;
    if (approve && u && !u.blueFree) { u.verified = true; u.blueUntil = Date.now() + BT_DAYS * 24 * 60 * 60 * 1000; await writeUsers(users); }
    await writeBlueRequests(reqs);
    if (u) notify(u.id, { type: 'bluetick', fromUserId: 'system', fromUsername: 'Blue tick',
      message: approve ? '✔ Blue tick mil gaya! 30 din ke liye active hai' : ('❌ Blue tick request reject hui' + (reason ? ': ' + reason : '')) }).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/bluetick/settings', requireAdmin, async (req, res) => {
  try {
    const price = Math.round(Number(req.body && req.body.price));
    if (!(price >= 5 && price <= 49)) return res.status(400).json({ error: 'Price ₹5 se ₹49 ke beech hona chahiye' });
    const st = await readBlueSettings();
    st.price = price;
    st.upi = String((req.body && req.body.upi) || '').trim().slice(0, 80);
    await writeBlueSettings(st);
    res.json(st);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/bluetick/qr', requireAdmin, upload.single('qr'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'QR image chuno' });
    const buf = readFileAsBuffer(req.file.path);
    // a new name for every upload, so browsers never show the old QR from cache
    const key = 'bluetick/qr-' + Date.now().toString(36) + '.png';
    await storePutBuffer(buf, key, req.file.mimetype || 'image/png');
    const st = await readBlueSettings();
    const old = st.qrUrl;
    st.qrUrl = key;
    await writeBlueSettings(st);
    if (old && old !== key) storeDelete(old).catch(() => {});
    res.json({ success: true, qrUrl: key });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// a verified badge from a paid plan lasts BT_DAYS days; after that it is removed (manual verifies have no end date)
setInterval(async () => {
  try {
    const [users, films] = await Promise.all([readUsers(), readFilms()]);
    let changed = grantFreeBlueTicks(users, films);
    users.forEach(u => { if (!u.blueFree && u.verified && u.blueUntil && Date.now() > u.blueUntil) { u.verified = false; delete u.blueUntil; changed = true; } });
    if (changed) await writeUsers(users);
  } catch (e) { /* try again next hour */ }
}, 60 * 60 * 1000);

// ---------------- Admin login form (dashboard) ----------------
const adminLoginTries = new Map();
app.post('/api/admin/login', (req, res) => {
  const ip = req.ip || 'ip';
  const now = Date.now();
  const tries = (adminLoginTries.get(ip) || []).filter(t => now - t < 15 * 60 * 1000);
  if (tries.length >= 8) return res.status(429).json({ error: 'Bahut zyada galat koshish — 15 minute baad try karo' });
  const { username, password } = req.body || {};
  if (!safeEq(username || '', ADMIN_USER) || !safeEq(password || '', ADMIN_PASS)) {
    tries.push(now); adminLoginTries.set(ip, tries);
    return res.status(401).json({ error: 'Username ya password galat hai' });
  }
  adminLoginTries.delete(ip);
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.cookie(ADMIN_COOKIE, token, { httpOnly: true, sameSite: 'lax', secure: !!req.secure, maxAge: 12 * 60 * 60 * 1000 });
  res.json({ success: true });
});
app.post('/api/admin/logout', (req, res) => { res.clearCookie(ADMIN_COOKIE); res.json({ success: true }); });
app.get('/api/admin/me', (req, res) => {
  if (!isAdminBasicAuth(req)) return res.status(401).json({ error: 'Admin login required' });
  res.json({ admin: true });
});

// a plain-text alert for the owner (in-app notification on the owner's account + optional email)
async function alertAdminText(message) {
  try {
    const users = await readUsers();
    for (const o of users.filter(u => (u.email || '').toLowerCase() === ALERT_EMAIL_TO.toLowerCase())) {
      await notify(o.id, { type: 'report_alert', fromUserId: 'system', fromUsername: 'Dashboard', message });
    }
  } catch (e) { console.error('admin alert failed:', e.message); }
}

app.listen(PORT, () => { console.log(`YouSeries server running on port ${PORT}`); });
setTimeout(refreshSuspendedIds, 3000);
setInterval(refreshSuspendedIds, 5 * 60 * 1000);
setTimeout(() => { usageLoad(); refreshStorageStats(true); }, 5000);
setInterval(() => refreshStorageStats(true), 30 * 60 * 1000);
setInterval(usageFlush, 5 * 60 * 1000);
['SIGTERM', 'SIGINT'].forEach(sig => process.on(sig, () => { usageFlush().then(() => gdFlushAll()).catch(() => {}).finally(() => process.exit(0)); }));
if (gdEnabled()) { setTimeout(() => gdIndexRefresh(true).then(() => gdEnsurePublic()).catch(e => console.error('Drive index failed:', e.message)), 1500); console.log('Storage: Google Drive'); }
