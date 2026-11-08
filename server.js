const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { Readable } = require('stream');
const zlib = require('zlib');
const { S3Client, ListObjectsV2Command, GetObjectCommand, HeadObjectCommand, CreateMultipartUploadCommand, UploadPartCommand, ListPartsCommand, CompleteMultipartUploadCommand, AbortMultipartUploadCommand, PutObjectCommand, DeleteObjectCommand, CopyObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

// ---- Storage: Cloudflare R2 only. A key is the object name in the bucket, e.g. "videos/abc.mp4" or "films.json" ----
const R2_KEY_RE = /^(videos|posters|photos)\/[A-Za-z0-9._-]+$/;
const isR2Key = k => typeof k === 'string' && k.length > 0;
const r2Strip = k => k;
const r2On = () => !!(process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY && process.env.R2_BUCKET_NAME && (process.env.R2_ACCOUNT_ID || process.env.R2_ENDPOINT) && process.env.R2_PUBLIC_URL);
const r2PublicUrl = k => `${(process.env.R2_PUBLIC_URL || '').replace(/\/$/, '')}/${k}`;
const r2Bucket = () => process.env.R2_BUCKET_NAME;
async function r2Put(k, buf, ct) { await getR2().send(new PutObjectCommand({ Bucket: r2Bucket(), Key: k, Body: buf, ContentType: ct || 'application/octet-stream' })); }
async function r2ListParts(key, uploadId) {
  const parts = []; let marker;
  for (let i = 0; i < 20; i++) {
    const out = await getR2().send(new ListPartsCommand({ Bucket: r2Bucket(), Key: r2Strip(key), UploadId: uploadId, PartNumberMarker: marker }));
    (out.Parts || []).forEach(p => parts.push({ PartNumber: p.PartNumber, ETag: p.ETag }));
    if (!out.IsTruncated) break;
    marker = out.NextPartNumberMarker;
  }
  return parts.sort((a, b) => a.PartNumber - b.PartNumber);
}
const crypto = require('crypto');
const ffmpeg = require('fluent-ffmpeg');
const { execFile } = require('child_process');
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

// Logins made before device tracking get a device session on their next visit (once per device)
const legacyMigrating = new Set();
app.use(async (req, res, next) => {
  const tok = req.cookies && req.cookies.token;
  if (!tok || legacyMigrating.has(tok)) return next();
  let p = null;
  try { p = jwt.verify(tok, JWT_SECRET); } catch (e) { return next(); }
  if (!p || !p.id || p.sid) return next();
  legacyMigrating.add(tok);
  try {
    const users = await readUsers();
    const u = users.find(x => x.id === p.id);
    if (u && !u.suspended) {
      const sid = await startSession(req, u);
      res.cookie('token', signToken(u, sid), { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    }
  } catch (e) { /* keep the old login; try again next time */ }
  finally { legacyMigrating.delete(tok); }
  next();
});

// Logged-out visitors see nothing from the site: no films, photos, videos, profiles or hashtags.
app.use((req, res, next) => {
  if (req.method !== 'GET' && !req.path.startsWith('/api/hashtags')) return next();
  const isProtected = (req.path.startsWith('/media/') && !req.path.startsWith('/media/poster/') && req.path !== '/media/founder-avatar')
    || /^\/api\/films(\/|$)/.test(req.path)
    || req.path.startsWith('/api/hashtags')
    || req.path === '/api/users/search'
    || /^\/api\/users\/[^/]+\/public$/.test(req.path);
  if (!isProtected) return next();
  if (getUserFromReq(req) || isAdminBasicAuth(req)) return next();
  if (req.path === '/api/films') return res.json([]);
  return res.status(401).json({ error: 'Login required' });
});
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
    sessionIndex.clear();
    users.forEach(u => (u && u.sessions || []).forEach(x => sessionIndex.set(x.sid, u.id)));
    sessionsReady = true;
  } catch (e) { /* storage hiccup: keep the previous list */ }
}

function getUserFromReq(req) {
  const token = req.cookies.token;
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload && suspendedIds.has(payload.id)) return null;
    if (payload && payload.sid && sessionsReady && !sessionIndex.has(payload.sid)) return null;
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

function signToken(user, sid) {
  return jwt.sign({ id: user.id, email: user.email, username: user.username, sid }, JWT_SECRET, { expiresIn: '30d' });
}

// ---------------- Devices (login sessions) ----------------
// Every login makes a session (one per device) stored on the user. A session can be removed to log that device out.
const sessionIndex = new Map();   // session id -> user id, kept in step with users.json
let sessionsReady = false;
function deviceName(ua) {
  ua = String(ua || '');
  let os = 'Device';
  if (/iPad/i.test(ua)) os = 'iPad';
  else if (/iPhone/i.test(ua)) os = 'iPhone';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Macintosh|Mac OS/i.test(ua)) os = 'Mac';
  else if (/Linux/i.test(ua)) os = 'Linux';
  let br = 'Browser';
  if (/Edg\//.test(ua)) br = 'Edge';
  else if (/OPR\//.test(ua)) br = 'Opera';
  else if (/SamsungBrowser/i.test(ua)) br = 'Samsung Internet';
  else if (/Chrome\//.test(ua)) br = 'Chrome';
  else if (/Firefox\//.test(ua)) br = 'Firefox';
  else if (/Safari\//.test(ua)) br = 'Safari';
  return `${os} · ${br}`;
}
async function startSession(req, user) {
  const sid = crypto.randomUUID();
  const users = await readUsers();
  const u = users.find(x => x.id === user.id);
  if (u) {
    u.sessions = [...(u.sessions || []), { sid, device: deviceName(req.get('user-agent')), createdAt: new Date().toISOString() }].slice(-20);
    await writeUsers(users);
  }
  sessionIndex.set(sid, user.id);
  return sid;
}
// keep(sid) === true means that session stays; everything else is logged out
async function dropSessions(userId, keep) {
  const users = await readUsers();
  const u = users.find(x => x.id === userId);
  if (!u) return;
  const all = u.sessions || [];
  all.filter(x => !keep(x.sid)).forEach(x => sessionIndex.delete(x.sid));
  u.sessions = all.filter(x => keep(x.sid));
  await writeUsers(users);
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
  const me = currentUser ? users.find(u => u.id === currentUser.id) : null;
  const isVip = !!(me && (me.verified || me.isAdmin));
  if (isVip && body && body.customLink) {
    const cl = String(body.customLink).trim();
    if (cl && /^https?:\/\//i.test(cl)) {
      newFilm.customLink = cl;
      newFilm.customLinkTitle = String(body.customLinkTitle || 'Visit Link').trim().slice(0, 40) || 'Visit Link';
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
    filmId: newFilm.id, message: `@${currentUser.username} invited you to collab on "${newFilm.title}"`
  });
  try {
    const convo = await getConversationForUsers(currentUser.id, newFilm.collaboratorId, true);
    if (convo) {
      const msgId = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
      const dmMsg = {
        id: msgId, conversationId: convo.id, senderId: currentUser.id,
        type: 'collab_invite', text: `🤝 Invited you to collaborate on "${newFilm.title || 'Post'}"`,
        mediaKey: null, mediaType: null, fileName: null, storageProvider: r2On() ? 'r2' : 'gdrive', duration: null,
        shortId: newFilm.id, shortTitle: newFilm.title || 'Post', shortOwnerUsername: currentUser.username,
        collabStatus: 'pending',
        createdAt: new Date().toISOString(), editedAt: null,
        deletedFor: [], unsent: false, readBy: [currentUser.id]
      };
      const msgs = await readChatMessages(convo.id);
      msgs.push(dmMsg);
      await writeChatMessages(convo.id, msgs);
      const convos = await readConversations();
      const cRef = convos.find(c => c.id === convo.id);
      if (cRef) {
        cRef.updatedAt = dmMsg.createdAt;
        cRef.lastMessage = { senderId: currentUser.id, preview: `🤝 Collab invite: ${newFilm.title || 'Post'}`, createdAt: dmMsg.createdAt };
        if (cRef.hiddenFor) delete cRef.hiddenFor[newFilm.collaboratorId];
        await writeConversations(convos);
      }
    }
  } catch (e) {}
}

// ---------------- File storage: Google Drive only ----------------
// Every file (videos, photos, avatars, stories, chat media) and the JSON "database" files live in one Google Drive folder.
// Each Drive file is named by its key (e.g. "videos/abc.mp4", "films.json"). See the Google Drive section below.
function storeNeedsDrive() {
  if (!r2On()) { const e = new Error('Cloudflare R2 set nahi hai (R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME, R2_PUBLIC_URL)'); e.status = 503; throw e; }
}
async function storePutBuffer(buffer, key, contentType) { storeNeedsDrive(); await gdPutByKey(key, buffer, contentType); }
async function storeCopy(sourceKey, destKey) {
  storeNeedsDrive();
  await getR2().send(new CopyObjectCommand({ Bucket: r2Bucket(), CopySource: r2Bucket() + '/' + sourceKey, Key: destKey }));
  gdIdx.set(destKey, true);
  return destKey;
}
async function storeDelete(key) {
  if (!key) return;
  await gdDelete(key);
}
async function storeUrl(key) {
  if (!key) return null;
  storeNeedsDrive();
  return r2PublicUrl(key);
}
async function storeStream(key, req, res) {
  if (!key) return res.status(404).send('Not found');
  return res.redirect(302, r2PublicUrl(key));
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
  const pend = gdPending.get(key);                               // a write that has not reached R2 yet is the newest truth
  if (pend) return JSON.parse(pend.raw);
  const buf = await gdGetByKey(key);
  usageAdd('jsonBytes', buf.length);
  const raw = buf.toString('utf-8');
  jsonCache.set(key, { at: Date.now(), raw });
  return JSON.parse(raw);
}

// A missing file means "not created yet" (null). Any other failure (Drive login, network) is thrown,
// so the app never treats a failed read as empty data and never overwrites real data with it.
async function storeTryReadJSON(key) {
  try { return await storeReadJSON(key); }
  catch (e) { if (e && e.name === 'NoSuchKey') return null; throw e; }
}

async function storeWriteJSON(key, data) {
  const raw = JSON.stringify(data, null, 2);
  jsonCache.set(key, { at: Date.now(), raw });
  gdQueueJSON(key, raw);                                          // write-behind: memory now, Drive within a few seconds
}







// ---------------- Notifications ----------------
const NOTIF_CATS = {
  like: ['comment_like', 'story_like'], comment: ['film_comment', 'story_comment'], follow: ['follow'], mention: ['mention'],
  message: ['message'], collab: ['collab_invite', 'collab_accepted'], story: ['story_view', 'story_reaction', 'story_comment']
};
async function notify(toUserId, { type, fromUserId, fromUsername, filmId, storyId, conversationId, message }) {
  if (!toUserId || toUserId === fromUserId) return;
  try {
    // respect the user's notification settings (system messages always come through)
    const cat = Object.keys(NOTIF_CATS).find(c => NOTIF_CATS[c].includes(type));
    if (cat && fromUserId !== 'system') {
      const owner = (await readUsers()).find(u => u.id === toUserId);
      if (owner && owner.notifPrefs && owner.notifPrefs[cat] === false) return;
    }
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

let feedVer = 0;
const feedCache = new Map();
const FEED_CACHE_MS = 30000;
async function writeFilms(films) {
  feedVer++;
  await storeWriteJSON('films.json', films);
  filmsCache = { data: films, expiresAt: Date.now() + FILMS_CACHE_MS };
}

// ---------------- Users "database" ----------------
async function readUsers() {
  return await storeTryReadJSON('users.json') || [];
}
async function writeUsers(users) {
  feedVer++;
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

app.get(['/admin', '/admin.html'], (req, res) => res.redirect('/dashboard.html'));

app.get('/moderation.html', (req, res) => {
  if (!isAdminBasicAuth(req)) {
    res.set('WWW-Authenticate', 'Basic realm="Moderation"');
    return res.status(401).send('Admin login required');
  }
  res.sendFile(path.join(__dirname, 'public', 'moderation.html'));
});

function escMetaAttr(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

app.get('/media/founder-avatar', async (req, res) => {
  try {
    const users = await readUsers();
    const fu = users.find(u => (u.email || '').toLowerCase() === 'sohailp541@gmail.com')
      || users.find(u => (u.username || '').toLowerCase() === 'sohail_parvezofficial' || (u.username || '').toLowerCase().includes('sohail'));
    if (fu && fu.profileImage) {
      if (fu.avatarStorageProvider === 'r2' && r2On()) {
        const url = await r2SignedGetUrl(fu.profileImage);
        if (url) return res.redirect(url);
      }
      return storeStream(fu.profileImage, req, res);
    }
    return res.sendFile(path.join(__dirname, 'public', 'icon-192.png'));
  } catch (e) {
    return res.sendFile(path.join(__dirname, 'public', 'icon-192.png'));
  }
});

app.get(['/founder', '/founder.html', '/about'], async (req, res) => {
  try {
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
    const host = req.get('host') || 'www.tamasha.qd.je';
    const baseUrl = `${proto}://${host}`;
    let founderImg = `${baseUrl}/media/founder-avatar`;

    const schemaJson = JSON.stringify({
      "@context": "https://schema.org",
      "@type": "ProfilePage",
      "@id": `${baseUrl}/founder#profilepage`,
      "url": `${baseUrl}/founder`,
      "name": "Sohail Parvez – Founder & CEO of YouSeries (TAMASHA)",
      "description": "Official biography, qualification, photos, and verified social media handles of Sohail Parvez, Founder & CEO of YouSeries (TAMASHA).",
      "dateCreated": "2025-01-01T00:00:00+05:30",
      "dateModified": new Date().toISOString(),
      "mainEntity": {
        "@type": "Person",
        "@id": `${baseUrl}/#founder`,
        "name": "Sohail Parvez",
        "alternateName": ["sohail_parvezofficial", "Sohail Parvez TAMASHA", "Sohail Parvez YouSeries"],
        "jobTitle": "Founder & CEO",
        "description": "Sohail Parvez (born 2003, age 23) is an Indian entrepreneur and the Founder & CEO of YouSeries (TAMASHA), a video, shorts, stories, and photo streaming social platform. He holds an MBA in Data Analytics.",
        "image": founderImg,
        "url": `${baseUrl}/founder`,
        "email": "mailto:sohailp541@gmail.com",
        "nationality": { "@type": "Country", "name": "India" },
        "alumniOf": { "@type": "EducationalOrganization", "name": "MBA in Data Analytics" },
        "knowsAbout": ["Data Analytics", "Social Media Platforms", "Video Streaming", "Business Administration"],
        "worksFor": {
          "@type": "Organization",
          "@id": `${baseUrl}/#organization`,
          "name": "YouSeries (TAMASHA)",
          "url": `${baseUrl}/`
        },
        "sameAs": [
          "https://www.instagram.com/sohail_parvezofficial/",
          "https://www.facebook.com/share/1CKJdD67rj/",
          `${baseUrl}/`,
          `${baseUrl}/founder`
        ]
      }
    }, null, 2);

    res.set('Content-Type', 'text/html; charset=utf-8');
    return res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sohail Parvez – Founder &amp; CEO of YouSeries (TAMASHA) | Biography &amp; Social Links</title>
  <meta name="description" content="Sohail Parvez (Age 23, MBA in Data Analytics) is the Founder &amp; CEO of YouSeries (TAMASHA). Official biography, photo, Instagram @sohail_parvezofficial, and Facebook.">
  <meta name="author" content="Sohail Parvez">
  <meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
  <link rel="canonical" href="${baseUrl}/founder">
  <meta property="og:type" content="profile">
  <meta property="og:title" content="Sohail Parvez – Founder &amp; CEO of YouSeries (TAMASHA)">
  <meta property="og:description" content="Official profile and biography of Sohail Parvez, Founder &amp; CEO of YouSeries (TAMASHA). MBA in Data Analytics. Instagram: @sohail_parvezofficial">
  <meta property="og:image" content="${escMetaAttr(founderImg)}">
  <meta property="og:url" content="${baseUrl}/founder">
  <script type="application/ld+json">${schemaJson}</script>
  <style>
    body { margin:0; font-family: system-ui, -apple-system, sans-serif; background:#0b0816; color:#f3f0ff; line-height:1.6; }
    .wrap { max-width:740px; margin:0 auto; padding:32px 18px 60px; }
    .card { background:#151129; border:1px solid rgba(255,255,255,0.14); border-radius:20px; padding:26px 22px; box-shadow:0 16px 40px rgba(0,0,0,0.45); }
    .top { display:flex; gap:20px; align-items:center; flex-wrap:wrap; margin-bottom:20px; }
    .avatar { width:108px; height:108px; border-radius:50%; object-fit:cover; border:3px solid #7C5CFF; background:#231c42; }
    h1 { margin:0 0 4px; font-size:26px; color:#fff; }
    .role { color:#a996ff; font-weight:700; font-size:15px; margin-bottom:6px; }
    .badge { display:inline-block; background:rgba(124,92,255,0.2); border:1px solid #7C5CFF; color:#d8d0ff; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600; }
    table { width:100%; border-collapse:collapse; margin:18px 0; font-size:14.5px; }
    th, td { text-align:left; padding:11px 10px; border-bottom:1px solid rgba(255,255,255,0.1); }
    th { color:#a9a3c9; width:38%; font-weight:600; }
    td { color:#fff; font-weight:500; }
    .socials { display:flex; gap:10px; flex-wrap:wrap; margin-top:18px; }
    .btn { display:inline-flex; align-items:center; gap:8px; padding:10px 16px; border-radius:12px; text-decoration:none; font-weight:700; font-size:14px; background:#7C5CFF; color:#fff; }
    .btn.sec { background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.2); }
  </style>
</head>
<body>
  <div class="wrap">
    <div style="margin-bottom:16px;"><a href="/" style="color:#a996ff;text-decoration:none;font-weight:600;">← Back to YouSeries (TAMASHA)</a></div>
    <article class="card">
      <div class="top">
        <img class="avatar" src="${escMetaAttr(founderImg)}" alt="Sohail Parvez – Founder &amp; CEO of YouSeries (TAMASHA)">
        <div>
          <h1>Sohail Parvez</h1>
          <div class="role">Founder &amp; CEO — YouSeries (TAMASHA)</div>
          <span class="badge">✔ Verified Founder Profile</span>
        </div>
      </div>
      <p><strong>Sohail Parvez</strong> is an Indian technology entrepreneur and the <strong>Founder &amp; CEO of YouSeries (TAMASHA)</strong> (<a href="${baseUrl}/" style="color:#a996ff;">www.tamasha.qd.je</a>), an Indian short-video, full-length film, story, and photo social streaming platform. At age 23, with an <strong>MBA in Data Analytics</strong>, he built and launched YouSeries (TAMASHA) with an integrated AI assistant (Ask AI), creator monetization &amp; verification, and real-time social messaging.</p>
      <table>
        <tr><th>Full Name</th><td>Sohail Parvez</td></tr>
        <tr><th>Role / Title</th><td>Founder &amp; Chief Executive Officer (CEO)</td></tr>
        <tr><th>Company / Platform</th><td><a href="${baseUrl}/" style="color:#a996ff;">YouSeries (TAMASHA)</a></td></tr>
        <tr><th>Age</th><td>23 years</td></tr>
        <tr><th>Qualification</th><td>MBA in Data Analytics</td></tr>
        <tr><th>Country</th><td>India</td></tr>
        <tr><th>Official Instagram</th><td><a href="https://www.instagram.com/sohail_parvezofficial/" rel="me noopener" target="_blank" style="color:#a996ff;">@sohail_parvezofficial</a></td></tr>
        <tr><th>Official Facebook</th><td><a href="https://www.facebook.com/share/1CKJdD67rj/" rel="me noopener" target="_blank" style="color:#a996ff;">Sohail Parvez on Facebook</a></td></tr>
        <tr><th>Contact Email</th><td><a href="mailto:sohailp541@gmail.com" style="color:#a996ff;">sohailp541@gmail.com</a></td></tr>
      </table>
      <div class="socials">
        <a class="btn" href="https://www.instagram.com/sohail_parvezofficial/" rel="me noopener" target="_blank">📸 Instagram (@sohail_parvezofficial)</a>
        <a class="btn sec" href="https://www.facebook.com/share/1CKJdD67rj/" rel="me noopener" target="_blank">📘 Facebook Profile</a>
        <a class="btn sec" href="${baseUrl}/">🎬 Open YouSeries (TAMASHA)</a>
      </div>
    </article>
  </div>
</body>
</html>`);
  } catch (e) { res.redirect('/'); }
});

app.get('/sitemap.xml', (req, res) => {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = req.get('host') || 'www.tamasha.qd.je';
  const baseUrl = `${proto}://${host}`;
  res.set('Content-Type', 'application/xml; charset=utf-8');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${baseUrl}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>
  <url><loc>${baseUrl}/founder</loc><changefreq>weekly</changefreq><priority>0.9</priority></url>
  <url><loc>${baseUrl}/login.html</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>
  <url><loc>${baseUrl}/signup.html</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>
</urlset>`);
});

app.get('/robots.txt', (req, res) => {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = req.get('host') || 'www.tamasha.qd.je';
  const baseUrl = `${proto}://${host}`;
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.send(`User-agent: *
Allow: /
Allow: /founder
Sitemap: ${baseUrl}/sitemap.xml
`);
});

app.get(['/', '/index.html'], async (req, res, next) => {
  const filmId = req.query.film || req.query.short;
  const profileId = req.query.profile;
  if (!filmId && !profileId) return next();
  try {
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    let html = fs.readFileSync(htmlPath, 'utf8');
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
    const host = req.get('host') || 'www.tamasha.qd.je';
    const baseUrl = `${proto}://${host}`;
    let ogTitle = 'YouSeries (TAMASHA) — Watch Films, Shorts & Stories';
    let ogDesc = 'Stream films, shorts, stories, and photos on YouSeries (TAMASHA), founded by Sohail Parvez.';
    let ogImg = `${baseUrl}/favicon.ico`;
    let ogUrl = `${baseUrl}${req.originalUrl}`;

    if (filmId) {
      const films = await readFilms();
      const f = films.find(x => x.id === filmId);
      if (f) {
        const kind = f.type === 'short' ? 'Short' : (f.type === 'photo' ? 'Photo' : 'Video');
        ogTitle = `${f.title || kind} by @${f.ownerUsername || 'creator'} — TAMASHA`;
        ogDesc = (f.description && f.description.trim()) ? f.description.trim().slice(0, 180) : `Watch this ${kind.toLowerCase()} by @${f.ownerUsername || 'creator'} on YouSeries (TAMASHA).`;
        ogImg = `${baseUrl}/media/poster/${encodeURIComponent(f.id)}`;
      }
    } else if (profileId) {
      const users = await readUsers();
      const u = users.find(x => x.id === profileId);
      if (u) {
        ogTitle = `@${u.username}${u.verified ? ' ✔' : ''} on YouSeries (TAMASHA)`;
        ogDesc = (u.bio && u.bio.trim()) ? u.bio.trim().slice(0, 180) : `Check out @${u.username}'s videos, shorts, and photos on YouSeries (TAMASHA).`;
        if (u.profileImage) {
          const directUrl = makeDirectUrlCache();
          const av = await directUrl(u.profileImage, u.avatarStorageProvider);
          if (av) ogImg = av.startsWith('http') ? av : `${baseUrl}${av}`;
        }
      }
    }

    const ogTags = `
  <meta property="og:site_name" content="YouSeries (TAMASHA)">
  <meta property="og:type" content="website">
  <meta property="og:title" content="${escMetaAttr(ogTitle)}">
  <meta property="og:description" content="${escMetaAttr(ogDesc)}">
  <meta property="og:image" content="${escMetaAttr(ogImg)}">
  <meta property="og:url" content="${escMetaAttr(ogUrl)}">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="${escMetaAttr(ogTitle)}">
  <meta name="twitter:description" content="${escMetaAttr(ogDesc)}">
  <meta name="twitter:image" content="${escMetaAttr(ogImg)}">`;
    html = html.replace('</head>', ogTags + '\n</head>');
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.set('Cache-Control', 'no-cache');
    return res.send(html);
  } catch (e) {
    return next();
  }
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

    const token = signToken(newUser, await startSession(req, newUser));
    activateAccountToken(req, res, newUser.id, token);
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
    if (user.suspended) return res.status(403).json({ error: 'This account has been suspended for violating the community guidelines.' });
    const token = signToken(user, await startSession(req, user));
    activateAccountToken(req, res, user.id, token);
    res.json({ id: user.id, email: user.email, username: user.username });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', async (req, res) => {
  const p = getUserFromReq(req);
  if (p && p.sid) await dropSessions(p.id, x => x !== p.sid);
  const rest = savedTokens(req).filter(t => {
    const pl = payloadOf(t);
    return pl && pl.id && (!p || pl.id !== p.id) && !suspendedIds.has(pl.id);
  });
  if (rest.length > 0) {
    const nextTok = rest[0];
    writeSaved(res, rest.slice(1));
    res.cookie('token', nextTok, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  } else {
    writeSaved(res, []);
    res.clearCookie('token');
  }
  res.json({ success: true });
});

// Devices list and logout (Settings and Privacy → Devices)
app.get('/api/me/sessions', async (req, res) => {
  const p = getUserFromReq(req);
  if (!p) return res.status(401).json({ error: 'Log in' });
  const users = await readUsers();
  const u = users.find(x => x.id === p.id);
  const list = ((u && u.sessions) || []).map(x => ({ sid: x.sid, device: x.device, createdAt: x.createdAt, current: x.sid === p.sid }))
    .sort((a, b) => (b.current - a.current) || String(b.createdAt).localeCompare(String(a.createdAt)));
  res.json({ sessions: list });
});
app.post('/api/me/sessions/:sid/logout', async (req, res) => {
  const p = getUserFromReq(req);
  if (!p) return res.status(401).json({ error: 'Log in' });
  await dropSessions(p.id, x => x !== req.params.sid);
  if (req.params.sid === p.sid) res.clearCookie('token');
  res.json({ success: true, current: req.params.sid === p.sid });
});
app.post('/api/me/sessions/logout-others', async (req, res) => {
  const p = getUserFromReq(req);
  if (!p) return res.status(401).json({ error: 'Log in' });
  await dropSessions(p.id, x => x === p.sid);
  res.json({ success: true });
});

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

    const token = signToken(user, await startSession(req, user));
    activateAccountToken(req, res, user.id, token);
    res.redirect('/');
  } catch (err) {
    console.error('Google auth error:', err);
    res.redirect('/login.html?error=google_failed');
  }
});

app.get('/api/me', async (req, res) => {
  let u = getUserFromReq(req);
  // If active token cookie was missing (e.g. returning from /login.html after stashing), restore the first valid saved account
  if (!u) {
    const validSaved = savedTokens(req).find(t => {
      const p = payloadOf(t);
      return p && p.id && !suspendedIds.has(p.id) && (!p.sid || !sessionsReady || sessionIndex.has(p.sid));
    });
    if (validSaved) {
      res.cookie('token', validSaved, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
      u = payloadOf(validSaved);
    }
  }
  // the token only holds id and username: add the blue tick status so the app knows this user is verified
  if (u && u.id) {
    try {
      const me = (await readUsers()).find(x => x.id === u.id);
      if (me) {
        const isFounder = (me.email || '').toLowerCase() === 'sohailp541@gmail.com';
        const active = (!!me.verified && (me.blueFree || !me.blueUntil || Date.now() < me.blueUntil)) || isFounder;
        u = { ...u, verified: active, isAdmin: !!(me.isAdmin || isFounder), vipRing: me.vipRing || 'none', blueFree: !!me.blueFree, blueUntil: me.blueUntil || null };
      }
    } catch (e) { /* keep the token data */ }
  }
  res.json(u);
});

// ---------------- Multiple accounts on this site ----------------
// Other accounts are kept in a "saved_accounts" cookie (their login tokens). Switching swaps the active token.
function savedTokens(req) {
  try { const a = JSON.parse(req.cookies.saved_accounts || '[]'); return Array.isArray(a) ? a.filter(x => typeof x === 'string') : []; } catch (e) { return []; }
}
function writeSaved(res, list) {
  res.cookie('saved_accounts', JSON.stringify(list.slice(0, 5)), { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
}
function payloadOf(tok) { try { return jwt.verify(tok, JWT_SECRET); } catch (e) { return null; } }
function activateAccountToken(req, res, newUserId, newToken) {
  const cur = getUserFromReq(req);
  let list = savedTokens(req).filter(t => {
    const p = payloadOf(t);
    return p && p.id && p.id !== newUserId && (!cur || p.id !== cur.id);
  });
  if (cur && req.cookies.token && cur.id !== newUserId) {
    list = [req.cookies.token, ...list];
  }
  writeSaved(res, list);
  res.cookie('token', newToken, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
}
app.get('/api/accounts', (req, res) => {
  const cur = getUserFromReq(req);
  const out = [];
  if (cur) out.push({ id: cur.id, username: cur.username, current: true });
  const seen = new Set(cur ? [cur.id] : []);
  for (const t of savedTokens(req)) {
    const p = payloadOf(t);
    if (!p || !p.id || seen.has(p.id) || suspendedIds.has(p.id)) continue;
    seen.add(p.id);
    out.push({ id: p.id, username: p.username, current: false });
  }
  res.json({ accounts: out });
});
// Backs up the current login in saved_accounts WITHOUT clearing the active token cookie,
// so pressing Back from /login.html never logs out the first account!
app.post('/api/accounts/stash', (req, res) => {
  const cur = getUserFromReq(req);
  let list = savedTokens(req);
  if (cur && req.cookies.token) list = [req.cookies.token, ...list.filter(t => payloadOf(t) && payloadOf(t).id !== cur.id)];
  writeSaved(res, list);
  res.json({ success: true });
});
// Makes a saved account the active one, and puts the current one aside
app.post('/api/accounts/switch', (req, res) => {
  const want = String((req.body && req.body.id) || '');
  const list = savedTokens(req);
  const target = list.find(t => { const p = payloadOf(t); return p && p.id === want && !suspendedIds.has(p.id); });
  if (!target) return res.status(404).json({ error: 'This account is not saved, log in again' });
  const cur = getUserFromReq(req);
  let rest = list.filter(t => t !== target);
  if (cur && req.cookies.token) rest = [req.cookies.token, ...rest.filter(t => payloadOf(t) && payloadOf(t).id !== cur.id)];
  writeSaved(res, rest);
  res.cookie('token', target, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ success: true });
});

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
    if (currentUser && currentUser.id !== user.id) {
      if (!Array.isArray(user.profileViews)) user.profileViews = [];
      user.profileViews = user.profileViews.filter(v => v && v.userId !== currentUser.id);
      user.profileViews.push({ userId: currentUser.id, username: currentUser.username, viewedAt: new Date().toISOString() });
      if (user.profileViews.length > 60) user.profileViews = user.profileViews.slice(-60);
      writeUsers(users).catch(() => {});
    }
    const isFollowing = me && me.following ? me.following.includes(user.id) : false;
    const followersCount = users.filter(u => u.following && u.following.includes(user.id)).length;
    const followingCount = user.following ? user.following.length : 0;
    const defaultRole = ((user.email || '').toLowerCase() === 'sohailp541@gmail.com') ? '👑 Founder & CEO' : null;

    const convosForChan = await readConversations();
    const userChan = convosForChan.find(c => c.type === 'channel' && c.ownerId === user.id);
    res.json({
      id: user.id, username: user.username, bio: user.bio || '', website: user.website || '',
      verified: !!user.verified,
      vipRing: user.vipRing || 'none',
      channelId: userChan ? userChan.id : null,
      channelTitle: userChan ? userChan.title : null,
      channelMembersCount: userChan ? (userChan.participants || []).length : 0,
      roleBadge: user.roleBadge || defaultRole,
      note: activeNote(user),
      pinnedFilmIds: Array.isArray(user.pinnedFilmIds) ? user.pinnedFilmIds : [],
      profileImage: user.profileImage ? await makeDirectUrlCache()(user.profileImage, user.avatarStorageProvider) : null,
      followersCount, followingCount, isFollowing,
      showSensitiveContent: (user.showSensitiveContent !== false && !user.hideSensitiveContent),
      hideSensitiveContent: !(user.showSensitiveContent !== false && !user.hideSensitiveContent),
      online: isUserOnline(user),
      blocked: !!(me && me.blockedUsers && me.blockedUsers.includes(user.id)),
      restricted: !!(me && me.restrictedUsers && me.restrictedUsers.includes(user.id)),
      hasBlockedMe: !!(currentUser && user.blockedUsers && user.blockedUsers.includes(currentUser.id))
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/me/profile-views', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    if (!me) return res.status(404).json({ error: 'User not found' });
    const directUrl = makeDirectUrlCache();
    const now = Date.now(), d7 = 7 * 24 * 60 * 60 * 1000;
    const recent = (me.profileViews || []).filter(v => v && v.viewedAt && (now - new Date(v.viewedAt).getTime() < d7)).slice().reverse();
    const isVip = !!(me.verified || me.isAdmin);
    let visitors = [];
    if (isVip) {
      visitors = await Promise.all(recent.slice(0, 30).map(async v => {
        const u = users.find(x => x.id === v.userId);
        return {
          userId: v.userId,
          username: u ? u.username : (v.username || 'user'),
          verified: !!(u && u.verified),
          profileImage: (u && u.profileImage) ? await directUrl(u.profileImage, u.avatarStorageProvider) : null,
          viewedAt: v.viewedAt
        };
      }));
    }
    res.json({ count7d: recent.length, isLocked: !isVip, visitors });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/me/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    if (!req.file) return res.status(400).json({ error: 'A photo file is required' });

    const ext = path.extname(req.file.originalname) || '.jpg';
    const key = `profiles/${currentUser.id}-${Date.now()}${ext}`;
    await storePutBuffer(readFileAsBuffer(req.file.path), key, req.file.mimetype);

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const oldKey = user.profileImage;
    user.profileImage = key;
    user.avatarStorageProvider = r2On() ? 'r2' : 'gdrive';
    await writeUsers(users);
    if (oldKey && oldKey !== key) {
      storeDelete(oldKey).catch(() => {});
    }
    const directUrl = makeDirectUrlCache();
    const freshUrl = await directUrl(key, user.avatarStorageProvider);
    res.json({ profileImage: freshUrl || ('/media/avatar/' + currentUser.id + '?t=' + Date.now()) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/me/avatar', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.profileImage) {
      await storeDelete(user.profileImage).catch(() => {});
      user.profileImage = null;
      await writeUsers(users);
    }
    res.json({ success: true });
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
    films.forEach(f => {
      if (f.ownerId === user.id) { f.ownerUsername = newUsername; updated = true; }
      if (f.collaboratorId === user.id) { f.collaboratorUsername = newUsername; updated = true; }
      (f.comments || []).forEach(c => { if (c.userId === user.id) { c.name = newUsername; updated = true; } });
    });
    if (updated) await writeFilms(films);
    try {
      const stories = await readStories();
      let stUpdated = false;
      stories.forEach(s => { if (s.ownerId === user.id) { s.ownerUsername = newUsername; stUpdated = true; } });
      if (stUpdated) await writeStories(stories);
    } catch (e) {}

    const token = signToken(user, await startSession(req, user));
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ username: user.username, changesLeft: 3 - changesThisYear.length - 1 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/me/password', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const { currentPassword, newPassword } = req.body;
    if (!newPassword) return res.status(400).json({ error: 'New password is required' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.passwordHash) {
      if (!currentPassword) return res.status(400).json({ error: 'Current password is required' });
      const ok = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });
    }

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
    const { vipRing } = req.body;
    if ((user.verified || user.isAdmin) && ['none', 'purple', 'gold', 'neon'].includes(vipRing)) {
      user.vipRing = vipRing;
    }
    await writeUsers(users);
    res.json({ bio: user.bio, website: user.website, vipRing: user.vipRing || 'none' });
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
        id: u.id, username: u.username, verified: !!u.verified,
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
      id: u.id, username: u.username, verified: !!u.verified,
      profileImage: u.profileImage ? await directUrl(u.profileImage, u.avatarStorageProvider) : null,
      isFollowing: !!(me && me.following && me.following.includes(u.id)),
      isMe: !!(currentUser && currentUser.id === u.id)
    })));
    res.json({ users: list });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/me/followers/:id/remove', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const users = await readUsers();
    const follower = users.find(u => u.id === req.params.id);
    if (!follower) return res.status(404).json({ error: 'User not found' });
    if (Array.isArray(follower.following)) {
      follower.following = follower.following.filter(id => id !== currentUser.id);
      await writeUsers(users);
    }
    res.json({ success: true });
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
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
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
    const currentUser = getUserFromReq(req);
    const ckey = (currentUser ? currentUser.id : 'anon') + '|' + feedVer;
    const hit = feedCache.get(ckey);
    if (hit && Date.now() - hit.at < FEED_CACHE_MS) return res.json(hit.out);
    const films = await readFilms();
    const users = await readUsers();
    const userById = new Map(users.map(u => [u.id, u]));
    const me = currentUser ? users.find(u => u.id === currentUser.id) : null;
    const hideSensitive = me ? (me.showSensitiveContent === false || me.hideSensitiveContent === true) : false;
    const myBlocked = (me && me.blockedUsers) || [];
    const directUrl = makeDirectUrlCache();

    const nowMs = Date.now();
    const out = await Promise.all(films
      .filter(f => !(f.pendingReview && !(currentUser && f.ownerId === currentUser.id)))
      .filter(f => !(f.publishAt && new Date(f.publishAt).getTime() > nowMs))
      .filter(f => !(hideSensitive && f.isSensitive))
      .filter(f => !myBlocked.includes(f.ownerId))
      .filter(f => {
        const owner = userById.get(f.ownerId);
        return !(owner && owner.blockedUsers && me && owner.blockedUsers.includes(me.id));
      })
      .map(async f => {
        const owner = userById.get(f.ownerId);
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
        const collabUser = (f.collabStatus === 'accepted' && f.collaboratorId) ? userById.get(f.collaboratorId) : null;
        const collabAvatarUrl = collabUser && collabUser.profileImage ? await directUrl(collabUser.profileImage, collabUser.avatarStorageProvider) : null;
        const ownerDefaultRole = (owner && (owner.email || '').toLowerCase() === 'sohailp541@gmail.com') ? '👑 Founder & CEO' : null;
        return {
          ...f, comments: enrichedComments,
          videoUrl, posterUrl,
          slideUrls: await buildSlideUrls(f, directUrl),
          ownerVerified: !!(owner && owner.verified),
          ownerVipRing: (owner && owner.vipRing) || 'none',
          ownerRoleBadge: (owner && owner.roleBadge) || ownerDefaultRole,
          ownerProfileImage: ownerAvatarUrl,
          collaboratorProfileImage: collabAvatarUrl,
          views: Math.max(f.views || 0, (f.viewedBy || []).length, f.likes || 0),
          adminBoosted: !!f.adminBoosted,
          isFollowing: !!(me && me.following && me.following.includes(f.ownerId))
        };
      }));
    feedCache.set(ckey, { at: Date.now(), out });
    if (feedCache.size > 300) feedCache.delete(feedCache.keys().next().value);
    res.json(out);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

async function markCollabInviteResolved(userId, ownerId, filmId, filmTitle, status) {
  try {
    let notifs = (await storeTryReadJSON('notifications.json')) || [];
    let changed = false;
    if (status === 'declined') {
      const before = notifs.length;
      notifs = notifs.filter(n => !(n.type === 'collab_invite' && String(n.filmId) === String(filmId) && n.userId === userId));
      if (notifs.length !== before) changed = true;
    } else {
      notifs.forEach(n => {
        if (n.type === 'collab_invite' && String(n.filmId) === String(filmId) && n.userId === userId) {
          n.type = 'collab_accepted';
          n.read = true;
          n.message = `🤝 You accepted the collab invite on "${filmTitle || 'Post'}"`;
          changed = true;
        }
      });
    }
    if (changed) await storeWriteJSON('notifications.json', notifs);
  } catch (e) {}
  try {
    if (userId && ownerId) {
      const cid = conversationIdFor(userId, ownerId);
      const msgs = await readChatMessages(cid);
      let mChanged = false;
      msgs.forEach(m => {
        if (m.type === 'collab_invite' && String(m.shortId) === String(filmId)) {
          m.collabStatus = status;
          m.editedAt = new Date().toISOString();
          mChanged = true;
        }
      });
      if (mChanged) await writeChatMessages(cid, msgs);
    }
  } catch (e) {}
}

app.post('/api/films/:id/collab/accept', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || f.collaboratorId !== currentUser.id) return res.status(404).json({ error: 'Invite not found' });
    f.collabStatus = 'accepted';
    await writeFilms(films);
    await markCollabInviteResolved(currentUser.id, f.ownerId, f.id, f.title, 'accepted');
    await notify(f.ownerId, { type: 'collab_accepted', fromUserId: currentUser.id, fromUsername: currentUser.username, filmId: f.id, message: `@${currentUser.username} accepted the collab on "${f.title}"` });
    res.json({ success: true, collabStatus: 'accepted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/collab/decline', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || !f.collaboratorId) return res.status(404).json({ error: 'Collab not found' });
    if (f.collaboratorId !== currentUser.id && f.ownerId !== currentUser.id) return res.status(403).json({ error: 'You don\'t have permission' });
    const oldCollabId = f.collaboratorId;
    delete f.collaboratorId; delete f.collaboratorUsername; delete f.collabStatus;
    await writeFilms(films);
    await markCollabInviteResolved(oldCollabId, f.ownerId, f.id, f.title, 'declined');
    res.json({ success: true, collabStatus: 'declined' });
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
    if (!f) return res.status(404).json({ error: 'Post not found' });
    if (f.ownerId !== currentUser.id) return res.status(403).json({ error: 'Only the post owner can set the collab' });

    const raw = String(req.body.username || '').trim().replace(/^@/, '');
    if (!raw) {
      delete f.collaboratorId; delete f.collaboratorUsername; delete f.collabStatus;
      await writeFilms(films);
      return res.json({ collabStatus: null });
    }
    const users = await readUsers();
    const target = users.find(u => (u.username || '').toLowerCase() === raw.toLowerCase());
    if (!target) return res.status(404).json({ error: 'This username was not found' });
    if (target.id === currentUser.id) return res.status(400).json({ error: 'You cannot collab with yourself' });
    if ((target.blockedUsers || []).includes(currentUser.id)) return res.status(403).json({ error: 'You cannot invite this user' });

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
    const me = currentUser ? users.find(u => u.id === currentUser.id) : null;
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
      ...f,
      views: Math.max(f.views || 0, (f.viewedBy || []).length, f.likes || 0),
      comments: enrichedComments,
      videoUrl: f.type !== 'photo' && f.videoFile ? await directUrl(f.videoFile, f.storageProvider) : null,
      posterUrl: f.posterFile ? await directUrl(f.posterFile, f.storageProvider) : null,
      slideUrls: await buildSlideUrls(f, directUrl),
      ownerVerified: !!(owner && owner.verified),
      ownerRoleBadge: (owner && owner.roleBadge) || ((owner && (owner.email || '').toLowerCase() === 'sohailp541@gmail.com') ? '👑 Founder & CEO' : null),
      ownerProfileImage: ownerAvatarUrl,
      collaboratorProfileImage: (f.collabStatus === 'accepted' && f.collaboratorId) ? (await (async () => { const cu = users.find(u => u.id === f.collaboratorId); return (cu && cu.profileImage) ? await directUrl(cu.profileImage, cu.avatarStorageProvider) : null; })()) : null,
      isFollowing: !!(me && me.following && me.following.includes(f.ownerId))
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
    if (!f) return res.status(404).send('Not found');
    const slide0 = Array.isArray(f.slides) && f.slides[0] ? f.slides[0] : null;
    const key = f.posterFile || (slide0 && slide0.mediaType === 'photo' ? slide0.key : null);
    if (!key) return res.status(404).send('Not found');
    return storeStream(key, req, res);
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

// ---------------- Storage engine (Cloudflare R2) ----------------
// Same helper names as before, but every read, write, copy and delete goes to the R2 bucket.
const GD_MONTH_CAP = Infinity;                  // no server-side media cap (bandwidth is R2's, and R2 egress is free)
const GD_PART = 8 * 1024 * 1024;                // the browser sends 8 MB parts
const gdEnabled = () => r2On();
const gdMediaUrl = id => r2PublicUrl(id);
async function gdMakePublic() {}                // R2 public bucket: nothing to set per file
async function gdEnsurePublic() {}
const isGdSession = () => false;
async function gdAbout() { return { enabled: false }; }
const gdIdx = new Map();                        // object key -> true, for every object in the bucket
let gdIdxAt = 0, gdIdxSizes = new Map(), gdIdxShared = new Map();
async function gdIndexRefresh(force) {
  if (!force && Date.now() - gdIdxAt < 20000) return;
  storeNeedsDrive();
  gdIdxAt = Date.now();
  const seen = new Map(), sizes = new Map();
  let token;
  do {
    const out = await getR2().send(new ListObjectsV2Command({ Bucket: r2Bucket(), ContinuationToken: token }));
    (out.Contents || []).forEach(o => { seen.set(o.Key, true); sizes.set(o.Key, o.Size || 0); });
    token = out.IsTruncated ? out.NextContinuationToken : undefined;
  } while (token);
  gdIdx.clear();
  seen.forEach((v, k) => gdIdx.set(k, true));
  gdIdxSizes = sizes;
}
let gdLastMissRefresh = 0;
async function gdResolve(key) {
  if (!key) return null;
  if (gdIdx.has(key)) return key;
  if (Date.now() - gdLastMissRefresh > 2000) { gdLastMissRefresh = Date.now(); try { await gdIndexRefresh(true); } catch (e) {} }
  return gdIdx.has(key) ? key : null;
}
const gdKeyLocks = new Map();
function gdWithLock(key, fn) {                  // one write at a time per key
  const prev = gdKeyLocks.get(key) || Promise.resolve();
  const next = prev.catch(() => {}).then(fn);
  gdKeyLocks.set(key, next);
  next.finally(() => { if (gdKeyLocks.get(key) === next) gdKeyLocks.delete(key); }).catch(() => {});
  return next;
}
function gdPutByKey(key, buf, contentType) {
  return gdWithLock(key, async () => {
    storeNeedsDrive();
    await getR2().send(new PutObjectCommand({ Bucket: r2Bucket(), Key: key, Body: buf, ContentType: contentType || 'application/octet-stream' }));
    gdIdx.set(key, true);
    gdIdxSizes.set(key, buf.length);
    return key;
  });
}
async function gdGetByKey(key) {
  try {
    const out = await getR2().send(new GetObjectCommand({ Bucket: r2Bucket(), Key: key }));
    const chunks = [];
    for await (const c of out.Body) chunks.push(c);
    return Buffer.concat(chunks);
  } catch (e) {
    if (e && (e.name === 'NoSuchKey' || (e.$metadata && e.$metadata.httpStatusCode === 404))) { const m = new Error('NoSuchKey'); m.name = 'NoSuchKey'; throw m; }
    throw e;
  }
}
async function gdDelete(key) {
  if (!key) return;
  await getR2().send(new DeleteObjectCommand({ Bucket: r2Bucket(), Key: key })).catch(() => {});
  gdIdx.delete(key);
}
// JSON "database" writes are batched: memory is updated at once, R2 gets the newest copy within a few seconds.
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
      console.error(`R2 save of ${key} failed (will retry):`, e.message);
      if (!gdFlushTimer) gdFlushTimer = setTimeout(() => { gdFlushTimer = null; gdFlushAll().catch(() => {}); }, 15000);
    }
  }));
}
async function gdServe(key, req, res) {
  if (!key) return res.status(404).end();
  return res.redirect(302, r2PublicUrl(key));
}

// ---------------- Resumable uploads (Cloudflare R2) ----------------
// The browser cuts a file into 8 MB parts and sends each one straight to R2 with a presigned link.
// The server only creates the upload, signs each part link, lists the parts that arrived and completes the file.
function mpAuth(req, res) {
  const currentUser = getUserFromReq(req);
  if (!currentUser && !isAdminBasicAuth(req)) { res.status(401).json({ error: 'Please log in' }); return null; }
  return currentUser || { id: 'admin' };
}
const keyOk = k => typeof k === 'string' && R2_KEY_RE.test(k);

app.post('/api/upload/mp/create', async (req, res) => {
  try {
    if (!mpAuth(req, res)) return;
    const { fileName, contentType, folder, size: sizeRaw } = req.body || {};
    if (!fileName || !folder) return res.status(400).json({ error: 'A file name and folder are required' });
    storeNeedsDrive();
    const safeFolder = ['videos', 'posters', 'photos'].includes(folder) ? folder : 'videos';
    const size = Number(sizeRaw);
    if (!(size > 0)) return res.status(400).json({ error: 'File size is required' });
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const ext = (path.extname(String(fileName)) || '').replace(/[^A-Za-z0-9.]/g, '').slice(0, 8);
    const key = `${safeFolder}/${id}${ext}`;
    const up = await getR2().send(new CreateMultipartUploadCommand({ Bucket: r2Bucket(), Key: key, ContentType: contentType || 'application/octet-stream' }));
    res.json({ key, uploadId: up.UploadId });
  } catch (err) { res.status(err.status || 500).json({ error: err.message }); }
});

app.get('/api/upload/mp/r2-part-url', async (req, res) => {
  try {
    if (!mpAuth(req, res)) return;
    const { key, uploadId } = req.query;
    const n = parseInt(req.query.n, 10);
    if (!keyOk(key) || !uploadId || !(n >= 1 && n <= 10000)) return res.status(400).json({ error: 'Bad request' });
    const url = await getSignedUrl(getR2(), new UploadPartCommand({ Bucket: r2Bucket(), Key: key, UploadId: uploadId, PartNumber: n }), { expiresIn: 3600 });
    res.json({ url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/upload/mp/parts', async (req, res) => {
  try {
    if (!mpAuth(req, res)) return;
    const { key, uploadId } = req.query;
    if (!keyOk(key) || !uploadId) return res.status(400).json({ error: 'Bad request' });
    const parts = await r2ListParts(key, uploadId);
    res.json({ parts: parts.map(p => ({ n: p.PartNumber })) });
  } catch (err) {
    if (err.name === 'NoSuchUpload') return res.status(404).json({ error: 'Upload session expired', expired: true });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/upload/mp/complete', async (req, res) => {
  try {
    if (!mpAuth(req, res)) return;
    const body = req.body || {};
    if (!keyOk(body.key) || !body.uploadId) return res.status(400).json({ error: 'Bad request' });
    const parts = await r2ListParts(body.key, body.uploadId);
    if (!parts.length || (body.total && parts.length !== Number(body.total))) return res.status(409).json({ error: 'Some parts are still missing', have: parts.length });
    await getR2().send(new CompleteMultipartUploadCommand({ Bucket: r2Bucket(), Key: body.key, UploadId: body.uploadId, MultipartUpload: { Parts: parts.map(p => ({ PartNumber: p.PartNumber, ETag: p.ETag })) } }));
    gdIdx.set(body.key, true);
    res.json({ ok: true, key: body.key });
  } catch (err) {
    if (err.name === 'NoSuchUpload') return res.status(404).json({ error: 'Upload session expired', expired: true });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/upload/mp/abort', async (req, res) => {
  try {
    if (!mpAuth(req, res)) return;
    const body = req.body || {};
    if (keyOk(body.key) && body.uploadId) await getR2().send(new AbortMultipartUploadCommand({ Bucket: r2Bucket(), Key: body.key, UploadId: body.uploadId })).catch(() => {});
    res.json({ ok: true });
  } catch (err) { res.json({ ok: true }); }
});

// A song attached by a user: { url, title, start, duration }. Duration rules: photo story/upload 8s, note 15s, video = its own length.
async function pickSong(body, kind) {
  const id = body && body.songId;
  if (!id) return null;
  const x = (await readSongs()).find(y => y.id === String(id));
  if (!x) return null;
  const start = Math.max(0, Math.min(3600, Number(body.songStart) || 0));
  const want = (kind === 'story' || kind === 'note') ? 15 : kind === 'photo' ? 15 : Math.max(1, Math.min(600, Number(body.songDuration) || 15));
  return { id: x.id, url: r2PublicUrl(x.key), title: x.title, artist: x.artist || '', Category: x.category || '', start, duration: want };
}
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
    // scheduled publish: the post stays hidden until this time
    const when = req.body.publishAt ? new Date(req.body.publishAt) : null;
    if (when && !isNaN(when) && when.getTime() > Date.now()) newFilm.publishAt = when.toISOString();
    // optional review queue: new uploads wait for the owner's approval in the dashboard
    const songKind = (req.body.type === 'photo' || req.body.type === 'carousel') ? 'photo' : 'video';
    const attachedSong = await pickSong(req.body, songKind);
    if (attachedSong) newFilm.song = attachedSong;
    const modSet = (await storeTryReadJSON('moderation-settings.json')) || {};
    if (modSet.reviewUploads) {
      let skipForVerified = false;
      if (modSet.autoApproveVerified !== false && currentUser) {
        const allU = await readUsers();
        const meU = allU.find(u => u.id === currentUser.id);
        if (meU && (meU.verified || meU.isAdmin || (meU.email || '').toLowerCase() === 'sohailp541@gmail.com')) skipForVerified = true;
      }
      if (!skipForVerified) newFilm.pendingReview = true;
    }
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
    const viewer = getUserFromReq(req);
    let counted = false;
    if (!Array.isArray(f.viewedBy)) f.viewedBy = [];
    if (Array.isArray(f.likedBy)) {
      f.likedBy.forEach(uid => { if (uid && !f.viewedBy.includes(uid)) f.viewedBy.push(uid); });
    }
    if (viewer && !f.viewedBy.includes(viewer.id)) {
      f.viewedBy.push(viewer.id);
      counted = true;
    }
    const minViews = Math.max((f.viewedBy || []).length, f.likes || 0);
    f.views = Math.max((f.views || 0) + (counted ? 1 : 0), minViews);
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

    res.json({ views: f.views, counted });
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
    if (!Array.isArray(f.viewedBy)) f.viewedBy = [];
    const idx = f.likedBy.indexOf(currentUser.id);
    let liked;
    if (idx === -1) {
      f.likedBy.push(currentUser.id);
      f.likedAt[currentUser.id] = new Date().toISOString();
      if (!f.viewedBy.includes(currentUser.id)) {
        f.viewedBy.push(currentUser.id);
        f.views = (f.views || 0) + 1;
      }
      liked = true;
    } else {
      f.likedBy.splice(idx, 1);
      delete f.likedAt[currentUser.id];
      liked = false;
    }
    f.likedBy.forEach(uid => { if (uid && !f.viewedBy.includes(uid)) f.viewedBy.push(uid); });
    f.likes = (f.likesBaseline || 0) + f.likedBy.length;
    f.views = Math.max(f.views || 0, f.viewedBy.length, f.likes);

    await writeFilms(films);
    res.json({ likes: f.likes, views: f.views, liked });
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
    if (!Array.isArray(f.viewedBy)) f.viewedBy = [];
    if (Array.isArray(f.likedBy)) {
      f.likedBy.forEach(uid => { if (uid && !f.viewedBy.includes(uid)) f.viewedBy.push(uid); });
    }
    const likes = f.likes || 0;
    const views = Math.max(f.views || 0, f.viewedBy.length, likes);
    if ((f.views || 0) < views) {
      f.views = views;
      await writeFilms(films);
    }
    const shares = f.shares || 0;
    const avgWatchSeconds = f.watchSamples ? Math.round((f.watchSeconds || 0) / f.watchSamples) : 0;
    const likeRate = views > 0 ? Math.min(100, Math.round((likes / views) * 1000) / 10) : 0;
    res.json({ views, likes, likeRate, shares, avgWatchSeconds, commentCount: (f.comments || []).length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/comments', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Please log in to comment' });

    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Please write a comment' });
    if (await findBannedWord(text)) return res.status(400).json({ error: 'This comment contains a word that is not allowed' });

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
    if (!isFilmOwnerOrCollab(f, currentUser.id)) return res.status(403).json({ error: 'Only the post owner can pin' });

    const comment = f.comments.find(c => c.id === req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    if (comment.hidden) return res.status(400).json({ error: 'A hidden comment cannot be pinned' });

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

app.post('/api/films/:filmId/comments/:commentId/like', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.filmId);
    if (!f || !f.comments) return res.status(404).json({ error: 'Not found' });
    const comment = f.comments.find(c => c.id === req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    if (!Array.isArray(comment.likes)) comment.likes = [];
    const idx = comment.likes.indexOf(currentUser.id);
    const liked = idx === -1;
    if (liked) {
      comment.likes.push(currentUser.id);
      if (comment.userId && comment.userId !== currentUser.id) {
        notify(comment.userId, {
          type: 'comment_like', fromUserId: currentUser.id, fromUsername: currentUser.username,
          filmId: f.id, message: `@${currentUser.username} liked your comment on "${f.title}"`
        }).catch(() => {});
      }
    } else {
      comment.likes.splice(idx, 1);
    }
    await writeFilms(films);
    res.json({ liked, likesCount: comment.likes.length, likes: comment.likes });
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
    let storyAdjust = null;
    try {
      const a = JSON.parse(req.body.adjust || 'null');
      if (a && isFinite(a.s) && isFinite(a.x) && isFinite(a.y)) storyAdjust = { s: Math.min(4, Math.max(1, a.s)), x: Math.min(1, Math.max(-1, a.x)), y: Math.min(1, Math.max(-1, a.y)) };
    } catch (e) {}
    if (storyAdjust) newStory.adjust = storyAdjust;
    if (req.body.poll) {
      try {
        const p = JSON.parse(req.body.poll);
        if (p && p.q && p.optA && p.optB) {
          newStory.poll = {
            q: String(p.q).trim().slice(0, 100),
            optA: String(p.optA).trim().slice(0, 40),
            optB: String(p.optB).trim().slice(0, 40),
            votesA: [],
            votesB: []
          };
        }
      } catch (e) {}
    }
    const storySong = await pickSong(req.body, 'story');
    if (storySong) newStory.song = storySong;
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
    if (!film) return res.status(404).json({ error: 'This video/photo is no longer available' });

    const sourceKey = film.type === 'photo' ? (film.posterFile || film.videoFile) : (film.videoFile || film.posterFile);
    if (!sourceKey) return res.status(400).json({ error: 'No usable media found for the story' });
    const isVideo = film.type !== 'photo';

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const ext = path.extname(sourceKey) || (isVideo ? '.mp4' : '.jpg');
    let mediaKey = `stories/${id}${ext}`;
    mediaKey = (await storeCopy(sourceKey, mediaKey)) || mediaKey;

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
      const userStories = await Promise.all(byUser[ownerId].slice().reverse().map(async s => {
        const likesArr = Array.isArray(s.likes) ? s.likes : [];
        const isLikedByMe = !!(currentUser && (likesArr.includes(currentUser.id) || (s.comments || []).some(c => c && c.userId === currentUser.id && c.text && c.text.trim() === '❤️')));
        return {
          id: s.id, ownerId: s.ownerId, ownerUsername: s.ownerUsername,
          mediaType: s.mediaType, textOverlay: s.textOverlay, song: s.song, adjust: s.adjust, poll: s.poll || null, createdAt: s.createdAt,
          mediaUrl: await directUrl(s.mediaFile, s.storageProvider),
          viewCount: (s.views || []).length,
          likeCount: likesArr.length,
          likedByMe: isLikedByMe,
          commentCount: (s.comments || []).filter(c => c && c.text && c.text.trim() !== '❤️').length,
          viewedByMe: !!(currentUser && (s.views || []).some(v => v.userId === currentUser.id))
        };
      }));
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
    const directUrl = makeDirectUrlCache();
    const userMap = new Map(users.map(u => [u.id, u]));

    const likesSet = new Set(s.likes || []);
    (s.comments || []).forEach(c => {
      if (c && c.text && c.text.trim() === '❤️') likesSet.add(c.userId);
    });

    const userCommentsMap = new Map();
    const rawComments = (s.comments || []).filter(c => c && c.text && c.text.trim() !== '❤️');
    rawComments.forEach(c => {
      if (!c || !c.userId) return;
      if (!userCommentsMap.has(c.userId)) userCommentsMap.set(c.userId, []);
      userCommentsMap.get(c.userId).push(c.text);
    });

    const viewsList = (s.views || []).slice();
    const viewsUserIds = new Set(viewsList.map(v => v.userId));
    rawComments.forEach(c => {
      if (c.userId && !viewsUserIds.has(c.userId)) {
        viewsUserIds.add(c.userId);
        viewsList.push({ userId: c.userId, username: c.name || 'viewer', viewedAt: c.createdAt || new Date().toISOString() });
      }
    });
    likesSet.forEach(uid => {
      if (uid && !viewsUserIds.has(uid)) {
        viewsUserIds.add(uid);
        const u = userMap.get(uid);
        viewsList.push({ userId: uid, username: u ? u.username : 'viewer', viewedAt: new Date().toISOString() });
      }
    });

    const viewers = await Promise.all(viewsList.reverse().map(async v => {
      const u = userMap.get(v.userId);
      const avatarUrl = u && u.profileImage ? await directUrl(u.profileImage, u.avatarStorageProvider) : null;
      const cmts = userCommentsMap.get(v.userId) || [];
      return {
        userId: v.userId,
        username: u ? u.username : v.username,
        profileImage: avatarUrl,
        viewedAt: v.viewedAt,
        liked: likesSet.has(v.userId),
        comment: cmts.length ? cmts[cmts.length - 1] : null,
        comments: cmts,
        commentCount: cmts.length
      };
    }));

    const comments = await Promise.all(rawComments.slice().reverse().map(async c => {
      const u = userMap.get(c.userId);
      const avatarUrl = u && u.profileImage ? await directUrl(u.profileImage, u.avatarStorageProvider) : null;
      return {
        id: c.id,
        userId: c.userId,
        name: u ? u.username : c.name,
        profileImage: avatarUrl,
        text: c.text,
        createdAt: c.createdAt
      };
    }));

    res.json({
      viewCount: viewers.length,
      likeCount: likesSet.size,
      commentCount: comments.length,
      viewers,
      comments
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/stories/:id/like', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Please log in to like' });
    const stories = await readStories();
    const s = stories.find(x => x.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Story not found' });
    if (!Array.isArray(s.likes)) s.likes = [];
    const idx = s.likes.indexOf(currentUser.id);
    const liked = idx === -1;
    if (liked) {
      s.likes.push(currentUser.id);
      if (s.ownerId !== currentUser.id) {
        notify(s.ownerId, {
          type: 'story_like',
          fromUserId: currentUser.id,
          fromUsername: currentUser.username,
          storyId: s.id,
          message: `@${currentUser.username} liked your story`
        }).catch(() => {});
      }
    } else {
      s.likes.splice(idx, 1);
    }
    await writeStories(stories);
    res.json({ liked, likesCount: s.likes.length, likes: s.likes });
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

app.post('/api/stories/:id/poll-vote', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const stories = await readStories();
    const s = stories.find(x => x.id === req.params.id);
    if (!s || !s.poll) return res.status(404).json({ error: 'Poll not found' });
    const choice = req.body && req.body.choice === 'B' ? 'B' : 'A';
    s.poll.votesA = (s.poll.votesA || []).filter(uid => uid !== currentUser.id);
    s.poll.votesB = (s.poll.votesB || []).filter(uid => uid !== currentUser.id);
    if (choice === 'A') s.poll.votesA.push(currentUser.id);
    else s.poll.votesB.push(currentUser.id);
    await writeStories(stories);
    res.json({ poll: s.poll });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/me/stories', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const includeArchive = req.query.archive === '1';
    const allMine = (await readStories()).filter(s => s.ownerId === currentUser.id);
    const filtered = includeArchive ? allMine : allMine.filter(isStoryActive);
    const directUrl = makeDirectUrlCache();
    const out = await Promise.all(filtered.slice().reverse().map(async s => ({
      id: s.id, mediaType: s.mediaType, textOverlay: s.textOverlay, song: s.song, adjust: s.adjust, poll: s.poll || null, createdAt: s.createdAt,
      mediaUrl: await directUrl(s.mediaFile, s.storageProvider),
      viewCount: (s.views || []).length,
      likeCount: (s.likes || []).length,
      commentCount: (s.comments || []).length,
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
    if (!title) return res.status(400).json({ error: 'Give the highlight a title' });
    if (!storyIds.length) return res.status(400).json({ error: 'Choose at least one story' });

    const stories = await readStories();
    const mine = storyIds.map(id => stories.find(s => s.id === id && s.ownerId === currentUser.id)).filter(Boolean);
    if (!mine.length) return res.status(404).json({ error: 'Stories not found' });

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
        mediaType: s.mediaType, textOverlay: s.textOverlay, song: s.song, adjust: s.adjust, createdAt: s.createdAt,
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
    const [all, films, stories, users] = await Promise.all([
      storeTryReadJSON('notifications.json').then(x => x || []),
      readFilms().catch(() => []),
      readStories().catch(() => []),
      readUsers().catch(() => [])
    ]);
    const directUrl = makeDirectUrlCache();
    const filmMap = new Map(films.map(f => [f.id, f]));
    const storyMap = new Map(stories.map(s => [s.id, s]));
    const userMap = new Map(users.map(u => [u.id, u]));

    const mineRaw = all.filter(n => n.userId === currentUser.id).slice().reverse().slice(0, 50);
    const unreadCount = mineRaw.filter(n => !n.read).length;

    const mine = await Promise.all(mineRaw.map(async n => {
      const out = { ...n, filmType: null, filmOwnerId: null, storyOwnerId: null, thumbUrl: null, mediaKind: null, fromAvatar: null };
      const fromU = userMap.get(n.fromUserId);
      if (fromU && fromU.profileImage) {
        out.fromAvatar = await directUrl(fromU.profileImage, fromU.avatarStorageProvider);
      }
      if (n.filmId) {
        const f = filmMap.get(n.filmId);
        if (f) {
          out.filmType = f.type || 'film';
          out.filmOwnerId = f.ownerId || null;
          const slide0 = Array.isArray(f.slides) && f.slides[0] ? f.slides[0] : null;
          const thumbKey = f.posterFile || (slide0 && slide0.mediaType === 'photo' ? slide0.key : null);
          if (thumbKey) {
            out.thumbUrl = await directUrl(thumbKey, f.storageProvider);
            out.mediaKind = 'image';
          } else if (f.videoFile || (slide0 && slide0.key)) {
            out.thumbUrl = await directUrl(f.videoFile || slide0.key, f.storageProvider);
            out.mediaKind = 'video';
          }
        }
      } else if (n.storyId) {
        const s = storyMap.get(n.storyId);
        if (s) {
          out.storyOwnerId = s.ownerId || null;
          if (s.mediaFile) {
            out.thumbUrl = await directUrl(s.mediaFile, s.storageProvider);
            out.mediaKind = s.mediaType === 'video' ? 'video' : 'image';
          }
        }
      }
      return out;
    }));

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
  if (m.type === 'collab_invite') return '🤝 Collab invite: ' + (m.shortTitle || 'Post');
  if (m.type === 'poll') return '📊 Poll: ' + (m.poll ? m.poll.question : 'Poll');
  return (m.text || '')
    .replace(/\*\*/g, '')
    .replace(/__/g, '')
    .replace(/`/g, '')
    .replace(/^#+\s*/gm, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);
}
async function enrichMessage(m, directUrl, usersList) {
  const sender = (usersList || []).find(u => u.id === m.senderId);
  const out = {
    id: m.id, conversationId: m.conversationId, senderId: m.senderId,
    senderUsername: sender ? sender.username : null,
    senderVerified: !!(sender && sender.verified),
    senderRoleBadge: sender ? (sender.roleBadge || (((sender.email || '').toLowerCase() === 'sohailp541@gmail.com') ? '👑 Founder & CEO' : null)) : null,
    senderAvatar: (sender && sender.profileImage) ? await directUrl(sender.profileImage, sender.avatarStorageProvider) : null,
    type: m.type, text: m.unsent ? null : (m.text || null),
    createdAt: m.createdAt, editedAt: m.editedAt || null,
    unsent: !!m.unsent, readBy: m.readBy || [], readAt: m.readAt || null,
    mediaUrl: null, duration: m.duration || null,
    shortId: null, shortTitle: null, shortThumb: null, shortOwnerUsername: null,
    replyTo: m.unsent ? null : (m.replyTo || null),
    reactions: m.reactions || {},
    poll: m.poll || null
  };
  if (!m.unsent && m.mediaKey && (m.type === 'photo' || m.type === 'video' || m.type === 'voice')) {
    out.mediaUrl = await directUrl(m.mediaKey, m.storageProvider || 'gdrive');
  }
  if (!m.unsent && (m.type === 'short' || m.type === 'collab_invite')) {
    out.shortId = m.shortId;
    out.shortTitle = m.shortTitle || null;
    out.shortOwnerUsername = m.shortOwnerUsername || null;
    out.shortThumb = m.shortId ? `/media/poster/${m.shortId}` : null;
    out.shortVideoUrl = m.shortId ? `/media/video/${m.shortId}` : null;
    out.collabStatus = m.collabStatus || 'pending';
  }
  return out;
}

// ---------------- Ask AI: Groq + Tavily Integration ----------------
const AI_ASSISTANT_ID = 'ai-assistant';
const AI_ASSISTANT_USERNAME = 'Ask AI';
const AI_ASSISTANT_USER = { id: AI_ASSISTANT_ID, username: AI_ASSISTANT_USERNAME, profileImage: null };

const GROQ_API_KEY = process.env.GROQ_API_KEY;
const TAVILY_API_KEY = process.env.TAVILY_API_KEY;

const AI_SYSTEM_PROMPT = `Tum "Ask AI" ho — YouSeries (TAMASHA) app ka built-in assistant. Hinglish me jawab do.\n\nFOUNDER: YouSeries (TAMASHA) ka founder aur CEO Sohail Parvez hai. Unki bio: Sohail Parvez, TAMASHA app / YouSeries social media platform ke founder aur CEO hain. Age 23 saal. Qualification: MBA (Data Analytics). Social profiles: Instagram @sohail_parvezofficial (https://www.instagram.com/sohail_parvezofficial/), Facebook: https://www.facebook.com/share/1CKJdD67rj/ . Agar koi bhi poochhe ki founder/CEO/owner kaun hai ya unke baare me kya hai, to ye jaankari de do. Ye sawal kisi bhi language me ho, yahi jawab do.

JAWAB KA FORMAT (bahut zaroori):
- Chhota aur seedha. Chat card me dikhega, essay mat likho.
- Mukhya baat ko **bold** me likho. Steps ho to 1. 2. 3. me likho. Points ke liye "- " lagao.
- Founder Sohail Parvez ke official Instagram aur Facebook links ke alawa koi anjaan external link mat banao. App ke features ke liye app ke andar ka rasta batao (jaise "Profile → ⋮ → Settings and Privacy → Notifications").
- Kabhi bhi cheez ko "dekh" ya "open" karne ka vaada mat karo jo tum nahi kar sakte.

PHOTO / VIDEO KE BAARE ME:
- Jab user KHUD photo ya video bheje (ya chat me post share kare), to use dhyan se dekh kar detail me Hinglish/Hindi me explain karo.
- Agar photo/video me koi mashhoor insaan (celebrity, actor, cricketer, public figure), character, jagah, gaadi, product ya cheez dikhe, ya photo ka title/file name diya ho, to uska **naam aur pehchaan saaf-saaf batao**. Agar kisi aam (private) insaan ka chehra ho jise pehchana na ja sake, to batao ki ye private person lag rahe hain aur unka look/scene describe karo.
- Photo me likha hua text (OCR), scene, kapde, background, objects, aur video me kya ho raha hai + audio transcript sab ache se samjhao.
- App ke doosre users ki posts ke liye [Site Context] me di gayi details (title, type, creator, date, views, likes, hashtags) se bhi madad lo.
- Private cheezein (kisi aur user ke DM, password, email) kabhi nahi batana.

APP KE FEATURES (ye sab jaante ho):
- **Feed (Home):** full videos 16:9 me, shorts/reels 9:16 me, photos ek ke baad ek. Photo par double-tap = like. Single tap par photo nahi khulti.
- **Full video page:** video upar sticky, neeche comments, "Suggested reels" (Instagram jaisi row) aur "Up next" (YouTube jaisi list). Video band karne par suggestions chhup jaate hain.
- **Shorts:** vertical scroll, pause par timer (0:12 / 0:45), khatam hone par agla short apne aap chalta hai. Speed 0.5x–2x. Hold karke 2x.
- **Upload:** "+ Upload" button se video, short, photo ya carousel (2-10 photo/video). Upload refresh ya band hone par bhi resume hota hai. Pehle se review ON ho to post admin approval ke baad dikhegi. "When to publish" se scheduled post bhi kar sakte ho.
- **Profile:** Videos, Photos, Saved tabs. Photo par tap karke photo-feed khulti hai (sirf us user ki photos). Post ke ⋮ me Pin (profile par 3 tak). Note (24 ghante).
- **Profile edit:** Edit Profile se naam, bio, avatar.
- **Stories:** Add Story se 24 ghante ki story. Highlights bhi.
- **Messages (DM):** message par hold karke reaction. Typing, online dot, Sent/Seen status. Ask AI ek chat hai.
- **Notifications:** bell se list. Settings → 🔔 Notifications me likes, comments, follows, mentions, messages, collab, stories ke on/off.
- **Settings and Privacy (⋮ profile se):** ☀️ White mode / 🌙 Dark mode, Notifications, ✔ Blue tick, 🆘 Help Desk.
- **Blue tick:** 10 followers aur 150 total views poore karo to free permanent blue tick. Ya UPI se monthly (approve hone par 30 din). Payment ke baad 12-digit UTR daalna hota hai, admin check karke approve karta hai.
- **Search:** upar search me username, #hashtag, films aur shorts. Kisi user ka naam dhoondho, profile khulegi.
- **Hashtags:** caption ya comment me #tag likho, wo clickable hoga.
- **Report / Block / Restrict:** post ke ⋮ me. Report ka review admin karta hai.
- **Help Desk:** Settings → Help Desk. Message bhejo, admin ka jawab app me aur email par aata hai.

COMMON PROBLEMS (inke solution do):
- Video nahi chal rahi: page refresh karo, browser cache clear karo (Chrome → Site settings → Clear & reset). Agar chalne ke baad bhi black ho to Help Desk par likho.
- Upload atak gaya: card par Retry / Resume dabao. Net ho to wapas aate hi resume hota hai.
- Notification nahi aa rahi: Settings → Notifications me us type ka toggle on hai ya nahi check karo.
- Page dheere khul raha hai: naya network ya thodi der wait karo, pehli baar server soya ho sakta hai.
- Blue tick nahi mil raha: criteria (10 followers, 150 views) check karo, ya UPI request bhejo.
- Login nahi ho raha: password bhool gaye to Forgot Password use karo.

Agar sawaal app se bahar ka ho (general knowledge, advice), to chhota sa best jawab do. Live news/score ke liye [Live Web Context] use karo, warna bolo ki pata nahi.`;

// Only spend a Tavily search credit when the question actually looks time-sensitive.
const REALTIME_HINT = /\b(today|now|current|latest|recent|live|score|news|price|weather|stock|update|trend|trending|viral|movie|film|release|box office|web series|webseries|ott|song|songs|hit|match|cricket|ipl|election|result|kal|aaj|abhi|mausam|taaza|khabar|samachar|naya|nayi|kitna hai|kya hai|2025|2026)\b/i;

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
    if (ids.includes('llama-3.3-70b-versatile')) {
      cachedGroqModel = { id: 'llama-3.3-70b-versatile', resolvedAt: Date.now() };
      return 'llama-3.3-70b-versatile';
    }
    const bad = /guard|whisper|tts|orpheus|prompt-guard|safeguard|embed|vision|scout|maverick/i;
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
    body: JSON.stringify({ model, messages, max_tokens: 800 })
  });
  const data = await res.json();
  return { ok: res.ok, data };
}

async function aiSiteContext(query) {
  try {
    const q = String(query || '').toLowerCase().replace(/^#/, '').trim();
    if (q.length < 3) return null;
    const words = q.split(/\s+/).filter(w => w.length >= 3 && !/^(kya|kaise|kaha|hai|hain|ka|ki|ke|video|photo|post|dikha|dikhao|batao|mein|me|ye|wo)$/.test(w));
    if (!words.length) return null;
    const films = await readFilms();
    const hits = films.filter(f => !f.pendingReview && !(f.publishAt && new Date(f.publishAt).getTime() > Date.now())).filter(f => {
      const hay = [f.title, f.description, f.ownerUsername, ...(f.hashtags || [])].join(' ').toLowerCase();
      return words.some(w => hay.includes(w));
    }).slice(0, 8);
    if (!hits.length) return null;
    return hits.map(f => `- ${f.type === 'short' ? 'Short' : f.type === 'photo' ? 'Photo' : 'Video'}: "${f.title}" | creator: @${f.ownerUsername} | ${f.uploadedAt ? new Date(f.uploadedAt).toLocaleDateString('en-IN') : ''} | views: ${f.views || 0} | likes: ${f.likes || 0}${(f.hashtags || []).length ? ' | tags: ' + f.hashtags.join(', ') : ''}`).join('\n');
  } catch (e) { return null; }
}

const GROQ_VISION_MODEL = process.env.GROQ_VISION_MODEL || 'meta-llama/llama-4-scout-17b-16e-instruct';
const GROQ_VISION_FALLBACK = 'meta-llama/llama-4-maverick-17b-128e-instruct';
function runFfmpegBin(args) {
  return new Promise((resolve, reject) => execFile(require('ffmpeg-static'), args, { timeout: 60000 }, err => err ? reject(err) : resolve()));
}

function guessImageMime(buf, key) {
  if (buf && buf.length >= 12) {
    if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) return 'image/png';
    if (buf[0] === 0xFF && buf[1] === 0xD8) return 'image/jpeg';
    if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46) return 'image/gif';
    if (buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP') return 'image/webp';
  }
  const ext = path.extname(String(key || '')).toLowerCase();
  if (ext === '.png') return 'image/png';
  if (ext === '.webp') return 'image/webp';
  if (ext === '.gif') return 'image/gif';
  return 'image/jpeg';
}

// The user sent a photo or a video in the Ask AI chat: look at it and explain it (Hindi by default)
async function answerWithMedia(msg) {
  const userText = String(msg.text || '').trim();
  const question = userText || 'Is photo/video ko dhyan se dekho aur detail me explain karo ki isme kya hai, kaun hai (agar mashhoor chehra/character/cheez hai to naam batao), aur kya ho raha hai.';
  const parts = [];
  let note = '';
  if (msg.metaInfo) note += msg.metaInfo + '\n';
  if (msg.fileName) note += `Uploaded file name: "${msg.fileName}"\n`;
  const tmp = path.join(os.tmpdir(), 'askai-' + String(msg.id || Date.now()).replace(/[^A-Za-z0-9]/g, '') + '-' + Math.random().toString(36).slice(2, 6));
  const cleanup = [];
  try {
    const buf = await gdGetByKey(msg.mediaKey);
    if (buf.length > 40 * 1024 * 1024) return 'Ye file bahut badi hai (40 MB se chhoti file bhejo).';
    if (msg.mediaType === 'photo') {
      // Groq base64 image limit is 4 MB (~3 MB raw). Resize/compress via ffmpeg if > 2.5 MB or non-standard format
      let imgBuf = buf;
      let mime = guessImageMime(buf, msg.mediaKey);
      const ext = path.extname(String(msg.mediaKey || '')).toLowerCase();
      if (buf.length > 2.5 * 1024 * 1024 || !['.jpg', '.jpeg', '.png', '.webp'].includes(ext)) {
        const pin = tmp + (ext || '.img');
        const pout = tmp + '-norm.jpg';
        cleanup.push(pin, pout);
        fs.writeFileSync(pin, buf);
        try {
          await runFfmpegBin(['-y', '-i', pin, '-vf', "scale='min(1280,iw)':-2", '-q:v', '4', '-frames:v', '1', pout]);
          if (fs.existsSync(pout)) {
            imgBuf = fs.readFileSync(pout);
            mime = 'image/jpeg';
          }
        } catch (e) { /* fallback to original buffer */ }
      }
      parts.push({ type: 'image_url', image_url: { url: `data:${mime};base64,` + imgBuf.toString('base64') } });
    } else {
      const vin = tmp + (path.extname(String(msg.mediaKey || '')) || '.mp4');
      cleanup.push(vin);
      fs.writeFileSync(vin, buf);
      // Extract up to 4 frames; fallback to single first frame for very short videos (< 4s)
      try { await runFfmpegBin(['-y', '-i', vin, '-vf', "fps=1/3,scale='min(640,iw)':-2", '-frames:v', '4', tmp + '-f%d.jpg']); } catch (e) {}
      for (let i = 1; i <= 4; i++) {
        const f = tmp + '-f' + i + '.jpg'; cleanup.push(f);
        if (fs.existsSync(f)) parts.push({ type: 'image_url', image_url: { url: 'data:image/jpeg;base64,' + fs.readFileSync(f).toString('base64') } });
      }
      if (!parts.length) {
        const f0 = tmp + '-f0.jpg'; cleanup.push(f0);
        try { await runFfmpegBin(['-y', '-i', vin, '-vf', "scale='min(640,iw)':-2", '-frames:v', '1', f0]); } catch (e) {}
        if (fs.existsSync(f0)) parts.push({ type: 'image_url', image_url: { url: 'data:image/jpeg;base64,' + fs.readFileSync(f0).toString('base64') } });
      }
      const mp3 = tmp + '.mp3'; cleanup.push(mp3);
      try {
        await runFfmpegBin(['-y', '-i', vin, '-vn', '-ac', '1', '-ar', '16000', '-t', '90', '-b:a', '32k', mp3]);
        if (fs.existsSync(mp3) && fs.statSync(mp3).size > 200) {
          const fd = new FormData();
          fd.append('file', new Blob([fs.readFileSync(mp3)], { type: 'audio/mpeg' }), 'audio.mp3');
          fd.append('model', 'whisper-large-v3');
          fd.append('response_format', 'json');
          const tr = await fetch('https://api.groq.com/openai/v1/audio/transcriptions', { method: 'POST', headers: { Authorization: 'Bearer ' + GROQ_API_KEY }, body: fd });
          const tj = await tr.json().catch(() => ({}));
          if (tj.text && String(tj.text).trim()) note += 'Video audio/speech transcript: "' + String(tj.text).trim().slice(0, 2000) + '"\n';
        }
      } catch (e) { /* no audio or transcription failed: frames are still used */ }
    }
  } catch (e) {
    cleanup.forEach(f => { try { fs.unlinkSync(f); } catch (x) {} });
    return 'Is photo/video ko open karne me dikkat aayi. Chhoti ya saaf file bhej kar dobara try karo.';
  }
  cleanup.forEach(f => { try { fs.unlinkSync(f); } catch (x) {} });
  if (!parts.length && !note) return 'Is media ko process nahi kar paaye. Kripya dobara bhejein.';
  const text = question + '\n\n' + (note ? note.trim() + '\n\n' : '') +
    'Jawab usi bhasha me do jisme user ne pucha hai (default Hinglish/Hindi). Simple shabdon me, chhote points me (**bold** headings ke saath) samjhao. Agar photo/video me koi mashhoor insaan (celebrity, actor, cricketer, public figure), character, brand, jagah ya cheez dikhe ya file/post ka naam ho, to uska naam zaroor batao.';
  const messages = [{ role: 'system', content: AI_SYSTEM_PROMPT }, { role: 'user', content: [{ type: 'text', text }, ...parts] }];
  let r = await callGroqChat(GROQ_VISION_MODEL, messages);
  if (!r.ok) {
    // Fallback if model rejected system message or if primary vision model is unavailable
    const userOnlyMessages = [{ role: 'user', content: [{ type: 'text', text: AI_SYSTEM_PROMPT + '\n\n' + text }, ...parts] }];
    r = await callGroqChat(GROQ_VISION_MODEL, userOnlyMessages);
    if (!r.ok) r = await callGroqChat(GROQ_VISION_FALLBACK, userOnlyMessages);
  }
  if (!r.ok) return 'Media samajhne me problem aayi: ' + ((r.data && r.data.error && r.data.error.message) || 'unknown');
  return (r.data.choices && r.data.choices[0] && r.data.choices[0].message && r.data.choices[0].message.content) || 'Samajh nahi aaya, dobara pucho.';
}

async function resolveSharedPostMedia(msg, overrideText) {
  const post = (await readFilms()).find(f => f.id === msg.shortId);
  if (!post) return null;
  const slide0 = Array.isArray(post.slides) && post.slides[0] ? post.slides[0] : null;
  const isPhoto = post.type === 'photo' ? (!slide0 || slide0.mediaType === 'photo') : false;
  const key = isPhoto
    ? (post.posterFile || (slide0 && slide0.key) || post.videoFile)
    : (post.videoFile || (slide0 && slide0.key) || post.posterFile);
  if (!key) return null;
  const metaInfo = `Shared Post Details — Title/Name: "${post.title || 'Untitled'}" | Creator: @${post.ownerUsername || 'unknown'}${post.description ? ' | Description: "' + post.description + '"' : ''}${(post.hashtags || []).length ? ' | Hashtags: #' + post.hashtags.join(' #') : ''}`;
  return {
    id: msg.id,
    text: overrideText !== undefined ? overrideText : (msg.text || ''),
    mediaKey: key,
    mediaType: isPhoto ? 'photo' : 'video',
    fileName: post.title || null,
    metaInfo
  };
}

const MEDIA_FOLLOWUP_RE = /\b(photo|image|pic|picture|video|reel|short|clip|post|media|isko|iske|isme|ispe|is\s+photo|is\s+video|ye\s+kaun|yeh\s+kaun|kaun\s+hai|kya\s+hai|naam\s+kya|naam\s+batao|explain|samjhao|describe|identify|pebchano|pehchano|bheja|bheji|upar\s+wali|upar\s+wale|pichli|last)\b/i;

async function callAiAssistant(recentMessages, currentUserId) {
  if (!GROQ_API_KEY) {
    return "Groq API key is not set. Please add GROQ_API_KEY.";
  }

  const validMsgs = recentMessages.filter(m => !m.unsent);
  const rawLast = validMsgs.slice(-1)[0];

  // 1. Direct shared post (short/film/photo)
  if (rawLast && rawLast.senderId !== AI_ASSISTANT_ID && rawLast.type === 'short' && rawLast.shortId) {
    const mediaPayload = await resolveSharedPostMedia(rawLast);
    if (mediaPayload) return await answerWithMedia(mediaPayload);
  }
  // 2. Direct uploaded photo or video
  if (rawLast && rawLast.senderId !== AI_ASSISTANT_ID && (rawLast.mediaType === 'photo' || rawLast.mediaType === 'video') && rawLast.mediaKey) {
    return await answerWithMedia(rawLast);
  }
  // 2b. Voice message sent to Ask AI: transcribe via Whisper and answer
  if (rawLast && rawLast.senderId !== AI_ASSISTANT_ID && (rawLast.type === 'voice' || rawLast.mediaType === 'voice') && rawLast.mediaKey) {
    try {
      const vbuf = await gdGetByKey(rawLast.mediaKey);
      const fd = new FormData();
      fd.append('file', new Blob([vbuf], { type: 'audio/webm' }), 'voice.webm');
      fd.append('model', 'whisper-large-v3');
      fd.append('response_format', 'json');
      const tr = await fetch('https://api.groq.com/openai/v1/audio/transcriptions', {
        method: 'POST', headers: { Authorization: 'Bearer ' + GROQ_API_KEY }, body: fd
      });
      const tj = await tr.json().catch(() => ({}));
      if (tj && tj.text && String(tj.text).trim()) {
        rawLast.text = String(tj.text).trim();
      } else {
        return 'Aapki voice message saaf sunai nahi di. Kripya dobara bolein ya text me likhein.';
      }
    } catch (e) {
      return 'Voice message samajhne me dikkat aayi. Kripya text me pucho.';
    }
  }
  // 3. Follow-up question about a recently sent photo, video, or shared post in the last few messages!
  if (rawLast && rawLast.senderId !== AI_ASSISTANT_ID && rawLast.type === 'text' && (rawLast.text || '').trim()) {
    const recentWindow = validMsgs.slice(-8, -1).reverse();
    const prevMediaMsg = recentWindow.find(m =>
      m.senderId !== AI_ASSISTANT_ID &&
      (((m.mediaType === 'photo' || m.mediaType === 'video') && m.mediaKey) || (m.type === 'short' && m.shortId))
    );
    // If the user just sent media right before this text, or if their text references the media/asks "naam batao / ye kaun hai / explain karo"
    const prevUserMsg = validMsgs.filter(m => m.senderId !== AI_ASSISTANT_ID).slice(-2, -1)[0];
    const justSentMedia = prevUserMsg && prevMediaMsg && prevUserMsg.id === prevMediaMsg.id;
    if (prevMediaMsg && (justSentMedia || MEDIA_FOLLOWUP_RE.test(rawLast.text))) {
      if (prevMediaMsg.type === 'short' && prevMediaMsg.shortId) {
        const mediaPayload = await resolveSharedPostMedia(prevMediaMsg, rawLast.text);
        if (mediaPayload) return await answerWithMedia(mediaPayload);
      } else {
        return await answerWithMedia({ ...prevMediaMsg, text: rawLast.text });
      }
    }
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
  if (!history.length) return "Hi! I’m Ask AI. You can ask me anything.";

  const latestUserText = history[history.length - 1].content;
  const webData = await getLiveWebContext(latestUserText);
  const siteData = await aiSiteContext(latestUserText);

  const messages = [{ role: 'system', content: AI_SYSTEM_PROMPT }];
  if (siteData) {
    messages.push({ role: 'system', content: `[Site Context] (app ke public posts ki details, media ki andar ki cheez nahi):\n${siteData}` });
  }
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
      return "Could not reply right now (error: " + (data.error && data.error.message || 'unknown') + ")";
    }
    return (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || "I didn’t understand, please ask again.";
  } catch (err) {
    console.error('Ask AI error:', err.message);
    return "Error: please try again later.";
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
    type: 'text', text: "Hi! I’m Ask AI 🤖 — if you have any problem using TAMASHA (account, upload, follow, anything), ask me here.",
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
  return gdWithLock('ai:' + conversationId, async () => {
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
  });
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

app.post('/api/ai/clear', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convo = await ensureAiConversation(currentUser.id);
    const oldMsgs = await readChatMessages(convo.id);
    for (const m of oldMsgs) {
      if (m.mediaKey) await storeDelete(m.mediaKey).catch(() => {});
    }
    const welcomeMsg = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
      conversationId: convo.id, senderId: AI_ASSISTANT_ID,
      type: 'text', text: "Hi! I’m Ask AI 🤖 — chat clear ho gayi hai. Koi bhi photo, video ya sawaal bhejo!",
      mediaKey: null, mediaType: null, storageProvider: null, duration: null,
      shortId: null, shortTitle: null, shortOwnerUsername: null,
      createdAt: new Date().toISOString(), editedAt: null,
      deletedFor: [], unsent: false, readBy: [AI_ASSISTANT_ID, currentUser.id]
    };
    await writeChatMessages(convo.id, [welcomeMsg]);
    const convos = await readConversations();
    const c = convos.find(x => x.id === convo.id);
    if (c) {
      c.updatedAt = welcomeMsg.createdAt;
      c.lastMessage = { senderId: AI_ASSISTANT_ID, preview: previewForMessage(welcomeMsg), createdAt: welcomeMsg.createdAt };
      await writeConversations(convos);
    }
    res.json({ ok: true, messages: [welcomeMsg] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/ai/caption', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    if (!GROQ_API_KEY) return res.status(400).json({ error: 'GROQ_API_KEY is not set' });
    const title = String((req.body && req.body.title) || '').trim().slice(0, 120);
    const type = String((req.body && req.body.type) || 'video').trim();
    const genre = String((req.body && req.body.genre) || '').trim();
    if (!title) return res.status(400).json({ error: 'Pehle Title likho taaki AI caption bana sake' });
    const prompt = `Post Title: "${title}"
Content Type: ${type}${genre ? "\\nGenre/Topic: " + genre : ''}

Is post ke liye ek catchy, engaging Hinglish caption (1-2 lines) aur uske neeche 6-8 trending relevant #hashtags likho. Sirf caption aur hashtags output karo, koi extra intro ya quotes mat likho.`;
    const model = await resolveGroqModel();
    const { ok, data } = await callGroqChat(model, [
      { role: 'system', content: 'Tum social media content expert ho jo Hinglish me viral captions aur #hashtags likhta hai.' },
      { role: 'user', content: prompt }
    ]);
    if (!ok) return res.status(500).json({ error: (data && data.error && data.error.message) || 'AI error' });
    const caption = ((data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '').trim().replace(/^["']|["']$/g, '');
    res.json({ caption });
  } catch (err) { res.status(500).json({ error: err.message }); }
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

    const outRaw = await Promise.all(list
      .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
      .map(async c => {
        const allMessages = await readChatMessages(c.id);
        const visibleMessages = allMessages.filter(m => !(m.deletedFor || []).includes(currentUser.id));
        const lastVisible = visibleMessages.length ? visibleMessages[visibleMessages.length - 1] : null;
        const dynamicLastMessage = lastVisible
          ? { senderId: lastVisible.senderId, preview: previewForMessage(lastVisible), createdAt: lastVisible.createdAt }
          : null;
        const unreadCount = visibleMessages.filter(m => m.senderId !== currentUser.id && !m.unsent &&
          !(m.readBy || []).includes(currentUser.id)).length;

        // Group Chat
        if (c.type === 'group') {
          return {
            id: c.id,
            type: 'group',
            title: c.title || 'Group Chat',
            description: c.description || '',
            avatarUrl: c.avatarKey ? await directUrl(c.avatarKey, c.storageProvider || 'gdrive') : null,
            ownerId: c.ownerId,
            admins: c.admins || [c.ownerId],
            memberCount: (c.participants || []).length,
            onlyAdminsCanPost: !!c.onlyAdminsCanPost,
            isMuted: !!(c.mutedFor && c.mutedFor.includes(currentUser.id)),
            lastMessage: dynamicLastMessage || c.lastMessage,
            updatedAt: (lastVisible && lastVisible.createdAt) || c.updatedAt,
            unreadCount
          };
        }

        // Broadcast Channel
        if (c.type === 'channel') {
          const owner = users.find(u => u.id === c.ownerId);
          return {
            id: c.id,
            type: 'channel',
            title: c.title || 'Broadcast Channel',
            description: c.description || '',
            avatarUrl: c.avatarKey ? await directUrl(c.avatarKey, c.storageProvider || 'gdrive') : (owner && owner.profileImage ? await directUrl(owner.profileImage, owner.avatarStorageProvider) : null),
            ownerId: c.ownerId,
            ownerUsername: owner ? owner.username : 'Creator',
            ownerVerified: !!(owner && owner.verified),
            admins: c.admins || [c.ownerId],
            memberCount: (c.participants || []).length,
            pinnedMessage: c.pinnedMessage || null,
            isMuted: !!(c.mutedFor && c.mutedFor.includes(currentUser.id)),
            lastMessage: dynamicLastMessage || c.lastMessage,
            updatedAt: (lastVisible && lastVisible.createdAt) || c.updatedAt,
            unreadCount
          };
        }

        // Direct Message (1-on-1)
        const otherId = c.participants.find(p => p !== currentUser.id);
        if (otherId === AI_ASSISTANT_ID) {
          return { id: c.id, type: 'dm', otherUser: AI_ASSISTANT_USER, lastMessage: dynamicLastMessage || c.lastMessage, updatedAt: (lastVisible && lastVisible.createdAt) || c.updatedAt, unreadCount };
        }
        if (c.hiddenFor && c.hiddenFor[currentUser.id] && !visibleMessages.length) {
          return null;
        }
        const other = users.find(u => u.id === otherId);
        return {
          id: c.id,
          type: 'dm',
          otherUser: other ? {
            id: other.id, username: other.username,
            verified: !!other.verified,
            profileImage: other.profileImage ? await directUrl(other.profileImage, other.avatarStorageProvider) : null,
            online: isUserOnline(other)
          } : { id: otherId, username: 'Unknown user', verified: false, profileImage: null, online: false },
          lastMessage: dynamicLastMessage,
          updatedAt: (lastVisible && lastVisible.createdAt) || c.updatedAt,
          unreadCount
        };
      }));
    const out = outRaw.filter(Boolean).sort((a, b) => new Date(b.updatedAt || 0) - new Date(a.updatedAt || 0));
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
    const users = await readUsers();

    if (req.params.userId === AI_ASSISTANT_ID) {
      const convo = await ensureAiConversation(currentUser.id);
      const rawMessages = (await readChatMessages(convo.id)).filter(m => !(m.deletedFor || []).includes(currentUser.id));
      const messages = await Promise.all(rawMessages.slice(-100).map(m => enrichMessage(m, directUrl, users)));
      return res.json({ id: convo.id, otherUser: AI_ASSISTANT_USER, messages });
    }
    const me = users.find(u => u.id === currentUser.id);
    const target = users.find(u => u.id === req.params.userId);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if ((me.blockedUsers || []).includes(target.id) || (target.blockedUsers || []).includes(me.id)) {
      return res.status(403).json({ error: 'You can\'t message this user' });
    }

    let convo = await getConversationForUsers(currentUser.id, target.id, false);
    if (!convo) {
      const iFollowThem = me && me.following && me.following.includes(target.id);
      if (!iFollowThem) return res.status(403).json({ error: 'Follow this user first to message them' });
      convo = await getConversationForUsers(currentUser.id, target.id, true);
    }

    const rawMessages = (await readChatMessages(convo.id)).filter(m => !(m.deletedFor || []).includes(currentUser.id));
    const messages = await Promise.all(rawMessages.slice(-100).map(m => enrichMessage(m, directUrl, users)));

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


app.get('/api/conversations/:id/details', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const c = convos.find(x => x.id === req.params.id);
    if (!c) return res.status(404).json({ error: 'Conversation not found' });
    if (!c.participants.includes(currentUser.id) && c.type !== 'channel') {
      return res.status(403).json({ error: 'Not a member of this chat' });
    }
    const users = await readUsers();
    const directUrl = makeDirectUrlCache();

    const members = await Promise.all((c.participants || []).map(async uid => {
      const u = users.find(x => x.id === uid);
      return {
        id: uid,
        username: u ? u.username : 'User',
        verified: !!(u && u.verified),
        isAdmin: (c.admins || []).includes(uid),
        isOwner: c.ownerId === uid,
        profileImage: (u && u.profileImage) ? await directUrl(u.profileImage, u.avatarStorageProvider) : null
      };
    }));

    let avatarUrl = null;
    if (c.avatarKey) avatarUrl = await directUrl(c.avatarKey, c.storageProvider || 'gdrive');
    else if (c.type === 'channel') {
      const owner = users.find(u => u.id === c.ownerId);
      if (owner && owner.profileImage) avatarUrl = await directUrl(owner.profileImage, owner.avatarStorageProvider);
    }

    res.json({
      id: c.id,
      type: c.type || 'dm',
      title: c.title || (c.type === 'channel' ? 'Broadcast Channel' : 'Group Chat'),
      description: c.description || '',
      avatarUrl,
      ownerId: c.ownerId,
      admins: c.admins || [c.ownerId],
      participants: c.participants || [],
      members,
      onlyAdminsCanPost: !!c.onlyAdminsCanPost,
      pinnedMessage: c.pinnedMessage || null,
      isMuted: !!(c.mutedFor && c.mutedFor.includes(currentUser.id)),
      isMember: c.participants.includes(currentUser.id)
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Discover Public Channels
app.get('/api/channels/discover', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    const convos = await readConversations();
    const channels = convos.filter(c => c.type === 'channel');
    const users = await readUsers();
    const directUrl = makeDirectUrlCache();

    const out = await Promise.all(channels.map(async c => {
      const owner = users.find(u => u.id === c.ownerId);
      return {
        id: c.id,
        title: c.title || 'Channel',
        description: c.description || '',
        avatarUrl: c.avatarKey ? await directUrl(c.avatarKey, c.storageProvider || 'gdrive') : (owner && owner.profileImage ? await directUrl(owner.profileImage, owner.avatarStorageProvider) : null),
        ownerId: c.ownerId,
        ownerUsername: owner ? owner.username : 'Creator',
        ownerVerified: !!(owner && owner.verified),
        memberCount: (c.participants || []).length,
        isMember: currentUser ? (c.participants || []).includes(currentUser.id) : false,
        updatedAt: c.updatedAt
      };
    }));
    out.sort((a, b) => b.memberCount - a.memberCount);
    res.json({ channels: out });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Create Broadcast Channel (Verified / Admin Only)
app.post('/api/channels', upload.single('avatar'), async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    if (!me) return res.status(404).json({ error: 'User not found' });
    if (!me.verified && !me.isAdmin) {
      return res.status(403).json({ error: 'Broadcast Channels are exclusive to Verified creators. Get a Blue Tick to unlock!' });
    }

    const { title, description } = req.body;
    if (!title || !title.trim()) return res.status(400).json({ error: 'Channel name is required' });

    const convos = await readConversations();
    const existing = convos.find(c => c.type === 'channel' && c.ownerId === currentUser.id);
    if (existing) {
      return res.status(400).json({ error: 'You already have an active Broadcast Channel' });
    }

    const id = 'ch_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    let avatarKey = null;
    if (req.file) {
      avatarKey = `channels/${id}${path.extname(req.file.originalname) || '.jpg'}`;
      await storePutBuffer(readFileAsBuffer(req.file.path), avatarKey, req.file.mimetype);
    }

    const newChannel = {
      id,
      type: 'channel',
      title: title.trim().slice(0, 50),
      description: (description || '').trim().slice(0, 200),
      avatarKey,
      storageProvider: r2On() ? 'r2' : 'gdrive',
      ownerId: currentUser.id,
      admins: [currentUser.id],
      participants: [currentUser.id],
      pinnedMessage: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastMessage: { senderId: currentUser.id, preview: 'Welcome to the channel! 📢', createdAt: new Date().toISOString() }
    };

    convos.push(newChannel);
    await writeConversations(convos);

    // Initial welcome message in channel
    const welcomeMsg = {
      id: Date.now().toString(36) + 'init',
      conversationId: id,
      senderId: currentUser.id,
      type: 'text',
      text: `Welcome to ${newChannel.title}! 📢 Updates, announcements and polls will be posted here.`,
      createdAt: newChannel.createdAt,
      readBy: [currentUser.id],
      deletedFor: []
    };
    await writeChatMessages(id, [welcomeMsg]);

    res.status(201).json({ ok: true, channel: newChannel });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Join / Leave Channel
app.post('/api/channels/:id/join', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const c = convos.find(x => x.id === req.params.id && x.type === 'channel');
    if (!c) return res.status(404).json({ error: 'Channel not found' });
    if (!c.participants.includes(currentUser.id)) {
      c.participants.push(currentUser.id);
      c.updatedAt = new Date().toISOString();
      await writeConversations(convos);
    }
    res.json({ ok: true, joined: true, memberCount: c.participants.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/channels/:id/leave', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const c = convos.find(x => x.id === req.params.id && x.type === 'channel');
    if (!c) return res.status(404).json({ error: 'Channel not found' });
    if (c.ownerId === currentUser.id) return res.status(400).json({ error: 'Channel owner cannot leave. Delete the channel instead.' });
    c.participants = (c.participants || []).filter(p => p !== currentUser.id);
    c.admins = (c.admins || []).filter(a => a !== currentUser.id);
    await writeConversations(convos);
    res.json({ ok: true, joined: false, memberCount: c.participants.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Create Group Chat
app.post('/api/groups', upload.single('avatar'), async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });

    const { title, description } = req.body;
    if (!title || !title.trim()) return res.status(400).json({ error: 'Group name is required' });

    let memberIds = [];
    try {
      memberIds = JSON.parse(req.body.memberIds || '[]');
    } catch (e) { memberIds = []; }

    const participants = [...new Set([currentUser.id, ...memberIds.filter(Boolean)])];
    if (participants.length < 2) return res.status(400).json({ error: 'Select at least 1 other user to create a group' });

    const id = 'grp_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    let avatarKey = null;
    if (req.file) {
      avatarKey = `groups/${id}${path.extname(req.file.originalname) || '.jpg'}`;
      await storePutBuffer(readFileAsBuffer(req.file.path), avatarKey, req.file.mimetype);
    }

    const convos = await readConversations();
    const newGroup = {
      id,
      type: 'group',
      title: title.trim().slice(0, 50),
      description: (description || '').trim().slice(0, 200),
      avatarKey,
      storageProvider: r2On() ? 'r2' : 'gdrive',
      ownerId: currentUser.id,
      admins: [currentUser.id],
      participants,
      onlyAdminsCanPost: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastMessage: { senderId: currentUser.id, preview: `@${currentUser.username} created group "${title.trim()}"`, createdAt: new Date().toISOString() }
    };

    convos.push(newGroup);
    await writeConversations(convos);

    const initMsg = {
      id: Date.now().toString(36) + 'init',
      conversationId: id,
      senderId: currentUser.id,
      type: 'text',
      text: `@${currentUser.username} created group "${newGroup.title}" 👥`,
      createdAt: newGroup.createdAt,
      readBy: [currentUser.id],
      deletedFor: []
    };
    await writeChatMessages(id, [initMsg]);

    res.status(201).json({ ok: true, group: newGroup });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Group Admin Actions: Add / Remove Member, Make Admin, Toggle Admin-Only Posting, Leave
app.post('/api/groups/:id/members', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const c = convos.find(x => x.id === req.params.id && (x.type === 'group' || x.type === 'channel'));
    if (!c) return res.status(404).json({ error: 'Chat not found' });
    if (!(c.admins || []).includes(currentUser.id) && c.ownerId !== currentUser.id) {
      return res.status(403).json({ error: 'Only admins can add members' });
    }
    const rawIds = Array.isArray(req.body.userIds) ? req.body.userIds : (req.body.userId ? [req.body.userId] : []);
    const idsToAdd = [...new Set(rawIds.map(x => String(x || '').trim()).filter(Boolean))];
    if (!idsToAdd.length) return res.status(400).json({ error: 'Select at least one follower to add' });

    let added = 0;
    idsToAdd.forEach(uid => {
      if (!c.participants.includes(uid)) {
        c.participants.push(uid);
        added++;
      }
    });
    if (added > 0) {
      c.updatedAt = new Date().toISOString();
      await writeConversations(convos);
    }
    res.json({ ok: true, added, memberCount: c.participants.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/conversations/:id/delete-chat', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const idx = convos.findIndex(x => x.id === req.params.id && (x.type === 'group' || x.type === 'channel'));
    if (idx === -1) return res.status(404).json({ error: 'Chat not found' });
    const c = convos[idx];
    if (c.ownerId !== currentUser.id && !currentUser.isAdmin) {
      return res.status(403).json({ error: 'Only the owner can delete this ' + c.type });
    }
    convos.splice(idx, 1);
    await writeConversations(convos);
    await storeDelete(`chats/${c.id}.json`).catch(() => {});
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/groups/:id/remove-member', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const c = convos.find(x => x.id === req.params.id && (x.type === 'group' || x.type === 'channel'));
    if (!c) return res.status(404).json({ error: 'Chat not found' });
    if (!c.admins.includes(currentUser.id) && c.ownerId !== currentUser.id) {
      return res.status(403).json({ error: 'Only admins can remove members' });
    }
    const { userId } = req.body;
    if (userId === c.ownerId) return res.status(400).json({ error: 'Cannot remove chat owner' });
    c.participants = (c.participants || []).filter(p => p !== userId);
    c.admins = (c.admins || []).filter(a => a !== userId);
    await writeConversations(convos);
    res.json({ ok: true, memberCount: c.participants.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/groups/:id/toggle-admin', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const c = convos.find(x => x.id === req.params.id && (x.type === 'group' || x.type === 'channel'));
    if (!c) return res.status(404).json({ error: 'Chat not found' });
    if (c.ownerId !== currentUser.id) return res.status(403).json({ error: 'Only owner can assign admins' });
    const { userId } = req.body;
    if (userId === c.ownerId) return res.json({ ok: true });
    if ((c.admins || []).includes(userId)) {
      c.admins = c.admins.filter(a => a !== userId);
    } else {
      if (!c.admins) c.admins = [c.ownerId];
      c.admins.push(userId);
    }
    await writeConversations(convos);
    res.json({ ok: true, admins: c.admins });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/groups/:id/toggle-admin-only', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const c = convos.find(x => x.id === req.params.id && x.type === 'group');
    if (!c) return res.status(404).json({ error: 'Group not found' });
    if (!c.admins.includes(currentUser.id) && c.ownerId !== currentUser.id) {
      return res.status(403).json({ error: 'Only admins can change settings' });
    }
    c.onlyAdminsCanPost = !c.onlyAdminsCanPost;
    await writeConversations(convos);
    res.json({ ok: true, onlyAdminsCanPost: c.onlyAdminsCanPost });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/conversations/:id/mute', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const c = convos.find(x => x.id === req.params.id);
    if (!c) return res.status(404).json({ error: 'Conversation not found' });
    if (!c.mutedFor) c.mutedFor = [];
    const isMuted = c.mutedFor.includes(currentUser.id);
    if (isMuted) c.mutedFor = c.mutedFor.filter(u => u !== currentUser.id);
    else c.mutedFor.push(currentUser.id);
    await writeConversations(convos);
    res.json({ ok: true, muted: !isMuted });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/conversations/:id/pin-message', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const c = convos.find(x => x.id === req.params.id);
    if (!c) return res.status(404).json({ error: 'Conversation not found' });
    if (c.type === 'channel' && c.ownerId !== currentUser.id && !(c.admins || []).includes(currentUser.id)) {
      return res.status(403).json({ error: 'Only admins can pin messages' });
    }
    const { messageId, text } = req.body;
    c.pinnedMessage = messageId ? { messageId, text: String(text || '').slice(0, 100) } : null;
    await writeConversations(convos);
    res.json({ ok: true, pinnedMessage: c.pinnedMessage });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Poll Vote inside Group / Channel
app.post('/api/conversations/:id/messages/:messageId/poll-vote', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const { optionIndex } = req.body;
    const messages = await readChatMessages(req.params.id);
    const msg = messages.find(m => m.id === req.params.messageId && m.type === 'poll');
    if (!msg || !msg.poll || !msg.poll.options) return res.status(404).json({ error: 'Poll not found' });

    const idx = parseInt(optionIndex, 10);
    if (isNaN(idx) || idx < 0 || idx >= msg.poll.options.length) {
      return res.status(400).json({ error: 'Invalid option' });
    }

    // Toggle or cast vote
    msg.poll.options.forEach((opt, i) => {
      if (!Array.isArray(opt.votes)) opt.votes = [];
      opt.votes = opt.votes.filter(uid => uid !== currentUser.id);
      if (i === idx) opt.votes.push(currentUser.id);
    });

    await writeChatMessages(req.params.id, messages);
    res.json({ ok: true, poll: msg.poll });
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
    const users = await readUsers();
    let raw = (await readChatMessages(convo.id)).filter(m => !(m.deletedFor || []).includes(currentUser.id));
    if (since) raw = raw.filter(m => new Date(m.createdAt).getTime() > since || (m.editedAt && new Date(m.editedAt).getTime() > since) || (m.reactedAt && new Date(m.reactedAt).getTime() > since) || (m.readAt && new Date(m.readAt).getTime() > since));
    const messages = await Promise.all(raw.map(m => enrichMessage(m, directUrl, users)));

    const otherId = convo.participants.find(p => p !== currentUser.id);
    let otherOnline = false;
    if (otherId && otherId !== AI_ASSISTANT_ID) {
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

    // Channel Posting Permission: Only Admins can post in broadcast channel
    if (convo.type === 'channel') {
      const isAdminOrOwner = convo.ownerId === req.currentUser.id || (convo.admins && convo.admins.includes(req.currentUser.id));
      if (!isAdminOrOwner) {
        return res.status(403).json({ error: 'Only channel admins can post updates. You can react to messages.' });
      }
    }

    // Group Posting Permission: If onlyAdminsCanPost is enabled
    if (convo.type === 'group' && convo.onlyAdminsCanPost) {
      const isAdminOrOwner = convo.ownerId === req.currentUser.id || (convo.admins && convo.admins.includes(req.currentUser.id));
      if (!isAdminOrOwner) {
        return res.status(403).json({ error: 'Only group admins can send messages right now.' });
      }
    }

    const otherParticipantId = (convo.type === 'dm' || !convo.type) ? convo.participants.find(p => p !== req.currentUser.id) : null;
    if (convo.type === 'dm' || !convo.type) {
      if (otherParticipantId && otherParticipantId !== AI_ASSISTANT_ID) {
        const users = await readUsers();
        const me = users.find(u => u.id === req.currentUser.id);
        const other = users.find(u => u.id === otherParticipantId);
        if ((me && me.blockedUsers && me.blockedUsers.includes(otherParticipantId)) || (other && other.blockedUsers && other.blockedUsers.includes(req.currentUser.id))) {
          return res.status(403).json({ error: 'You can\'t message this user' });
        }
      }
    }

    const text = (req.body.text || '').trim().slice(0, 2000);
    const shortId = req.body.shortId || null;
    const isVoice = toBool(req.body.isVoice);
    const isPollReq = !!(req.body.isPoll && req.body.pollQuestion);
    const mediaFile = req.files && req.files.media && req.files.media[0];

    if (!text && !mediaFile && !shortId && !isPollReq) return res.status(400).json({ error: 'Send something — a message, photo, video, poll or short' });

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    let type = 'text', mediaKey = null, mediaType = null, duration = null, fileName = null;
    let shortTitle = null, shortOwnerUsername = null;
    let pollData = null;

    if (req.body.isPoll && req.body.pollQuestion) {
      type = 'poll';
      let opts = [];
      try {
        opts = JSON.parse(req.body.pollOptions || '[]');
      } catch (e) { opts = []; }
      pollData = {
        question: String(req.body.pollQuestion).trim().slice(0, 150),
        options: opts.slice(0, 6).map(o => ({ text: String(o).trim().slice(0, 80), votes: [] }))
      };
    }

    if (mediaFile) {
      const isVideo = mediaFile.mimetype.startsWith('video') && !isVoice;
      const isAudio = mediaFile.mimetype.startsWith('audio') || isVoice;
      type = isAudio ? 'voice' : (isVideo ? 'video' : 'photo');
      fileName = path.basename(String(mediaFile.originalname || '')).slice(0, 120) || null;
      const defaultAudioExt = (mediaFile.mimetype && mediaFile.mimetype.includes('mp4')) ? '.m4a' : '.webm';
      mediaKey = `chats/${convo.id}/${id}${path.extname(mediaFile.originalname) || (isAudio ? defaultAudioExt : '')}`;
      await storePutBuffer(readFileAsBuffer(mediaFile.path), mediaKey, mediaFile.mimetype);
      mediaType = type;
      if (isAudio && req.body.duration) duration = parseFloat(req.body.duration) || null;
    } else if (shortId) {
      const films = await readFilms();
      const film = films.find(f => f.id === shortId);
      if (!film) return res.status(404).json({ error: 'This short is no longer available' });
      type = 'short';
      shortTitle = film.title;
      shortOwnerUsername = film.ownerUsername;
    }

    const messages = await readChatMessages(convo.id);
    let replyTo = null;
    if (req.body.replyToId) {
      const targetMsg = messages.find(x => x.id === req.body.replyToId);
      if (targetMsg && !targetMsg.unsent) {
        replyTo = {
          id: targetMsg.id,
          senderId: targetMsg.senderId,
          senderName: req.body.replyToSender || (targetMsg.senderId === req.currentUser.id ? req.currentUser.username : 'User'),
          text: previewForMessage(targetMsg).slice(0, 120),
          type: targetMsg.type || 'text'
        };
      }
    }

    const newMessage = {
      id, conversationId: convo.id, senderId: req.currentUser.id,
      type, text: text || null,
      mediaKey, mediaType, fileName, storageProvider: r2On() ? 'r2' : 'gdrive', duration,
      shortId: type === 'short' ? shortId : null, shortTitle, shortOwnerUsername,
      poll: pollData,
      replyTo,
      createdAt: new Date().toISOString(), editedAt: null,
      deletedFor: [], unsent: false, readBy: [req.currentUser.id]
    };

    if (convo.hiddenFor) {
      delete convo.hiddenFor[req.currentUser.id];
      if (otherParticipantId) delete convo.hiddenFor[otherParticipantId];
    }
    messages.push(newMessage);
    await writeChatMessages(convo.id, messages);

    convo.updatedAt = newMessage.createdAt;
    convo.lastMessage = { senderId: req.currentUser.id, preview: previewForMessage(newMessage), createdAt: newMessage.createdAt };
    await writeConversations(convos);

    if (convo.type === 'group' || convo.type === 'channel') {
      const mutedSet = new Set(convo.mutedFor || []);
      const targets = (convo.participants || []).filter(pid => pid !== req.currentUser.id && !mutedSet.has(pid));
      const notifMsg = convo.type === 'channel'
        ? `📢 @${req.currentUser.username} posted in "${convo.title || 'Channel'}": ${previewForMessage(newMessage).slice(0, 60)}`
        : `👥 @${req.currentUser.username} in "${convo.title || 'Group'}": ${previewForMessage(newMessage).slice(0, 60)}`;
      await Promise.allSettled(targets.slice(0, 80).map(pid => notify(pid, {
        type: 'message', fromUserId: req.currentUser.id, fromUsername: req.currentUser.username,
        conversationId: convo.id, filmId: type === 'short' ? shortId : null, message: notifMsg
      })));
    } else {
      const otherId = convo.participants.find(p => p !== req.currentUser.id);
      if (otherId === AI_ASSISTANT_ID) {
        triggerAiReply(convo.id, req.currentUser.id).catch(() => {});
      } else if (otherId) {
        await notify(otherId, {
          type: 'message', fromUserId: req.currentUser.id, fromUsername: req.currentUser.username,
          conversationId: convo.id, message: `@${req.currentUser.username} sent you a message`
        });
      }
    }

    const directUrl = makeDirectUrlCache();
    const allUsersForEnrich = await readUsers();
    res.status(201).json(await enrichMessage(newMessage, directUrl, allUsersForEnrich));
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
    if (!text || !text.trim()) return res.status(400).json({ error: 'Message cannot be empty' });
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
    const nowIso = new Date().toISOString();
    messages.forEach(m => {
      if (m.senderId !== currentUser.id) {
        if (!m.readBy) m.readBy = [];
        if (!m.readBy.includes(currentUser.id)) {
          m.readBy.push(currentUser.id);
          m.readAt = nowIso;
          changed = true;
        }
      }
    });
    if (changed) await writeChatMessages(convo.id, messages);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/conversations/:id/clear', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const convos = await readConversations();
    const convo = convos.find(c => c.id === req.params.id);
    if (!convo || !convo.participants.includes(currentUser.id)) return res.status(403).json({ error: 'Not allowed' });

    const messages = await readChatMessages(convo.id);
    messages.forEach(m => {
      if (!m.deletedFor) m.deletedFor = [];
      if (!m.deletedFor.includes(currentUser.id)) m.deletedFor.push(currentUser.id);
    });
    await writeChatMessages(convo.id, messages);

    if (!convo.hiddenFor) convo.hiddenFor = {};
    convo.hiddenFor[currentUser.id] = new Date().toISOString();
    await writeConversations(convos);
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
    const out = await Promise.all(mine.map(async f => {
      const slide0 = Array.isArray(f.slides) && f.slides[0] ? f.slides[0] : null;
      const posterKey = f.posterFile || (slide0 && slide0.mediaType === 'photo' ? slide0.key : null);
      const videoKey = f.videoFile || (slide0 && slide0.mediaType === 'video' ? slide0.key : null);
      return {
        id: f.id, filmId: f.id, ownerId: f.ownerId, title: f.title, type: f.type,
        views: Math.max(f.views || 0, (f.viewedBy || []).length, f.likes || 0),
        slidesCount: Array.isArray(f.slides) ? f.slides.length : 0,
        posterUrl: posterKey ? await directUrl(posterKey, f.storageProvider) : null,
        videoUrl: videoKey ? await directUrl(videoKey, f.storageProvider) : null
      };
    }));
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
    if (typeof req.body.showSensitiveContent === 'boolean') {
      user.showSensitiveContent = req.body.showSensitiveContent;
      user.hideSensitiveContent = !req.body.showSensitiveContent;
    } else if (typeof req.body.hideSensitiveContent === 'boolean') {
      user.hideSensitiveContent = req.body.hideSensitiveContent;
      user.showSensitiveContent = !req.body.hideSensitiveContent;
    }
    await writeUsers(users);
    res.json({
      showSensitiveContent: (user.showSensitiveContent !== false && !user.hideSensitiveContent),
      hideSensitiveContent: !(user.showSensitiveContent !== false && !user.hideSensitiveContent)
    });
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
      for (const sl of (f.slides || [])) await storeDelete(sl.key);
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
  return {
    id: t.id,
    category: t.category || 'General',
    problem: t.problem,
    screenshotUrl: t.screenshotKey ? r2PublicUrl(t.screenshotKey) : null,
    status: t.status,
    rating: t.rating || null,
    createdAt: t.createdAt,
    replies: t.replies || [],
    hasNewReply: !!t.hasNewReply
  };
}

app.post('/api/help-desk', upload.single('screenshot'), async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    const { name, problem, email, category } = req.body || {};
    const text = String(problem || '').trim().slice(0, 2000);
    if (!text) return res.status(400).json({ error: 'Please describe your problem' });
    const contact = String(email || (currentUser && currentUser.email) || '').trim();
    if (contact && !looksLikeEmail(contact)) return res.status(400).json({ error: 'Email does not look valid' });
    if (!helpRateOk(currentUser ? 'u:' + currentUser.id : 'ip:' + req.ip)) return res.status(429).json({ error: 'Bahut zyada messages — thodi der baad try karo' });

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    let screenshotKey = null;
    if (req.file) {
      const ext = (path.extname(req.file.originalname) || '.jpg').replace(/[^A-Za-z0-9.]/g, '').slice(0, 6);
      screenshotKey = `helpdesk/${id}${ext}`;
      await storePutBuffer(readFileAsBuffer(req.file.path), screenshotKey, req.file.mimetype || 'image/jpeg');
    }

    const list = await readHelpdesk();
    const ticket = {
      id,
      userId: currentUser ? currentUser.id : null,
      username: currentUser ? currentUser.username : null,
      name: String(name || (currentUser && currentUser.username) || 'User').slice(0, 60),
      email: contact || null,
      category: String(category || 'General').trim().slice(0, 40),
      problem: text,
      screenshotKey,
      status: 'open',
      createdAt: new Date().toISOString(),
      replies: []
    };
    list.push(ticket);
    await writeHelpdesk(list.slice(-1000));
    alertAdminText(`📩 New Help Desk [${ticket.category}]: ${ticket.name}${ticket.email ? ' (' + ticket.email + ')' : ''} — "${text.slice(0, 80)}"`).catch(() => {});
    sendResendMail('sohailp541@gmail.com', `YouSeries Help Desk [${ticket.category}] - ` + ticket.name,
      `Name: ${ticket.name}
Category: ${ticket.category}
Email: ${ticket.email || '-'}
User ID: ${ticket.userId || '-'}

Problem:
${text}

You can reply from Dashboard → Help Desk.`).catch(() => {});
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
    if (!t) return res.status(404).json({ error: 'Ticket not found' });
    if (!helpRateOk('u:' + currentUser.id)) return res.status(429).json({ error: 'Bahut zyada messages — thodi der baad try karo' });
    t.replies = t.replies || [];
    t.replies.push({ from: 'user', text, at: new Date().toISOString() });
    t.status = 'open'; t.adminSeen = false;
    await writeHelpdesk(list);
    alertAdminText(`💬 Help Desk follow-up: ${t.name} — "${text.slice(0, 80)}"`).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/help-desk/:id/resolve', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const list = await readHelpdesk();
    const t = list.find(x => x.id === req.params.id && x.userId === currentUser.id);
    if (!t) return res.status(404).json({ error: 'Ticket not found' });
    t.status = 'closed';
    t.rating = req.body && req.body.rating === 'helpful' ? 'helpful' : 'resolved';
    await writeHelpdesk(list);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/helpdesk', requireAdmin, async (req, res) => {
  try {
    const list = await readHelpdesk();
    // Compute Help Desk analytics for the admin dashboard
    let openCount = 0, answeredCount = 0, closedCount = 0, helpfulCount = 0;
    let respMinutesTotal = 0, respSamples = 0;
    const byCategory = {};
    list.forEach(t => {
      if (t.status === 'open') openCount++;
      else if (t.status === 'answered') answeredCount++;
      else closedCount++;
      if (t.rating === 'helpful') helpfulCount++;
      const cat = t.category || 'General';
      byCategory[cat] = (byCategory[cat] || 0) + 1;
      const firstAdmin = (t.replies || []).find(r => r.from === 'admin');
      if (firstAdmin && t.createdAt && firstAdmin.at) {
        const diffMin = Math.max(1, Math.round((new Date(firstAdmin.at) - new Date(t.createdAt)) / 60000));
        if (diffMin < 60 * 24 * 30) { respMinutesTotal += diffMin; respSamples++; }
      }
    });
    const enriched = list.slice().reverse().map(t => ({
      ...t,
      category: t.category || 'General',
      screenshotUrl: t.screenshotKey ? r2PublicUrl(t.screenshotKey) : null
    })).sort((a, b) => (a.status === 'open' ? 0 : 1) - (b.status === 'open' ? 0 : 1));
    res.json({
      tickets: enriched,
      analytics: {
        total: list.length,
        open: openCount,
        answered: answeredCount,
        closed: closedCount,
        helpful: helpfulCount,
        avgResponseMinutes: respSamples ? Math.round(respMinutesTotal / respSamples) : null,
        byCategory
      }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// AI Help Desk Analyst: generates a smart Hinglish support reply & diagnosis for any ticket
app.post('/api/admin/helpdesk/:id/ai-suggest', requireAdmin, async (req, res) => {
  try {
    if (!GROQ_API_KEY) return res.status(400).json({ error: 'GROQ_API_KEY is not set' });
    const list = await readHelpdesk();
    const t = list.find(x => x.id === req.params.id);
    if (!t) return res.status(404).json({ error: 'Ticket not found' });
    const thread = (t.replies || []).map(r => `${r.from === 'admin' ? 'Admin' : 'User'}: ${r.text}`).join("\\n");
    const prompt = `User Name: ${t.name} (${t.username ? '@' + t.username : 'guest'})
Category: ${t.category || 'General'}
Problem: "${t.problem}"
${thread ? "Previous Thread:\\n" + thread : ''}

Tum YouSeries (TAMASHA) ke Help Desk Support Analyst ho. Is user ko bhejne ke liye ek polite, helpful, aur to-the-point Hinglish reply likho (bina kisi markdown heading ke, seedha message jo user ko bheja ja sake, 2-4 sentences me).`;
    const model = await resolveGroqModel();
    const { ok, data } = await callGroqChat(model, [
      { role: 'system', content: AI_SYSTEM_PROMPT },
      { role: 'user', content: prompt }
    ]);
    if (!ok) return res.status(500).json({ error: (data && data.error && data.error.message) || 'AI error' });
    const suggestion = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '';
    res.json({ suggestion: suggestion.trim() });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/helpdesk/:id/reply', requireAdmin, async (req, res) => {
  try {
    const text = String((req.body && req.body.message) || '').trim().slice(0, 1500);
    if (!text) return res.status(400).json({ error: 'Jawab likho' });
    const list = await readHelpdesk();
    const t = list.find(x => x.id === req.params.id);
    if (!t) return res.status(404).json({ error: 'Ticket not found' });
    t.replies = t.replies || [];
    t.replies.push({ from: 'admin', text, at: new Date().toISOString() });
    t.hasNewReply = true; t.adminSeen = true; t.status = 'answered';
    await writeHelpdesk(list);
    if (t.userId) await notify(t.userId, { type: 'helpdesk_reply', fromUserId: 'system', fromUsername: 'Help Desk', message: '🆘 Help Desk replied to your question' });
    let emailed = false;
    if (t.email) emailed = await sendResendMail(t.email, 'YouSeries Help Desk — reply to your question', `Hi ${t.name},

${text}

— YouSeries Help Desk

(Tumhara sawal: ${t.problem.slice(0, 200)})`);
    res.json({ success: true, emailed });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/helpdesk/:id/status', requireAdmin, async (req, res) => {
  try {
    const status = (req.body && req.body.status) === 'closed' ? 'closed' : 'open';
    const list = await readHelpdesk();
    const t = list.find(x => x.id === req.params.id);
    if (!t) return res.status(404).json({ error: 'Ticket not found' });
    t.status = status; await writeHelpdesk(list);
    res.json({ success: true, status });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/helpdesk/:id/delete', requireAdmin, async (req, res) => {
  try {
    const list = await readHelpdesk();
    const t = list.find(x => x.id === req.params.id);
    if (!t) return res.status(404).json({ error: 'Ticket not found' });
    if (t.screenshotKey) await storeDelete(t.screenshotKey).catch(() => {});
    await writeHelpdesk(list.filter(x => x.id !== req.params.id));
    res.json({ success: true });
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
    const [reports, films] = await Promise.all([readReports(), readFilms()]);
    const filmMap = new Map(films.map(f => [f.id, f]));
    const enriched = reports.slice().reverse().map(r => {
      const f = r.filmId ? filmMap.get(r.filmId) : null;
      return {
        ...r,
        filmType: f ? f.type : null,
        filmTitle: f ? f.title : null
      };
    });
    res.json({ reports: enriched });
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
        for (const sl of (f.slides || [])) await storeDelete(sl.key);
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
      events.push({ type: 'signup', at: u.createdAt, userId: u.id, username: u.username, text: 'create a new account' });
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
      online: isUserOnline(u), suspended: !!u.suspended, verified: !!u.verified, roleBadge: u.roleBadge || (((u.email || '').toLowerCase() === 'sohailp541@gmail.com') ? '👑 Founder & CEO' : null), google: !u.passwordHash,
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
        pendingReports: reports.filter(r => r.status === 'pending').length,
        pendingModeration: films.filter(f => f.pendingReview).length
      },
      trending: { posts: trendingPosts, hashtags: trendingTags, creators: trendingCreators },
      storage: { ok: st.ok, error: st.error, usedBytes: st.usedBytes, limitBytes: st.accountLimit || STORAGE_LIMIT_BYTES, objects: st.objects, byFolder: st.byFolder, listedAt: st.at ? new Date(st.at).toISOString() : null },
      egress: { mode: 'render', month: usage.month, jsonBytes: usage.jsonBytes, mediaBytes: 0, proxyBytes: usage.proxyBytes, totalBytes: usage.proxyBytes, allowedBytes: GD_MONTH_CAP, views: usage.views },
      drive: { enabled: false },
      systemStatus: {
        groqConfigured: !!GROQ_API_KEY,
        visionModel: GROQ_VISION_MODEL,
        tavilyConfigured: !!TAVILY_API_KEY,
        resendConfigured: !!RESEND_API_KEY,
        r2Configured: r2On()
      },
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
  return { text: u.note.text, createdAt: u.note.createdAt, song: u.note.song || null };
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
      await notify(o.id, { type: 'report_alert', fromUserId: 'system', fromUsername: 'Reports', message: `🚨 New ${label}${preview}` });
    }
    if (process.env.RESEND_API_KEY) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: 'YouSeries <onboarding@resend.dev>', to: [ALERT_EMAIL_TO], subject: '🚨 New report — ' + label,
          text: `New ${label}\nReporter: ${r.reporterUsername || 'unknown'}\nNote: ${r.note || '-'}\n${r.targetPreview ? 'Content: ' + r.targetPreview + '\n' : ''}\nDashboard: /dashboard.html (Reports tab)` })
      });
    }
  } catch (e) { console.error('report alert failed:', e.message); }
}

// ---------------- Pin posts to profile + Notes ----------------
app.get('/api/me/uploads', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const [films, users] = await Promise.all([readFilms(), readUsers()]);
    const me = users.find(u => u.id === currentUser.id);
    const pinnedIds = (me && Array.isArray(me.pinnedFilmIds)) ? me.pinnedFilmIds : [];
    const directUrl = makeDirectUrlCache();
    const mine = films.filter(f => f.ownerId === currentUser.id || (f.collaboratorId === currentUser.id && f.collabStatus === 'accepted'));
    const out = await Promise.all(mine.map(async f => {
      const slide0 = Array.isArray(f.slides) && f.slides[0] ? f.slides[0] : null;
      const posterKey = f.posterFile || (slide0 && slide0.mediaType === 'photo' ? slide0.key : null);
      const videoKey = f.videoFile || (slide0 && slide0.mediaType === 'video' ? slide0.key : null);
      return {
        id: f.id,
        title: f.title || 'Untitled',
        description: f.description || '',
        type: f.type || 'film',
        ownerId: f.ownerId,
        ownerUsername: f.ownerUsername || currentUser.username,
        collaboratorId: f.collaboratorId || null,
        collaboratorUsername: f.collaboratorUsername || null,
        collabStatus: f.collabStatus || null,
        views: Math.max(f.views || 0, (f.viewedBy || []).length, f.likes || 0),
        likes: f.likes || 0,
        commentsCount: (f.comments || []).length,
        savesCount: (f.savedBy || []).length,
        sharesCount: f.shares || 0,
        uploadedAt: f.uploadedAt,
        publishAt: f.publishAt || null,
        pendingReview: !!f.pendingReview,
        isSensitive: !!f.isSensitive,
        pinned: pinnedIds.includes(f.id),
        slidesCount: Array.isArray(f.slides) ? f.slides.length : 0,
        posterUrl: posterKey ? await directUrl(posterKey, f.storageProvider) : null,
        videoUrl: videoKey ? await directUrl(videoKey, f.storageProvider) : null
      };
    }));
    res.json({ uploads: out, pinnedFilmIds: pinnedIds });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/publish-now', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Post not found' });
    if (f.ownerId !== currentUser.id) return res.status(403).json({ error: 'Not allowed' });
    delete f.publishAt;
    f.uploadedAt = new Date().toISOString();
    await writeFilms(films);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/pin-profile', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const [users, films] = await Promise.all([readUsers(), readFilms()]);
    const me = users.find(u => u.id === currentUser.id);
    const f = films.find(x => x.id === req.params.id);
    if (!me || !f) return res.status(404).json({ error: 'Post not found' });
    if (!isFilmOwnerOrCollab(f, me.id)) return res.status(403).json({ error: 'You can only pin your own posts' });
    const live = new Set(films.map(x => x.id));
    let pins = (me.pinnedFilmIds || []).filter(id => live.has(id));
    const has = pins.includes(f.id);
    if (has) pins = pins.filter(id => id !== f.id);
    else { if (pins.length >= 3) return res.status(400).json({ error: 'Only 3 posts can be pinned — unpin one first' }); pins.push(f.id); }
    me.pinnedFilmIds = pins;
    await writeUsers(users);
    res.json({ pinned: !has, pinnedFilmIds: pins });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/me/notif-prefs', async (req, res) => {
  const cu = getUserFromReq(req);
  if (!cu) return res.status(401).json({ error: 'Login required' });
  const me = (await readUsers()).find(u => u.id === cu.id);
  const prefs = me && me.notifPrefs || {};
  const out = {}; Object.keys(NOTIF_CATS).forEach(c => { out[c] = prefs[c] !== false; });
  res.json(out);
});
app.put('/api/me/notif-prefs', async (req, res) => {
  const cu = getUserFromReq(req);
  if (!cu) return res.status(401).json({ error: 'Login required' });
  const users = await readUsers();
  const me = users.find(u => u.id === cu.id);
  if (!me) return res.status(404).json({ error: 'User not found' });
  const body = req.body || {};
  me.notifPrefs = me.notifPrefs || {};
  Object.keys(NOTIF_CATS).forEach(c => { if (typeof body[c] === 'boolean') me.notifPrefs[c] = body[c]; });
  await writeUsers(users);
  res.json({ success: true });
});

app.post('/api/me/note', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const text = String((req.body && req.body.text) || '').trim().slice(0, 60);
    if (text && await findBannedWord(text)) return res.status(400).json({ error: 'This note contains a word that is not allowed' });
    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    if (!me) return res.status(404).json({ error: 'User not found' });
    const noteSong = await pickSong(req.body, 'note');
    if (text) me.note = { text, createdAt: new Date().toISOString(), ...(noteSong ? { song: noteSong } : {}) }; else delete me.note;
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
      text: u.note.text, createdAt: u.note.createdAt, song: u.note.song || null
    })));
    notes.sort((a, b) => (b.mine ? 1 : 0) - (a.mine ? 1 : 0) || new Date(b.createdAt) - new Date(a.createdAt));
    const myProfileImage = me.profileImage ? await directUrl(me.profileImage, me.avatarStorageProvider) : null;
    res.json({ notes, myProfileImage });
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

// Admin Channels & Groups Monitoring
app.get('/api/admin/channels-groups', requireAdmin, async (req, res) => {
  try {
    const convos = await readConversations();
    const users = await readUsers();
    const directUrl = makeDirectUrlCache();
    const list = await Promise.all(convos.filter(c => c.type === 'channel' || c.type === 'group').map(async c => {
      const owner = users.find(u => u.id === c.ownerId);
      return {
        id: c.id,
        type: c.type,
        title: c.title,
        description: c.description || '',
        ownerId: c.ownerId,
        ownerUsername: owner ? owner.username : 'User',
        memberCount: (c.participants || []).length,
        avatarUrl: c.avatarKey ? await directUrl(c.avatarKey, c.storageProvider || 'gdrive') : null,
        createdAt: c.createdAt,
        updatedAt: c.updatedAt
      };
    }));
    res.json({ items: list });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/conversations/:id/delete', requireAdmin, async (req, res) => {
  try {
    const convos = await readConversations();
    const idx = convos.findIndex(c => c.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Conversation not found' });
    convos.splice(idx, 1);
    await writeConversations(convos);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
    if (!u) return res.status(404).json({ error: 'User not found' });
    u.verified = !u.verified;
    await writeUsers(users);
    res.json({ verified: u.verified });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/search-log', async (req, res) => {
  try {
    const q = String((req.body && req.body.q) || '').trim().toLowerCase().slice(0, 60);
    if (q.length < 2) return res.json({ ok: true });
    const terms = (await storeTryReadJSON('search-terms.json')) || {};
    terms[q] = { count: ((terms[q] && terms[q].count) || 0) + 1, last: new Date().toISOString() };
    const keys = Object.keys(terms);
    if (keys.length > 500) keys.sort((a, b) => terms[a].count - terms[b].count).slice(0, keys.length - 500).forEach(k => delete terms[k]);
    await storeWriteJSON('search-terms.json', terms);
    res.json({ ok: true });
  } catch (err) { res.json({ ok: true }); }
});
app.get('/api/admin/search-terms', requireAdmin, async (req, res) => {
  const terms = (await storeTryReadJSON('search-terms.json')) || {};
  const top = Object.entries(terms).map(([term, v]) => ({ term, count: v.count, last: v.last }))
    .sort((a, b) => b.count - a.count).slice(0, 50);
  res.json({ terms: top });
});

app.post('/api/admin/search-terms/delete', requireAdmin, async (req, res) => {
  try {
    if (req.body && req.body.clearAll) {
      await storeWriteJSON('search-terms.json', {});
      return res.json({ success: true });
    }
    const term = String((req.body && req.body.term) || '').trim().toLowerCase();
    const terms = (await storeTryReadJSON('search-terms.json')) || {};
    delete terms[term];
    await storeWriteJSON('search-terms.json', terms);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/stories', requireAdmin, async (req, res) => {
  try {
    const stories = await readStories();
    const directUrl = makeDirectUrlCache();
    const now = Date.now();
    const active = stories.filter(s => now - new Date(s.createdAt).getTime() < 24 * 60 * 60 * 1000);
    const list = await Promise.all(active.slice().reverse().map(async s => {
      const key = s.mediaFile || s.videoFile || s.posterFile;
      return {
        id: s.id,
        ownerId: s.ownerId,
        ownerUsername: s.ownerUsername || 'user',
        mediaType: s.mediaType || 'photo',
        textOverlay: s.textOverlay || '',
        createdAt: s.createdAt,
        viewCount: (s.views || []).length,
        likeCount: (s.likes || []).length,
        commentCount: (s.comments || []).length,
        mediaUrl: key ? await directUrl(key, s.storageProvider || 'gdrive') : null
      };
    }));
    res.json({ stories: list });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/stories/:id/delete', requireAdmin, async (req, res) => {
  try {
    let stories = await readStories();
    const s = stories.find(x => x.id === req.params.id);
    if (!s) return res.status(404).json({ error: 'Story not found' });
    const key = s.mediaFile || s.videoFile || s.posterFile;
    if (key) { try { await storeDelete(key); } catch (e) {} }
    stories = stories.filter(x => x.id !== req.params.id);
    await writeStories(stories);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- 3b. admin content manager ----------
app.get('/api/admin/content', requireAdmin, async (req, res) => {
  try {
    const films = await readFilms();
    const directUrl = makeDirectUrlCache();
    const list = await Promise.all(films.slice(0, 200).map(async f => {
      const slide0 = Array.isArray(f.slides) && f.slides[0] ? f.slides[0] : null;
      const posterKey = f.posterFile || (slide0 && slide0.mediaType === 'photo' ? slide0.key : null);
      const videoKey = f.videoFile || (slide0 && slide0.mediaType === 'video' ? slide0.key : null);
      return {
        id: f.id,
        title: f.title || 'Untitled',
        description: (f.description || '').slice(0, 300),
        type: f.type === 'photo' ? ((f.slides && f.slides.length > 1) ? 'carousel' : 'photo') : (f.type === 'short' ? 'short' : 'film'),
        ownerId: f.ownerId,
        ownerUsername: f.ownerUsername || 'user',
        views: f.views || 0,
        likes: f.likes || 0,
        comments: (f.comments || []).length,
        uploadedAt: f.uploadedAt,
        pendingReview: !!f.pendingReview,
        isSensitive: !!f.isSensitive,
        adminBoosted: !!f.adminBoosted,
        posterUrl: posterKey ? await directUrl(posterKey, f.storageProvider) : null,
        videoUrl: videoKey ? await directUrl(videoKey, f.storageProvider) : null
      };
    }));
    res.json({ content: list });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/content/:id/edit', requireAdmin, async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Post not found' });
    if (typeof req.body.title === 'string' && req.body.title.trim()) f.title = req.body.title.trim().slice(0, 140);
    if (typeof req.body.description === 'string') f.description = req.body.description.trim().slice(0, 2000);
    if (typeof req.body.isSensitive === 'boolean') f.isSensitive = req.body.isSensitive;
    await writeFilms(films);
    res.json({ success: true, title: f.title, description: f.description, isSensitive: !!f.isSensitive });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/content/:id/boost', requireAdmin, async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Post not found' });
    f.adminBoosted = !f.adminBoosted;
    await writeFilms(films);
    res.json({ success: true, adminBoosted: !!f.adminBoosted });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/content/:id/delete', requireAdmin, async (req, res) => {
  try {
    let films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Post not found' });
    await storeDelete(f.videoFile);
    await storeDelete(f.posterFile);
    for (const sl of (f.slides || [])) await storeDelete(sl.key);
    films = films.filter(x => x.id !== f.id);
    await writeFilms(films);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/users/:id/dm', requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id;
    const text = String((req.body && req.body.message) || '').trim().slice(0, 2000);
    if (!text) return res.status(400).json({ error: 'Message likho' });
    const users = await readUsers();
    const target = users.find(u => u.id === targetId);
    if (!target) return res.status(404).json({ error: 'User not found' });

    const senderId = AI_ASSISTANT_ID;
    const senderUsername = AI_ASSISTANT_USERNAME;

    const convo = await ensureAiConversation(targetId);
    const msgId = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const formattedText = `🛡️ [Official Admin Message]: ${text}`;
    const newMessage = {
      id: msgId, conversationId: convo.id, senderId,
      type: 'text', text: formattedText,
      mediaKey: null, mediaType: null, fileName: null, storageProvider: r2On() ? 'r2' : 'gdrive', duration: null,
      shortId: null, shortTitle: null, shortOwnerUsername: null,
      createdAt: new Date().toISOString(), editedAt: null,
      deletedFor: [], unsent: false, readBy: [senderId]
    };
    const messages = await readChatMessages(convo.id);
    messages.push(newMessage);
    await writeChatMessages(convo.id, messages);

    const convos = await readConversations();
    const cRef = convos.find(c => c.id === convo.id);
    if (cRef) {
      cRef.updatedAt = newMessage.createdAt;
      cRef.lastMessage = { senderId, preview: previewForMessage(newMessage), createdAt: newMessage.createdAt };
      if (cRef.hiddenFor) delete cRef.hiddenFor[targetId];
      await writeConversations(convos);
    }

    await notify(targetId, {
      type: 'message',
      fromUserId: senderId,
      fromUsername: senderUsername,
      conversationId: convo.id,
      message: `🛡️ Admin sent you a direct message: "${text.slice(0, 60)}"`
    });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- 4. moderation queue ----------
app.get('/api/admin/moderation', requireAdmin, async (req, res) => {
  try {
    const set = (await storeTryReadJSON('moderation-settings.json')) || {};
    const films = await readFilms();
    const directUrl = makeDirectUrlCache();
    const queue = await Promise.all(films.filter(f => f.pendingReview).map(async f => {
      const slide0 = Array.isArray(f.slides) && f.slides[0] ? f.slides[0] : null;
      const posterKey = f.posterFile || (slide0 && slide0.mediaType === 'photo' ? slide0.key : null);
      const videoKey = f.videoFile || (slide0 && slide0.mediaType === 'video' ? slide0.key : null);
      return {
        id: f.id,
        title: f.title,
        description: (f.description || '').slice(0, 200),
        type: f.type,
        owner: f.ownerUsername,
        uploadedAt: f.uploadedAt,
        posterUrl: posterKey ? await directUrl(posterKey, f.storageProvider) : null,
        videoUrl: videoKey ? await directUrl(videoKey, f.storageProvider) : null
      };
    }));
    res.json({ reviewUploads: !!set.reviewUploads, autoApproveVerified: !!set.autoApproveVerified, queue });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/moderation/settings', requireAdmin, async (req, res) => {
  const set = (await storeTryReadJSON('moderation-settings.json')) || {};
  if (req.body && typeof req.body.reviewUploads === 'boolean') set.reviewUploads = req.body.reviewUploads;
  if (req.body && typeof req.body.autoApproveVerified === 'boolean') set.autoApproveVerified = req.body.autoApproveVerified;
  await storeWriteJSON('moderation-settings.json', set);
  res.json({ success: true, reviewUploads: !!set.reviewUploads, autoApproveVerified: !!set.autoApproveVerified });
});
app.post('/api/admin/moderation/approve-all', requireAdmin, async (req, res) => {
  try {
    const films = await readFilms();
    const pending = films.filter(f => f.pendingReview);
    pending.forEach(f => { delete f.pendingReview; });
    await writeFilms(films);
    for (const f of pending) {
      if (f.ownerId) {
        notify(f.ownerId, { type: 'bluetick', fromUserId: 'system', fromUsername: 'Moderation', filmId: f.id, message: `✅ Your upload "${f.title}" has been approved and is now live!` }).catch(() => {});
      }
    }
    res.json({ success: true, approvedCount: pending.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/moderation/:id/approve', requireAdmin, async (req, res) => {
  const films = await readFilms();
  const f = films.find(x => x.id === req.params.id);
  if (!f) return res.status(404).json({ error: 'Post not found' });
  delete f.pendingReview;
  if (req.body && req.body.boost) f.adminBoosted = true;
  await writeFilms(films);
  if (f.ownerId) {
    notify(f.ownerId, { type: 'bluetick', fromUserId: 'system', fromUsername: 'Moderation', filmId: f.id, message: `✅ Your upload "${f.title}" has been approved${f.adminBoosted ? ' and featured 📌' : ''}!` }).catch(() => {});
  }
  res.json({ success: true });
});
app.post('/api/admin/moderation/:id/reject', requireAdmin, async (req, res) => {
  let films = await readFilms();
  const f = films.find(x => x.id === req.params.id);
  if (!f) return res.status(404).json({ error: 'Post not found' });
  const reason = String((req.body && req.body.reason) || '').trim().slice(0, 200);
  const ownerId = f.ownerId, title = f.title || 'Post';
  await storeDelete(f.videoFile); await storeDelete(f.posterFile);
  for (const sl of (f.slides || [])) await storeDelete(sl.key);
  films = films.filter(x => x.id !== f.id);
  await writeFilms(films);
  if (ownerId) {
    notify(ownerId, {
      type: 'helpdesk_reply',
      fromUserId: 'system',
      fromUsername: 'Moderation',
      message: `❌ Your upload "${title}" was rejected by moderation${reason ? ' — Reason: ' + reason : '.'}`
    }).catch(() => {});
  }
  res.json({ success: true });
});

app.post('/api/admin/users/:id/role-badge', requireAdmin, async (req, res) => {
  try {
    const users = await readUsers();
    const u = users.find(x => x.id === req.params.id);
    if (!u) return res.status(404).json({ error: 'User not found' });
    const badge = String((req.body && req.body.roleBadge) || '').trim().slice(0, 32);
    if (badge) u.roleBadge = badge; else delete u.roleBadge;
    await writeUsers(users);
    feedVer++;
    res.json({ success: true, roleBadge: u.roleBadge || null });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/backup.json', requireAdmin, async (req, res) => {
  try {
    const [users, films, stories, highlights, reports, tickets, blueReqs, announcements, banned, songs] = await Promise.all([
      readUsers(), readFilms(), readStories(), readHighlights(), readReports(), readHelpdesk(), readBlueRequests(),
      readAnnouncements(), getBannedWords(), storeTryReadJSON('songs.json')
    ]);
    const payload = {
      exportedAt: new Date().toISOString(),
      platform: 'YouSeries (TAMASHA)',
      founder: 'Sohail Parvez',
      users, films, stories, highlights, reports, helpdesk: tickets, bluetickRequests: blueReqs,
      announcements, bannedWords: banned, songs: songs || []
    };
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="youseries-backup-${new Date().toISOString().slice(0, 10)}.json"`);
    res.send(JSON.stringify(payload, null, 2));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- 5. one user's full picture for the dashboard ----------
app.get('/api/admin/users/:id/detail', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const [users, films, reqs, tickets, reports] = await Promise.all([readUsers(), readFilms(), readBlueRequests(), readHelpdesk(), readReports()]);
    const u = users.find(x => x.id === id);
    if (!u) return res.status(404).json({ error: 'User not found' });
    const mine = films.filter(f => f.ownerId === id);
    res.json({
      user: { id: u.id, username: u.username, email: u.email, createdAt: u.createdAt, lastActiveAt: u.lastActiveAt, suspended: !!u.suspended, verified: !!u.verified, blueFree: !!u.blueFree, blueUntil: u.blueUntil || null, google: !u.passwordHash, notifPrefs: u.notifPrefs || {} },
      followers: users.filter(x => (x.following || []).includes(id)).length,
      following: (u.following || []).length,
      posts: mine.map(f => ({ id: f.id, title: f.title, type: f.type, views: f.views || 0, likes: (f.likes || 0), comments: (f.comments || []).length, uploadedAt: f.uploadedAt, pending: !!f.pendingReview, scheduledFor: f.publishAt || null })),
      totalViews: mine.reduce((a, f) => a + (f.views || 0), 0),
      commentsWritten: films.reduce((a, f) => a + (f.comments || []).filter(c => c.userId === id).length, 0),
      reportsAgainst: reports.filter(r => r.targetOwnerId === id).map(r => ({ type: r.type, reason: r.reason, status: r.status, createdAt: r.createdAt })),
      bluetickRequests: reqs.filter(r => r.userId === id).map(r => ({ status: r.status, amount: r.amount, createdAt: r.createdAt })),
      helpTickets: tickets.filter(t => t.userId === id).map(t => ({ problem: t.problem, status: t.status, createdAt: t.createdAt }))
    });
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
    if (!u) return res.status(404).json({ error: 'User not found' });
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

// ---------------- Blue tick (verified badge), paid by UPI, approved by the owner ----------------
const BT_KEY_QR = 'bluetick/qr.png';
async function readBlueSettings() {
  const d = await storeTryReadJSON('bluetick-settings.json');
  return {
    price: 49,
    upi: '',
    qrUrl: null,
    minFollowers: 10,
    minViews: 150,
    freeEnabled: true,
    ...(d || {})
  };
}
async function writeBlueSettings(x) { await storeWriteJSON('bluetick-settings.json', x); }
async function readBlueRequests() { return (await storeTryReadJSON('bluetick.json')) || []; }
async function writeBlueRequests(x) { await storeWriteJSON('bluetick.json', x.slice(-2000)); }

// Criteria met -> permanent free blue tick (no payment, never removed later)
function grantFreeBlueTicks(users, films, settings) {
  if (!settings.freeEnabled) return false;
  let changed = false;
  users.forEach(u => {
    if (u.blueFree) return;
    const st = blueStats(u, users, films, settings);
    if (st.eligible) { u.verified = true; u.blueFree = true; delete u.blueUntil; changed = true; }
  });
  return changed;
}
function blueStats(user, users, films, settings) {
  const minF = typeof settings.minFollowers === 'number' ? settings.minFollowers : 10;
  const minV = typeof settings.minViews === 'number' ? settings.minViews : 150;
  const followers = users.filter(u => (u.following || []).includes(user.id)).length;
  const views = films.filter(f => f.ownerId === user.id).reduce((a, f) => a + (f.views || 0), 0);
  const eligible = !!settings.freeEnabled && (followers >= minF && views >= minV);
  return { followers, views, minFollowers: minF, minViews: minV, freeEnabled: !!settings.freeEnabled, eligible };
}

app.get('/api/bluetick/status', async (req, res) => {
  try {
    const cu = getUserFromReq(req);
    if (!cu) return res.status(401).json({ error: 'Login required' });
    const [users, films, reqs, st] = await Promise.all([readUsers(), readFilms(), readBlueRequests(), readBlueSettings()]);
    const me = users.find(u => u.id === cu.id);
    if (!me) return res.status(404).json({ error: 'User not found' });
    if (grantFreeBlueTicks(users, films, st)) await writeUsers(users);
    const mine = reqs.filter(r => r.userId === me.id).slice(-1)[0] || null;
    const qrUrl = st.qrUrl ? await storeUrl(st.qrUrl).catch(() => null) : null;
    let daysRemaining = null;
    if (me.verified && me.blueUntil) {
      daysRemaining = Math.max(0, Math.ceil((new Date(me.blueUntil).getTime() - Date.now()) / (24 * 60 * 60 * 1000)));
    }
    res.json({
      ...blueStats(me, users, films, st),
      verified: !!me.verified, verifiedUntil: me.blueUntil || null, daysRemaining, free: !!me.blueFree,
      price: st.price, upi: st.upi || '', qrUrl,
      pending: !!reqs.find(r => r.userId === me.id && r.status === 'pending'),
      latest: mine ? { status: mine.status, createdAt: mine.createdAt, reason: mine.reason || null } : null
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/bluetick/request', upload.single('screenshot'), async (req, res) => {
  try {
    const cu = getUserFromReq(req);
    if (!cu) return res.status(401).json({ error: 'Login required' });
    const utr = String((req.body && req.body.utr) || '').replace(/\s/g, '');
    if (!/^\d{12}$/.test(utr)) return res.status(400).json({ error: 'UPI transaction ID (UTR) must be 12 digits' });
    const [users, films, reqs, st] = await Promise.all([readUsers(), readFilms(), readBlueRequests(), readBlueSettings()]);
    const me = users.find(u => u.id === cu.id);
    if (!me) return res.status(404).json({ error: 'User not found' });
    if (me.blueFree) return res.status(409).json({ error: 'Your blue tick is permanent, no payment needed' });
    if (reqs.some(r => r.utr === utr)) return res.status(409).json({ error: 'This UTR has already been used' });
    if (reqs.some(r => r.userId === me.id && r.status === 'pending')) return res.status(409).json({ error: 'You already have a pending request' });

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    let screenshotKey = null;
    if (req.file) {
      const ext = (path.extname(req.file.originalname) || '.jpg').replace(/[^A-Za-z0-9.]/g, '').slice(0, 6);
      screenshotKey = `bluetick/${id}${ext}`;
      await storePutBuffer(readFileAsBuffer(req.file.path), screenshotKey, req.file.mimetype || 'image/jpeg');
    }

    reqs.push({
      id,
      userId: me.id,
      username: me.username,
      utr,
      amount: st.price,
      screenshotKey,
      status: 'pending',
      createdAt: new Date().toISOString()
    });
    await writeBlueRequests(reqs);
    alertAdminText(`💳 New Blue Tick request from @${me.username} (UTR: ${utr}, ₹${st.price})`).catch(() => {});
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/bluetick', requireAdmin, async (req, res) => {
  try {
    const [reqs, st, users] = await Promise.all([readBlueRequests(), readBlueSettings(), readUsers()]);
    const totalRevenue = reqs.filter(r => r.status === 'approved').reduce((a, r) => a + (Number(r.amount) || 0), 0);
    const pendingCount = reqs.filter(r => r.status === 'pending').length;
    const approvedCount = reqs.filter(r => r.status === 'approved').length;
    const activeVerifiedCount = users.filter(u => u.verified).length;
    const enrichedReqs = reqs.map(r => ({
      ...r,
      screenshotUrl: r.screenshotKey ? r2PublicUrl(r.screenshotKey) : null
    }));
    res.json({
      requests: enrichedReqs.slice().reverse(),
      settings: st,
      analytics: { totalRevenue, pendingCount, approvedCount, activeVerifiedCount }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/bluetick/:id/decide', requireAdmin, async (req, res) => {
  try {
    const approve = !!(req.body && req.body.approve);
    const reason = String((req.body && req.body.reason) || '').slice(0, 200);
    const duration = String((req.body && req.body.duration) || '30'); // 30, 90, 365, permanent
    const reqs = await readBlueRequests();
    const r = reqs.find(x => x.id === req.params.id);
    if (!r || r.status !== 'pending') return res.status(404).json({ error: 'Pending request not found' });
    const users = await readUsers();
    const u = users.find(x => x.id === r.userId);
    r.status = approve ? 'approved' : 'rejected';
    r.decidedAt = new Date().toISOString();
    r.duration = duration;
    if (!approve) r.reason = reason || null;
    if (approve && u) {
      u.verified = true;
      if (duration === 'permanent') {
        u.blueFree = true;
        delete u.blueUntil;
      } else {
        const days = parseInt(duration, 10) || 30;
        u.blueUntil = Date.now() + days * 24 * 60 * 60 * 1000;
      }
      await writeUsers(users);
    }
    await writeBlueRequests(reqs);
    if (u) {
      const durText = duration === 'permanent' ? 'Permanent' : `${duration} days`;
      notify(u.id, {
        type: 'bluetick', fromUserId: 'system', fromUsername: 'Blue tick',
        message: approve ? `✔ Blue tick granted! Active for ${durText}` : ('❌ Blue tick request rejected' + (reason ? ': ' + reason : ''))
      }).catch(() => {});
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/bluetick/:userId/revoke', requireAdmin, async (req, res) => {
  try {
    const users = await readUsers();
    const u = users.find(x => x.id === req.params.userId);
    if (!u) return res.status(404).json({ error: 'User not found' });
    u.verified = false;
    delete u.blueFree;
    delete u.blueUntil;
    await writeUsers(users);
    notify(u.id, { type: 'bluetick', fromUserId: 'system', fromUsername: 'Blue tick', message: 'Your Blue tick verified badge has been revoked by admin.' }).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/bluetick/settings', requireAdmin, async (req, res) => {
  try {
    const price = Math.round(Number(req.body && req.body.price));
    if (!(price >= 1 && price <= 9999)) return res.status(400).json({ error: 'Price must be between ₹1 and ₹9999' });
    const st = await readBlueSettings();
    st.price = price;
    st.upi = String((req.body && req.body.upi) || '').trim().slice(0, 80);
    if (req.body.minFollowers !== undefined) st.minFollowers = Math.max(0, parseInt(req.body.minFollowers, 10) || 0);
    if (req.body.minViews !== undefined) st.minViews = Math.max(0, parseInt(req.body.minViews, 10) || 0);
    if (req.body.freeEnabled !== undefined) st.freeEnabled = !!req.body.freeEnabled;
    await writeBlueSettings(st);
    res.json(st);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/bluetick/qr', requireAdmin, upload.single('qr'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Choose a QR image' });
    const buf = readFileAsBuffer(req.file.path);
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

app.post('/api/admin/bluetick/qr/delete', requireAdmin, async (req, res) => {
  try {
    const st = await readBlueSettings();
    const old = st.qrUrl;
    st.qrUrl = null;
    await writeBlueSettings(st);
    if (old) storeDelete(old).catch(() => {});
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// a verified badge from a paid plan lasts until blueUntil; after that it is removed
setInterval(async () => {
  try {
    const [users, films, st] = await Promise.all([readUsers(), readFilms(), readBlueSettings()]);
    let changed = grantFreeBlueTicks(users, films, st);
    users.forEach(u => { if (!u.blueFree && u.verified && u.blueUntil && Date.now() > u.blueUntil) { u.verified = false; delete u.blueUntil; changed = true; } });
    if (changed) await writeUsers(users);
  } catch (e) {}
}, 60 * 60 * 1000);

// ---------------- Songs library (admin uploads; users pick a song for stories, notes and uploads) ----------------
async function readSongs() { return (await storeTryReadJSON('songs.json')) || []; }
async function writeSongs(list) { await storeWriteJSON('songs.json', list); }
async function computeSongUsageMap() {
  const counts = {};
  try {
    const [films, stories, users] = await Promise.all([
      readFilms().catch(() => []),
      readStories().catch(() => []),
      readUsers().catch(() => [])
    ]);
    const bump = s => {
      if (!s) return;
      const key = s.id || s.url || s.title;
      if (key) counts[key] = (counts[key] || 0) + 1;
    };
    films.forEach(f => bump(f && f.song));
    stories.filter(isStoryActive).forEach(s => bump(s && s.song));
    users.forEach(u => { const n = activeNote(u); if (n && n.song) bump(n.song); });
  } catch (e) {}
  return counts;
}
app.get('/api/songs', async (req, res) => {
  if (!getUserFromReq(req) && !isAdminBasicAuth(req)) return res.status(401).json({ error: 'Login required' });
  const [list, usageMap] = await Promise.all([readSongs(), computeSongUsageMap()]);
  const out = list.map(x => {
    const url = r2PublicUrl(x.key);
    const useCount = (usageMap[x.id] || 0) + (usageMap[url] || 0);
    return {
      id: x.id,
      title: x.title,
      artist: x.artist || '',
      category: x.category || 'General',
      trending: !!x.trending,
      useCount,
      createdAt: x.createdAt || null,
      url
    };
  });
  out.sort((a, b) => (b.trending - a.trending) || (b.useCount - a.useCount) || String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
  res.json(out);
});
app.post('/api/admin/songs', requireAdmin, upload.single('song'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Choose a song file' });
    const title = String((req.body && req.body.title) || '').trim().slice(0, 80);
    if (!title) return res.status(400).json({ error: 'Enter the song title' });
    storeNeedsDrive();
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const ext = (path.extname(req.file.originalname) || '.mp3').replace(/[^A-Za-z0-9.]/g, '').slice(0, 6);
    const key = `songs/${id}${ext}`;
    await storePutBuffer(readFileAsBuffer(req.file.path), key, req.file.mimetype || 'audio/mpeg');
    const list = await readSongs();
    list.push({
      id,
      key,
      title,
      artist: String((req.body && req.body.artist) || '').trim().slice(0, 80),
      category: String((req.body && req.body.category) || 'General').trim().slice(0, 40),
      trending: toBool(req.body && req.body.trending),
      createdAt: new Date().toISOString()
    });
    await writeSongs(list);
    res.json({ success: true, id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/admin/songs/:id', requireAdmin, async (req, res) => {
  try {
    const list = await readSongs();
    const x = list.find(y => y.id === req.params.id);
    if (!x) return res.status(404).json({ error: 'Song not found' });
    if (req.body.title !== undefined) {
      const t = String(req.body.title || '').trim().slice(0, 80);
      if (!t) return res.status(400).json({ error: 'Title cannot be empty' });
      x.title = t;
    }
    if (req.body.artist !== undefined) x.artist = String(req.body.artist || '').trim().slice(0, 80);
    if (req.body.category !== undefined) x.category = String(req.body.category || 'General').trim().slice(0, 40);
    await writeSongs(list);
    res.json({ success: true, song: x });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/admin/songs/:id/trend', requireAdmin, async (req, res) => {
  const list = await readSongs();
  const x = list.find(y => y.id === req.params.id);
  if (!x) return res.status(404).json({ error: 'Song not found' });
  x.trending = !!(req.body && req.body.on);
  await writeSongs(list);
  res.json({ success: true });
});
app.post('/api/admin/songs/:id/delete', requireAdmin, async (req, res) => {
  const list = await readSongs();
  const x = list.find(y => y.id === req.params.id);
  if (!x) return res.status(404).json({ error: 'Song not found' });
  await storeDelete(x.key);
  await writeSongs(list.filter(y => y.id !== x.id));
  res.json({ success: true });
});

// ---------------- Admin login form (dashboard) ----------------
const adminLoginTries = new Map();
// ---------------- Cloudflare R2 usage (dashboard card) ----------------
// Set in Render: R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME (optional R2_LIMIT_GB, default 10).
const R2_LIMIT_BYTES = (parseFloat(process.env.R2_LIMIT_GB) || 10) * 1024 * 1024 * 1024;
const r2Configured = () => !!(process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY && process.env.R2_BUCKET_NAME && (process.env.R2_ACCOUNT_ID || process.env.R2_ENDPOINT));
let r2Client = null;
function getR2() {
  if (!r2Client) r2Client = new S3Client({
    region: 'auto',
    endpoint: process.env.R2_ENDPOINT || `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    forcePathStyle: true,
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY }
  });
  return r2Client;
}
let r2UsageCache = { at: 0, data: null };
async function r2Usage() {
  if (!r2Configured()) return { configured: false };
  if (r2UsageCache.data && Date.now() - r2UsageCache.at < 10 * 60 * 1000) return r2UsageCache.data;
  try {
    let token, total = 0, objects = 0; const by = {};
    do {
      const out = await getR2().send(new ListObjectsV2Command({ Bucket: process.env.R2_BUCKET_NAME, ContinuationToken: token }));
      for (const o of (out.Contents || [])) {
        const size = o.Size || 0; total += size; objects++;
        const folder = o.Key.includes('/') ? o.Key.split('/')[0] : 'data (json)';
        by[folder] = (by[folder] || 0) + size;
      }
      token = out.IsTruncated ? out.NextContinuationToken : undefined;
    } while (token);
    r2UsageCache = { at: Date.now(), data: { configured: true, ok: true, usedBytes: total, limitBytes: R2_LIMIT_BYTES, objects, byFolder: by } };
  } catch (e) {
    r2UsageCache = { at: Date.now(), data: { configured: true, ok: false, error: e.message, limitBytes: R2_LIMIT_BYTES } };
  }
  return r2UsageCache.data;
}
app.get('/api/admin/r2-usage', requireAdmin, async (req, res) => {
  res.json(await r2Usage());
});

app.post('/api/admin/login', (req, res) => {
  const ip = req.ip || 'ip';
  const now = Date.now();
  const tries = (adminLoginTries.get(ip) || []).filter(t => now - t < 15 * 60 * 1000);
  if (tries.length >= 8) return res.status(429).json({ error: 'Too many failed attempts — try again after 15 minutes' });
  const { username, password } = req.body || {};
  if (!safeEq(username || '', ADMIN_USER) || !safeEq(password || '', ADMIN_PASS)) {
    tries.push(now); adminLoginTries.set(ip, tries);
    return res.status(401).json({ error: 'Wrong username or password' });
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
if (gdEnabled()) { setTimeout(() => gdIndexRefresh(true).then(() => gdEnsurePublic()).catch(e => console.error('Drive index failed:', e.message)), 1500); console.log('Storage: Cloudflare R2'); }