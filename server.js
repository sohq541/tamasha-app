const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { Readable } = require('stream');
const ffmpeg = require('fluent-ffmpeg');
ffmpeg.setFfmpegPath(require('ffmpeg-static'));
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const webpush = require('web-push');
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme123';

const B2_KEY_ID = process.env.B2_KEY_ID;
const B2_APPLICATION_KEY = process.env.B2_APPLICATION_KEY;
const B2_BUCKET_ID = process.env.B2_BUCKET_ID;
const B2_BUCKET_NAME = process.env.B2_BUCKET_NAME;

const E2_ACCESS_KEY_ID = process.env.E2_ACCESS_KEY_ID;
const E2_SECRET_ACCESS_KEY = process.env.E2_SECRET_ACCESS_KEY;
const E2_BUCKET_NAME = process.env.E2_BUCKET_NAME;
const E2_REGION = process.env.E2_REGION;
const E2_ENDPOINT = process.env.E2_ENDPOINT;

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

function getUserFromReq(req) {
  const token = req.cookies.token;
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; }
}

function isAdminBasicAuth(req) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Basic ')) return false;
  const decoded = Buffer.from(header.split(' ')[1], 'base64').toString();
  const [user, pass] = decoded.split(':');
  return user === ADMIN_USER && pass === ADMIN_PASS;
}

function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}

function toBool(v) { return v === true || v === 'true'; }

// ---------------- Backblaze B2 helper ----------------
let b2Cache = { authToken: null, apiUrl: null, downloadUrl: null, expiresAt: 0 };

async function b2Authorize() {
  if (b2Cache.authToken && Date.now() < b2Cache.expiresAt) return b2Cache;
  const credentials = Buffer.from(`${B2_KEY_ID}:${B2_APPLICATION_KEY}`).toString('base64');
  const res = await fetch('https://api.backblazeb2.com/b2api/v3/b2_authorize_account', {
    headers: { Authorization: `Basic ${credentials}` }
  });
  if (!res.ok) throw new Error('B2 authorization failed: ' + (await res.text()));
  const data = await res.json();
  b2Cache = {
    authToken: data.authorizationToken,
    apiUrl: data.apiInfo.storageApi.apiUrl,
    downloadUrl: data.apiInfo.storageApi.downloadUrl,
    expiresAt: Date.now() + 12 * 60 * 60 * 1000
  };
  return b2Cache;
}

async function b2GetUploadUrl() {
  const { authToken, apiUrl } = await b2Authorize();
  const res = await fetch(`${apiUrl}/b2api/v3/b2_get_upload_url`, {
    method: 'POST',
    headers: { Authorization: authToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ bucketId: B2_BUCKET_ID })
  });
  if (!res.ok) throw new Error('B2 get upload url failed: ' + (await res.text()));
  return res.json();
}

async function b2UploadBuffer(buffer, fileName, contentType) {
  const { uploadUrl, authorizationToken } = await b2GetUploadUrl();
  const res = await fetch(uploadUrl, {
    method: 'POST',
    headers: {
      Authorization: authorizationToken,
      'X-Bz-File-Name': encodeURIComponent(fileName),
      'Content-Type': contentType || 'b2/x-auto',
      'X-Bz-Content-Sha1': 'do_not_verify',
      'Content-Length': buffer.length
    },
    body: buffer
  });
  if (!res.ok) throw new Error('B2 upload failed: ' + (await res.text()));
  return res.json();
}

async function b2StreamToResponse(fileName, req, res) {
  const { authToken, downloadUrl } = await b2Authorize();
  const url = `${downloadUrl}/file/${B2_BUCKET_NAME}/${encodeURIComponent(fileName)}`;
  const headers = { Authorization: authToken };
  if (req.headers.range) headers.Range = req.headers.range;
  const b2res = await fetch(url, { headers });
  if (!b2res.ok && b2res.status !== 206) {
    return res.status(b2res.status === 404 ? 404 : 502).send('Could not fetch file from storage');
  }
  res.status(b2res.status);
  ['content-type', 'content-length', 'content-range', 'accept-ranges'].forEach(h => {
    const v = b2res.headers.get(h);
    if (v) res.set(h, v);
  });
  Readable.fromWeb(b2res.body).pipe(res);
}

async function b2DeleteFile(fileName) {
  const { authToken, apiUrl } = await b2Authorize();
  const listRes = await fetch(`${apiUrl}/b2api/v3/b2_list_file_names`, {
    method: 'POST',
    headers: { Authorization: authToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ bucketId: B2_BUCKET_ID, startFileName: fileName, maxFileCount: 1 })
  });
  const listData = await listRes.json();
  const match = listData.files && listData.files.find(f => f.fileName === fileName);
  if (!match) return;
  await fetch(`${apiUrl}/b2api/v3/b2_delete_file_version`, {
    method: 'POST',
    headers: { Authorization: authToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileName, fileId: match.fileId })
  });
}

// ---------------- IDrive e2 (S3-compatible) helper ----------------
const e2Client = new S3Client({
  region: E2_REGION,
  endpoint: E2_ENDPOINT,
  credentials: { accessKeyId: E2_ACCESS_KEY_ID, secretAccessKey: E2_SECRET_ACCESS_KEY },
  forcePathStyle: true
});

async function e2UploadBuffer(buffer, key, contentType) {
  await e2Client.send(new PutObjectCommand({
    Bucket: E2_BUCKET_NAME, Key: key, Body: buffer, ContentType: contentType || 'application/octet-stream'
  }));
}

async function e2StreamToResponse(key, req, res) {
  try {
    const params = { Bucket: E2_BUCKET_NAME, Key: key };
    if (req.headers.range) params.Range = req.headers.range;
    const data = await e2Client.send(new GetObjectCommand(params));
    res.status(req.headers.range ? 206 : 200);
    if (data.ContentType) res.set('content-type', data.ContentType);
    if (data.ContentLength != null) res.set('content-length', data.ContentLength);
    if (data.ContentRange) res.set('content-range', data.ContentRange);
    res.set('accept-ranges', 'bytes');
    data.Body.pipe(res);
  } catch (err) {
    if (err.name === 'NoSuchKey') return res.status(404).send('Not found');
    res.status(502).send('Could not fetch file from storage');
  }
}

async function e2DeleteFile(key) {
  try { await e2Client.send(new DeleteObjectCommand({ Bucket: E2_BUCKET_NAME, Key: key })); } catch (e) {}
}

async function e2GetPresignedUploadUrl(key, contentType) {
  const command = new PutObjectCommand({
    Bucket: E2_BUCKET_NAME, Key: key, ContentType: contentType || 'application/octet-stream'
  });
  return getSignedUrl(e2Client, command, { expiresIn: 900 });
}

async function e2GetPresignedDownloadUrl(key) {
  const command = new GetObjectCommand({ Bucket: E2_BUCKET_NAME, Key: key });
  return getSignedUrl(e2Client, command, { expiresIn: 3600 });
}

let b2DownloadAuthCache = { token: null, expiresAt: 0 };
async function getB2DownloadAuthToken() {
  if (b2DownloadAuthCache.token && Date.now() < b2DownloadAuthCache.expiresAt) return b2DownloadAuthCache.token;
  const { authToken, apiUrl } = await b2Authorize();
  const res = await fetch(`${apiUrl}/b2api/v3/b2_get_download_authorization`, {
    method: 'POST',
    headers: { Authorization: authToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ bucketId: B2_BUCKET_ID, fileNamePrefix: '', validDurationInSeconds: 3600 })
  });
  const data = await res.json();
  if (!data.authorizationToken) throw new Error('Could not get B2 download authorization');
  b2DownloadAuthCache = { token: data.authorizationToken, expiresAt: Date.now() + 3500 * 1000 };
  return b2DownloadAuthCache.token;
}

async function b2GetDirectUrl(fileName) {
  const { downloadUrl } = await b2Authorize();
  const token = await getB2DownloadAuthToken();
  return `${downloadUrl}/file/${B2_BUCKET_NAME}/${encodeURIComponent(fileName)}?Authorization=${encodeURIComponent(token)}`;
}

function makeDirectUrlCache() {
  const cache = {};
  return async function directUrl(key, provider) {
    if (!key) return null;
    const cacheKey = (provider || 'b2') + ':' + key;
    if (cache[cacheKey]) return cache[cacheKey];
    try {
      const url = provider === 'e2' ? await e2GetPresignedDownloadUrl(key) : await b2GetDirectUrl(key);
      cache[cacheKey] = url;
      return url;
    } catch (e) { return null; }
  };
}

async function e2ReadJSON(key) {
  const data = await e2Client.send(new GetObjectCommand({ Bucket: E2_BUCKET_NAME, Key: key }));
  const chunks = [];
  for await (const chunk of data.Body) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString('utf-8'));
}

async function e2TryReadJSON(key) {
  try { return await e2ReadJSON(key); }
  catch (e) {
    if (e.name !== 'NoSuchKey') console.error(`e2TryReadJSON('${key}') failed:`, e.message);
    return null;
  }
}

async function e2WriteJSON(key, data) {
  await e2UploadBuffer(Buffer.from(JSON.stringify(data, null, 2)), key, 'application/json');
}

// If B2 is unreachable/capped, return null (caller can degrade gracefully) instead of throwing
async function b2TryReadJSON(fileName) {
  try {
    const { authToken, downloadUrl } = await b2Authorize();
    const url = `${downloadUrl}/file/${B2_BUCKET_NAME}/${fileName}`;
    const res = await fetch(url, { headers: { Authorization: authToken } });
    if (res.status === 404) return [];
    if (!res.ok) return null;
    return await res.json();
  } catch (e) { return null; }
}

async function getMigrationStatus() {
  const status = await e2TryReadJSON('migration-status.json');
  return status || { films: false, users: false, stories: false };
}
async function markMigrated(key) {
  const status = await getMigrationStatus();
  status[key] = true;
  await e2WriteJSON('migration-status.json', status);
}

// ---------------- Notifications ----------------
async function notify(toUserId, { type, fromUserId, fromUsername, filmId, storyId, message }) {
  if (!toUserId || toUserId === fromUserId) return;
  try {
    const notifications = await e2TryReadJSON('notifications.json') || [];
    notifications.push({
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      userId: toUserId, type, fromUserId, fromUsername,
      filmId: filmId || null, storyId: storyId || null,
      message, read: false, createdAt: new Date().toISOString()
    });
    await e2WriteJSON('notifications.json', notifications.slice(-500));
  } catch (e) { console.error('notify failed:', e.message); }
  sendPushToUser(toUserId, { title: 'YouSeries', body: message, filmId, storyId, fromUserId, fromUsername }).catch(() => {});
}

async function sendPushToUser(userId, payload) {
  const subs = await e2TryReadJSON('push-subscriptions.json') || [];
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
  if (changed) await e2WriteJSON('push-subscriptions.json', subs);
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
  const status = await getMigrationStatus();
  let films = await e2TryReadJSON('films.json') || [];

  if (!status.films) {
    const b2Films = await b2TryReadJSON('films.json');
    if (b2Films !== null) {
      const existingIds = new Set(b2Films.map(f => f.id));
      films = [...b2Films, ...films.filter(f => !existingIds.has(f.id))];
      await e2WriteJSON('films.json', films);
      await markMigrated('films');
    }
    // else: B2 is still unreachable/capped — serve whatever's on e2 (new uploads) for now, retry next time
  }

  filmsCache = { data: films, expiresAt: Date.now() + FILMS_CACHE_MS };
  return films;
}

async function writeFilms(films) {
  await e2WriteJSON('films.json', films);
  filmsCache = { data: films, expiresAt: Date.now() + FILMS_CACHE_MS };
}

// ---------------- Users "database" ----------------
async function readUsers() {
  const status = await getMigrationStatus();
  let users = await e2TryReadJSON('users.json') || [];

  if (!status.users) {
    const b2Users = await b2TryReadJSON('users.json');
    if (b2Users !== null) {
      const existingIds = new Set(b2Users.map(u => u.id));
      users = [...b2Users, ...users.filter(u => !existingIds.has(u.id))];
      await e2WriteJSON('users.json', users);
      await markMigrated('users');
    }
  }

  return users;
}
async function writeUsers(users) {
  await e2WriteJSON('users.json', users);
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

    const token = signToken(user);
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.redirect('/');
  } catch (err) {
    console.error('Google auth error:', err);
    res.redirect('/login.html?error=google_failed');
  }
});

app.get('/api/me', (req, res) => { res.json(getUserFromReq(req)); });

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
      profileImage: user.profileImage ? await makeDirectUrlCache()(user.profileImage, user.avatarStorageProvider) : null,
      followersCount, followingCount, isFollowing,
      hideSensitiveContent: !!user.hideSensitiveContent
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/me/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    if (!req.file) return res.status(400).json({ error: 'A photo file is required' });

    const key = `profiles/${currentUser.id}${path.extname(req.file.originalname) || '.jpg'}`;
    await e2UploadBuffer(readFileAsBuffer(req.file.path), key, req.file.mimetype);

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.profileImage = key;
    user.avatarStorageProvider = 'e2';
    await writeUsers(users);

    res.json({ profileImage: '/media/avatar/' + currentUser.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/media/avatar/:id', async (req, res) => {
  try {
    const users = await readUsers();
    const user = users.find(u => u.id === req.params.id);
    if (!user || !user.profileImage) return res.status(404).send('Not found');
    if (user.avatarStorageProvider === 'e2') return res.redirect(302, await e2GetPresignedDownloadUrl(user.profileImage));
    else await b2StreamToResponse(user.profileImage, req, res);
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
    const directUrl = makeDirectUrlCache();

    const out = await Promise.all(films
      .filter(f => !(hideSensitive && f.isSensitive))
      .map(async f => {
        const owner = users.find(u => u.id === f.ownerId);
        const ownerAvatarUrl = owner && owner.profileImage ? await directUrl(owner.profileImage, owner.avatarStorageProvider) : null;
        const enrichedComments = await Promise.all((f.comments || []).map(async c => {
          const cUser = users.find(u => u.id === c.userId);
          const cAvatarUrl = cUser && cUser.profileImage ? await directUrl(cUser.profileImage, cUser.avatarStorageProvider) : null;
          return { ...c, name: cUser ? cUser.username : c.name, profileImage: cAvatarUrl };
        }));
        const videoUrl = f.type !== 'photo' && f.videoFile ? await directUrl(f.videoFile, f.storageProvider) : null;
        const posterUrl = f.posterFile ? await directUrl(f.posterFile, f.storageProvider) : null;
        return {
          ...f, comments: enrichedComments,
          videoUrl, posterUrl,
          ownerProfileImage: ownerAvatarUrl
        };
      }));
    res.json(out);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/films/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });
    const users = await readUsers();
    const owner = users.find(u => u.id === f.ownerId);
    const directUrl = makeDirectUrlCache();
    const ownerAvatarUrl = owner && owner.profileImage ? await directUrl(owner.profileImage, owner.avatarStorageProvider) : null;
    const enrichedComments = await Promise.all((f.comments || []).map(async c => {
      const cUser = users.find(u => u.id === c.userId);
      const cAvatarUrl = cUser && cUser.profileImage ? await directUrl(cUser.profileImage, cUser.avatarStorageProvider) : null;
      return { ...c, name: cUser ? cUser.username : c.name, profileImage: cAvatarUrl };
    }));
    res.json({
      ...f, comments: enrichedComments,
      videoUrl: f.type !== 'photo' && f.videoFile ? await directUrl(f.videoFile, f.storageProvider) : null,
      posterUrl: f.posterFile ? await directUrl(f.posterFile, f.storageProvider) : null,
      ownerProfileImage: ownerAvatarUrl
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/media/video/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || !f.videoFile) return res.status(404).send('Not found');
    if (f.storageProvider === 'e2') return res.redirect(302, await e2GetPresignedDownloadUrl(f.videoFile));
    else await b2StreamToResponse(f.videoFile, req, res);
  } catch (err) { res.status(500).send(err.message); }
});

app.get('/media/poster/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || !f.posterFile) return res.status(404).send('Not found');
    if (f.storageProvider === 'e2') return res.redirect(302, await e2GetPresignedDownloadUrl(f.posterFile));
    else await b2StreamToResponse(f.posterFile, req, res);
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

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

    if (type === 'photo') {
      if (!req.files || !req.files.photo) return res.status(400).json({ error: 'A photo file is required' });
      const photoFile = req.files.photo[0];
      const photoKey = `posters/${id}${path.extname(photoFile.originalname)}`;
      await e2UploadBuffer(readFileAsBuffer(photoFile.path), photoKey, photoFile.mimetype);

      const films = await readFilms();
      const newFilm = {
        id, title, year: year || '', language: language || '', genre: genre || '',
        description: description || '', videoFile: null, posterFile: photoKey, type: 'photo',
        isSensitive: toBool(isSensitive),
        storageProvider: 'e2',
        ownerId: req.currentUser ? req.currentUser.id : 'admin',
        ownerUsername: req.currentUser ? req.currentUser.username : 'YouSeries',
        views: 0, likes: 0, comments: [], uploadedAt: new Date().toISOString()
      };
      films.unshift(newFilm);
      await writeFilms(films);
      return res.status(201).json(newFilm);
    }

    if (!req.files || !req.files.video) return res.status(400).json({ error: 'A video file is required' });

    const videoFile = req.files.video[0];
    const videoKey = `videos/${id}${path.extname(videoFile.originalname)}`;
    await e2UploadBuffer(fs.readFileSync(videoFile.path), videoKey, videoFile.mimetype);

    let posterKey = null;
    if (req.files.poster) {
      const posterFile = req.files.poster[0];
      posterKey = `posters/${id}${path.extname(posterFile.originalname)}`;
      await e2UploadBuffer(readFileAsBuffer(posterFile.path), posterKey, posterFile.mimetype);
    }

    const films = await readFilms();
    const newFilm = {
      id, title, year: year || '', language: language || '', genre: genre || '',
      description: description || '', videoFile: videoKey, posterFile: posterKey,
      type: type === 'short' ? 'short' : 'film',
      isSensitive: toBool(isSensitive),
      storageProvider: 'e2',
      ownerId: req.currentUser ? req.currentUser.id : 'admin',
      ownerUsername: req.currentUser ? req.currentUser.username : 'YouSeries',
      views: 0, likes: 0, comments: [], uploadedAt: new Date().toISOString()
    };
    films.unshift(newFilm);
    await writeFilms(films);
    res.status(201).json(newFilm);

    // Generate thumbnail in the background so the upload response returns faster
    if (!posterKey) {
      const videoPathForThumb = videoFile.path;
      generateThumbnail(fs.readFileSync(videoPathForThumb), path.extname(videoFile.originalname))
        .then(async (thumbBuffer) => {
          fs.unlink(videoPathForThumb, () => {});
          const genPosterKey = `posters/${id}.jpg`;
          await e2UploadBuffer(thumbBuffer, genPosterKey, 'image/jpeg');
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
    const uploadUrl = await e2GetPresignedUploadUrl(key, contentType);
    res.json({ uploadUrl, key });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/finalize', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser && !isAdminBasicAuth(req)) return res.status(401).json({ error: 'Please log in' });
    const { title, year, language, genre, description, type, mediaKey, posterKey, isSensitive } = req.body;
    if (!title) return res.status(400).json({ error: 'A title is required' });
    if (!mediaKey) return res.status(400).json({ error: 'Could not find a reference to the uploaded file' });

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const films = await readFilms();

    const newFilm = type === 'photo'
      ? {
          id, title, year: year || '', language: language || '', genre: genre || '',
          description: description || '', videoFile: null, posterFile: mediaKey, type: 'photo',
          isSensitive: toBool(isSensitive),
          storageProvider: 'e2',
          ownerId: currentUser ? currentUser.id : 'admin',
          ownerUsername: currentUser ? currentUser.username : 'YouSeries',
          views: 0, likes: 0, comments: [], uploadedAt: new Date().toISOString()
        }
      : {
          id, title, year: year || '', language: language || '', genre: genre || '',
          description: description || '', videoFile: mediaKey, posterFile: posterKey || null,
          type: type === 'short' ? 'short' : 'film',
          isSensitive: toBool(isSensitive),
          storageProvider: 'e2',
          ownerId: currentUser ? currentUser.id : 'admin',
          ownerUsername: currentUser ? currentUser.username : 'YouSeries',
          views: 0, likes: 0, comments: [], uploadedAt: new Date().toISOString()
        };

    films.unshift(newFilm);
    await writeFilms(films);
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

app.post('/api/films/:id/comments', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Please log in to comment' });

    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Please write a comment' });

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
    f.comments.push(comment);
    await writeFilms(films);
    if (f.ownerId) {
      await notify(f.ownerId, { type: 'film_comment', fromUserId: currentUser.id, fromUsername: currentUser.username, filmId: f.id, message: `@${currentUser.username} commented on your "${f.title}"` });
    }
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

    if (req.files && req.files.poster) {
      const posterFile = req.files.poster[0];
      const newPosterKey = `posters/${f.id}-edit${Date.now()}${path.extname(posterFile.originalname)}`;
      await e2UploadBuffer(readFileAsBuffer(posterFile.path), newPosterKey, posterFile.mimetype);
      const oldPoster = f.posterFile;
      const oldProvider = f.storageProvider;
      f.posterFile = newPosterKey;
      f.storageProvider = 'e2';
      if (oldPoster) {
        if (oldProvider === 'e2') e2DeleteFile(oldPoster).catch(() => {});
        else b2DeleteFile(oldPoster).catch(() => {});
      }
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

    if (f.videoFile) { if (f.storageProvider === 'e2') await e2DeleteFile(f.videoFile); else await b2DeleteFile(f.videoFile); }
    if (f.posterFile) { if (f.storageProvider === 'e2') await e2DeleteFile(f.posterFile); else await b2DeleteFile(f.posterFile); }

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
  return await e2TryReadJSON('watch-history.json') || [];
}
async function writeWatchHistory(list) {
  await e2WriteJSON('watch-history.json', list.slice(-3000));
}

async function readStories() {
  if (storiesCache.data && Date.now() < storiesCache.expiresAt) return storiesCache.data;
  const status = await getMigrationStatus();
  let stories = await e2TryReadJSON('stories.json') || [];

  if (!status.stories) {
    const b2Stories = await b2TryReadJSON('stories.json');
    if (b2Stories !== null) {
      const existingIds = new Set(b2Stories.map(s => s.id));
      stories = [...b2Stories, ...stories.filter(s => !existingIds.has(s.id))];
      await e2WriteJSON('stories.json', stories);
      await markMigrated('stories');
    }
  }

  storiesCache = { data: stories, expiresAt: Date.now() + STORIES_CACHE_MS };
  return stories;
}

async function writeStories(stories) {
  await e2WriteJSON('stories.json', stories);
  storiesCache = { data: stories, expiresAt: Date.now() + STORIES_CACHE_MS };
}

function isStoryActive(s) {
  return (Date.now() - new Date(s.createdAt).getTime()) < STORY_TTL_MS;
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
    await e2UploadBuffer(fs.readFileSync(mediaFile.path), mediaKey, mediaFile.mimetype);
    fs.unlink(mediaFile.path, () => {});

    let stories = await readStories();
    stories = stories.filter(isStoryActive);
    const newStory = {
      id,
      ownerId: req.currentUser.id,
      ownerUsername: req.currentUser.username,
      mediaFile: mediaKey,
      mediaType: isVideo ? 'video' : 'photo',
      storageProvider: 'e2',
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
    if (s.storageProvider === 'e2') return res.redirect(302, await e2GetPresignedDownloadUrl(s.mediaFile));
    else await b2StreamToResponse(s.mediaFile, req, res);
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
    if (s.mediaFile) { if (s.storageProvider === 'e2') await e2DeleteFile(s.mediaFile); else await b2DeleteFile(s.mediaFile); }
    stories = stories.filter(x => x.id !== req.params.id);
    await writeStories(stories);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


app.get('/api/notifications', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const all = await e2TryReadJSON('notifications.json') || [];
    const mine = all.filter(n => n.userId === currentUser.id).slice().reverse().slice(0, 50);
    const unreadCount = mine.filter(n => !n.read).length;
    res.json({ notifications: mine, unreadCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/notifications/unread-count', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.json({ unreadCount: 0 });
    const all = await e2TryReadJSON('notifications.json') || [];
    const unreadCount = all.filter(n => n.userId === currentUser.id && !n.read).length;
    res.json({ unreadCount });
  } catch (err) { res.json({ unreadCount: 0 }); }
});

app.post('/api/notifications/mark-read', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const all = await e2TryReadJSON('notifications.json') || [];
    let changed = false;
    all.forEach(n => { if (n.userId === currentUser.id && !n.read) { n.read = true; changed = true; } });
    if (changed) await e2WriteJSON('notifications.json', all);
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
      if (f.videoFile) { if (f.storageProvider === 'e2') await e2DeleteFile(f.videoFile); else await b2DeleteFile(f.videoFile); }
      if (f.posterFile) { if (f.storageProvider === 'e2') await e2DeleteFile(f.posterFile); else await b2DeleteFile(f.posterFile); }
    }
    const remainingFilms = films.filter(f => f.ownerId !== currentUser.id);
    await writeFilms(remainingFilms);

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (user && user.profileImage) {
      if (user.avatarStorageProvider === 'e2') await e2DeleteFile(user.profileImage); else await b2DeleteFile(user.profileImage);
    }
    users.forEach(u => { if (u.following) u.following = u.following.filter(id => id !== currentUser.id); });
    const remainingUsers = users.filter(u => u.id !== currentUser.id);
    await writeUsers(remainingUsers);

    res.clearCookie('token');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

let mailTransporter = null;
function getMailTransporter() {
  if (mailTransporter) return mailTransporter;
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) return null;
  mailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD }
  });
  return mailTransporter;
}

app.post('/api/help-desk', async (req, res) => {
  try {
    const { name, userId, problem } = req.body;
    if (!problem || !problem.trim()) return res.status(400).json({ error: 'Please describe your problem' });
    const transporter = getMailTransporter();
    if (!transporter) {
      console.error('Help desk: GMAIL_USER/GMAIL_APP_PASSWORD env vars missing or empty');
      return res.status(500).json({ error: 'Email service isn\'t set up yet, please try again later' });
    }
    console.log('Help desk: sending mail for user', userId || '-');
    await transporter.sendMail({
      from: GMAIL_USER,
      to: 'sohailp541@gmail.com',
      subject: 'YouSeries Help Desk — ' + (name || 'User'),
      text: `Name: ${name || '-'}\nUser ID: ${userId || '-'}\n\nProblem:\n${problem}`
    });
    console.log('Help desk: mail sent successfully');
    res.json({ success: true });
  } catch (err) {
    console.error('Help desk mail error:', err);
    res.status(500).json({ error: 'Email bhejne me error aaya: ' + err.message });
  }
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

    const subs = await e2TryReadJSON('push-subscriptions.json') || [];
    const existingIdx = subs.findIndex(s => s.subscription.endpoint === subscription.endpoint);
    const entry = { userId: currentUser.id, subscription, createdAt: new Date().toISOString() };
    if (existingIdx !== -1) subs[existingIdx] = entry; else subs.push(entry);
    await e2WriteJSON('push-subscriptions.json', subs);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/push/unsubscribe', async (req, res) => {
  try {
    const { endpoint } = req.body;
    if (!endpoint) return res.status(400).json({ error: 'Endpoint required' });
    const subs = await e2TryReadJSON('push-subscriptions.json') || [];
    const filtered = subs.filter(s => s.subscription.endpoint !== endpoint);
    await e2WriteJSON('push-subscriptions.json', filtered);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(PORT, () => { console.log(`YouSeries server running on port ${PORT}`); });
