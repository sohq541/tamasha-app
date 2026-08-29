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
  const { authToken, downloadUrl } = await b2Authorize();
  const url = `${downloadUrl}/file/${B2_BUCKET_NAME}/films.json`;
  const res = await fetch(url, { headers: { Authorization: authToken } });
  let films;
  if (res.status === 404) films = [];
  else if (!res.ok) throw new Error('Could not read films.json from B2 (status ' + res.status + '): ' + (await res.text()));
  else films = await res.json();
  filmsCache = { data: films, expiresAt: Date.now() + FILMS_CACHE_MS };
  return films;
}

async function writeFilms(films) {
  const buffer = Buffer.from(JSON.stringify(films, null, 2));
  await b2UploadBuffer(buffer, 'films.json', 'application/json');
  filmsCache = { data: films, expiresAt: Date.now() + FILMS_CACHE_MS };
}

// ---------------- Users "database" ----------------
async function readUsers() {
  const { authToken, downloadUrl } = await b2Authorize();
  const url = `${downloadUrl}/file/${B2_BUCKET_NAME}/users.json`;
  const res = await fetch(url, { headers: { Authorization: authToken } });
  if (res.status === 404) return [];
  if (!res.ok) throw new Error('Could not read users.json from B2');
  return res.json();
}
async function writeUsers(users) {
  const buffer = Buffer.from(JSON.stringify(users, null, 2));
  await b2UploadBuffer(buffer, 'users.json', 'application/json');
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
    if (!email || !password || !username) return res.status(400).json({ error: 'Email, password aur username zaroori hain' });
    if (!ageConfirm) return res.status(400).json({ error: 'Aapko confirm karna hoga ki aap 18+ content upload nahi karenge' });
    if (password.length < 6) return res.status(400).json({ error: 'Password kam se kam 6 characters ka ho' });
    if (!securityQuestion || !securityAnswer || !securityAnswer.trim()) return res.status(400).json({ error: 'Security question aur answer zaroori hai' });

    const users = await readUsers();
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) return res.status(400).json({ error: 'Ye email already registered hai' });
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(400).json({ error: 'Ye username already liya gaya hai' });

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
    if (!user) return res.status(401).json({ error: 'Email ya password galat hai' });
    if (!user.passwordHash) return res.status(401).json({ error: 'Ye account Google se bana hai. Neeche "Continue with Google" se login karo.' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Email ya password galat hai' });
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
    if (!profile.email) throw new Error('Google se email nahi mila');

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
      profileImage: user.profileImage ? '/media/avatar/' + user.id : null,
      followersCount, followingCount, isFollowing
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/me/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    if (!req.file) return res.status(400).json({ error: 'Photo file zaroori hai' });

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
    if (user.avatarStorageProvider === 'e2') await e2StreamToResponse(user.profileImage, req, res);
    else await b2StreamToResponse(user.profileImage, req, res);
  } catch (err) { res.status(500).send(err.message); }
});

app.put('/api/me/username', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    const { username } = req.body;
    if (!username || !username.trim()) return res.status(400).json({ error: 'Username zaroori hai' });

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (users.find(u => u.id !== user.id && u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(400).json({ error: 'Ye username already liya gaya hai' });
    }

    if (!user.usernameChanges) user.usernameChanges = [];
    const oneYearAgo = Date.now() - 365 * 24 * 60 * 60 * 1000;
    const changesThisYear = user.usernameChanges.filter(t => new Date(t).getTime() > oneYearAgo);
    if (changesThisYear.length >= 3) return res.status(400).json({ error: 'Aap saal me sirf 3 baar username badal sakte hain. Limit ho gayi.' });

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
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Dono password fields zaroori hain' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Naya password kam se kam 6 characters ka ho' });

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const ok = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Current password galat hai' });

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
    if (!securityQuestion || !securityAnswer || !securityAnswer.trim()) return res.status(400).json({ error: 'Question aur answer dono zaroori hai' });

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
    if (currentUser.id === req.params.id) return res.status(400).json({ error: 'Khud ko follow nahi kar sakte' });

    const users = await readUsers();
    const me = users.find(u => u.id === currentUser.id);
    const target = users.find(u => u.id === req.params.id);
    if (!me || !target) return res.status(404).json({ error: 'User not found' });

    if (!me.following) me.following = [];
    const idx = me.following.indexOf(target.id);
    let nowFollowing;
    if (idx === -1) { me.following.push(target.id); nowFollowing = true; }
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
    if (!user) return res.status(404).json({ error: 'Ye email registered nahi hai' });
    res.json({ securityQuestion: user.securityQuestion });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/forgot-password/reset', async (req, res) => {
  try {
    const { email, securityAnswer, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Naya password kam se kam 6 characters ka ho' });
    const users = await readUsers();
    const user = users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
    if (!user) return res.status(404).json({ error: 'Ye email registered nahi hai' });

    const ok = await bcrypt.compare((securityAnswer || '').trim().toLowerCase(), user.securityAnswerHash);
    if (!ok) return res.status(401).json({ error: 'Security answer galat hai' });

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
    const out = films.map(f => {
      const owner = users.find(u => u.id === f.ownerId);
      const enrichedComments = (f.comments || []).map(c => {
        const cUser = users.find(u => u.id === c.userId);
        return { ...c, name: cUser ? cUser.username : c.name, profileImage: cUser && cUser.profileImage ? '/media/avatar/' + cUser.id : null };
      });
      return {
        ...f, comments: enrichedComments,
        videoUrl: f.type === 'photo' ? null : '/media/video/' + f.id,
        posterUrl: f.posterFile ? '/media/poster/' + f.id : null,
        ownerProfileImage: owner && owner.profileImage ? '/media/avatar/' + owner.id : null
      };
    });
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
    const enrichedComments = (f.comments || []).map(c => {
      const cUser = users.find(u => u.id === c.userId);
      return { ...c, name: cUser ? cUser.username : c.name, profileImage: cUser && cUser.profileImage ? '/media/avatar/' + cUser.id : null };
    });
    res.json({
      ...f, comments: enrichedComments,
      videoUrl: f.type === 'photo' ? null : '/media/video/' + f.id,
      posterUrl: f.posterFile ? '/media/poster/' + f.id : null,
      ownerProfileImage: owner && owner.profileImage ? '/media/avatar/' + owner.id : null
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/media/video/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || !f.videoFile) return res.status(404).send('Not found');
    if (f.storageProvider === 'e2') await e2StreamToResponse(f.videoFile, req, res);
    else await b2StreamToResponse(f.videoFile, req, res);
  } catch (err) { res.status(500).send(err.message); }
});

app.get('/media/poster/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || !f.posterFile) return res.status(404).send('Not found');
    if (f.storageProvider === 'e2') await e2StreamToResponse(f.posterFile, req, res);
    else await b2StreamToResponse(f.posterFile, req, res);
  } catch (err) { res.status(500).send(err.message); }
});

app.post('/api/films', (req, res, next) => {
  req.currentUser = getUserFromReq(req);
  if (!req.currentUser && !isAdminBasicAuth(req)) return res.status(401).json({ error: 'Upload karne ke liye login zaroori hai' });
  next();
}, upload.fields([{ name: 'video', maxCount: 1 }, { name: 'poster', maxCount: 1 }, { name: 'photo', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, year, language, genre, description, type } = req.body;
    if (!title) return res.status(400).json({ error: 'Title zaroori hai' });

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

    if (type === 'photo') {
      if (!req.files || !req.files.photo) return res.status(400).json({ error: 'Photo file zaroori hai' });
      const photoFile = req.files.photo[0];
      const photoKey = `posters/${id}${path.extname(photoFile.originalname)}`;
      await e2UploadBuffer(readFileAsBuffer(photoFile.path), photoKey, photoFile.mimetype);

      const films = await readFilms();
      const newFilm = {
        id, title, year: year || '', language: language || '', genre: genre || '',
        description: description || '', videoFile: null, posterFile: photoKey, type: 'photo',
        storageProvider: 'e2',
        ownerId: req.currentUser ? req.currentUser.id : 'admin',
        ownerUsername: req.currentUser ? req.currentUser.username : 'YouSeries',
        views: 0, likes: 0, comments: [], uploadedAt: new Date().toISOString()
      };
      films.unshift(newFilm);
      await writeFilms(films);
      return res.status(201).json(newFilm);
    }

    if (!req.files || !req.files.video) return res.status(400).json({ error: 'Video file zaroori hai' });

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
    if (!currentUser && !isAdminBasicAuth(req)) return res.status(401).json({ error: 'Login zaroori hai' });
    const { fileName, contentType, folder } = req.body;
    if (!fileName || !folder) return res.status(400).json({ error: 'fileName aur folder zaroori hai' });
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
    if (!currentUser && !isAdminBasicAuth(req)) return res.status(401).json({ error: 'Login zaroori hai' });
    const { title, year, language, genre, description, type, mediaKey, posterKey } = req.body;
    if (!title) return res.status(400).json({ error: 'Title zaroori hai' });
    if (!mediaKey) return res.status(400).json({ error: 'Uploaded file ka reference nahi mila' });

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    const films = await readFilms();

    const newFilm = type === 'photo'
      ? {
          id, title, year: year || '', language: language || '', genre: genre || '',
          description: description || '', videoFile: null, posterFile: mediaKey, type: 'photo',
          storageProvider: 'e2',
          ownerId: currentUser ? currentUser.id : 'admin',
          ownerUsername: currentUser ? currentUser.username : 'YouSeries',
          views: 0, likes: 0, comments: [], uploadedAt: new Date().toISOString()
        }
      : {
          id, title, year: year || '', language: language || '', genre: genre || '',
          description: description || '', videoFile: mediaKey, posterFile: posterKey || null,
          type: type === 'short' ? 'short' : 'film',
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
    res.json({ views: f.views });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/like', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });
    f.likes = (f.likes || 0) + 1;
    await writeFilms(films);
    res.json({ likes: f.likes });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/films/:id/comments', async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Comment karne ke liye login zaroori hai' });

    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Comment likhna zaroori hai' });

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
    if (!isCommentOwner && !isFilmOwner) return res.status(403).json({ error: 'Permission nahi hai' });

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
    if (!text || !text.trim()) return res.status(400).json({ error: 'Comment khaali nahi ho sakta' });

    const films = await readFilms();
    const f = films.find(x => x.id === req.params.filmId);
    if (!f || !f.comments) return res.status(404).json({ error: 'Not found' });

    const comment = f.comments.find(c => c.id === req.params.commentId);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });

    if (comment.userId !== currentUser.id) return res.status(403).json({ error: 'Sirf apna comment edit kar sakte ho' });

    const ageMs = Date.now() - new Date(comment.createdAt).getTime();
    if (ageMs > 24 * 60 * 60 * 1000) return res.status(400).json({ error: '24 ghante ke baad comment edit nahi kar sakte' });

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
    if (!isOwner && !isAdminBasicAuth(req)) return res.status(403).json({ error: 'Ye tumhari content nahi hai' });

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
    if (!isOwner && !isAdminBasicAuth(req)) return res.status(403).json({ error: 'Ye tumhari content nahi hai' });

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

async function readStories() {
  if (storiesCache.data && Date.now() < storiesCache.expiresAt) return storiesCache.data;
  const { authToken, downloadUrl } = await b2Authorize();
  const url = `${downloadUrl}/file/${B2_BUCKET_NAME}/stories.json`;
  const res = await fetch(url, { headers: { Authorization: authToken } });
  let stories;
  if (res.status === 404) stories = [];
  else if (!res.ok) throw new Error('Could not read stories.json from B2 (status ' + res.status + '): ' + (await res.text()));
  else stories = await res.json();
  storiesCache = { data: stories, expiresAt: Date.now() + STORIES_CACHE_MS };
  return stories;
}

async function writeStories(stories) {
  const buffer = Buffer.from(JSON.stringify(stories, null, 2));
  await b2UploadBuffer(buffer, 'stories.json', 'application/json');
  storiesCache = { data: stories, expiresAt: Date.now() + STORIES_CACHE_MS };
}

function isStoryActive(s) {
  return (Date.now() - new Date(s.createdAt).getTime()) < STORY_TTL_MS;
}

// ===================== STORY ROUTES =====================

app.post('/api/stories', (req, res, next) => {
  req.currentUser = getUserFromReq(req);
  if (!req.currentUser) return res.status(401).json({ error: 'Story lagane ke liye login zaroori hai' });
  next();
}, upload.fields([{ name: 'media', maxCount: 1 }]), async (req, res) => {
  try {
    if (!req.files || !req.files.media) return res.status(400).json({ error: 'Photo ya video zaroori hai' });
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

    const byUser = {};
    stories.forEach(s => {
      if (!byUser[s.ownerId]) byUser[s.ownerId] = [];
      byUser[s.ownerId].push(s);
    });

    const groups = Object.keys(byUser).map(ownerId => {
      const owner = users.find(u => u.id === ownerId);
      const userStories = byUser[ownerId].slice().reverse().map(s => ({
        id: s.id, ownerId: s.ownerId, ownerUsername: s.ownerUsername,
        mediaType: s.mediaType, textOverlay: s.textOverlay, createdAt: s.createdAt,
        mediaUrl: '/media/story/' + s.id,
        viewCount: (s.views || []).length,
        commentCount: (s.comments || []).length,
        viewedByMe: !!(currentUser && (s.views || []).some(v => v.userId === currentUser.id))
      }));
      return {
        ownerId,
        ownerUsername: owner ? owner.username : userStories[0].ownerUsername,
        ownerProfileImage: owner && owner.profileImage ? '/media/avatar/' + owner.id : null,
        stories: userStories,
        allViewed: userStories.every(s => s.viewedByMe)
      };
    });

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
    const enrichedComments = (s.comments || []).map(c => {
      const cUser = users.find(u => u.id === c.userId);
      return {
        ...c, likes: c.likes || [],
        name: cUser ? cUser.username : c.name,
        profileImage: cUser && cUser.profileImage ? '/media/avatar/' + cUser.id : null
      };
    });
    res.json({
      ...s, comments: enrichedComments,
      mediaUrl: '/media/story/' + s.id,
      viewCount: (s.views || []).length,
      ownerProfileImage: owner && owner.profileImage ? '/media/avatar/' + owner.id : null
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/media/story/:id', async (req, res) => {
  try {
    const stories = await readStories();
    const s = stories.find(x => x.id === req.params.id);
    if (!s || !s.mediaFile) return res.status(404).send('Not found');
    if (s.storageProvider === 'e2') await e2StreamToResponse(s.mediaFile, req, res);
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
    if (s.ownerId !== currentUser.id) return res.status(403).json({ error: 'Sirf story owner dekh sakta hai' });
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
    if (!currentUser) return res.status(401).json({ error: 'Comment karne ke liye login zaroori hai' });
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Comment likhna zaroori hai' });

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
    if (idx === -1) c.likes.push(currentUser.id); else c.likes.splice(idx, 1);
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
    if (!isCommentOwner && !isStoryOwner) return res.status(403).json({ error: 'Permission nahi hai' });
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
    if (s.ownerId !== currentUser.id) return res.status(403).json({ error: 'Permission nahi hai' });
    if (s.mediaFile) { if (s.storageProvider === 'e2') await e2DeleteFile(s.mediaFile); else await b2DeleteFile(s.mediaFile); }
    stories = stories.filter(x => x.id !== req.params.id);
    await writeStories(stories);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


app.listen(PORT, () => { console.log(`YouSeries server running on port ${PORT}`); });
