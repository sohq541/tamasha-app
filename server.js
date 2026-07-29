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

const app = express();
const PORT = process.env.PORT || 3000;

// ---- Admin (legacy) credentials ----
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme123';

// ---- Backblaze B2 credentials ----
const B2_KEY_ID = process.env.B2_KEY_ID;
const B2_APPLICATION_KEY = process.env.B2_APPLICATION_KEY;
const B2_BUCKET_ID = process.env.B2_BUCKET_ID;
const B2_BUCKET_NAME = process.env.B2_BUCKET_NAME;

// ---- Auth ----
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';

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
        } catch (err) {
          reject(err);
        }
      })
      .on('error', (err) => {
        try { fs.unlinkSync(inputPath); } catch (e) {}
        reject(err);
      })
      .screenshots({
        count: 1,
        timemarks: ['2'],
        filename: outputName,
        folder: tmpDir,
        size: '640x?'
      });
  });
}

// ---------------- Films "database" (JSON file in B2, cached briefly) ----------------
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

// ---------------- Users "database" (JSON file in B2) ----------------
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
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 }
});

app.use(express.static(path.join(__dirname, 'public')));

// ===================== AUTH ROUTES =====================

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, username, ageConfirm, securityQuestion, securityAnswer } = req.body;
    if (!email || !password || !username) {
      return res.status(400).json({ error: 'Email, password aur username zaroori hain' });
    }
    if (!ageConfirm) {
      return res.status(400).json({ error: 'Aapko confirm karna hoga ki aap 18+ content upload nahi karenge' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password kam se kam 6 characters ka ho' });
    }
    if (!securityQuestion || !securityAnswer || !securityAnswer.trim()) {
      return res.status(400).json({ error: 'Security question aur answer zaroori hai (password bhoolne pe kaam aayega)' });
    }

    const users = await readUsers();
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).json({ error: 'Ye email already registered hai' });
    }
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(400).json({ error: 'Ye username already liya gaya hai' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const securityAnswerHash = await bcrypt.hash(securityAnswer.trim().toLowerCase(), 10);
    const newUser = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
      email, username, passwordHash,
      securityQuestion, securityAnswerHash,
      usernameChanges: [],
      createdAt: new Date().toISOString()
    };
    users.push(newUser);
    await writeUsers(users);

    const token = signToken(newUser);
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ id: newUser.id, email: newUser.email, username: newUser.username });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const users = await readUsers();
    const user = users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
    if (!user) return res.status(401).json({ error: 'Email ya password galat hai' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Email ya password galat hai' });

    const token = signToken(user);
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ id: user.id, email: user.email, username: user.username });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  const user = getUserFromReq(req);
  res.json(user);
});
// Get public info about any user (used to show avatars on profiles)
app.get('/api/users/:id/public', async (req, res) => {
  try {
    const users = await readUsers();
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      id: user.id,
      username: user.username,
      profileImage: user.profileImage ? '/media/avatar/' + user.id : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Upload / change your own profile photo
app.post('/api/me/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const currentUser = getUserFromReq(req);
    if (!currentUser) return res.status(401).json({ error: 'Login required' });
    if (!req.file) return res.status(400).json({ error: 'Photo file zaroori hai' });

    const key = `profiles/${currentUser.id}${path.extname(req.file.originalname) || '.jpg'}`;
    await b2UploadBuffer(req.file.buffer, key, req.file.mimetype);

    const users = await readUsers();
    const user = users.find(u => u.id === currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.profileImage = key;
    await writeUsers(users);

    res.json({ profileImage: '/media/avatar/' + currentUser.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/media/avatar/:id', async (req, res) => {
  try {
    const users = await readUsers();
    const user = users.find(u => u.id === req.params.id);
    if (!user || !user.profileImage) return res.status(404).send('Not found');
    await b2StreamToResponse(user.profileImage, req, res);
  } catch (err) {
    res.status(500).send(err.message);
  }
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
    if (changesThisYear.length >= 3) {
      return res.status(400).json({ error: 'Aap saal me sirf 3 baar username badal sakte hain. Limit ho gayi.' });
    }

    user.username = username.trim();
    user.usernameChanges.push(new Date().toISOString());
    await writeUsers(users);

    const token = signToken(user);
    res.cookie('token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ username: user.username, changesLeft: 3 - changesThisYear.length - 1 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/forgot-password/question', async (req, res) => {
  try {
    const { email } = req.body;
    const users = await readUsers();
    const user = users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
    if (!user) return res.status(404).json({ error: 'Ye email registered nahi hai' });
    res.json({ securityQuestion: user.securityQuestion });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/forgot-password/reset', async (req, res) => {
  try {
    const { email, securityAnswer, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'Naya password kam se kam 6 characters ka ho' });
    }
    const users = await readUsers();
    const user = users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
    if (!user) return res.status(404).json({ error: 'Ye email registered nahi hai' });

    const ok = await bcrypt.compare((securityAnswer || '').trim().toLowerCase(), user.securityAnswerHash);
    if (!ok) return res.status(401).json({ error: 'Security answer galat hai' });

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await writeUsers(users);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post('/api/claim-existing-films', async (req, res) => {
  try {
    const user = getUserFromReq(req);
    if (!user) return res.status(401).json({ error: 'Login required' });
    const films = await readFilms();
    let count = 0;
    films.forEach(f => {
      if (!f.ownerId) {
        f.ownerId = user.id;
        f.ownerUsername = user.username;
        count++;
      }
    });
    await writeFilms(films);
    res.json({ claimed: count });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== FILMS ROUTES =====================

app.get('/api/films', async (req, res) => {
  try {
    const films = await readFilms();
    const out = films.map(f => ({
      ...f,
      videoUrl: f.type === 'photo' ? null : '/media/video/' + f.id,
      posterUrl: f.posterFile ? '/media/poster/' + f.id : null
    }));
    res.json(out);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/films/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });
    res.json({
      ...f,
      videoUrl: '/media/video/' + f.id,
      posterUrl: f.posterFile ? '/media/poster/' + f.id : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/media/video/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).send('Not found');
    await b2StreamToResponse(f.videoFile, req, res);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.get('/media/poster/:id', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f || !f.posterFile) return res.status(404).send('Not found');
    await b2StreamToResponse(f.posterFile, req, res);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.post('/api/films', (req, res, next) => {
  req.currentUser = getUserFromReq(req);
  if (!req.currentUser && !isAdminBasicAuth(req)) {
    return res.status(401).json({ error: 'Upload karne ke liye login zaroori hai' });
  }
  next();
}, upload.fields([{ name: 'video', maxCount: 1 }, { name: 'poster', maxCount: 1 }, { name: 'photo', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, year, language, genre, description, type } = req.body;
    if (!title) return res.status(400).json({ error: 'Title zaroori hai' });

    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

    if (type === 'photo') {
      if (!req.files || !req.files.photo) {
        return res.status(400).json({ error: 'Photo file zaroori hai' });
      }
      const photoFile = req.files.photo[0];
      const photoKey = `posters/${id}${path.extname(photoFile.originalname)}`;
      await b2UploadBuffer(photoFile.buffer, photoKey, photoFile.mimetype);

      const films = await readFilms();
      const newFilm = {
        id, title, year: year || '', language: language || '', genre: genre || '',
        description: description || '', videoFile: null, posterFile: photoKey,
        type: 'photo',
        ownerId: req.currentUser ? req.currentUser.id : 'admin',
        ownerUsername: req.currentUser ? req.currentUser.username : 'YouSeries',
        views: 0, likes: 0, comments: [],
        uploadedAt: new Date().toISOString()
      };
      films.unshift(newFilm);
      await writeFilms(films);
      return res.status(201).json(newFilm);
    }

    if (!req.files || !req.files.video) {
      return res.status(400).json({ error: 'Video file zaroori hai' });
    }

    const videoFile = req.files.video[0];
    const videoKey = `videos/${id}${path.extname(videoFile.originalname)}`;
    await b2UploadBuffer(videoFile.buffer, videoKey, videoFile.mimetype);

    let posterKey = null;
    if (req.files.poster) {
      const posterFile = req.files.poster[0];
      posterKey = `posters/${id}${path.extname(posterFile.originalname)}`;
      await b2UploadBuffer(posterFile.buffer, posterKey, posterFile.mimetype);
    } else {
      try {
        const thumbBuffer = await generateThumbnail(videoFile.buffer, path.extname(videoFile.originalname));
        posterKey = `posters/${id}.jpg`;
        await b2UploadBuffer(thumbBuffer, posterKey, 'image/jpeg');
      } catch (err) {
        console.error('Auto-thumbnail failed:', err.message);
      }
    }

    const films = await readFilms();
    const newFilm = {
      id, title, year: year || '', language: language || '', genre: genre || '',
      description: description || '', videoFile: videoKey, posterFile: posterKey,
      type: type === 'short' ? 'short' : 'film',
      ownerId: req.currentUser ? req.currentUser.id : 'admin',
      ownerUsername: req.currentUser ? req.currentUser.username : 'YouSeries',
      views: 0, likes: 0, comments: [],
      uploadedAt: new Date().toISOString()
    };
    films.unshift(newFilm);
    await writeFilms(films);

    res.status(201).json(newFilm);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/films/:id/view', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });
    f.views = (f.views || 0) + 1;
    await writeFilms(films);
    res.json({ views: f.views });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/films/:id/like', async (req, res) => {
  try {
    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });
    f.likes = (f.likes || 0) + 1;
    await writeFilms(films);
    res.json({ likes: f.likes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/films/:id/comments', async (req, res) => {
  try {
    const { name, text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Comment likhna zaroori hai' });

    const films = await readFilms();
    const f = films.find(x => x.id === req.params.id);
    if (!f) return res.status(404).json({ error: 'Film not found' });

    if (!f.comments) f.comments = [];
    const comment = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
      name: (name || 'Anonymous').trim().slice(0, 40),
      text: text.trim().slice(0, 500),
      createdAt: new Date().toISOString()
    };
    f.comments.push(comment);
    await writeFilms(films);
    res.status(201).json(comment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
    if (!isOwner && !isAdminBasicAuth(req)) {
      return res.status(403).json({ error: 'Ye tumhari content nahi hai' });
    }

    if (title !== undefined) f.title = title;
    if (year !== undefined) f.year = year;
    if (language !== undefined) f.language = language;
    if (genre !== undefined) f.genre = genre;
    if (description !== undefined) f.description = description;
    if (type !== undefined) f.type = type === 'short' ? 'short' : 'film';

    if (req.files && req.files.poster) {
      const posterFile = req.files.poster[0];
      const newPosterKey = `posters/${f.id}-edit${Date.now()}${path.extname(posterFile.originalname)}`;
      await b2UploadBuffer(posterFile.buffer, newPosterKey, posterFile.mimetype);
      const oldPoster = f.posterFile;
      f.posterFile = newPosterKey;
      if (oldPoster) b2DeleteFile(oldPoster).catch(() => {});
    }

    await writeFilms(films);
    res.json(f);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
    if (!isOwner && !isAdminBasicAuth(req)) {
      return res.status(403).json({ error: 'Ye tumhari content nahi hai' });
    }

    await b2DeleteFile(f.videoFile);
    if (f.posterFile) await b2DeleteFile(f.posterFile);

    const remaining = films.filter(x => x.id !== req.params.id);
    await writeFilms(remaining);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`YouSeries server running on port ${PORT}`);
});
    
