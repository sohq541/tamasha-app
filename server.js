const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const DB_FILE = path.join(__dirname, 'films.json');
const VIDEO_DIR = path.join(__dirname, 'uploads', 'videos');
const POSTER_DIR = path.join(__dirname, 'uploads', 'posters');

if (!fs.existsSync(VIDEO_DIR)) fs.mkdirSync(VIDEO_DIR, { recursive: true });
if (!fs.existsSync(POSTER_DIR)) fs.mkdirSync(POSTER_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');

function readFilms() {
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
}
function writeFilms(films) {
  fs.writeFileSync(DB_FILE, JSON.stringify(films, null, 2));
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'video') cb(null, VIDEO_DIR);
    else if (file.fieldname === 'poster') cb(null, POSTER_DIR);
    else cb(new Error('Unknown field'), null);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});

// 2GB max per video file — adjust as needed
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }
});

app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// List all films
app.get('/api/films', (req, res) => {
  res.json(readFilms());
});

// Get one film
app.get('/api/films/:id', (req, res) => {
  const film = readFilms().find(f => f.id === req.params.id);
  if (!film) return res.status(404).json({ error: 'Film not found' });
  res.json(film);
});

// Upload a new film (video required, poster optional)
app.post('/api/films', upload.fields([{ name: 'video', maxCount: 1 }, { name: 'poster', maxCount: 1 }]), (req, res) => {
  const { title, year, language, genre, description } = req.body;

  if (!title || !req.files || !req.files.video) {
    return res.status(400).json({ error: 'Title and video file are required' });
  }

  const films = readFilms();
  const newFilm = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
    title,
    year: year || '',
    language: language || '',
    genre: genre || '',
    description: description || '',
    videoUrl: '/uploads/videos/' + req.files.video[0].filename,
    posterUrl: req.files.poster ? '/uploads/posters/' + req.files.poster[0].filename : null,
    uploadedAt: new Date().toISOString()
  };

  films.unshift(newFilm);
  writeFilms(films);
  res.status(201).json(newFilm);
});

// Delete a film
app.delete('/api/films/:id', (req, res) => {
  let films = readFilms();
  const film = films.find(f => f.id === req.params.id);
  if (!film) return res.status(404).json({ error: 'Film not found' });

  const videoPath = path.join(__dirname, film.videoUrl);
  if (fs.existsSync(videoPath)) fs.unlinkSync(videoPath);
  if (film.posterUrl) {
    const posterPath = path.join(__dirname, film.posterUrl);
    if (fs.existsSync(posterPath)) fs.unlinkSync(posterPath);
  }

  films = films.filter(f => f.id !== req.params.id);
  writeFilms(films);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Tamasha server running at http://localhost:${PORT}`);
  console.log(`Admin upload page: http://localhost:${PORT}/admin.html`);
});
