# Tamasha — Indian cinema streaming demo (with real film upload)

A simple full-stack app: upload video files through a form, and they show up
on the homepage for anyone visiting the site to watch.

## What's inside
- `server.js` — Express backend. Handles uploads and stores film info.
- `public/index.html` — homepage, lists all uploaded films, click to play.
- `public/admin.html` — upload form (title, year, language, genre, poster, video).
- `uploads/videos`, `uploads/posters` — where uploaded files are actually stored.
- `films.json` — auto-created database file (just a JSON list of films).

## Run it on your own computer

1. Install [Node.js](https://nodejs.org) if you don't have it (version 18+).
2. Open a terminal in this folder and run:
   ```
   npm install
   npm start
   ```
3. Open **http://localhost:3000** in your browser — that's the homepage.
4. Open **http://localhost:3000/admin.html** to upload a film.

Once uploaded, the film appears on the homepage immediately and anyone
on the same computer/network (if you share your local IP) can watch it.

## Making it live for everyone on the internet

Right now this only runs on your own machine. To make it a real public
website, deploy it to a hosting service that keeps a Node.js server running
24/7. A few beginner-friendly options:

- **Render.com** — free tier, connect your GitHub repo, it auto-deploys.
- **Railway.app** — similar, very quick to set up.
- **A VPS** (DigitalOcean, Hetzner) — more control, run `node server.js`
  behind a process manager like `pm2`.

Steps in general:
1. Push this folder to a GitHub repository.
2. Connect that repo to Render/Railway.
3. Set the start command to `npm start`.
4. Once deployed, you'll get a public URL (e.g. `https://tamasha.onrender.com`)
   that anyone can visit and watch uploaded films on.

### Important things to change before going fully public
- **Storage**: local disk storage (what this uses) gets wiped on most free
  hosting platforms when the server restarts. For real permanence, switch to
  cloud storage like **Cloudflare R2** or **AWS S3** (swap the `multer`
  disk storage for an S3-compatible upload).
- **File size limits**: currently capped at 2GB per video in `server.js`
  (`limits.fileSize`) — adjust based on your hosting plan's limits.
- **Access control**: right now anyone with the link can upload a film.
  Add a login/password check on `/admin.html` and the upload API before
  going public, or people could upload anything.
- **Video streaming**: for long films, consider proper video streaming
  (HLS) instead of serving the raw file, so playback doesn't require
  downloading the whole file first. Services like Mux or Cloudflare Stream
  handle this for you.
