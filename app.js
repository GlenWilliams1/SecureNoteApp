const express = require('express');
const session = require('express-session');
const csrf = require('csurf');
const helmet = require('helmet');
const morgan = require('morgan');
const sqlite3 = require('sqlite3');

const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(session({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));
app.use(csrf());
app.use(helmet());
app.use(morgan('combined'));

// SQLite Database
const db = new sqlite3.Database('database.db');

// Insecure Routes (Step 5)
app.get('/insecure', (req, res) => {
  // SQL Injection Vulnerability
  const userInput = req.query.input;
  db.all(`SELECT * FROM notes WHERE title = '${userInput}'`, (err, rows) => {
    if (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    } else {
      res.json({ notes: rows });
    }
  });
});

app.get('/xss', (req, res) => {
  // Reflected XSS Vulnerability
  const userInput = req.query.input;
  res.send(`<p>${userInput}</p>`);
});

app.post('/store', (req, res) => {
  // Sensitive Data Exposure
  const { username, password } = req.body;
  // Process login, but we shouldn't log or store sensitive data like this
  console.log(`Login attempt - Username: ${username}, Password: ${password}`);
  res.send('Login attempt processed.');
});

// Secure Routes (Step 6)
app.get('/secure', (req, res) => {
  // CSRF Token Protection
  const csrfToken = req.csrfToken();
  res.json({ csrfToken });
});

app.post('/secure/store', (req, res) => {
  // Proper Session Management
  const { title, content } = req.body;
  if (req.session.authenticated) {
    db.run('INSERT INTO notes (title, content) VALUES (?, ?)', [title, content], (err) => {
      if (err) {
        console.error(err);
        res.status(500).send('Internal Server Error');
      } else {
        res.send('Note added successfully.');
      }
    });
  } else {
    res.status(401).send('Unauthorized');
  }
});

// Security Headers
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// Logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Index Route
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Start Server
app.listen(port, () => console.log(`Server is running on http://localhost:${port}`));
