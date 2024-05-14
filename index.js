const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const { check, validationResult } = require('express-validator');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 3000;

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Middleware to parse incoming request bodies
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware for session management
app.use(session({
    secret: 'secret-key', // Change this to a random string
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false, // Set secure:true if using HTTPS
        maxAge: 20 * 60 * 1000 // 20 minutes (in milliseconds)
    }
}));

// Middleware to sanitize input
const sanitizeInput = [
    check('username').trim().escape(),
    check('password').trim().escape()
];

// SQLite database setup
const db = new sqlite3.Database(':memory:'); // In-memory database, change to file database in production

// Create users table
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
});

// Route to render the registration form
app.get('/register', (req, res) => {
    if (req.session.username) {
        // If there is an active session, redirect to the dashboard
        return res.redirect('/dashboard');
    }
    res.render('register');
});

// Route to handle registration form submission
app.post('/register', sanitizeInput, (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        // If there are validation errors, render the registration form again with error messages
        return res.render('register', { errors: errors.array() });
    }

    const { username, password } = req.body;

    // Insert user into the database
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, password], (err) => {
        if (err) {
            // If username is already taken, return error
            if (err.errno === 19) {
                return res.render('register', { error: "Username already exists" });
            }
            // Otherwise, handle other errors
            console.error(err.message);
            return res.status(500).send("Internal Server Error");
        }

        // Registration successful, redirect to login page
        res.redirect('/login');
    });
});

// Route to render the login form
app.get('/login', (req, res) => {
    // Check if there is an active session
    if (req.session.username) {
        // If there is an active session, redirect to the dashboard
        return res.redirect('/dashboard');
    }
    // Otherwise, render the login form
    res.render('login');
});

// Route to handle login form submission
app.post('/login', sanitizeInput, (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        // If there are validation errors, render the login form again with error messages
        return res.render('login', { errors: errors.array() });
    }

    const { username, password } = req.body;

    // Check if user exists in the database
    db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, row) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send("Internal Server Error");
        }

        if (!row) {
            // If user does not exist or password is incorrect, render login form with error message
            return res.render('login', { error: "Invalid username or password" });
        }

        // Set session data
        req.session.username = username;

        // Redirect the user to the dashboard after login
        res.redirect('/dashboard');
    });
});

// Route to render the dashboard (just a placeholder)
app.get('/dashboard', (req, res) => {
    // Check if the user is logged in by checking session data
    if (!req.session.username) {
        // If the user is not logged in, redirect to the login page
        return res.redirect('/login');
    }
    res.render('dashboard', { user: req.session.username });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
