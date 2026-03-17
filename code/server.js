const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
require('dotenv').config();

const app = express();

const recruiterRouter = require('./recruiter_server');

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Support for JSON-encoded bodies
app.use(express.static(__dirname)); // Serve static files like HTML, CSS
app.use('/', recruiterRouter); // Add recruiter routing
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// MySQL Connection Pool
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10
}).promise();

// --- 1. REGISTRATION ROUTE (Stores data in DB) ---
app.post('/register', async (req, res) => {
    const { usn, email, password, role } = req.body;

    try {
        // Hash the password before storing
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert into the 'users' table (using empty string for full_name since we no longer collect it)
        const [result] = await db.query(
            'INSERT INTO users (full_name, university_id, email, password, role) VALUES (?, ?, ?, ?, ?)',
            ['', usn || null, email, hashedPassword, role]
        );

        res.status(201).send("User registered successfully! ID: " + result.insertId);
    } catch (err) {
        console.error(err);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).send("Email or University ID already exists.");
        }
        res.status(500).send("Server error during registration.");
    }
});

// --- ADMIN ROW: ADD STUDENT ROUTE ---
app.post('/admin/add-student', async (req, res) => {
    const { usn, full_name, class_name, branch, email, password } = req.body;

    // Check if the current user is logged in as an admin (Optional but useful if auth is used)
    // if (!req.session.user || req.session.user.role.toLowerCase() !== 'admin') {
    //     return res.status(403).send("Unauthorized: Admin access required.");
    // }

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert new student into the database with 'Student' role
        const [result] = await db.query(
            'INSERT INTO users (full_name, university_id, email, password, role, class, branch) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [full_name, usn || null, email, hashedPassword, 'student', class_name || null, branch || null]
        );

        res.status(201).send("Student added successfully!");
    } catch (err) {
        console.error(err);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).send("A student with this Email or USN already exists.");
        }
        res.status(500).send("Server error while adding student.");
    }
});

// --- 2. LOGIN ROUTE (Retrieves and verifies data) ---
app.post('/login', async (req, res) => {
    const { usn, email, password, role } = req.body;

    try {
        // Search by Email OR University ID, restricted by the selected Role
        const [rows] = await db.query(
            'SELECT * FROM users WHERE (email = ? OR university_id = ?) AND role = ?',
            [email, usn, role]
        );

        if (rows.length > 0) {
            const user = rows[0];
            // Compare entered password with the hashed password in DB
            const isMatch = await bcrypt.compare(password, user.password);

            if (isMatch) {
                // Fixed: using column names from your SQL schema (user_id, full_name)
                req.session.user = {
                    id: user.user_id,
                    name: user.full_name,
                    role: user.role
                };
                return res.redirect('/profile');
            }
        }
        res.status(401).send("Invalid Credentials or Role Selection");

    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error during login.");
    }
});

// PROFILE ROUTE
app.get('/profile', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.send(`<h1>Welcome to your ${req.session.user.role} Dashboard, ${req.session.user.name}</h1>`);
});

// LOGOUT ROUTE
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.send("Logged out successfully.");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));