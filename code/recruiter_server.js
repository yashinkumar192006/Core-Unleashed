const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
require('dotenv').config();

// MySQL Connection Pool
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
}).promise();

router.post('/signup/recruiter', async (req, res) => {
  const { company_name, work_email, password, role } = req.body;

  try {
    // 1. Check if email already exists
    const [userCheck] = await db.query('SELECT * FROM recruiters WHERE work_email = ?', [work_email]);
    if (userCheck.length > 0) {
      return res.status(400).json({ message: "Email already registered." });
    }

    // 2. Hash the password (using 10 salt rounds)
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Insert into the recruiters table
    const [newUser] = await db.query(
      'INSERT INTO recruiters (company_name, work_email, password_hash, role) VALUES (?, ?, ?, ?)',
      [company_name, work_email, hashedPassword, role || 'Recruiter']
    );

    res.status(201).json({
      message: "Recruiter account created successfully",
      user: {
        id: newUser.insertId,
        work_email: work_email
      }
    });

  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

module.exports = router;