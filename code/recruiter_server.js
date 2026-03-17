const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

// Database connection
const pool = new Pool({
  user: 'your_db_user',
  host: 'localhost',
  database: 'your_database',
  password: 'your_password',
  port: 5432,
});

router.post('/signup/recruiter', async (req, res) => {
  const { company_name, work_email, password, role } = req.body;

  try {
    // 1. Check if email already exists
    const userCheck = await pool.query('SELECT * FROM recruiters WHERE work_email = $1', [work_email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered." });
    }

    // 2. Hash the password (using 10 salt rounds)
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Insert into the recruiters table
    const newUser = await pool.query(
      'INSERT INTO recruiters (company_name, work_email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, work_email',
      [company_name, work_email, hashedPassword, role || 'Recruiter']
    );

    res.status(201).json({
      message: "Recruiter account created successfully",
      user: newUser.rows[0]
    });

  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

module.exports = router;