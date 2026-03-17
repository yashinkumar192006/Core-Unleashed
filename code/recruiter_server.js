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

router.post('/signup', async (req, res) => {
  const { role, password } = req.body;

  try {
    // Hash password before saving
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    if (role === 'admin') {
      const { staff_id, staff_email } = req.body;
      const query = `INSERT INTO admins (staff_id, staff_email, password_hash, role) VALUES (?, ?, ?, ?)`;
      await db.query(query, [staff_id, staff_email, hashedPassword, 'Admin']);
    } else {
      const { company_name, work_email } = req.body;
      const query = `INSERT INTO recruiters (company_name, work_email, password_hash, role) VALUES (?, ?, ?, ?)`;
      await db.query(query, [company_name, work_email, hashedPassword, 'Recruiter']);
    }

    res.status(201).json({ message: `${role} account created successfully!` });

  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: "Email or ID already exists." });
    }
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = router;