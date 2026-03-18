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
      const query = `INSERT INTO admin_login (staff_id, staff_email, password_hash, role) VALUES (?, ?, ?, ?)`;
      await db.query(query, [staff_id, staff_email, hashedPassword, 'Admin']);
    } else {
      const { company_name, work_email } = req.body;
      const query = `INSERT INTO recruiter_login (company_name, work_email, password_hash, role) VALUES (?, ?, ?, ?)`;
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

router.post('/login/admin', async (req, res) => {
  const { identifier, password } = req.body;

  try {
    const [rows] = await db.query(
      'SELECT * FROM admin_login WHERE staff_email = ? OR staff_id = ?',
      [identifier, identifier]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Admin account not found" });
    }

    const admin = rows[0];

    // Password verification
    const isMatch = await bcrypt.compare(password, admin.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    res.status(200).json({
      message: "Success",
      admin: { id: admin.id, staff_id: admin.staff_id }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post('/login/recruiter', async (req, res) => {
  const { work_email, password } = req.body;

  try {
    // 1. Find recruiter by Work Email
    const [rows] = await db.query(
      'SELECT * FROM recruiter_login WHERE work_email = ?',
      [work_email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const recruiter = rows[0];

    // 2. Compare entered password with hashed password
    const isMatch = await bcrypt.compare(password, recruiter.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // 3. Optional: Update last_login timestamp
    await db.query(
      'UPDATE recruiter_login SET last_login = NOW() WHERE id = ?',
      [recruiter.id]
    );

    // 4. Success Response
    res.status(200).json({
      message: "Login successful",
      recruiter: {
        id: recruiter.id,
        email: recruiter.work_email,
        role: recruiter.role
      }
    });

  } catch (error) {
    console.error("Recruiter Login Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post('/login/student', async (req, res) => {
  const { identifier, password } = req.body; // 'identifier' is the ID or Email from UI

  try {
    // 1. Query the student_login table
    // We check both the email and university_id columns
    const [rows] = await db.query(
      'SELECT * FROM student_login WHERE email = ? OR university_id = ?',
      [identifier, identifier]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Student record not found" });
    }

    const student = rows[0];

    // 2. Compare the password provided with the hash created by the Admin
    const isMatch = await bcrypt.compare(password, student.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    // 3. Success
    res.status(200).json({
      message: "Login successful",
      student: {
        id: student.id,
        university_id: student.university_id,
        email: student.email
      }
    });

  } catch (error) {
    console.error("Student Login Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = router;