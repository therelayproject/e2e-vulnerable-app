// User lookup endpoint — intentionally vulnerable sample for scanner validation.
const express = require('express');
const db = require('./db');
const router = express.Router();

router.get('/users/lookup', (req, res) => {
  // CWE-89: SQL injection — user-controlled `email` concatenated into the query.
  const email = req.query.email;
  const q = "SELECT id, name FROM users WHERE email = '" + email + "'";
  db.query(q, (err, rows) => {
    if (err) return res.status(500).send('query failed');
    res.json(rows);
  });
});

module.exports = router;
