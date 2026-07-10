// Report export endpoint — intentionally vulnerable sample for scanner validation.
const express = require('express');
const { exec } = require('child_process');
const router = express.Router();

router.get('/reports/export', (req, res) => {
  // CWE-78: OS command injection — user-controlled `name` flows into a shell.
  const name = req.query.name;
  exec('report-tool --out /tmp/' + name, (err, stdout) => {
    if (err) return res.status(500).send('export failed');
    res.send(stdout);
  });
});

module.exports = router;
