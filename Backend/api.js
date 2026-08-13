const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

app.use(express.json());

const port = process.env.PORT || 3000;

// Define the path to the alerts.json file
const alertFile= path.join(
    __dirname,
    "..",
    "reports",
    "alerts.json"
);

app.get('/demo', (req, res) => {
    res.send('Welcome to the Alerts API');
});

app.get('/alerts', (req, res) => {
    fs.readFile(alertFile, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading alerts.json:', err);
            return res.status(500).json({ error: 'Failed to read alerts.json' });
        }
        try {
            const alerts = data
            .trim()
            .split('\n')
            .map(line => JSON.parse(line));
            res.json(alerts);
        } catch (parseErr) {
            console.error('Error parsing alerts.json:', parseErr);
            res.status(500).json({ error: 'Failed to parse alerts.json' });
        }
    });
});

app.listen(port, () => {
    console.log(`http://localhost:${port} Server is running on port ${port}`);
});



