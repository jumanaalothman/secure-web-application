const express = require('express'); 
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');  // bcrypt
// Required for session-based access control
const session = require('express-session');
const path = require('path');

const xss = require('xss');
const https = require('https');
const fs = require('fs');

const app = express();

app.use(bodyParser.json());
// Enable server-side sessions to manage logged-in users
app.use(session({
    secret: 'secure-web-app-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: true // Ensure secureness of session cookies
    }
}));


const db = new sqlite3.Database('./database.sqlite');
const SALT_ROUNDS = 10;  

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        bio TEXT
    )`);
});



// Access Control - RBAC

// Check if the user is logged in
function requireLogin(req, res, next) {
    if (!req.session.user) {     // Redirect users who are not logged in
        return res.redirect('/login.html');
    }
    next();
}

// Check if the logged-in user has the admin role
function requireAdmin(req, res, next) {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send(`
            <h2>Access Denied</h2>
            <p>You are authenticated, but you are not authorized to access the admin page.</p>
            <a href="/dashboard.html">Back to Dashboard</a>
        `);
    }
    next();
}

// Protected admin page
app.get('/admin.html', requireLogin, requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Serve static files after protecting admin.html
app.use(express.static('.'));








// ==============================================
// use MD5 (week passwords)
// ==============================================
/*
function hashMD5(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}


app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = hashMD5(password);

    const sql = `INSERT INTO users (username, password) VALUES ('${username}', '${hashedPassword}')`;
    
    db.run(sql, (err) => {
        if (err) {
            return res.status(400).send({ message: "Error: User might already exist." });
        }
        res.send({ message: "User registered successfully with MD5!" });
    });
});


app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = hashMD5(password);
    
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${hashedPassword}'`;
    
    db.get(query, (err, row) => {
        if (row) {
            res.json(row);
        } else {
            res.status(401).send({ message: "Invalid credentials" });
        }
    });
});
*/



// ==============================================
// use bcrypt (secure)
// ==============================================

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        
       const sql = "INSERT INTO users (username, password) VALUES (?, ?)";

db.run(sql, [username, hashedPassword], (err) => {
    if (err) {
        return res.status(400).send({ message: "Error: User might already exist." });
    }
    res.send({ message: "User registered successfully with bcrypt!" });
});
        
    } catch (error) {
        res.status(500).send({ message: "Server error" });
    }
});

app.post('/login', async (req, res) => {

    const { username, password } = req.body;

    const sql = "SELECT * FROM users WHERE username = ?";

    db.get(sql, [username], async (err, user) => {

        if (!user) {
            return res.status(401).send({
                message: "Invalid username or password"
            });
        }

        const match = await bcrypt.compare(password, user.password);

        if (match) {
            res.send({ message: "Login successful" });
        } else {
            res.status(401).send({
                message: "Invalid username or password"
            });
        }

    });

}); 



// ==============================================
// SQL Injection VULNERABLE Login
// ==============================================

app.post('/login_vulnerable', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // Vulnerable SQL query: user input is directly added to the query
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    console.log("Vulnerable SQL Query:", query);

    db.get(query, (err, user) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: "Database error" });
        }

        if (user) {
            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role
            };

            return res.json({
                username: user.username,
                role: user.role
            });
        } else {
            return res.status(401).json({ message: "Invalid username or password" });
        }
    });
});


// ==============================================
// SQL Injection SECURE Login
// ==============================================
app.post('/login_secure', async (req, res) => {
    const { username, password } = req.body;

    // Secure SQL query: parameterized query prevents SQL Injection
    const query = "SELECT * FROM users WHERE username = ?";

    db.get(query, [username], async (err, row) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: "Database error" });
        }

        if (!row) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const isValid = await bcrypt.compare(password, row.password);

        if (isValid) {
     // Store user data in the session for access control
            req.session.user = {
                id: row.id,
                username: row.username,
                role: row.role
            };

            return res.json({
                username: row.username,
                role: row.role
            });
        } else {
            return res.status(401).json({ message: "Invalid username or password" });
        }
    });
});


    // Destroy the session when the user logs out
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.send({ message: "Logged out successfully" });
    });
});






// ==============================================
//  XSS WEAK 
// ==============================================
/*

app.post('/update-bio', requireLogin, (req, res) => {
    const { bio } = req.body;
    const userId = req.session.user.id;

    db.run(
        "UPDATE users SET bio = ? WHERE id = ?",
        [bio, userId],
        (err) => {
            if (err) {
                return res.status(500).send({ message: "Error updating bio (weak)" });
            }
            res.send({ message: "Bio updated (weak)!" });
        }
    );
});

app.get('/all-bios', (req, res) => {
    db.all("SELECT username, bio FROM users", (err, rows) => {
        if (err) {
            return res.send("Error (weak)");
        }

        let html = `
        <html>
        <head><title>VULNERABLE</title></head>
        <body>
        <h1>Vulnerable Version (XSS)</h1>
        <p style="color:red;"> This page is vulnerable to XSS</p>
        <ul>
        `;

        rows.forEach(row => {
            
            html += `<li><b>${row.username}</b>: ${row.bio}</li>`;
        });

        html += `</ul></body></html>`;
        res.send(html);
    });
}); */


// ==============================================
//  XSS SECURE
// ==============================================


app.post('/update-bio', requireLogin, (req, res) => {
    const { bio } = req.body;
    const userId = req.session.user.id;

   
    db.run(
        "UPDATE users SET bio = ? WHERE id = ?",
        [bio, userId],
        (err) => {
            if (err) {
                return res.status(500).send({ message: "Error updating bio (secure)" });
            }
            res.send({ message: "Bio updated (secure)!" });
        }
    );
});

app.get('/all-bios', (req, res) => {
    db.all("SELECT username, bio FROM users", (err, rows) => {
        if (err) {
            return res.send("Error (secure)");
        }

        let html = `
        <html>
        <head><title>SECURE</title></head>
        <body>
        <h1>Secure Version (Protected)</h1>
        <p style="color:green;"> This page is protected from XSS</p>
        <ul>
        `;

        rows.forEach(row => {
           
            const clean = xss(row.bio);
            html += `<li><b>${row.username}</b>: ${clean}</li>`;
        });

        html += `</ul></body></html>`;
        res.send(html);
    });
});



// Ensuring sensitive data is stored securely and transmitted over HTTPS

// Load SSL certificates generated via OpenSSL
const sslOptions = {
    key: fs.readFileSync('server.key'), // Your private key
    cert: fs.readFileSync('server.cert') // Your certificate
};

https.createServer(sslOptions, app).listen(3000, () => {
    console.log('Secure Server running at: https://localhost:3000');
});
