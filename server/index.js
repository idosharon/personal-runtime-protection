const express   = require('express');
const http      = require('http');
const socketIO  = require('socket.io');
const sqlite3   = require('sqlite3').verbose();
const crypto    = require("crypto");

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
});

// Create an Express app
const app = express();
const server = http.createServer(app);
const io = socketIO(server);

// Create a SQLite database connection
const db = new sqlite3.Database('database.db');

const stats = {};
var clients = {};

const TEMPLATES_DIR = __dirname + '/templates';

// Handle incoming socket connections
io.on('connection', (socket) => {
  console.log('A client connected.');
  clients[socket.id] = socket.conn.remoteAddress;

  // Handle incoming event from the client
  socket.on('event', (event) => {
    let buf = Buffer.from(event, 'base64').toString('utf8');
    let json = JSON.parse(buf);

    if (!stats[json["syscall"]]) {
        stats[json["syscall"]] = 1;
    } else {
        stats[json["syscall"]]++;
    }

    saveDataToDB(json);
});

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('A client disconnected.');
    delete clients[socket.id];
    });
});

// Save event to the database
function saveDataToDB(event) {
    const table_name = event["syscall"];
    // Create a table for the event type if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS ${table_name} (ts TIMESTAMP, pid TEXT, ppid TEXT, uid TEXT, comm TEXT, value TEXT, args TEXT)`);

    // Insert the event into the table
    const query = `INSERT INTO ${table_name} (ts, pid, ppid, uid, comm, value, args) VALUES (?, ?, ?, ?, ?, ?, ?)`;
    data = event["data"]
    db.run(query, [data["ts"], event["pid"], data["ppid"], data["uid"], data["comm"], data["value"], JSON.stringify(data["args"])], (err) => {
        if (err) {
            console.error('Error saving event to the database:', err);
        }
    });

    // const query = `INSERT INTO ${table_name} (value) VALUES (?)`;
    // db.run(query, [event], (err) => {
    //     if (err) {
    //         console.error('Error saving event to the database:', err);
    //     } else {
    //         console.log('Data saved to the database.');
    //     }
    // });
}

app.get('/', (_, res) => {
    res.sendFile(TEMPLATES_DIR + '/index.html');
});

app.get('/stats', (_, res) => {
    res.send(stats);
});

app.get('/clients', (_, res) => {
    res.send(clients);
});

app.post('/scan', (_, res) => {
    scanResults = scanDB();
    res.send(scanResults);
});

const rules = [
    {
        "name": "Shell spawned",
        "description": "A shell was spawned",
        "syscall": ["execve"],
        "level": "mid",
        "sql_pattern": "SELECT * FROM execve WHERE comm LIKE '%sh%'"
    },
    {
        "name": "Suspicious process",
        "description": "A process was spawned with a suspicious name",
        "syscall": ["execve"],
        "level": "low",
        "sql_pattern": "SELECT * FROM execve WHERE value LIKE '%/bin/%'"
    },
];
function scanDB() {
    let suspicious_events = [];
    for (let i = 0; i < rules.length; i++) {
        let rule = rules[i];
        let query = rule["sql_pattern"];
        db.all(query, [], (err, rows) => {
            if (err) {
                throw err;
            }
            if (rows.length > 0) {
                found_events = {
                    "name": rule["name"],
                    "description": rule["description"],
                    "level": rule["level"],
                    // "events": rows
                };
                suspicious_events.push(found_events);
            }
        });
    }
    return suspicious_events;
}

app.get('/public-key', (_, res) => {
    res.send(publicKey.export({
        type: "pkcs1",
        format: "pem",
      }));
});

// Start the server
const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
