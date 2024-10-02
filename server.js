const cluster = require('cluster');
const numCPUs = require('os').cpus().length;
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const https = require('https'); // SSL support
const cronScheduler = require('./commonServices/cronScheduler');

// CORS configuration
const corsOption = {
    origin: "https://localhost:4200",
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    exposedHeaders: ['Authorization']
};

// Load your SSL certificates
const sslKey = fs.readFileSync(path.join(__dirname, 'ssl', 'server.key'));
const sslCert = fs.readFileSync(path.join(__dirname, 'ssl', 'server.cert'));

const httpsOptions = {
  key: sslKey,
  cert: sslCert
};

const AuthRoutes = require('./routes/AuthUrl');
const port = process.env.PORT || 7000;

if (cluster.isMaster) {
    console.log(`Master ${process.pid} is running`);

    // Fork workers with a delay
    let forkIndex = 0;
    const forkWorkerWithDelay = () => {
        if (forkIndex < numCPUs) {
            setTimeout(() => {
                cluster.fork();
                forkIndex++;
                forkWorkerWithDelay();
            }, 500);
        }
    };
    forkWorkerWithDelay();

    cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died`);
    });
} else {
    const app = express();
    
    // Apply CORS
    app.use(cors(corsOption));
    app.use(express.json());
    app.use('/user', AuthRoutes);

    // CORS Headers for preflight requests (for OPTIONS method)
    app.use((req, res, next) => {
        res.setHeader('Access-Control-Allow-Origin', 'https://localhost:4200');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
        res.setHeader('Access-Control-Allow-Credentials', true);
        if (req.method === 'OPTIONS') {
            return res.sendStatus(200);  // Respond with OK for preflight requests
        }
        next();
    });

    // HTTP Basic Authentication for the /status page
    const auth = require('http-auth');
    const basic = auth.basic({ realm: 'Monitor Area' }, function (user, pass, callback) {
        callback(user === 'adminOne' && pass === 'adminOne');
    });

    // Status monitor setup
    const statusMonitor = require('express-status-monitor')({ path: '' });
    app.use(statusMonitor.middleware);
    app.get('/status', basic.check(statusMonitor.pageRoute));

    // Create HTTPS server using the SSL options
    https.createServer(httpsOptions, app).listen(port, () => {
        console.log(`Worker ${process.pid} started HTTPS server at port ${port}`);
    });
}
