const cluster = require('cluster');
const numCPUs = require('os').cpus().length;
const express = require('express');
const cors = require('cors');
const cronScheduler = require('./commonServices/cronScheduler');
//scheduler lock file should be removed before running the scheduler

const corsOption = {
    "origin": ["http://localhost:4200"],
    "credentials": true,
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
        console.log(`worker ${worker.process.pid} died`);
    });
} else {
    const app = express();
    app.use(cors(corsOption));
    app.use(express.json());
    app.use('/user', AuthRoutes);
    const auth = require('http-auth');

    const basic = auth.basic({ realm: 'Monitor Area' }, function (user, pass, callback) {
        callback(user === 'adminOne' && pass === 'adminOne');
    });
    // Set '' to config path to avoid middleware serving the html page (path must be a string not equal to the wanted route)
    const statusMonitor = require('express-status-monitor')({ path: '' });
    app.use(statusMonitor.middleware); // use the "middleware only" property to manage websockets
    app.get('/status', basic.check(statusMonitor.pageRoute));

    app.listen(port, () => {
        console.log(`Worker ${process.pid} started server at port ${port}`);
    });
}
