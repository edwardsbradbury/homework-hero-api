/* Database configuration settings, exported to src/app.js once configured */

/* Use MySQL */
const mysql = require('mysql');

// Need to access .env file for variables which should be kept secret for security reasons
const config = require('dotenv').config()

/* Create a pool of database connections - had to use a pool rather than a single connection because the ClearDB database
    server hosting the database closes connections after a short period of inactivity - so the app was crashing when trying
    to perform database operations after database connections timed out. Pool handles closing connections & opening new ones */
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

/* Export the connection pool so it can be:
    1) imported in src/app.js - enabling session manager to access its session store and Express app instance to make global db property
        which routes/main can then use to query the database
    2) allow config/passport.js to query the database for user authentication */
module.exports = db;