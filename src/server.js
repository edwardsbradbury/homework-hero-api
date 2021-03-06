// Express virtual server file with middleware configuration settings

// Import the Express library
const express = require('express');
// Import Express sanitizer
const expressSanitizer = require('express-sanitizer');
// Import the database configuration settings
const db = require('./config/database');
// Need to access .env file for variables which should be kept secret for security reasons
const config = require('dotenv').config()
// Import session manager module
const session = require('express-session');
// Use MYSQLStore middleware to store/retrieve/check user session data in our database when routes are triggered
const MySQLStore = require('express-mysql-session')(session);
// Require the Passportjs authentication & authorisation library
var passport = require('passport');
// Import cors module to prevent cross origin errors
const cors = require('cors');

// Create new Express app instance
const app = express();
/* Necessary configuration due to how Heroku handles requests via SSL: when requests are sent to https://homework-hero-api.herokuapp.com the SSL
    terminates at the Heroku dyno and request is proxied to this Express server. I use secure cookies for session management, which means that
    browsers need to send their requests via HTTPS & the server setting the cookies (i.e. this file) must send its responses via HTTPS */
app.set('trust proxy', 1);

// Middleware to allow the route callback functions in main.js access to data from the body of HTML pages via req.query
app.use(express.urlencoded({extended: true}));

/* Middleware to allow route callback functions (in main.js) to receive data from frontend as JSON { key: value } objects
    e.g. in the Login UI component, submitLogin() sends { email: <what the user input> , password: <what the user input>} to the
    /login route in main.js on the server. Inside the route's callback function, req.body.email and req.body.password are the user input values
    from the object sent from the frontend */
app.use(express.json());

/* Middleware telling callback functions for routes in main.js to accept HTTPS requests from my React UI running at the URL below
    https://www.homework-hero.co.uk */
app.use(cors({
        credentials: true,
        origin: 'https://www.homework-hero.co.uk',
        preflightContinue: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
}))

// Middleware to make req.sanitize command available within route callback functions
app.use(expressSanitizer());

/* Make the database instance available in routes/main.js (probably unecessary since refactoring code such that the database config settings
    can be imported from a dedicated file in config, but if it aint broke...) */
global.db = db;

// Create a store in our database for user sessions & cookies
const sessionStore = new MySQLStore({
    createDatabaseTable: true,
    clearExpired: true,
    checkExpirationInterval: 300000,
    expiration: 86400000,
    schema: {
        tableName: 'sessions',
        columnNames: {
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
            }
        }
}, db)

// Configure session manager
app.use(session({
    secret: process.env.SECURE_KEY,
    store: sessionStore,
    proxy: true,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 5 /* Session expires after 5 days */,
        secure: true,
        sameSite: 'none'
    }
}))

global.passport = passport;
// Get the Passportjs auth configuration settings
require('./config/passport');

/* Each time a route in routes/main.js is triggered by a HTTP request, run these middlewares to check if the request
    has a session (req.session) property. If so retrieve the corresponding record from sessions table in db, if the
    session has not expired. Then retrieve the user id (id of record in tables) from the session record. Retrieve the
    record with that user id from the users table and append it to the request object */
app.use(passport.initialize());
app.use(passport.session());

// Import the backend routing from main.js
require('./routes/main')(app);

// Listen for HTTP requests
app.listen(process.env.PORT, () => {
    console.log(`Listening on port ${process.env.PORT}`)
})