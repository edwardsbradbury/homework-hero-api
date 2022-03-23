// Routes/endpoints for handling HTTP requests

module.exports = function(app) {

	// Middleware to protect routes so that only users with a valid session can send requests to those routes
	const isAuth = require('./authMiddleware').isAuth;
	// Use the Express validator module
	const { check, validationResult } = require('express-validator');
	/* emailRegex is used in login & register routes below to test whether email addresses sent from frontend match an email address format pattern, i.e.
	<some letters and numbers> @ <some letters and numbers> . <some letters and numbers> */
	const emailRegex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
	// nameRegex is used in login & register routes to check that first & last names only contain letters and hyphen (dash -) characters
	const nameRegex = /^[a-zA-Z]+(-[a-zA-Z]+)*$/;
	// Regex to test that the subject of a new Request for help contains only letters and spaces
	// const subjectRegex = /^[a-zA-Z ]*$/;
	// List of subjects, used in some routes to check a subject is valid
	const subjects = ['Maths', 'English', 'Biology', 'Chemistry', 'Physics', 'Geography', 'History', 'Design and Technology', 'ICT', 'Computer Science', 'Religious Education', 'Art', 'French', 'German', 'Spanish', 'Italian'];
	// List of levels of study, used in some routes to check validity of a level of study
	const levels = ['GCSE', 'A level', 'Year 7', 'Year 8', 'Year 9', 'Year 10', 'Year 11', 'Year 12', 'Year 13'];
	// Regex to test the 'study level' of a new help Request
	// const studyLevelRegex = /^[a-zA-Z0-9 ]*$/;
	// Time format regex (used in Requests routes) to check the time a request was posted is in format hh:mm:ss
	const timeFormatRegex = /^(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])$/;

	// Use the bcrypt password module
	const bcrypt = require('bcrypt');
	// Number of salting rounds for password hashing
	const saltRounds = 10;


	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Handler for HTTP requests from unauthenticated clients
	
	app.get('/unauthenticated', function(req, res) {
		res.json({
			outcome: 'failure',
			error: 'unauthenticated'
		})
	})
	

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Route to receive registration form data, sanitize it, then post it to the database

	app.post('/register',

		// Check input using validators
		[check('userType').isAlpha().isLength({max: 6}).withMessage('userTypeInvalid')],
		[check('first').matches(nameRegex).withMessage('firstNameInvalid').isLength({min: 2, max: 30}).withMessage('nameLength')],
		[check('last').matches(nameRegex).withMessage('lastNameInvalid').isLength({min: 2, max: 30}).withMessage('nameLength')],
		[check('email1').matches(emailRegex).withMessage('emailInvalid').isLength({max: 100}).withMessage('email1Length')],
		[check('dob').isDate().withMessage('dobInvalid')],
		[check('email2').matches(emailRegex).withMessage('emailInvalid').isLength({max: 100}).withMessage('email2Length')],
		[check('password').isStrongPassword().withMessage('passwordStrength').isLength({max: 20}).withMessage('passwordLength')],
		
		function (req, res) {

			/* Whether the Express validator raised any errors (invalid names, email or password) determines whether the form data is posted to database or not.
				If not, error prompts will be sent back to frontend to be displayed to user. Although data is validated before sending from frontend, we still need to
				validate it again because somebody could change it in-transit (using browser developer tools) and potentially crash the server or get access to the db */
			const errors = validationResult(req);
			if (!errors.isEmpty() || !(req.body.userType === 'client' || req.body.userType === 'tutor')) {
				let errMessages = [];
				for (let anError of errors.errors) {
					errMessages.push(anError.msg);
				}
				if (req.body.password !== req.body.confirm) {
					errMessages.push('mismatchedPasswords');
				}
				// if (!(req.body.userType === 'client' || req.body.userType === 'tutor')) {
				// 	errMessages.push('generalError');
				// }
				res.json({
					outcome: 'failure',
					error: errMessages
				})
			} else {
				// Form input all passed the validation checks

				// Check there's not already a user record in db with the email address (we don't want duplicate accounts)
				const checkAlreadyExists = 'SELECT email1 FROM users WHERE email1 = ?;';
				const email1 = req.sanitize(req.body.email1);

				db.query(checkAlreadyExists, [email1], (error, result) => {
					if (error) {
						res.json({
							outcome: 'failure',
							error: 'checking db for existing user failed'
						})
					// If there's a result from the database, we know there's already a user account with that username
					} else if (result.length > 0) {
						// Send message back to frontend
						res.json({
							outcome: 'failure',
							error: 'user already exists'
						})
					
					// At this point, form input passed validation & username isn't already associated wtih an account
					} else {

						// Store the form data from the frontend registration form
						const userType = req.sanitize(req.body.userType);
						const first = req.sanitize(req.body.first);
						const last = req.sanitize(req.body.last);
						const dob = req.sanitize(req.body.dob);
						const email2 = req.sanitize(req.body.email2);
						const password = req.sanitize(req.body.password);

						// Create SQL query string
						let sqlQuery = 'INSERT INTO users (first, last, userType, email1, dob, email2, password) VALUES (?, ?, ?, ?, ?, ?, ?);';

						// Hash the password, then connect to the database and insert new user record in database
						bcrypt.hash(password, saltRounds, function(err, hashedPassword) {
							if (err) res.json({
								outcome: 'failure',
								error: 'bcrypt failed to hash password'
							});
							else {
								const newRecord = [first, last, userType, email1, dob, email2, hashedPassword];
								db.query(sqlQuery, newRecord, (someErr, result) => {
									if (someErr) {
										res.json({
											outcome: 'failure',
											error: 'insertion into db failed'
										})
									} else {
										// Need to get the id property of the record just created & return to frontend with sucsess
										db.query('SELECT * FROM users WHERE email1 = ?', [email1], (anError, user) => {
											if (anError) {
												res.json({
													outcome: 'failure',
													error: 'failed to retrieve id of new record'
												})
											} else {
												req.login(user[0], function (someErr) {
													if (someErr) {
														res.json({
															outcome: 'failure',
															error: 'req.login failed'
														})
													} else {
														// Send confirmation back to frontend
														res.json({
															outcome: 'success',
															userId: user[0].id
														})
													}
												})
											}
										});
									}
								})
							}
						})

					}
				})
			}

  })


	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Route to receive login credentials from frontend, check them against the database and send result back to frontend
	app.post('/login',

		// Check input using validator
		[check('email').matches(emailRegex).withMessage('emailInvalid')],
		[check('password').isStrongPassword().withMessage('passwordInvalid')],

		function (req, res) {
		
			const errors = validationResult(req);
			// If some input sent from frontend failed validation
			if (!errors.isEmpty()) {
				let errMessages = [];
							for (let anError of errors.errors) {
									errMessages.push(anError.msg);
							}
				// Return error messages to frontend
				res.json({
					outcome: 'failure',
					error: errMessages
				})
			// The data received from frontend end is a valid email and password
			} else {
				// Store the credentials sent from frontend. See comment above bodyParser in server/src/app.js for more info about how data is passed from frontend
				const email = req.sanitize(req.body.email);
				const password = req.sanitize(req.body.password);
				// Construct SQL 'prepared statement' to search the database for a record with matching email address
				const sqlQuery = 'SELECT * FROM users WHERE email1 = ?;';
			
				// Execute the SQL query to retrieve matching record (if there is one)
				db.query(sqlQuery, [email], (err, result) => {
					if (err) {
						res.json({
							outcome: 'failure',
							error: 'checking db for user failed'
						})
					// If the result variable is empty, no records were found in the database with matching username
					} else if (result.length < 1) {
						res.json({
							outcome: 'failure',
							error: 'user not found'
						})
					} else {
					// Check the password from the matching db record
						const passwordFromRecord = result[0].password;
						bcrypt.compare(password, passwordFromRecord, function (error, passResult) {
							if (error) {
								res.json({
									outcome: 'failure',
									error: 'bcrypt.compare caused an error'
								})
							} else if (passResult === false) {
								// Passwords didn't match - send failure message back to frontend
								res.json({
									outcome: 'failure',
									error: 'incorrect password'
								})
							} else {
								// Try to create a user session record
								req.login(result[0], function(anErr) {
									if (anErr) {
										res.json({
											outcome: 'failure',
											error: 'req.login failed'
										})
									} else {
										// Send success message back to frontend
										res.json({
											outcome: 'success',
											userId: result[0].id,
											userType: result[0].userType,
											first: result[0].first,
											last: result[0].last
										})
									}
								})
							}
						})
					}
				})
			
			}
	})


	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Logout route/endpoint: deletes user's session record

	app.get('/logout', function (req, res) {
		// Delete the Passportjs user object
		req.logout();
		// Delete the session
		req.session.destroy();
		res.json({loggedOut: true});
	})


	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Route for users to record a subject which either they need help with (client type user) or can teach (tutor type user)
	// used by Onboarding UI component upon successful new registration and maybe later a Profile component

	app.post('/add_subject', isAuth,

		// Check data from frontend using validators
		[check('first').matches(nameRegex)],
		[check('last').matches(nameRegex)],
		[check('userType').isIn(['client', 'tutor'])],
		[check('subject').isIn(subjects)],
		[check('level').isIn(levels)],

		function(req, res) {

			const errors = validationResult(req);
			// If any validators failed, send error message back to UI
			if (!errors.isEmpty()) {
				res.json({
					outcome: 'failure',
					error: 'Invalid data'
				});
			} else {
				// Data from UI is safe but some values could be missing
				const id = req.sanitize(req.body.id);
				const first = req.sanitize(req.body.first);
				const last = req.sanitize(req.body.last);
				const userType = req.sanitize(req.body.userType);
				const subject = req.sanitize(req.body.subject);
				const level = req.sanitize(req.body.level);
				// If any data is missing, return error message to UI
				if (!(id && first && last && subject && level)) {
					res.json({
						outcome: 'failure',
						error: 'Missing data'
					});
				} else {
					// All data is present and valid, insert it into the database
					let sqlQuery = 'INSERT INTO userSubjectLevel (userId, first, last, userType, subject, level) VALUES (?, ?, ?, ?, ?, ?)';
					const params = [id, first, last, userType, subject, level];
					db.query(sqlQuery, params, (err, result) => {
						if (err) {
							res.json({
								outcome: 'failure',
								error: 'SQL insertion failed'
							});
						} else {
							res.json({
								outcome: 'success'
							});
						}
					});
				}
			}
	})

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Route to search the database for members (either tutors or clients) based on subject and/or level of study parameters

	app.post('/search',

		// Basic validation of data from frontend
		[check('userType').isIn(['client', 'tutor'])],
		[check('subject').isIn(subjects)],

		function (req, res) {

			// If any data failed validation, send error message back to frontend
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				res.json({
					oucome: 'failure',
					error: 'Invalid data'
				})
			} else {

				const type = req.sanitize(req.body.userType);
				const subject = req.sanitize(req.body.subject);
				const level = req.sanitize(req.body.level);

				// If the user's a client, search needs to return tutors and if user's a tutor, search should return clients
				let findThese = type === 'client' ? 'tutor' : 'client';
				let sqlQuery = `SELECT * FROM usersubjectlevel WHERE userType = '${findThese}' AND `;
				let params = [];

				// If user's a client, need to search for tutors teaching at appropriate level
				if (type === 'client') {
					// Hence if either value is missing or unrecognised, return error to UI
					if (!(subject && level) || !subjects.includes(subject)) {
						res.json({
							outcome: 'failure',
							error: 'Missing search param'
						})
					} else {
						// Finish writing SQL paramaterised query
						sqlQuery += 'subject = ? AND level = ?;';
						params.push(subject, level);
					}
				} else if (type === 'tutor' && (subject && level)) {
					// Tutors can search for clients who need teaching to a particular level in a subject
					sqlQuery += 'subject = ? AND level = ?;';
					params.push(subject, level);
				} else {
					// Or they can search for all clients needing help at all levels in a particular subject
					sqlQuery += 'subject = ?;';
					params.push(subject);
				}
				db.query(sqlQuery, params, (err, result) => {
					if (err) console.log(err);
					else if (result.length < 1) {
						// No users matched search criteria
						res.json({
							outcome: 'success',
							result: 'Nothing found'
						})
					} else {
						// Send results to UI
						res.json({
							outcome: 'success',
							result: result
						});
					}
				})
			}
		}
	)

	
	// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// // Save a new message to the database

	// app.post('/new-message', isAuth, [check('requestId').isInt({min: 1}).withMessage('generalError')], [check('userLang').matches(userLangRegex).withMessage('generalError')], [check('sender').matches(usernameRegex).withMessage('generalError').isLength({min: 8, max: 25}).withMessage('generalError')], [check('recipient').matches(usernameRegex).withMessage('generalError').isLength({min: 8, max: 25}).withMessage('generalError')], [check('message').isLength({min: 2, max: 500}).withMessage('lengthError')], [check('dateSent').isDate().withMessage('generalError')], [check('timeSent').matches(timeFormatRegex).withMessage('generalError')], function (req, res) {

	// 	// We need to validate that the message sent date from the frontend isn't before the current date
  //       const today = new Date();
  //       today.setHours(0, 0, 0, 0);
  //       const tempDateSent = new Date(req.body.dateSent);
  //       const dateSentInvalid = tempDateSent < today;

	// 	const errors = validationResult(req);
  //       if (!errors.isEmpty()) {
  //           let errMessages = [];
  //           for (let anError of errors.errors) {
	// 			console.log(anError.param);
  //               errMessages.push(anError.msg);
  //           }
  //           res.send(errMessages);
	// 	} else if (dateSentInvalid) {
	// 		res.send(['generalError']);
	// 	} else {
			
	// 		let query = 'INSERT INTO messages(requestId, language, sender, recipient, message, dateSent, timeSent) VALUES(?, ?, ?, ?, ?, ?, ?);';
	// 		const requestId = req.sanitize(req.body.requestId);
	// 		const language = req.sanitize(req.body.userLang);
	// 		const sender = req.sanitize(req.body.sender);
	// 		const recipient = req.sanitize(req.body.recipient);
	// 		const message = req.sanitize(req.body.message);
	// 		const dateSent = req.sanitize(req.body.dateSent);
	// 		const timeSent = req.sanitize(req.body.timeSent);
	// 		const newMessage = [requestId, language, sender, recipient, message, dateSent, timeSent];

	// 		db.query(query, newMessage, (error, result) => {
	// 			if (error) {
	// 				console.log("SQL insertion error");
	// 				res.send(['generalError']);
	// 			} else {
	// 				res.send(['success']);
	// 			}
	// 		})
	// 	}

	// })


	// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// // Retrieve a user's chats/conversations and send them to the React UI

	// app.get('/conversations', isAuth, function (req, res) {
		
	// 	const username = req.sanitize(req.query.username);

	// 	const queryRequestIds = 'SELECT DISTINCT requestId FROM messages WHERE sender = ? OR recipient = ? ;';

	// 	db.query(queryRequestIds, [username, username], (error, result) => {
	// 		if (error) {
	// 			console.log("Error getting unique requestIds");
	// 			res.send(['generalError']);
	// 		} else if (result.length < 1) {
	// 			console.log("User has no messages");
	// 			res.send(['noMessages']);
	// 		} else {
	// 			/* Conversations will hold arrays of Message objects. Each sub-array in conversations will only contain messages objects which share the
  //                       		same requestId property - i.e. messages which all relate to one specific Request object will be grouped in their own sub-array */
	// 			let conversations = [];
	// 			result.forEach(aResult => {
	// 				let convoQuery = `SELECT * FROM messages WHERE requestId = ${aResult.requestId} AND (sender = ? OR recipient = ?);`;
	// 				db.query(convoQuery, [username, username], (err, outcome) => {
  //                       if (err) {
	// 						console.log("Error getting conversations");
  //                           res.send(['generalError']);
  //                       } else {
  //                           conversations.push(outcome);
	// 						if (aResult === result[result.length - 1]) {
	// 							res.send(conversations);
	// 						}
  //                       }
  //                   })
	// 			})
	// 		}
	// 	})

	// })
	

	// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// // Retrieve an updated (when a new reply has been sent) list of messages in a conversation and send back to the React UI

	// app.get('/messages', isAuth, function (req, res) {

	// 	const username = req.sanitize(req.query.username);
	// 	const requestId = req.sanitize(req.query.requestId);
	// 	const query = 'SELECT * FROM messages WHERE requestId = ? AND (sender = ? OR recipient = ?);';

	// 	db.query(query, [requestId, username, username], (error, result) => {
	// 		if (error) {
	// 			console.log("Error getting messages in chat from database");
	// 			res.send(['generalError']);
	// 		} else if (result.length < 1) {
	// 			res.send(['noMessages'])
	// 		} else {
	// 			res.send(result);
	// 		}
	// 	})

	// })

	
	// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// // Delete the message with the specified messageId

	// app.delete('/delete-message/:id', isAuth, function (req, res) {
	// 	const messageId = req.params.id;
	// 	const query = 'DELETE FROM messages WHERE messageId = ?;';

	// 	db.query(query, [messageId], (err, result) => {
	// 		if (err) {
	// 			console.log(err);
	// 			res.send(['deletionFailed']);
	// 		} else {
	// 			res.send(['success']);
	// 		}
	// 	})
	// })

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
}
