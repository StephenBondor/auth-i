const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const morgan = require('morgan');
const helmet = require('helmet');
const knex = require('knex');
const knexConfig = require('./knexfile.js');

const db = knex(knexConfig.development);
let logedIn = false;
const server = express();

server.use(express.json());
server.use(cors());
server.use(morgan());
server.use(helmet());

server.get('/', (req, res) => {
	res.send('API running');
});

//register
server.post('/api/register', (req, res) => {
	///grab username and passowrd
	const creds = req.body;

	//generate the hash from the user passowrd
	const hash = bcrypt.hashSync(creds.password, 14);

	//override the user.password with the hash
	creds.password = hash;

	// save the user to the database
	db('users')
		.insert(creds)
		.then(ids => res.status(201).json(ids))
		.catch(err => res.status(500).json(err));
});

//login
server.post('/api/login', (req, res) => {
	///grab username and passowrd
	const creds = req.body;
	db('users')
		.where({username: creds.username})
		.first()
		.then(user => {
			if (user && bcrypt.compareSync(creds.password, user.password)) {
				logedIn = true;
				res.status(200).json({message: 'Logged in'});
			} else {
				res.status(401).json({message: 'You shall not pass!'});
			}
		})
		.catch(err => res.status(500).json({message: 'bad user name'}));
});

//logout
server.post('/api/logout', (req, res) => {
	///log out if logged in
	if (logedIn) {
        logedIn = false;
        res.send({message : "Successfully logged out"})
	} else{
        res.send({message: 'Not logged in'})
    }
});

// protect this route, only authenticated users should see it
server.get('/api/users', (req, res) => {
	if (logedIn) {
		db('users')
			.select('id', 'username')
			.then(users => {
				res.json(users);
			})
			.catch(err => res.send(err));
	} else {
		res.send({
			message:
				'You are not logged in, and thus can not view those resourses'
		});
	}
});

const port = 3300;
server.listen(port, function() {
	console.log(`\n=== Web API Listening on http://localhost:${port} ===\n`);
});
