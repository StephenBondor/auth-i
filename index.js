const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const morgan = require('morgan');
const helmet = require('helmet');
const knex = require('knex');
const knexConfig = require('./knexfile.js');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);

const db = knex(knexConfig.development);

const server = express();

const sessionConfig = {
	name: 'ape', //default is sid
	secret:
		'alksjdfhalskjdhlkajshdfliuaht98h497fh7sdhv87qhp7hqperg9a8s7hg90a8shrf',
	cookie: {
		maxAge: 1000 * 15, //10 minutes
		secure: false //only send the cookie over https, in production = true, otherwise, false
	},
	httpOnly: true, //JS can't touch this cookie
	resave: false, //compliance with law????
	saveUninitialized: false, //also compliance
	store: new KnexSessionStore({
		tablename: 'sessions',
		sidfieldname: 'sid',
		knex: db,
		createtable: true, //if it doesnt exist, create it
		clearInterval: 1000 * 60 * 10 //clears out expired sessions every 10 min
	})
};

server.use(express.json());
server.use(cors());
server.use(morgan());
server.use(session(sessionConfig));
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
				req.session.user = user;
				res.status(200).json({message: 'Logged in'});
			} else {
				res.status(401).json({message: 'You shall not pass!'});
			}
		})
		.catch(err => res.status(500).json({message: 'bad user name'}));
});

//logout
server.get('/api/logout', (req, res) => {
	if (req.session) {
		req.session.destroy(err => {
			if (err) {
				res.status(500).status('you can not log out');
			} else {
				res.status(200).send('bye bye');
			}
		});
	} else {
		res.json({message: 'logged out already'});
	}
});

function protected(req, res, next) {
	//if the user is logged in call next otherwise bounce
	if (req.session && req.session.user) {
		next();
	} else {
		res.status(401).json({
			message: 'you shall not pass cus your not logged in'
		});
	}
}

// protect this route, only authenticated users should see it
server.get('/api/users', protected, (req, res) => {
	db('users')
		.select('id', 'username')
		.then(users => {
			res.json(users);
		})
		.catch(err => res.send(err));
});

const port = 3300;
server.listen(port, function() {
	console.log(`\n=== Web API Listening on http://localhost:${port} ===\n`);
});
