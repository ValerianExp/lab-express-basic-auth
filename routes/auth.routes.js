const router = require('express').Router();
const UserModel = require('../models/User.model');
const bcrypt = require('bcryptjs');
const SALT = Number(process.env.SALT);

// GET route ==> to display the signup form to users
router.get('/signup', (req, res) => {
    res.render('auth/signup');
});

// POST route ==> to process form data
router.post('/signup', (req, res, next) => {
    const { username, email, password } = req.body;
    bcrypt
        .genSalt(10)
        .then(salt => bcrypt.hash(password, SALT))
        .then(hashedPassword => {
            return UserModel.create({
                username,
                email,
                passwordHash: hashedPassword
            });
        })
        .then(userFromDB => {
            // You signup, and then you save the user in the session
            // req.session.user = userFromDB;
            console.log('Newly created user is: ', userFromDB);
            res.redirect('/profile');
        })
        .catch(err => next(err));
});

// GET route ==> to display the login form to users
router.get('/login', (req, res) => {
    res.render('auth/login');
});

// POST route ==> to process form data
router.post('/login', (req, res, next) => {
    const { username, password } = req.body;
    // console.log('SESSION =====> ', req.session);
    if (username === '' || password === '') {
        res.render('auth/login', {
            errorMessage: 'Please enter both, username and password to login.'
        });
        return;
    }
    UserModel.findOne({ username })
        .then(user => {
            if (!user) {
                res.render('auth/login', {
                    errorMessage: 'Username is not registered. Try with other username.'
                });
                return;
            } else if (bcrypt.compareSync(password, user.password)) {
                req.session.user = user;
                res.redirect('/profile');
            } else {
                res.render('auth/login', {
                    errorMessage: 'Incorrect password.'
                });
            }
        })
        .catch(err => next(err));
});


module.exports = router;