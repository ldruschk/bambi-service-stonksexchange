var express = require('express');
const app = require('../app');
const argon2 = require('argon2');
var router = express.Router();

/* GET home page. */
router.get('/', function (req, res, next) {
  res.render('index', { title: 'Stonks Exchange' });
});

router.get('/about', function (req, res, next) {
  res.render('about', { title: 'About' });
});

router.get('/login', function (req, res, next) {
  res.render('login', { title: 'Login' });
});

router.get('/register', function (req, res, next) {
  res.render('register', { title: 'Register' });
});

router.get('/messages', function (req, res, next) {
  if (!req.session.user) {
    res.status(403).send('Not logged in');
    return;
  }
  var db = req.app.locals.db;
  db.collection('messages').find({ 'username': req.session.user }, { 'sort': { '$natural': -1 } }).limit(50).toArray((err, results) => {
    if (err) {
      res.status(500).send('Internal server error');
      return;
    }
    res.locals.messages = results;
    res.render('messages', { title: 'Messages' });
  });
});

router.get('/logout', function (req, res, next) {
  req.session.destroy(function (err) {
    if (err) throw err;
    res.redirect('/');
  });
});

router.post('/login', function (req, res) {
  if (!req.body.username || !req.body.password) {
    res.status(400).send('Missing username or password');
    return;
  }
  var db = req.app.locals.db;
  db.collection('users').findOne({ 'username': req.body.username }, { 'sort': { '$natural': -1 } }).then(results => {
    if (!results) {
      res.status(400).send('Invalid username or password');
      return;
    }
    argon2.verify(results.password, req.body.password).then(result => {
      if (!result) {
        res.status(400).send('Invalid username or password');
        return;
      }
      req.session.user = req.body.username;
      res.redirect('/');
    });
  });
});

router.post('/register', function (req, res, next) {
  if (!req.body.username || !req.body.password) {
    res.status(400).send('Missing username or password');
    return;
  }
  var db = req.app.locals.db;
  db.collection('users').findOne({ 'username': req.body.username }).then(results => {
    if (results) {
      res.status(400).send('Username already in use');
      return;
    }
    argon2.hash(req.body.password).then(hash => {
      db.collection('users').insertOne({ 'username': req.body.username, 'password': hash }).then(results => {
        req.session.user = req.body.username;
        res.redirect('/');
      });
    });
  });
});

router.post('/message', function (req, res, next) {
  if (!req.body.username || !req.body.message) {
    res.status(400).send('Missing username or message');
    return;
  }
  var db = req.app.locals.db;
  db.collection('messages').insertOne({ 'username': req.body.username, 'message': req.body.message, 'from': req.session.user }).then(results => {
    res.redirect('/messages');
  });
});

module.exports = router;
