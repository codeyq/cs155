import express from 'express';
import sqlite from 'sqlite';

import { asyncMiddleware } from './utils/asyncMiddleware';
import { generateRandomness, HMAC, KDF, checkPassword } from './utils/crypto';

const router = express.Router();
const dbPromise = sqlite.open('./db/database.sqlite', { cached: true });

function render(req, res, next, page, title, errorMsg = false, result = null) {
  res.render(
    'layout/template', {
      page,
      title,
      loggedIn: req.session.loggedIn,
      account: req.session.account,
      errorMsg,
      result,
    }
  );
}


router.get('/', (req, res, next) => {
  render(req, res, next, 'index', 'Bitbar Home');
});


router.post('/set_profile', asyncMiddleware(async (req, res, next) => {
  req.session.account.profile = req.body.new_profile;
  console.log(req.body.new_profile);
  const db = await dbPromise;
  const query = `UPDATE Users SET profile = ? WHERE username = "${req.session.account.username}";`;
  const result = await db.run(query, req.body.new_profile);
  render(req, res, next, 'index', 'Bitbar Home');

}));


router.get('/login', (req, res, next) => {
  render(req, res, next, 'login/form', 'Login');
});


router.post('/post_login', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  const query = `SELECT * FROM Users WHERE username == "${req.body.username}";`;
  const result = await db.get(query);
  if(result) { // if this username actually exists
    if(checkPassword(req.body.password, result)) { // if password is valid
      req.session.loggedIn = true;
      req.session.account = result;
      render(req, res, next, 'login/success', 'Bitbar Home');
      return;
    }
  }
  render(req, res, next, 'login/form', 'Login', 'This username and password combination does not exist!');
}));


router.get('/register', (req, res, next) => {
  render(req, res, next, 'register/form', 'Register');
});


router.post('/post_register', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.username}";`;
  let result = await db.get(query);
  if(result) { // query returns results
    if(result.username === req.body.username) { // if username exists
      render(req, res, next, 'register/form', 'Register', 'This username already exists!');
      return;
    }
  }
  const salt = generateRandomness();
  const hashedPassword = KDF(req.body.password, salt);
  query = `INSERT INTO Users(username, hashedPassword, salt, profile, bitbars) VALUES(?, ?, ?, ?, ?)`;
  await db.run(query, [req.body.username, hashedPassword, salt, '', 100]);
  req.session.loggedIn = true;
  req.session.account = {
    username: req.body.username,
    hashedPassword,
    salt,
    profile: '',
    bitbars: 100,
  };
  render(req, res, next,'register/success', 'Bitbar Home');
}));


router.get('/close', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  const db = await dbPromise;
  const query = `DELETE FROM Users WHERE username == "${req.session.account.username}";`;
  await db.get(query);
  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', 'Deleted account successfully!');
}));


router.get('/logout', (req, res, next) => {
  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
});


router.get('/profile', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(req.query.username != null) { // if visitor makes a search query
    const db = await dbPromise;
    const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
    let result;
    try {
      result = await db.get(query);
    } catch(err) {
      result = false;
    }
    if(result) { // if user exists
      render(req, res, next, 'profile/view', 'View Profile', false, result);
    }
    else { // user does not exist
      render(req, res, next, 'profile/view', 'View Profile', `${req.query.username} does not exist!`, req.session.account);
    }
  } else { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account);
  }
}));


router.get('/transfer', (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  render(req, res, next, 'transfer/form', 'Transfer Bitbars', false, {receiver:null, amount:null});
});


router.post('/post_transfer', asyncMiddleware(async(req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(req.body.destination_username === req.session.account.username) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'You cannot send money to yourself!', {receiver:null, amount:null});
    return;
  }

  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.destination_username}";`;
  const receiver = await db.get(query);
  if(receiver) { // if user exists
    const amount = parseInt(req.body.quantity);
    if(Number.isNaN(amount) || amount > req.session.account.bitbars || amount < 1) {
      render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Invalid transfer amount!', {receiver:null, amount:null});
      return;
    }

    req.session.account.bitbars -= amount;
    query = `UPDATE Users SET bitbars = "${req.session.account.bitbars}" WHERE username == "${req.session.account.username}";`;
    await db.exec(query);
    const receiverNewBal = receiver.bitbars + amount;
    query = `UPDATE Users SET bitbars = "${receiverNewBal}" WHERE username == "${receiver.username}";`;
    await db.exec(query);
    render(req, res, next, 'transfer/success', 'Transfer Complete', false, {receiver, amount});
  } else { // user does not exist
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'This user does not exist!', {receiver:null, amount:null});
  }
}));


router.get('/steal_cookie', (req, res, next) => {
  let stolenCookie = req.query.cookie;
  console.log('\n\n' + stolenCookie + '\n\n');
  render(req, res, next, 'theft/view_stolen_cookie', 'Cookie Stolen!', false, stolenCookie);
});


module.exports = router;
