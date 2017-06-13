const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  // the sub(ject) of this token is the users id
  // iat = issued at time
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret)
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if(!email || !password) {
    return res.status(422).send({ error: 'email and password are required'});
  }

  // see if a user with a given email exists
  User.findOne({ email: email }, function(err, existingUser) {
    if(err) { return next(err); }

    // if a user with an email does exist, return an error
    if(existingUser) {
      return res.status(422).send({ error: 'Email is already in use' });
    }

    // if a user with email does not exist, create and save record
    const user = new User({
      email: email,
      password: password
    });

    user.save(function(err) {
      if(err) { return next(err); }

    // respond to the request indicating the user was created
    res.json({token: tokenForUser(user)});
    });

  });
  

}