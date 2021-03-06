const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');

// session: false so that it doesn't use cookies
const requireAuth = passport.authenticate('jwt', { session: false });
const requireSignin = passport.authenticate('local', { session: false });

module.exports = function(app) {
  app.get('/', requireAuth, function(req, res) {
    res.send({ message: 'Super secret code is ALEXISCOOL' });
  });
  app.post('/signin', requireSignin, Authentication.signin)
  app.post('/signup', Authentication.signup);
}