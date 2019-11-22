// Copyright IBM Corp. 2015. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.


const SG = require('strong-globalize');

const g = SG();
const async = require('async');
const oauth2Provider = require('./oauth2orize');
const scopeValidator = require('./scope');
const helpers = require('./oauth2-helper');
const TokenError = require('./errors/tokenerror');
const debug = require('debug')('loopback:oauth2');
const passport = require('passport');
const jwt = require('jws');
const BearerStrategy = require('passport-http-bearer').Strategy;
const MacStrategy = require('./strategy/mac').Strategy;

const { clientInfo } = helpers;
const { userInfo } = helpers;
const { isExpired } = helpers;

module.exports = setupResourceServer;

/**
 * Set up oAuth 2.0 strategies
 * @param {Object} app App instance
 * @param {Object} options Options
 * @param {Object} models oAuth 2.0 metadata models
 * @param {Boolean} jwt if jwt-bearer should be enabled
 * @returns {Function}
 */
function setupResourceServer(app, options, models) {
  function checkAccessToken(req, accessToken, done) {
    debug('Verifying access token %s', accessToken);
    models.accessTokens.find(accessToken, (err, token) => {
      if (err || !token) {
        return done(err);
      }

      debug('Access token found: %j', token);

      if (isExpired(token)) {
        return done(new TokenError(g.f('Access token is expired'),
          'invalid_grant'));
      }

      const userId = token.userId || token.resourceOwner;
      const appId = token.appId || token.clientId;

      let user; let
        app;
      async.parallel([
        function lookupUser(done) {
          if (userId == null) {
            return process.nextTick(done);
          }
          models.users.find(userId, (err, u) => {
            if (err) {
              return done(err);
            }
            if (!u) {
              return done(
                new TokenError(g.f('Access token has invalid {{user id}}: %s', userId), 'invalid_grant'),
              );
            }
            debug('User found: %s', userInfo(u));
            user = u;
            done();
          });
        },
        function lookupApp(done) {
          if (appId == null) {
            return process.nextTick(done);
          }
          models.clients.find(appId, (err, a) => {
            if (err) {
              return done(err);
            }
            if (!a) {
              return done(
                new TokenError(g.f('Access token has invalid {{app id}}: %s', appId), 'invalid_grant'),
              );
            }
            debug('Client found: %s', clientInfo(a));
            app = a;
            done();
          });
        }], (err) => {
        if (err) {
          return done(err);
        }
        if (options.addHttpHeaders) {
          let prefix = 'X-OAUTH2-';
          if (typeof options.addHttpHeaders === 'string') {
            prefix = options.addHttpHeaders;
          }
          if (appId != null) {
            req.headers[`${prefix}CLIENT-ID`] = appId;
          }
          if (userId != null) {
            req.headers[`${prefix}USER-ID`] = userId;
          }
        }
        const authInfo = {
          accessToken: token, user, app, client: app,
        };
        done(null, user || {}, authInfo);
      });
    });
  }

  let verifyAccessToken = checkAccessToken;
  if (typeof options.checkAccessToken === 'function') {
    verifyAccessToken = options.checkAccessToken;
  }

  function accessTokenValidator(req, accessToken, done) {
    verifyAccessToken(req, accessToken, (err, user, info) => {
      if (!err && info) {
        req.accessToken = info.accessToken;
      }
      done(err, user, info);
    });
  }

  /**
   * BearerStrategy
   *
   * This strategy is used to authenticate users based on an access token (aka a
   * bearer token).  The user must have previously authorized a client
   * application, which is issued an access token to make requests on behalf of
   * the authorizing user.
   */
  passport.use('loopback-oauth2-bearer',
    new BearerStrategy({ passReqToCallback: true }, accessTokenValidator));

  passport.use('loopback-oauth2-mac',
    new MacStrategy({ passReqToCallback: true, jwtAlgorithm: 'HS256' },
      ((req, accessToken, done) => {
        accessTokenValidator(req, accessToken, (err, user, info) => {
          if (err || !user) {
            return done(err, user, info);
          }
          const client = info && info.client;
          const secret = client.clientSecret || client.restApiKey;
          try {
            const token = jwt.verify(accessToken, 'HS256', secret);
            debug('JWT token verified: %j', token);
          } catch (err) {
            debug('Fail to verify JWT: %j', err);
            done(err);
          }
          done(null, user, info);
        });
      })));

  /**
   * Return the middleware chain to enforce oAuth 2.0 authentication and
   * authorization
   * @param {Object} [options] Options object
   * - scope
   * - jwt
   */
  function authenticate(options) {
    options = options || {};
    debug('Setting up authentication:', options);

    let authenticators = [];
    authenticators = [
      passport.authenticate(['loopback-oauth2-bearer', 'loopback-oauth2-mac'],
        options)];
    if (options.scopes || options.scope) {
      authenticators.push(scopeValidator(options));
    }
    authenticators.push(oauth2Provider.errorHandler());
    return authenticators;
  }

  return authenticate;
}
