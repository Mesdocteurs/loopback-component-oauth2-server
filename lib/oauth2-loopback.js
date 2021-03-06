/* ************************************************************************************ */
/*     __  __           ____             _                                              */
/*    |  \/  | ___  ___|  _ \  ___   ___| |_ ___ _   _ _ __ ___   ___ ___  _ __ ___     */
/*    | |\/| |/ _ \/ __| | | |/ _ \ / __| __/ _ \ | | | '__/ __| / __/ _ \| '_ ` _ \    */
/*    | |  | |  __/\__ \ |_| | (_) | (__| ||  __/ |_| | |  \__ \| (_| (_) | | | | | |   */
/*    |_|  |_|\___||___/____/ \___/ \___|\__\___|\__,_|_|  |___(_)___\___/|_| |_| |_|   */
/*                                                                                      */
/*     oauth2-loopback.js                                                               */
/*                                                                                      */
/*     By: Marshall Chan <yahoohung@gmail.com>                                          */
/*                                                                                      */
/*     created: 15/09/17 12:22:42 by Marshall Chan                                      */
/*     updated: 08/07/20 17:31:09 by Guillaume Torresani                                */
/*                                                                                      */
/* ************************************************************************************ */

// Copyright IBM Corp. 2014,2015. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.


/**
 * Module dependencies.
 */
const SG = require('strong-globalize');

const g = SG();
const url = require('url');
const oauth2Provider = require('./oauth2orize');
const TokenError = require('./errors/tokenerror');
const AuthorizationError = require('./errors/authorizationerror');
const utils = require('./utils');
const helpers = require('./oauth2-helper');
const MacTokenGenerator = require('./mac-token');
const modelBuilder = require('./models/index');
const debug = require('debug')('loopback:oauth2');
const passport = require('passport');
const login = require('connect-ensure-login');
const LocalStrategy = require('passport-local').Strategy;
const { BasicStrategy } = require('passport-http');
const ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
const ClientJWTBearerStrategy = require('./strategy/jwt-bearer').Strategy;
const bodyParser = require('body-parser');

const { clientInfo } = helpers;
const { userInfo } = helpers;
const { isExpired } = helpers;
const { validateClient } = helpers;

const setupResourceServer = require('./resource-server');

/**
 *
 * @param {Object} app The app instance
 * @param {Object} options The options object
 * @property {Function} generateToken A custom function to generate tokens
 * @property {boolean} session
 * @property {String[]} supportedGrantTypes
 * @property {boolean} configureEndpoints
 * @returns {{}}
 */
module.exports = function (app, options) {
  options = options || {};
  const models = modelBuilder(app, options);

  const handlers = {};
  app._oauth2Handlers = handlers;

  // Default to true
  const session = (options.session !== false);

  app.middleware('auth:before', passport.initialize());
  if (session) {
    app.middleware('auth', passport.session());
  }

  if (options.resourceServer !== false) {
    handlers.authenticate = setupResourceServer(app, options, models, true);
  }

  if (options.authorizationServer === false) {
    // Skip the configuration of protocol endpoints
    return handlers;
  }

  const macTokenGenerator = new MacTokenGenerator('sha256');

  const generateToken = options.generateToken || function (options) {
    options = options || {};
    const id = utils.uid(32);
    if (options.client && options.client.tokenType === 'jwt') {
      const secret = options.client.clientSecret || options.client.restApiKey;
      const payload = {
        id,
        clientId: options.client.id,
        userId: options.user && options.user.id,
        scope: options.scope,
        createdAt: new Date(),
      };
      const token = helpers.generateJWT(payload, secret, 'HS256');
      return {
        id: token,
      };
    } if (options.client && options.client.tokenType === 'mac') {
      options.jwtAlgorithm = 'HS256'; // HS256 for mac token
      return macTokenGenerator.generateToken(options);
    }
    return {
      id,
    };
  };

  // create OAuth 2.0 server
  const server = oauth2Provider.createServer();

  /*
     Register serialization and deserialization functions.

     When a client redirects a user to user authorization endpoint, an
     authorization transaction is initiated.  To complete the transaction, the
     user must authenticate and approve the authorization request.  Because this
     may involve multiple HTTP request/response exchanges, the transaction is
     stored in the session.

     An application must supply serialization functions, which determine how the
     client object is serialized into the session.  Typically this will be a
     simple matter of serializing the client's ID, and deserializing by finding
     the client by ID from the database.
     */
  if (session) {
    server.serializeClient((client, done) => {
      debug('serializeClient: %s', clientInfo(client));
      return done(null, client.id);
    });

    server.deserializeClient((id, done) => {
      debug('deserializeClient: %s', id);
      models.clients.findByClientId(id, done);
    });
  }

  const supportedGrantTypes = options.supportedGrantTypes || ['authorizationCode', 'implicit', 'clientCredentials',
    'resourceOwnerPasswordCredentials', 'refreshToken', 'jwt',
  ];

  /*
     Register supported grant types.

     OAuth 2.0 specifies a framework that allows users to grant client
     applications limited access to their protected resources.  It does this
     through a process of the user granting access, and the client exchanging
     the grant for an access token.

     Grant authorization codes.  The callback takes the `client` requesting
     authorization, the `redirectURI` (which is used as a verifier in the
     subsequent exchange), the authenticated `user` granting access, and
     their response, which contains approved scope, duration, etc. as parsed by
     the application.  The application issues a code, which is bound to these
     values, and will be exchanged for an access token.
     */
  let codeGrant;
  if (supportedGrantTypes.indexOf('authorizationCode') !== -1) {
    codeGrant = server.grant(oauth2Provider.grant.code({ allowsPost: options.allowsPostForAuthorization, authorizePage: options.authorizePage },
      (client, redirectURI, user, scope, ares, req, done) => {
        if (validateClient(client, {
          scope,
          redirectURI,
          grantType: 'authorization_code',
        }, done)) {
          return;
        }

        const field = options.transactionField || 'transaction_id';
        const key = options.sessionKey || 'authorize';
        const tid = req.body[field];

        let claims = {};
        if (req.query.claims) {
          try {
            claims = JSON.parse(req.query.claims);
          } catch (e) {}
        } else if (tid && req.session[key][tid]) {
          const txn = req.session[key][tid];
          claims = txn.req.claims;
        }

        function generateAuthCode() {
          const code = generateToken({
            grant: 'Authorization Code',
            client,
            user,
            scope,
            redirectURI,
          }).id;

          debug('Generating authorization code: %s %s %s %s %s',
            code, clientInfo(client), redirectURI, userInfo(user), scope);
          const connectionToken = (req.cookies && req.cookies.token) ? req.cookies.token : null;
          models.authorizationCodes.save(code, client.id, redirectURI,
            user.id,
            scope,
            claims,
            connectionToken,
            (err) => {
              done(err, err ? null : code, options);
            });
        }

        if (ares.authorized) {
          generateAuthCode();
        } else {
          models.permissions.addPermission(client.id, user.id, scope, claims,
            (err) => {
              if (err) {
                return done(err);
              }
              generateAuthCode();
            });
        }
      }));

    /*
         Exchange authorization codes for access tokens.  The callback accepts the
         `client`, which is exchanging `code` and any `redirectURI` from the
         authorization request for verification.  If these values are validated, the
         application issues an access token on behalf of the user who authorized the
         code.
         */
    server.exchange(oauth2Provider.exchange.code(
      (client, code, redirectURI, req, done) => {
        debug('Verifying authorization code: %s %s %s',
          code, clientInfo(client), redirectURI);

        models.authorizationCodes.findByCode(code, (err, authCode) => {
          if (err || !authCode) {
            return done(err);
          }

          debug('Authorization code found: %j', authCode);

          const clientId = authCode.appId || authCode.clientId;
          const resourceOwner = authCode.userId || authCode.resourceOwner;

          // The client id can be a number instead of string
          if (client.id != clientId) {
            return done(new TokenError(g.f('Client id mismatches'),
              'invalid_grant'));
          }
          if (redirectURI != authCode.redirectURI) {
            return done(new TokenError(g.f('Redirect {{uri}} mismatches'),
              'invalid_grant'));
          }

          if (isExpired(authCode)) {
            return done(new TokenError(g.f('Authorization code is expired'),
              'invalid_grant'));
          }

          const token = generateToken({
            grant: 'Authorization Code',
            client,
            scope: authCode.scopes,
            code: authCode,
            redirectURI,
          });

          const refreshToken = generateToken({
            grant: 'Authorization Code',
            client,
            code: authCode,
            scope: authCode.scopes,
            redirectURI,
            refreshToken: true,
          }).id;

          debug('Generating access token: %j %s %s',
            token, clientInfo(client), redirectURI);

          // Remove the authorization code
          models.authorizationCodes.delete(code, (err) => {
            if (err) return done(err);

            models.accessTokens.save(token.id, clientId,
              resourceOwner, authCode.scopes, authCode.claims, refreshToken, authCode.connectionToken,
              getTokenHandler(token, done));
          });
        });
      },
    ));
  }

  function userLogin(username, password, done) {
    debug('userLogin: %s', username);
    models.users.findByUsernameOrEmail(username, (err, user) => {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false);
      }
      user.hasPassword(password, (err, matched) => {
        if (err || !matched) {
          return done(err, false);
        }
        done(null, user);
      });
    });
  }

  function getTokenHandler(params, done) {
    return function (err, accessToken) {
      if (err || !accessToken) {
        return done(err);
      }
      done(null, accessToken.id, helpers.buildTokenParams(accessToken, params), options, accessToken);
    };
  }

  /*
     * Handle password flow
     */
  if (supportedGrantTypes.indexOf('resourceOwnerPasswordCredentials') !== -1) {
    server.exchange(oauth2Provider.exchange.password(
      (client, username, password, scope, done) => {
        debug('Verifying username/password: %s %s %s',
          clientInfo(client), username, scope);

        if (validateClient(client, {
          scope,
          grantType: 'password',
        }, done)) {
          return;
        }

        userLogin(username, password, (err, user) => {
          if (err || !user) {
            return done(err, null);
          }
          const token = generateToken({
            grant: 'Resource Owner Password Credentials',
            client,
            user,
            scope,
          });

          const refreshToken = generateToken({
            grant: 'Resource Owner Password Credentials',
            client,
            user,
            scope,
            refreshToken: true,
          }).id;

          debug('Generating access token: %j %s %s %s',
            token, clientInfo(client), username, scope);

          models.accessTokens.save(token.id, client.id, user.id,
            scope, {}, refreshToken, null, getTokenHandler(token, done));
        });
      },
    ));
  }

  /*
     * Client credentials flow
     */
  if (supportedGrantTypes.indexOf('clientCredentials') !== -1) {
    server.exchange(oauth2Provider.exchange.clientCredentials(
      (client, subject, scope, req, done) => {
        if (validateClient(client, {
          scope,
          grantType: 'client_credentials',
        }, done)) {
          return;
        }

        function generateAccessToken(user) {
          const token = generateToken({
            grant: 'Client Credentials',
            client,
            user,
            scope,
          });
          debug('Generating access token: %j %s %s',
            token, clientInfo(client), scope);

          const refreshToken = generateToken({
            grant: 'Client Credentials',
            client,
            user,
            scope,
            refreshToken: true,
          }).id;
          const connectionToken = (req.cookies && req.cookies.token) ? req.cookies.token : null;
          models.accessTokens.save(
            token.id, client.id, user && user.id, scope, {}, refreshToken, connectionToken,
            getTokenHandler(token, done),
          );
        }

        if (subject) {
          models.users.findByUsernameOrEmail(subject, (err, user) => {
            if (err) {
              return done(err);
            }
            if (!user) {
              return done(new AuthorizationError(g.f(
                'Invalid subject: %s', subject,
              ), 'access_denied'));
            }
            models.permissions.isAuthorized(client.id, user.id, scope, {},
              (err, authorized) => {
                if (err) {
                  return done(err);
                }
                if (authorized) {
                  generateAccessToken(user);
                } else {
                  return done(new AuthorizationError(g.f(
                    'Permission denied by %s', subject,
                  ), 'access_denied'));
                }
              });
          });
        } else {
          generateAccessToken();
        }
      },
    ));
  }

  /*
     * Refresh token flow
     */
  if (supportedGrantTypes.indexOf('refreshToken') !== -1) {
    server.exchange(oauth2Provider.exchange.refreshToken(
      (client, refreshToken, scope, req, done) => {
        if (validateClient(client, {
          scope,
          grantType: 'refresh_token',
        }, done)) {
          return;
        }

        models.accessTokens.findByRefreshToken(refreshToken,
          (err, accessToken) => {
            if (err || !accessToken) {
              // Refresh token is not found
              return done(err, false);
            }
            if (accessToken.appId != client.id) {
              // The client id doesn't match
              return done(null, false);
            }

            // Test if scope is a subset of accessToken.scopes
            if (scope) {
              for (let i = 0, n = scope.length; i < n; i++) {
                if (accessToken.scopes.indexOf(scope[i]) === -1) {
                  return done(null, false);
                }
              }
            } else {
              scope = accessToken.scopes;
            }

            const token = generateToken({
              grant: 'Refresh Token',
              client,
              scope,
            });

            const refreshToken = generateToken({
              grant: 'Refresh Token',
              client,
              scope,
              refreshToken: true,
            }).id;

            debug('Generating access token: %j %s %s %j',
              token, clientInfo(client), scope, refreshToken);

            const connectionToken = (req.cookies && req.cookies.token) ? req.cookies.token : null;
            models.accessTokens.save(token.id, client.id, accessToken.userId,
              scope, accessToken.claims, refreshToken, connectionToken, getTokenHandler(token, done));
          });
      },
    ));
  }

  let tokenGrant;
  if (supportedGrantTypes.indexOf('implicit') !== -1) {
    tokenGrant = server.grant(oauth2Provider.grant.token({ allowsPost: options.allowsPostForAuthorization },
      (client, user, scope, ares, req, done) => {
        if (validateClient(client, {
          scope,
          grantType: 'implicit',
        }, done)) {
          return;
        }

        function generateAccessToken() {
          const token = generateToken({
            grant: 'Implicit',
            client,
            user,
            scope,
          });
          debug('Generating access token: %j %s %s %s',
            token, clientInfo(client), userInfo(user), scope);

          const connectionToken = (req.cookies && req.cookies.token) ? req.cookies.token : null;
          models.accessTokens.save(token.id, client.id, user.id, scope, {}, null, connectionToken,
            getTokenHandler(token, done));
        }

        if (ares.authorized) {
          generateAccessToken();
        } else {
          models.permissions.addPermission(client.id, user.id, scope, {},
            (err) => {
              if (err) {
                return done(err);
              }
              generateAccessToken();
            });
        }
      }));
  }

  const jwtAlgorithm = options.jwtAlgorithm || 'RS256';
  if (supportedGrantTypes.indexOf('jwt') !== -1) {
    const jwt = require('jws');

    server.exchange('urn:ietf:params:oauth:grant-type:jwt-bearer',
      oauth2Provider.exchange.jwt((client, jwtToken, done) => {
        debug('Verifying JWT: %s %s', clientInfo(client), jwtToken);
        const pub = client.jwks || client.publicKey;
        let decodedJWT;
        try {
          if (jwt.verify(jwtToken, jwtAlgorithm, pub)) {
            decodedJWT = jwt.decode(jwtToken);
            debug('Decoded JWT: %j', decodedJWT);
          } else {
            done(new Error(g.f('Invalid {{JWT}}: %j', jwtToken)));
          }
        } catch (err) {
          return done(err);
        }
        // TODO - verify client_id, scope and expiration are valid
        const payload = JSON.parse(decodedJWT.payload);

        if (validateClient(client, {
          scope: payload.scope,
          grantType: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        }, done)) {
          return;
        }

        function generateAccessToken(user) {
          const token = generateToken({
            grant: 'JWT',
            client,
            user,
            claims: payload,
          });
          debug('Generating access token %j %s %s', token,
            clientInfo(client), jwtToken);
          // Check OAuthPermission model to see if it's pre-approved
          models.accessTokens.save(
            token.id, client.id, user && user.id, payload.scope, {}, null, null,
            getTokenHandler(token, done),
          );
        }

        if (payload.sub) {
          models.users.findByUsernameOrEmail(payload.sub, (err, user) => {
            if (err) {
              return done(err);
            }
            if (!user) {
              return done(new AuthorizationError(g.f(
                'Invalid subject: %s', payload.sub,
              ), 'access_denied'));
            }
            models.permissions.isAuthorized(client.id, user.id, payload.scope, {},
              (err, authorized) => {
                if (err) {
                  return done(err);
                }
                if (authorized) {
                  generateAccessToken(user);
                } else {
                  done(new AuthorizationError(g.f(
                    'Permission denied by %s', payload.sub,
                  ), 'access_denied'));
                }
              });
          });
        } else {
          generateAccessToken();
        }
      }));
  }

  function ensureLoggedIn(option) {
    if (options.ensureLoggedIn) {
      return options.ensureLoggedIn(option);
    } else {
      return login.ensureLoggedIn(option);
    }
  }
  /*
     user authorization endpoint

     `authorization` middleware accepts a `validate` callback which is
     responsible for validating the client making the authorization request.  In
     doing so, is recommended that the `redirectURI` be checked against a
     registered value, although security requirements may vary accross
     implementations.  Once validated, the `done` callback must be invoked with
     a `client` instance, as well as the `redirectURI` to which the user will be
     redirected after an authorization decision is obtained.

     This middleware simply initializes a new authorization transaction.  It is
     the application's responsibility to authenticate the user and render a dialog
     to obtain their approval (displaying details about the client requesting
     authorization).  We accomplish that here by routing through `ensureLoggedIn()`
     first, and rendering the `dialog` view.
     */
  handlers.authorization = [
    server.authorization(
      (clientID, redirectURI, scope, responseType, done) => {
        debug('Verifying client %s redirect-uri: %s scope: %s response-type: %s',
          clientID, redirectURI, scope, responseType);
        models.clients.findByClientId(clientID, (err, client) => {
          if (err || !client) {
            return done(err);
          }
          debug('Client found: %s', clientInfo(client));
          if (validateClient(client, {
            scope,
            redirectURI,
            responseType,
          }, done)) {
            return;
          }
          return done(null, client, redirectURI);
        });
      },
    ),
    // Ensure the user is logged in
    ensureLoggedIn({ redirectTo: options.loginPage || '/login' }),
    // Check if the client application is enabled
    function (req, res, next) {
      if (!options.disabledApplicationPage && !models.authorizedApplication) {
        return next();
      }
      const clientId = req.oauth2.client.id;
      models.authorizedApplication.isAuthorized(clientId)
        .then((authorized) => {
          if (!authorized) {
            const urlObj = {
              pathname: options.disabledApplicationPage,
              query: {
                userId: req.oauth2.user.id,
                clientId: req.oauth2.client.id,
                scope: req.oauth2.req.scope,
              },
            };
            if (typeof options.disabledApplicationPage === 'function') {
              return options.disabledApplicationPage(res, urlObj.query);
            } else {
              return res.redirect(url.format(urlObj));
            }
          }
          next();
        })
        .catch((error) => next(error));
    },
    // Check if the user is authorized to use client app
    function (req, res, next) {
      if (!options.forbiddenUserPage && !models.authorizedUser) {
        return next();
      }
      const userId = req.oauth2.user.id;
      const clientId = req.oauth2.client.id;
      models.authorizedUser.isAuthorized(userId, clientId)
        .then((authorized) => {
          if (!authorized) {
            const urlObj = {
              pathname: options.forbiddenUserPage,
              query: {
                userId: req.oauth2.user.id,
                clientId: req.oauth2.client.id,
                scope: req.oauth2.req.scope,
              },
            };
            if (typeof options.forbiddenUserPage === 'function') {
              return options.forbiddenUserPage(res, urlObj.query);
            } else {
              return res.redirect(url.format(urlObj));
            }
          }
          next();
        })
        .catch((error) => next(error));
    },
    // Check if the user has granted permissions to the client app
    function (req, res, next) {
      if (options.forceAuthorize) {
        return next();
      }
      const userId = req.oauth2.user.id;
      const clientId = req.oauth2.client.id;
      const { scope, claims } = req.oauth2.req;
      models.permissions.isAuthorized(clientId, userId, scope, claims,
        (err, authorized) => {
          if (err) {
            return next(err);
          } if (authorized) {
            req.oauth2.res = {};
            req.oauth2.res.allow = true;
            server._respond(req.oauth2, res, (err) => {
              if (err) {
                return next(err);
              }
              return next(new AuthorizationError(g.f(
                'Unsupported response type: %s', req.oauth2.req.type,
              ), 'unsupported_response_type'));
            });
          } else {
            next();
          }
        });
    },
    // Now try to render the dialog to approve client app's request for permissions
    function (req, res, next) {
      if (options.decisionPage) {
        const urlObj = {
          pathname: options.decisionPage,
          query: {
            transactionId: req.oauth2.transactionID,
            userId: req.oauth2.user.id,
            clientId: req.oauth2.client.id,
            scope: req.oauth2.req.scope,
            claims: req.oauth2.req.claims,
            redirectURI: req.oauth2.redirectURI,
          },
        };
        if (typeof options.decisionPage === 'function') {
          return options.decisionPage(res, urlObj.query);
        } else {
          return res.redirect(url.format(urlObj));
        }
      }
      res.render(options.decisionView || 'dialog', {
        transactionId: req.oauth2.transactionID,
        user: req.user,
        client: req.oauth2.client,
        scopes: req.oauth2.req.scope,
        redirectURI: req.oauth2.redirectURI,
      });
    },
    server.errorHandler({ mode: 'indirect', disableAuthenticateBasic: options.disableAuthenticateBasic }),
  ];

  /*
     user decision endpoint

     `decision` middleware processes a user's decision to allow or deny access
     requested by a client application.  Based on the grant type requested by the
     client, the above grant middleware configured above will be invoked to send
     a response.
     */

  handlers.decision = [
    ensureLoggedIn({ redirectTo: options.loginPage || '/login' }),
    server.decision(),
  ];


  /*
     token endpoint

     `token` middleware handles client requests to exchange authorization grants
     for access tokens.  Based on the grant type being exchanged, the above
     exchange middleware will be invoked to handle the request.  Clients must
     authenticate when making requests to this endpoint.
     */
  handlers.token = [
    passport.authenticate(
      ['loopback-oauth2-client-password',
        'loopback-oauth2-client-basic',
        'loopback-oauth2-jwt-bearer',
      ], { session: false },
    ),
    server.token(),
    server.errorHandler({ disableAuthenticateBasic: options.disableAuthenticateBasic }),
  ];

  handlers.revoke = [
    passport.authenticate(
      ['loopback-oauth2-client-password',
        'loopback-oauth2-client-basic',
        'loopback-oauth2-jwt-bearer',
      ], { session: false },
    ),
    server.revoke((client, token, tokenType, cb) => {
      models.accessTokens.delete(client.id, token, tokenType, cb);
    }),
    server.errorHandler({ disableAuthenticateBasic: options.disableAuthenticateBasic }),
  ];

  /**
     * BasicStrategy & ClientPasswordStrategy
     *
     * These strategies are used to authenticate registered OAuth clients.  They are
     * employed to protect the `token` endpoint, which consumers use to obtain
     * access tokens.  The OAuth 2.0 specification suggests that clients use the
     * HTTP Basic scheme to authenticate.  Use of the client password strategy
     * allows clients to send the same credentials in the request body (as opposed
     * to the `Authorization` header).  While this approach is not recommended by
     * the specification, in practice it is quite common.
     */

  function clientLogin(clientId, clientSecret, done) {
    debug('clientLogin: %s', clientId);
    models.clients.findByClientId(clientId, (err, client) => {
      if (err) {
        return done(err);
      }
      if (!client) {
        return done(null, false);
      }
      const secret = client.clientSecret || client.restApiKey;
      if (secret !== clientSecret) {
        return done(null, false);
      }
      return done(null, client);
    });
  }

  // Strategies for oauth2 client-id/client-secret login
  // HTTP basic
  passport.use('loopback-oauth2-client-basic', new BasicStrategy(clientLogin));
  // Body
  passport.use('loopback-oauth2-client-password',
    new ClientPasswordStrategy(clientLogin));

  /**
     * JWT bearer token
     */
  passport.use('loopback-oauth2-jwt-bearer', new ClientJWTBearerStrategy({
    audience: options.tokenPath || '/oauth/token',
    jwtAlgorithm,
    passReqToCallback: true,
  },
  ((req, iss, header, done) => {
    debug('Looking up public key for %s', iss);
    models.clients.findByClientId(iss, (err, client) => {
      if (err) {
        return done(err);
      }
      if (!client) {
        return done(null, false);
      }
      req.client = client;
      return done(null, client.jwks || client.publicKey);
    });
  }),
  ((req, iss, sub, payload, done) => {
    process.nextTick(() => {
      if (validateClient(req.client, {
        scope: payload.scope,
        grantType: req.body.grant_type,
      }, done)) {
        return;
      }
      done(null, req.client);
    });
    /*
            models.clients.findByClientId(iss, function(err, client) {
              if (err) {
                return done(err);
              }
              if (!client) {
                return done(null, false);
              }
              return done(null, client);
            });
            */
  })));

  // The urlencoded middleware is required for oAuth 2.0 protocol endpoints
  const oauth2Paths = [
    options.authorizePath || '/oauth/authorize',
    options.tokenPath || '/oauth/token',
    options.revokePath || '/oauth/revoke',
    options.decisionPath || '/oauth/authorize/decision',
    options.loginPath || '/login',
  ];
  app.middleware('parse', oauth2Paths,
    bodyParser.urlencoded({ extended: false }));
  app.middleware('parse', oauth2Paths, bodyParser.json({ strict: false }));

  // Set up the oAuth 2.0 protocol endpoints
  if (options.authorizePath !== false) {
    app.get(options.authorizePath || '/oauth/authorize', handlers.authorization);
    app.post(options.authorizePath || '/oauth/authorize', handlers.authorization);
  }
  if (options.decisionPath !== false) {
    app.post(options.decisionPath || '/oauth/authorize/decision', handlers.decision);
  }
  if (options.tokenPath !== false) {
    app.post(options.tokenPath || '/oauth/token', handlers.token);
  }
  if (options.revokePath !== false) {
    app.post(options.revokePath || '/oauth/revoke', handlers.revoke);
  }

  if (options.loginPath !== false) {
    if (session) {
      passport.serializeUser((user, done) => {
        debug('serializeUser %s', userInfo(user));
        done(null, user.id);
      });

      passport.deserializeUser((id, done) => {
        debug('deserializeUser %s', id);
        models.users.find(id, (err, user) => {
          done(err, user);
        });
      });
    }
  }

  return handlers;
};
