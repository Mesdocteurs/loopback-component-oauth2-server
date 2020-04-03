/* ************************************************************************************ */
/*     __  __           ____             _                                              */
/*    |  \/  | ___  ___|  _ \  ___   ___| |_ ___ _   _ _ __ ___   ___ ___  _ __ ___     */
/*    | |\/| |/ _ \/ __| | | |/ _ \ / __| __/ _ \ | | | '__/ __| / __/ _ \| '_ ` _ \    */
/*    | |  | |  __/\__ \ |_| | (_) | (__| ||  __/ |_| | |  \__ \| (_| (_) | | | | | |   */
/*    |_|  |_|\___||___/____/ \___/ \___|\__\___|\__,_|_|  |___(_)___\___/|_| |_| |_|   */
/*                                                                                      */
/*     index.js                                                                         */
/*                                                                                      */
/*     By: Guillaume TORRESANI <g.torresani@mesdocteurs.com>                            */
/*                                                                                      */
/*     created: 04/03/20 14:08:23 by Guillaume TORRESANI                                */
/*     updated: 04/03/20 17:13:58 by Guillaume TORRESANI                                */
/*                                                                                      */
/* ************************************************************************************ */
// Copyright IBM Corp. 2014,2015. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.


const debug = require('debug')('loopback:oauth2:models');
const helpers = require('../oauth2-helper');

/**
 * Create oAuth 2.0 metadata models
 * @param app
 * @param options
 */
module.exports = function (app, options) {
  const { loopback } = app;
  options = options || {};

  let { dataSource } = options;
  if (typeof dataSource === 'string') {
    dataSource = app.dataSources[dataSource];
  }

  const oauth2 = require('./oauth2-models')(dataSource);

  const userModel = loopback.findModel(options.userModel)
        || loopback.getModelByType(loopback.User);
  debug('User model: %s', userModel.modelName);
  const applicationModel = loopback.findModel(options.applicationModel) || loopback.getModelByType(loopback.Application);
  debug('Application model: %s', applicationModel.modelName);

  const oAuthTokenModel = oauth2.OAuthToken;
  const oAuthAuthorizationCodeModel = oauth2.OAuthAuthorizationCode;
  const oAuthPermissionModel = oauth2.OAuthPermission;

  oAuthTokenModel.belongsTo(userModel, { as: 'user', foreignKey: 'userId' });

  oAuthTokenModel.belongsTo(applicationModel, { as: 'application', foreignKey: 'appId' });

  oAuthAuthorizationCodeModel.belongsTo(userModel, { as: 'user', foreignKey: 'userId' });

  oAuthAuthorizationCodeModel.belongsTo(applicationModel, { as: 'application', foreignKey: 'appId' });

  oAuthPermissionModel.belongsTo(userModel, { as: 'user', foreignKey: 'userId' });

  oAuthPermissionModel.belongsTo(applicationModel, { as: 'application', foreignKey: 'appId' });

  const getTTL = (
    typeof options.getTTL === 'function'
    || (options.getTTL && options.getTTL[Symbol.toStringTag] === 'AsyncFunction')) ? options.getTTL
    : function (responseType, clientId, resourceOwner, scopes) {
      if (typeof options.ttl === 'function') {
        return options.ttl(responseType, clientId, resourceOwner, scopes);
      }
      if (typeof options.ttl === 'number') {
        return options.ttl;
      }
      if (typeof options.ttl === 'object' && options.ttl !== null) {
        return options.ttl[responseType];
      }
      switch (responseType) {
        case 'code':
          return 300;
        default:
          return 14 * 24 * 3600; // 2 weeks
      }
    };

  const users = {};
  users.find = function (id, done) {
    debug(`users.find(${id})`);
    userModel.findOne({
      where: {
        id,
      },
    }, done);
  };

  users.findByUsername = function (username, done) {
    debug(`users.findByUsername(${username})`);
    userModel.findOne({
      where: {
        username,
      },
    }, done);
  };

  users.findByUsernameOrEmail = function (usernameOrEmail, done) {
    debug(`users.findByUsernameOrEmail(${usernameOrEmail})`);
    userModel.findOne({
      where: {
        or: [
          { username: usernameOrEmail },
          { email: usernameOrEmail },
        ],
      },
    }, done);
  };

  users.save = function (id, username, password, done) {
    debug(`users.save(${username})`);
    userModel.create({
      id,
      username,
      password,
    }, done);
  };

  const clients = {};
  clients.find = clients.findByClientId = function (clientId, done) {
    applicationModel.findById(clientId, done);
  };

  const token = {};
  token.find = function (accessToken, done) {
    oAuthTokenModel.findOne({
      where: {
        id: accessToken,
      },
    }, done);
  };

  token.findByRefreshToken = function (refreshToken, done) {
    oAuthTokenModel.findOne({
      where: {
        refreshToken,
      },
    }, done);
  };

  token.delete = function (clientId, token, tokenType, done) {
    const where = {
      appId: clientId,
    };
    if (tokenType === 'access_token') {
      where.id = token;
    } else {
      where.refreshToken = token;
    }
    oAuthTokenModel.destroyAll(where, done);
  };

  token.save = async function (token, clientId, resourceOwner, scopes, refreshToken, connectionToken, done) {
    let tokenObj;
    if (arguments.length === 2 && typeof token === 'object') {
      // save(token, cb)
      tokenObj = token;
      done = clientId;
    }
    let ttl;
    if (getTTL[Symbol.toStringTag] === 'AsyncFunction') {
      ttl = await getTTL('token', clientId, resourceOwner, scopes);
    } else {
      ttl = getTTL('token', clientId, resourceOwner, scopes);
    }
    if (!tokenObj) {
      tokenObj = {
        id: token,
        appId: clientId,
        userId: resourceOwner,
        scopes,
        issuedAt: new Date(),
        expiresIn: ttl,
        refreshToken,
        connectionToken,
      };
    }
    tokenObj.expiresIn = ttl;
    tokenObj.issuedAt = new Date();
    tokenObj.expiredAt = new Date(tokenObj.issuedAt.getTime() + ttl * 1000);
    oAuthTokenModel.create(tokenObj, done);
  };


  const code = {};
  code.findByCode = code.find = function (key, done) {
    oAuthAuthorizationCodeModel.findOne({
      where: {
        id: key,
      },
    }, done);
  };

  code.delete = function (id, done) {
    oAuthAuthorizationCodeModel.destroyById(id, done);
  };

  code.save = async function (code, clientId, redirectURI, resourceOwner, scopes, connectionToken, done) {
    let codeObj;
    if (arguments.length === 2 && typeof token === 'object') {
      // save(code, cb)
      codeObj = code;
      done = clientId;
    }
    let ttl;
    if (getTTL[Symbol.toStringTag] === 'AsyncFunction') {
      ttl = await getTTL('code', clientId, resourceOwner, scopes);
    } else {
      ttl = getTTL('code', clientId, resourceOwner, scopes);
    }
    if (!codeObj) {
      codeObj = {
        id: code,
        appId: clientId,
        userId: resourceOwner,
        scopes,
        redirectURI,
        connectionToken,
      };
    }
    codeObj.expiresIn = ttl;
    codeObj.issuedAt = new Date();
    codeObj.expiredAt = new Date(codeObj.issuedAt.getTime() + ttl * 1000);
    oAuthAuthorizationCodeModel.create(codeObj, done);
  };

  const permission = {};
  permission.find = function (appId, userId, done) {
    oAuthPermissionModel.findOne({
      where: {
        appId,
        userId,
      },
    }, done);
  };

  /*
     * Check if a client app is authorized by the user
     */
  permission.isAuthorized = function (appId, userId, scopes, done) {
    permission.find(appId, userId, (err, perm) => {
      if (err) {
        return done(err);
      }
      if (!perm) {
        return done(null, false);
      }
      const ok = helpers.isScopeAuthorized(scopes, perm.scopes);
      const info = ok ? { authorized: true } : {};
      return done(null, ok, info);
    });
  };

  /*
     * Grant permissions to a client app by a user
     */
  permission.addPermission = function (appId, userId, scopes, done) {
    oAuthPermissionModel.findOrCreate({
      where: {
        appId,
        userId,
      },
    }, {
      appId,
      userId,
      scopes,
      issuedAt: new Date(),
    }, (err, perm, created) => {
      if (created) {
        return done(err, perm, created);
      }
      if (helpers.isScopeAuthorized(scopes, perm.scopes)) {
        return done(err, perm);
      }
      perm.updateAttributes({ scopes: helpers.normalizeList(scopes) }, done);
    });
  };

  // Adapter for the oAuth2 provider
  const customModels = options.models || {};
  const models = {
    users: customModels.users || users,
    clients: customModels.clients || clients,
    accessTokens: customModels.accessTokens || token,
    authorizationCodes: customModels.authorizationCodes || code,
    permissions: customModels.permission || permission,
    authorizedApplication: customModels.authorizedApplication || null,
    authorizedUser: customModels.authorizedUser || null,
  };
  return models;
};
