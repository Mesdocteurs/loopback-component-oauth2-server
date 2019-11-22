// Copyright IBM Corp. 2012,2015. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.


/**
 * Module dependencies.
 */
const SG = require('strong-globalize');

const g = SG();
const AuthorizationError = require('../errors/authorizationerror');
const BadRequestError = require('../errors/badrequesterror');
const ForbiddenError = require('../errors/forbiddenerror');

/**
 * Loads an OAuth 2.0 authorization transaction from the session.
 *
 * This middleware is used to load a pending OAuth 2.0 transaction that is
 * serialized into the session.  In most circumstances, this is transparently
 * done prior to processing a user's decision with `decision` middleware, and an
 * implementation shouldn't need to mount this middleware explicitly.
 *
 * Options:
 *
 *     transactionField  name of field that contains the transaction ID (default: 'transaction_id')
 *     sessionKey        key under which transactions are stored in the session (default: 'authorize')
 *
 * @param {Server} server
 * @param {Object} options
 * @return {Function}
 * @api protected
 */
module.exports = function (server, options) {
  options = options || {};

  if (!server) {
    throw new TypeError(g.f('{{oauth2orize.transactionLoader}} middleware requires a {{server}} argument'));
  }

  const field = options.transactionField || 'transaction_id';
  const key = options.sessionKey || 'authorize';

  return function transactionLoader(req, res, next) {
    if (!req.session) {
      return next(new Error(g.f(
        '{{OAuth2orize}} requires {{session}} support. Did you forget {{app.use(express.session(...))}}?',
      )));
    }
    if (!req.session[key]) {
      return next(new ForbiddenError(g.f('Unable to load {{OAuth 2.0}} transactions from session')));
    }

    const query = req.query || {};
    const body = req.body || {};
    const tid = query[field] || body[field];

    if (!tid) { return next(new BadRequestError(g.f('Missing required parameter: %s', field))); }
    const txn = req.session[key][tid];
    if (!txn) { return next(new ForbiddenError(g.f('Unable to load {{OAuth 2.0}} transaction: %s', tid))); }

    server.deserializeClient(txn.client, (err, client) => {
      if (err) { return next(err); }
      if (!client) {
        // At the time the request was initiated, the client was validated.
        // Since then, however, it has been invalidated.  The transaction will
        // be invalidated and no response will be sent to the client.
        delete req.session[key][tid];
        return next(new AuthorizationError(g.f('Unauthorized client'), 'unauthorized_client'));
      }

      req.oauth2 = {};
      req.oauth2.transactionID = tid;
      req.oauth2.client = client;
      req.oauth2.redirectURI = txn.redirectURI;
      req.oauth2.req = txn.req;
      req.oauth2.info = txn.info;
      next();
    });
  };
};
