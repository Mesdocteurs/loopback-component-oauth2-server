/* ************************************************************************************ */
/*     __  __           ____             _                                              */
/*    |  \/  | ___  ___|  _ \  ___   ___| |_ ___ _   _ _ __ ___   ___ ___  _ __ ___     */
/*    | |\/| |/ _ \/ __| | | |/ _ \ / __| __/ _ \ | | | '__/ __| / __/ _ \| '_ ` _ \    */
/*    | |  | |  __/\__ \ |_| | (_) | (__| ||  __/ |_| | |  \__ \| (_| (_) | | | | | |   */
/*    |_|  |_|\___||___/____/ \___/ \___|\__\___|\__,_|_|  |___(_)___\___/|_| |_| |_|   */
/*                                                                                      */
/*     code.js                                                                          */
/*                                                                                      */
/*     By: Marshall Chan <yahoohung@gmail.com>                                          */
/*                                                                                      */
/*     created: 15/09/17 12:22:42 by Marshall Chan                                      */
/*     updated: 08/07/20 16:22:18 by Guillaume Torresani                                */
/*                                                                                      */
/* ************************************************************************************ */

// Copyright IBM Corp. 2012,2014. All Rights Reserved.
// Node module: loopback-component-oauth2
// US Government Users Restricted Rights - Use, duplication or disclosure
// restricted by GSA ADP Schedule Contract with IBM Corp.


/**
 * Module dependencies.
 */
const SG = require('strong-globalize');

const g = SG();
const url = require('url');
const AuthorizationError = require('../errors/authorizationerror');

/**
 * Handles requests to obtain a grant in the form of an authorization code.
 *
 * Callbacks:
 *
 * This middleware requires an `issue` callback, for which the function
 * signature is as follows:
 *
 *     function(client, redirectURI, user, scope, ares, done) { ... }
 *
 * `client` is the client instance making the authorization request.
 * `redirectURI` is the redirect URI specified by the client, and used as a
 * verifier in the subsequent access token exchange.  `user` is the
 * authenticated user approving the request.  `ares` is any additional
 * parameters parsed from the user's decision, including scope, duration of
 * access, etc.  `done` is called to issue an authorization code:
 *
 *     done(err, code)
 *
 * `code` is the code that will be sent to the client.  If an error occurs,
 * `done` should be invoked with `err` set in idomatic Node.js fashion.
 *
 * The code issued in this step will be used by the client in exchange for an
 * access token.  This code is bound to the client identifier and redirection
 * URI, which is included in the token request for verification.  The code is a
 * single-use token, and should expire shortly after it is issued (the maximum
 * recommended lifetime is 10 minutes).
 *
 * Options:
 *
 *     scopeSeparator  separator used to demarcate scope values (default: ' ')
 *
 * Examples:
 *
 *     server.grant(oauth2orize.grant.code(function(client, redirectURI, user, scope, ares, done) {
 *       AuthorizationCode.create(client.id, redirectURI, user.id, scope, function(err, code) {
 *         if (err) { return done(err); }
 *         done(null, code);
 *       });
 *     }));
 *
 * References:
 *  - [Authorization Code](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-1.3.1)
 *  - [Authorization Code Grant](http://tools.ietf.org/html/draft-ietf-oauth-v2-28#section-4.1)
 *
 * @param {Object} options
 * @param {Function} issue
 * @return {Object} module
 * @api public
 */
module.exports = function code(options, issue) {
  if (typeof options === 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError(g.f('{{oauth2orize.code}} grant requires an {{issue}} callback')); }

  // For maximum flexibility, multiple scope separators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  let separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [separators];
  }

  function getParam(req, name) {
    if (options.allowsPost && req.body) {
      return req.query[name] || req.body[name];
    }
    return req.query[name];
  }

  /* Parse requests that request `code` as `response_type`.
     *
     * @param {http.ServerRequest} req
     * @api public
     */
  function request(req) {
    const clientID = getParam(req, 'client_id');
    const redirectURI = getParam(req, 'redirect_uri');
    let scope = getParam(req, 'scope');
    let claims = {};
    try {
      claims = JSON.parse(getParam(req, 'claims'));
    } catch (e) {}
    const state = getParam(req, 'state');

    if (!clientID) {
      throw new AuthorizationError(g.f('Missing required parameter: {{client_id}}'), 'invalid_request');
    }

    if (scope) {
      for (let i = 0, len = separators.length; i < len; i++) {
        const separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }

      if (!Array.isArray(scope)) { scope = [scope]; }
    }

    return {
      clientID,
      redirectURI,
      scope,
      state,
      claims,
    };
  }

  /* Sends responses to transactions that request `code` as `response_type`.
     *
     * @param {Object} txn
     * @param {http.ServerResponse} res
     * @param {Function} next
     * @api public
     */
  function response(txn, res, next) {
    if (!txn.redirectURI) {
      return next(new Error(g.f('Unable to issue redirect for {{OAuth 2.0}} transaction')));
    }
    if (!txn.res.allow) {
      const parsed = url.parse(txn.redirectURI, true);
      delete parsed.search;
      parsed.query.error = 'access_denied';
      if (txn.req && txn.req.state) { parsed.query.state = txn.req.state; }

      const location = url.format(parsed);
      if (typeof options.authorizePage === 'function') {
        return options.authorizePage(res, location);
      } else {
        return res.redirect(location);
      }
    }

    function issued(err, code, options) {
      if (err) { return next(err); }
      if (!code) {
        return next(new AuthorizationError(g.f('Request denied by authorization server'), 'access_denied'));
      }

      const parsed = url.parse(txn.redirectURI, true);
      delete parsed.search;
      parsed.query.code = code;
      if (txn.req && txn.req.state) { parsed.query.state = txn.req.state; }

      const location = url.format(parsed);
      if (typeof options.authorizePage === 'function') {
        return options.authorizePage(res, location);
      } else {
        return res.redirect(location);
      }
    }

    // NOTE: The `redirect_uri`, if present in the client's authorization
    //       request, must also be present in the subsequent request to exchange
    //       the authorization code for an access token.  Acting as a verifier,
    //       the two values must be equal and serve to protect against certain
    //       types of attacks.  More information can be found here:
    //
    //       http://hueniverse.com/2011/06/oauth-2-0-redirection-uri-validation/

    try {
      const arity = issue.length;
      if (arity === 7) {
        issue(txn.client, txn.req.redirectURI, txn.user, txn.req.scope, txn.res, res.req, issued);
      } else { // arity == 5
        issue(txn.client, txn.req.redirectURI, txn.user, txn.req.scope, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  }

  /**
     * Return `code` approval module.
     */
  const mod = {};
  mod.name = 'code';
  mod.request = request;
  mod.response = response;
  return mod;
};
