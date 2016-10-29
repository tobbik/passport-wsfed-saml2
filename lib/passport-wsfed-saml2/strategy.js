var util      = require('util');
var url       = require('url');
var xmldom    = require('xmldom');
var jwt       = require('jsonwebtoken');
var Strategy  = require('passport-strategy');
var saml      = require('./saml');
var wsfed     = require('./wsfederation');
var samlp     = require('./samlp');

var NullStateStore    = require('./state/null');
var SessionStateStore = require('./state/session');

var BEARER_TOKEN_PREFIX = 'Bearer ';

function WsFedSaml2Strategy (options, verify) {
  if (typeof options === 'function') {
    verify = options;
    options = {};
  }

  this.options = options || {};
  this.options.protocol = this.options.protocol || 'wsfed';

  if (!verify) {
    throw new Error('this strategy requires a verify function');
  }

  this.name = 'wsfed-saml2';

  Strategy.call(this);

  this._verify = verify;
  this._passReqToCallback = !!options.passReqToCallback;

  if (!this.options.jwt) {
    this._saml = new saml.SAML(this.options);
    this._samlp =  new samlp(this.options, this._saml);
  } else {
    this._jwt = this.options.jwt;
  }

  this._wsfed =  new wsfed(options.realm, options.homeRealm, options.identityProviderUrl, options.wreply);

  this._key = options.sessionKey || (this.options.protocol + ':' + url.parse(options.identityProviderUrl || '').hostname);

  if (options.store) {
    this._stateStore = options.store;
  } else {
    if (options.state) {
      this._stateStore = new SessionStateStore({ key: this._key });
    } else {
      this._stateStore = new NullStateStore();
    }
  }
}

util.inherits(WsFedSaml2Strategy, Strategy);

WsFedSaml2Strategy.prototype._authenticate_saml_barer = function (req, state) {  
  var self = this;
 
  var header = req.headers.authorization;
  var rawToken = header.substring(BEARER_TOKEN_PREFIX.length, header.length);
  var rawXml = new Buffer(rawToken, 'base64').toString('utf8');
  var token = new xmldom.DOMParser().parseFromString(rawXml);

  self._authenticate_saml(req, token, state);
}

WsFedSaml2Strategy.prototype._authenticate_saml_post = function (req, state) {
  var self = this;

  self._wsfed.retrieveToken(req, function(err, token) {
    if (err) return self.fail(err, err.status || 400);
    
    self._authenticate_saml(req, token, state);    
  });
}

WsFedSaml2Strategy.prototype._authenticate_saml = function (req, token, state) {
  var self = this;

  self._saml.validateSamlAssertion(token, function (err, profile) {
    if (err) {
      return self.error(err);
    }

    var verified = function (err, user, info) {
      if (err) {
        return self.error(err);
      }

      if (!user) {
        return self.fail(info);
      }

      info = info || {};
      if (state) { info.state = state; }
      self.success(user, info);
    };

    if (self._passReqToCallback) {
      self._verify(req, profile, verified);
    } else {
      self._verify(profile, verified);
    }
  });
};

WsFedSaml2Strategy.prototype._authenticate_jwt_bearer = function (req, state) {
  throw 'Not implemented!';
}

WsFedSaml2Strategy.prototype._authenticate_jwt_post = function (req, state) {
    var self = this;
    var token = req.body.wresult;

    self._authenticate_jwt(req, token, state);
}

WsFedSaml2Strategy.prototype._authenticate_jwt = function (req, token, state) {
  var self = this;

  jwt.verify(token, this.options.cert, this._jwt, function (err, profile) {
    if (err) {
      return self.error(err);
    }

    var verified = function (err, user, info) {
      if (err) {
        return self.error(err);
      }

      if (!user) {
        return self.fail(info);
      }

      info = info || {};
      if (state) { info.state = state; }
      self.success(user, info);
    };

    if (self._passReqToCallback) {
      self._verify(req, profile, verified);
    } else {
      self._verify(profile, verified);
    }
  });
};

WsFedSaml2Strategy.prototype.authenticate = function (req, opts) {
  var self = this;
  var protocol = opts.protocol || this.options.protocol;
  var meta = {
    identityProviderUrl: this.options.identityProviderUrl
  };

  var storeState = function (stored) {
    try {
      var arity = self._stateStore.store.length;
      if (arity === 3) {
        self._stateStore.store(req, meta, stored);
      } else { // arity == 2
        self._stateStore.store(req, stored);
      }
    } catch (ex) {
      return self.error(ex);
    }
  };

  var verifyState = function (state, loaded) {
    try {
      var arity = self._stateStore.verify.length;
      if (arity === 4) {
        self._stateStore.verify(req, state, meta, loaded);
      } else { // arity == 3
        self._stateStore.verify(req, state, loaded);
      }
    } catch (ex) {
      return self.error(ex);
    }
  };

  function executeWsfed(req) {
    if(req.headers.authorization && req.headers.authorization.startsWith(BEARER_TOKEN_PREFIX)) {
      // We have a bearer token in the request, get the user identity out of it.
      var loaded_bearer = function (err, ok, state) {
        if (err) { return self.error(err); }
        if (!ok) { return self.fail(state, 403); }

        if (self._jwt) {
          self._authenticate_jwt_bearer(req);
        } else {
          self._authenticate_saml_bearer(req);
        }
      };

      verifyState(req.body.wctx, loaded_bearer);
    } else if (req.body && req.method === 'POST' && req.body.wresult) {
      // We have a response, get the user identity out of it.
      var loaded_post = function (err, ok, state) {
        if (err) { return self.error(err); }
        if (!ok) { return self.fail(state, 403); }

        if (self._jwt) {
          self._authenticate_jwt_post(req, state);
        } else {
          self._authenticate_saml_post(req, state);
        }
      };

      verifyState(req.body.wctx, loaded_post);
    } else {
      // Initiate new ws-fed authentication request
      var authzParams = self.authorizationParams(opts);
      var redirectToIdp = function () {
        var idpUrl = self._wsfed.getRequestSecurityTokenUrl(authzParams);
        self.redirect(idpUrl);
      };

      var state = opts.wctx;
      if (state) {
        authzParams.wctx = state;
        redirectToIdp();
      } else {
        var stored = function (err, state) {
          if (err) { return self.error(err); }
          if (state) { authzParams.wctx = state; }
          redirectToIdp();
        };
        
        storeState(stored);
      }
    }
  }

  function executeSamlp(req) {
    if (req.body && req.method === 'POST' && req.body.SAMLResponse) {
      // We have a response, get the user identity out of it
      var loaded = function (err, ok, state) {
        if (err) { return self.error(err); }
        if (!ok) { return self.fail(state, 403); }

        var samlResponse = self._samlp.decodeResponse(req);
        if (samlResponse.indexOf('<') === -1) {
          return self.fail('SAMLResponse should be a valid xml', 400);
        }

        var samlResponseDom = new xmldom.DOMParser().parseFromString(samlResponse);
        self._samlp.validateSamlResponse(samlResponseDom, function (err, profile) {
          if (err) return self.fail(err, err.status || 400);

          var verified = function (err, user, info) {
            if (err) return self.error(err);
            if (!user) return self.fail(info);

            info = info || {};
            if (state) { info.state = state; }
            self.success(user, info);
          };

          if (self._passReqToCallback) {
            self._verify(req, profile, verified);
          } else {
            self._verify(profile, verified);
          }
        });
      };

      verifyState(req.body.RelayState, loaded);
    } else {
      // Initiate new samlp authentication request
      var authzParams = self.authorizationParams(opts);
      var sendRequestToIdp = function () {
        if (self.options.protocolBinding === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') {
          self._samlp.getSamlRequestForm(authzParams, function (err, form) {
            if (err) return self.error(err);
            var res = req.res;
            res.set('Content-Type', 'text/html');
            res.send(form);
          });
        }
        else {
          self._samlp.getSamlRequestUrl(authzParams, function (err, url) {
            if (err) return self.error(err);
            self.redirect(url);
          });
        }
      };

      var state = opts.RelayState;
      if (state) {
        authzParams.RelayState = state;
        sendRequestToIdp();
      } else {
        var stored = function (err, state) {
          if (err) { return self.error(err); }
          if (state) { authzParams.RelayState = state; }
          sendRequestToIdp();
        };
        
        storeState(stored);
      }
    }
  }

  switch (protocol) {
  case 'wsfed':
    executeWsfed(req, this.options);
    break;
  case 'samlp':
    executeSamlp(req, this.options);
    break;
  default:
    throw new Error('not supported protocol: ' + protocol);
  }
};

WsFedSaml2Strategy.prototype.authorizationParams = function(options) {
  return options;
};

module.exports = WsFedSaml2Strategy;
