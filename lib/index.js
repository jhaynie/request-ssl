/**
 * Copyright (c) 2015 by Jeff Haynie. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var request = require('request'),
	_ = require('lodash'),
	util = require('util'),
	urlib = require('url'),
	debug = require('debug')('request-ssl');

// internal variables
var secureProtocol = 'SSLv23_method';

// since this library really needs to act as a singleton, we are binding a few
// commands to global such that all loads of this module will always use the
// same certificates, etc. since that's a key part of the design
if (typeof(global.requestSSLHooks)==='undefined') {
	global.requestSSLHooks = [];
}
if (typeof(global.requestSSLFingerprints)==='undefined') {
	global.requestSSLFingerprints = {};
}

/**
 * shim the request function to do SSL certificate pinning
 *
 * we don't want software which talks to servers which we don't explicitly trust for performing 
 * operations which we trust.  We use TLS and X.509 certificates to ensure that we trust that 
 * the server is who we think it should be.  
 *
 * The SSL certificate fingerprint is located in the ./support/ssl directory of 
 * this distribution by domain and we compare what the server we are connect to is returning
 * and if the fingerprints don't match, we likely have an untrusted TLS connection to 
 * someone that is not Appcelerator (or the SSL certificate is invalid, expired, etc).
 * 
 * @see https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning
 */
function Request() {
	var args = Array.prototype.slice.call(arguments),
		opts = _.isObject(args[0]) ? args[0] : {},
		url = _.isObject(args[0]) ? opts.url || opts.uri : args[0],
		callback = arguments[arguments.length-1];
	if (!url) { throw new Error("missing url"); }
	var isSSL = urlib.parse(url).protocol === 'https:';
	// if passed in a URL string
	if (_.isString(args[0])) {
		opts = {
			url: url
		};
		args[0] = opts;
	}
	if (isSSL) {
		opts.agentOptions = _.merge(_.clone(opts.agentOptions||{}),{secureProtocol: secureProtocol});
	}
	debug('request-> %j (%d) [%s]',opts,isSSL,url);
	var req = request.apply(null, args);
	if (isSSL) {
		var hasCallback = !!callback && _.isFunction(callback);
		// wrap our callback to only allow once callback
		var originalCallback = hasCallback && callback;
		var wrappedCallback = function() {
			if (hasCallback && originalCallback) {
				originalCallback.apply(null,arguments);
				originalCallback = null;
			}
			else if (!hasCallback) {
				hasCallback = true; // so we don't call again
				req.emit('error',arguments[0]);
			}
		};
		callback = wrappedCallback;
		Request._lastURL = url; // useful for testing
		req.on('response',function(resp){
			// in case of a redirect
			debug('TLS response final url %s, begin with %s',resp.request.uri.host,url);
			Request._lastURL = url = resp.request.uri.host;
			if (!/^https:/.test(Request._lastURL)) {
				Request._lastURL = 'https://'+Request._lastURL;
			}
			var socket = resp.socket;
			var fingerprint = socket.getPeerCertificate().fingerprint;
			var shouldMatch = opts.fingerprint || getFingerprintForURL(url);
			debug('TLS server fingerprint is: %s, expected: %s',fingerprint,shouldMatch);
			debug('TLS server certificate',socket.getPeerCertificate());
			debug('TLS cipher %j',socket.getCipher());
			debug('TLS remoteAddress/port: %s:%d',socket.remoteAddress,socket.remotePort);
			if (!shouldMatch) {
				req.abort();
				callback(createErrorMessage("request.ssl.security.domain.invalid",url));
			}
			else if (shouldMatch!==fingerprint) {
				req.abort();
				callback(createErrorMessage("request.ssl.security.domain.fingerprint.mismatch",url));
			}
			else {
				// good to go if we get here. we have a trusted TSL connection
			}
		});
		req.on('socket', function(socket){
			socket.on('secureConnect', function(){
				debug('TLS connection established to %s',url);
				if (socket.authorized) {
					// do the authorization in the response above
					// we do it there instead of here since this method can be 
					// called multiple times for each redirect
				}
				else {
					req.abort();
					callback(createErrorMessage("request.ssl.security.domain.notauthorized",url));
				}
			});
		});
	}
	return req;
}

/**
 * create a custom error so we can get proper error code
 */
function RequestSSLError(message, id) {
	Error.call(this);
	Error.captureStackTrace(this, RequestSSLError);
	this.id = id;
	this.name = 'RequestSSLError';
	this.message = message;
}
util.inherits(RequestSSLError, Error);

const ERRORS = {
	'request.ssl.security.domain.invalid': {
		message: "SSL authorization failed. URL: %s does not have a valid fingerprint which can be used to verify the SSL certificate.",
		argcount: 1,
	},
	'request.ssl.security.domain.notauthorized': {
		message: 'SSL authorization failed. URL to %s is not authorized for SSL.',
		argcount: 1
	},
	'request.ssl.security.domain.fingerprint.mismatch': {
		message: "SSL authorization failed. URL to %s is not authorized for SSL. Mismatched SSL fingerprint. This likely means that the URL doesn't point to the expected server or there is an unexpected man-in-the-middle.",
		argcount: 1
	}
};

/**
 * construct the proper error message
 */
function createErrorMessage(errorcode) {
	if (errorcode in ERRORS) {
		var args = Array.prototype.slice.call(arguments,1);
		var entry = ERRORS[errorcode];
		if (entry.argcount && entry.argcount!==args.length) {
			// this should only ever get called if we have a bug in this library
			throw new Error("Internal failure. Unexpected usage of internal command. Please report error code: "+errorcode+"(invalid args) to the developer with the following stack trace:"+new Error().stack);
		}
		return new RequestSSLError((args.length ? util.format.apply(util.format,[entry.message].concat(args)) : entry.message), errorcode);
	}
	else {
		// this should only ever get called if we have a bug in this library
		throw new Error("Internal failure. Unexpected usage of internal command. Please report error code: "+errorcode+"(invalid error code) to the developer with the following stack trace:"+new Error().stack);
	}
}

/**
 * given a url return a domain part
 */
function getDomain(url) {
	var domain = _.isObject(url) ? url.host : urlib.parse(url).host;
	return domain || url;
}

/**
 * lookup a fingerprint for a given URL by using the domain. returns null if
 * not found
 */
function getFingerprintForURL(url) {
	var domain = getDomain(url);
	var found = global.requestSSLFingerprints[domain];
	debug('getFingerprintForURL %s -> %s=%s',url,domain,found);
	if (!found) {
		// try a wildcard search
		var u = urlib.parse(domain),
			tokens = (u && u.host || domain).split('.');
		domain = '*.'+tokens.splice(tokens.length > 1 ? 0 : 1).join('.');
		found = global.requestSSLFingerprints[domain];
		debug('getFingerprintForURL (wildcard) %s -> %s=%s',url,domain,found);
	}
	return found;
}

/**
 * add a directory to read fingerprints from. The domain name (without protocol or port)
 * that we are connecting to is the name of the file (with no extension) and the contents
 * should be the fingerprint in SHA1 format
 */
Request.addFingerprintDirectory = function addCertificatesDirectory(dir) {
	debug('addFingerprint %s',dir);
	var fs = require('fs'),
		path = require('path');
	fs.readdirSync(dir).forEach(function(name) {
		var fingerprint = fs.readFileSync(path.join(dir, name)).toString().trim();
		Request.addFingerprint(name, fingerprint);
	});
};

/**
 * add a fingerprint for a domain
 */
Request.addFingerprint = function addFingerprint(url, fingerprint) {
	if (!url) { throw new Error("missing name"); }
	if (!fingerprint) { throw new Error("missing fingerprint"); }
	var name = getDomain(url);
	fingerprint = fingerprint.replace(/^SHA1\sFingerprint=(.*)/,'$1');
	debug('addFingerprint %s=%s',name,fingerprint);
	global.requestSSLFingerprints[name] = fingerprint;
};

/**
 * remove a fingerprint for a domain
 */
Request.removeFingerprint = function removeFingerprint(name) {
	name = getDomain(name);
	debug('removeFingerprint %s',name);
	delete global.requestSSLFingerprints[name];
};

/**
 * remove all fingerprints
 */
Request.removeAllFingerprints = function removeAllFingerprints() {
	debug('removeAllFingerprints');
	global.requestSSLFingerprints = {};
};

/**
 * set the value of the secureProtocol such as SSLv23_method that will be used internally by the request
 */
Request.setDefaultSecureProtocol = function setDefaultSecureProtocol(value) {
	debug('setDefaultSecureProtocol %s',value);
	secureProtocol = value;
};

/**
 * return the last requested SSL url
 */
Request.getLastURL = function getLastURL() {
	return Request._lastURL;
};

/**
 * reset the last requested SSL url
 */
Request.resetLastURL = function resetLastURL() {
	Request._lastURL = null;
};

// patch our initializer so we can run our hooks
var patchedInit = request.Request.prototype.init;
request.Request.prototype.init = function() {
	debug('init called',global.requestSSLInsideHook);
	var self = this, 
		args = arguments;

	if (global.requestSSLInitializing && !global.requestSSLInsideHook) {
		debug('init need to retry');
		return setTimeout(function(){
			debug('init retry');
			request.Request.prototype.init.apply(self,args);
		},100);
	}
	if (global.requestSSLInsideHook || global.requestSSLInitialized || !global.requestSSLHooks || global.requestSSLHooks.length === 0) {
		debug('init is calling real init');
		return patchedInit.apply(this, arguments);
	}
	debug('init running');
	// run our hooks until we're done and then run our initializer
	var done = function() {
			global.requestSSLInitializing = false;
			global.requestSSLInitialized = true;
			global.requestSSLHooks = null;
			// unpatch ourselves
			request.Request.prototype.init = patchedInit;
			debug('init done');
			return patchedInit.apply(self,args);
		},
		index = 0,
		nextHook = function() {
			debug('next hook');
			var hook = global.requestSSLHooks[index++];
			if (hook) {
				debug('init hook',hook);
				// if async
				global.requestSSLInsideHook = true;
				if (hook.length > 0) {
					debug('calling a hook async');
					hook(nextHook);
					debug('after calling a hook async');
				}
				// else sync
				else {
					debug('calling a hook sync');
					hook();
					nextHook();
					debug('after calling a hook sync');
				}
				global.requestSSLInsideHook = false;
			}
			else {
				debug('init has no more hooks');
				done();
			}
		};
	global.requestSSLInitializing = true;
	nextHook();
};

/**
 * register an initializer callback. this callback will get called only
 * once before any requests are executed using this library. this will
 * allow clients to run initialization type routines (for example, to
 * register a fingerprint, etc.) before the request actually is invoked.
 *
 * the initializer will only work in the case where you are passing a
 * callback to the first use of the request library
 */
Request.registerInitializer = function registerInitializer(callback) {
	if (global.requestSSLInitialized) {
		return callback.length ? callback(function(){}) : callback();
	}
	debug('registerInitializer %o',callback);
	global.requestSSLHooks.push(callback);
};

module.exports = Request;

// these should map the url correctly
['get','head','post','put','del','options','patch'].forEach(function(k){
	Request[k] = function() {
		var args = Array.prototype.slice.call(arguments),
			method = _translateMethod(k);
		if (_.isObject(args[0])) {
			args[0].method = method;
		}
		else {
			args[0] = {url:args[0], method: method};
		}
		return Request.apply(null, args);
	};
});

function _translateMethod(method) {
	var m = method;
	m = m.toUpperCase();
	if(m === 'DEL') {
		m = 'DELETE'; }
	return m;
}

// these can just be patched
['forever','defaults','cookie','jar'].forEach(function(k){
	Request[k] = request[k];
});

// provide a pointer back in case you want to just use this library in your 
// distribution but want to be able to get the request for non-pinned use cases
Request.request = request;

// get a fingerprint for a url
Request.getFingerprintForURL = require('./helper').getFingerprintForURL;
