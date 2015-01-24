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
/**
 * script for generating a SHA1 fingerprint for a remote SSL certificate
 */
var urllib = require('url'),
	request = require('request'),
	debug = require('debug')('request-ssl');

function getFingerprintForURL(arg, callback) {
	var url = urllib.parse(arg),
		host = url.host || arg,
		port = url.port || (!url.host || url.protocol==='https:' ? 443 : 80),
		cb = callback || function(err) { err && console.log(err); },
		req = request({url:'https://'+host+':'+port+'/',method:'get'});
	req.on('response',function(resp){
		// in case of a redirect
		debug('TLS response final url %s, begin with %s',resp.request.uri.host,url);
		var socket = resp.socket;
		var fingerprint = socket.getPeerCertificate().fingerprint;
		// var shouldMatch = getFingerprintForURL(url);
		// debug('TLS server fingerprint is: %s, expected: %s',fingerprint,shouldMatch);
		debug('TLS server certificate',socket.getPeerCertificate());
		debug('TLS cipher %j',socket.getCipher());
		debug('TLS remoteAddress/port: %s:%d',socket.remoteAddress,socket.remotePort);
		req.abort();
		cb(null, fingerprint);
	});
	req.on('socket', function(socket){
		socket.on('secureConnect', function(){
			debug('TLS connection established to %s',url);
			if (!socket.authorized) {
				req.abort();
			}
		});
	});
}

exports.getFingerprintForURL = getFingerprintForURL;

if (module.id===".") {
	var path = require('path');
	var arg = process.argv[2];
	if (!arg) {
		console.error("node "+path.basename(process.argv[1])+" <url>");
		process.exit(1);
	}
	getFingerprintForURL(arg, function(err,fingerprint){
		if (err) {
			console.error(err);
			process.exit(1);
		}
		console.log(fingerprint);
	});
}
