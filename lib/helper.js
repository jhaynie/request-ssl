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
	fs = require('fs'),
	path = require('path'),
	spawn = require('child_process').spawn;

//openssl x509  -noout -fingerprint -sha1 -in <(openssl x509 -in <(openssl s_client -connect www.google.com:443 -prexit 2>/dev/null))

/**
 * for a given url, get the fingerprint
 */
function getFingerprintForURL(arg, callback) {
	var url = urllib.parse(arg),
		host = url.host,
		port = url.port || (url.protocol==='https:' ? 443 : 80),
		cb = callback || function(err) { err && console.log(err); },
		cmd = 'openssl s_client -connect '+host+':'+port+' -prexit 2>/dev/null';

	var child = spawn('openssl',['s_client','-connect',host+':'+port,'-no_ign_eof','-prexit'],{stdout:'pipe'});
	var response = '';
	child.stdout.on('data',function(buf){
		response+=buf+'\n';
		if (response.indexOf('-END CERTIFICATE-') > 0) {
			child.kill();
		}
	});
	child.on('exit',function(){
		child = spawn('openssl',['x509'],{stdio:'pipe'});
		child.stdin.write(response);
		response = '';
		child.stdout.on('data',function(buf){
			response+=buf+'\n';
		});
		child.on('exit',function(){
			child = spawn('openssl',['x509','-noout','-fingerprint','-sha1'],{stdout:'pipe'});
			child.stdin.write(response);
			response = '';
			child.on('error',cb);
			child.stdout.on('data',function(buf){
				response+=buf+'\n';
			});
			child.on('exit',function(){
				var fingerprint = response.trim().replace(/^SHA1\sFingerprint=(.*)/,'$1');
				cb(null, fingerprint);
			});
		});
		child.on('error',cb);
	});
	child.on('error',cb);
}

exports.getFingerprintForURL = getFingerprintForURL;

if (module.id===".") {
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
