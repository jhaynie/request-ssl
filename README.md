# Request SSL [![Build Status](https://travis-ci.org/jhaynie/request-ssl.svg?branch=master)](https://travis-ci.org/jhaynie/request-ssl) [![npm version](https://badge.fury.io/js/request-ssl.svg)](http://badge.fury.io/js/request-ssl)


## Quick Start

```javascript
$ npm install request-ssl
```

## Overview 

Pinned SSL version of the Node.JS [Request](https://github.com/request/request) library by Mikeal Rogers.

This can be used in place of the request library to support [SSL Certificate Pinning](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning).

For SSL, HTTP clients will establish a secure connection with a remote server when HTTPS is the protocol.  The client and server will exchange certificates as a way to establish secure communication.  By default, the client blindly trusts that the server presenting the SSL Certificate is who they say they are.  However, how does the client trust that the server presenting the SSL certificate is you think that they are?

Using SSL pinning in the client, the client will verify that the SSL Certificate being presented by the server matches the SHA1 fingerprint of the X.509 Certificate's public key.  If the SHA1 matches the fingerprint for the domain that you expect, then you can proceed with the communication.

## Usage

First, you should get the SHA1 fingerprint from your server.  Make sure you get the final URL if the server performs 301/302 HTTP redirects.

You can use the openssl tool (if you have it installed on your system):

```
openssl x509  -noout -fingerprint -sha1 -in <(openssl x509 -in <(openssl s_client -connect www.google.com:443 -prexit 2>/dev/null))
```

The output should be something like:

```
SHA1 Fingerprint=AD:B8:73:14:D5:26:84:AD:CC:6D:DE:34:09:08:DD:A4:96:F9:B2:90
```

Optionally, you can also use your browser to get the fingerprint.  In your browser, typically, there is a lock in the URL bar for a HTTPS URL. If you click on the lock you usually can get details about the certificate and can find the SHA1 fingerprint string.

The other easy way is to use a [fingerprint site](https://www.grc.com/fingerprints.htm).

You should use this fingerprint such as:

```javascript
var request = require('request-ssl');
request.addFingerprint('www.google.com', 'AD:B8:73:14:D5:26:84:AD:CC:6D:DE:34:09:08:DD:A4:96:F9:B2:90');
request('https://www.google.com',function(err,resp,body){
    // if you get here, it should be secure
});
```

You can also load fingerprints by domain from a file directory.

```javascript
var request = require('request-ssl');
request.addFingerprintDirectory('./mydirectory');
request('https://www.google.com',function(err,resp,body){
    // if you get here, it should be secure
});
```

The filename should be the name of the domain (without protocol and with no file extension).  The contents of the file should be the fingerprint.

You can have multiple fingerprints in the directory, in which case all fingerprints will be added.

## API

- `addFingerprint(name,fingerprint)`: add a fingerprint
- `addFingerprintDirectory(directory)`: add one or more fingerprints from directory
- `removeFingerprint(name)`: remove a named fingerprint
- `removeAllFingerprints`: remove all fingerprints
- `setDefaultSecureProtocol(protocol)`: set the default protocol to use for `agentOptions`
- `getLastURL`: called to return the very last url pinned
- `getFingerprintForURL(url,callback)`: get a fingerprint for a url. (only available on machines with openssl binary such as OSX and Linux. For Win32, you have to install openssl to use this)

In addition to the APIs above, all APIs that are on the `request` library are also available (such as `get`, `post`, etc).  This library should be a drop-in replacement for the request library.

## Debugging

You can turn on debug logging to help aid debugging.

Run your application and set the environment variable `DEBUG` to `request-ssl` such as:

```bash
DEBUG=request-ssl node app
```

This should print a lot of debug logging to the console which should provide more information about each request.

## Licensing

This library was written by [Jeff Haynie](https://github.com/jhaynie) / [@jhaynie](http://twitter.com/jhaynie).  Copyright(c) 2015 by Jeff Haynie. All Rights Reserved. Licensed under the [Apache Public License, version 2](http://www.apache.org/licenses/LICENSE-2.0).  See the LICENSE file for more details.


