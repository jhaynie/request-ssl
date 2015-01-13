var should = require('should'),
	wrench = require('wrench'),
	request = require('../'),
	fs = require('fs'),
	path = require('path'),
	helper = require('./helper');

var TMP = path.join(require('os').tmpdir(), String(+new Date()));

describe('pinned url', function(){
	this.timeout(30000);

	var fingerprint1, fingerprint2;

	before(function(){
		fs.mkdirSync(TMP);
	});

	after(function(){
		fs.existsSync(TMP) && wrench.rmdirSyncRecursive(TMP);
	});

	afterEach(function(){
		request.resetLastURL();
	});

	it('should fetch www.google.com fingerprint', function(done) {
		helper.getFingerprintForURL('https://www.google.com', function(err,f) {
			fingerprint1 = f;
			should(err).be.null;
			should(fingerprint1).be.a.String;
			request.addFingerprint('https://www.google.com',fingerprint1);
			done();
		});
	});

	it('should fetch google.com fingerprint', function(done) {
		helper.getFingerprintForURL('https://google.com', function(err,f) {
			fingerprint2 = f;
			should(err).be.null;
			should(fingerprint2).be.a.String;
			request.addFingerprint('https://google.com',fingerprint2);
			done();
		});
	});

	it('should pin https://www.google.com with #request.get', function(done){
		request.get('https://www.google.com', function(err,resp,body){
			should(err).be.null;
			should(resp).be.an.object;
			should(body).be.a.string;
			should(request.getLastURL()).be.eql('https://www.google.com');
			done();
		});
	});

	it('should pin https://google with #request.get', function(done){
		request.get('https://google.com', function(err,resp,body){
			should(err).be.null;
			should(resp).be.an.object;
			should(body).be.a.string;
			should(request.getLastURL()).be.eql('https://www.google.com');
			done();
		});
	});

	it('should remove fingerprints',function(){
		request.removeFingerprint('https://www.google.com');
		request.removeFingerprint('https://google.com');
	});

	it('should fail to pin https://google with #request.get', function(done){
		request.get('https://google.com', function(err,resp,body){
			should(err).not.be.null;
			should(err).be.an.object;
			should(err.message).eql('SSL authorization failed. URL: www.google.com does not have a valid fingerprint which can be used to verify the SSL certificate.');
			done();
		});
	});

	it('should fail to pin https://www.google with #request.get', function(done){
		request.get('https://www.google.com', function(err,resp,body){
			should(err).not.be.null;
			should(err).be.an.object;
			should(err.message).eql('SSL authorization failed. URL: www.google.com does not have a valid fingerprint which can be used to verify the SSL certificate.');
			done();
		});
	});

	it('should fail to pin https://www.google with #request.get using bad fingerprint', function(done){
		request.addFingerprint('https://google.com','FF:11:22:33:44');
		request.addFingerprint('https://www.google.com','AA:BB:CC:DD:EE');
		request.get('https://www.google.com', function(err,resp,body){
			should(err).not.be.null;
			should(err).be.an.object;
			should(err.message).eql("SSL authorization failed. URL to www.google.com is not authorized for SSL. Mismatched SSL fingerprint. This likely means that the URL doesn't point to the expected server or there is an unexpected man-in-the-middle.");
			done();
		});
	});

	it('should add fingerprints from directory', function(done){
		var fn1 = fs.writeFileSync(path.join(TMP,'www.google.com'),fingerprint1);
		var fn2 = fs.writeFileSync(path.join(TMP,'google.com'),fingerprint2);
		request.addFingerprintDirectory(TMP);
		request.get('https://google.com', function(err,resp,body){
			should(err).be.null;
			should(resp).be.an.object;
			should(body).be.a.string;
			should(request.getLastURL()).be.eql('https://www.google.com');
			done();
		});
	});

	it('should request with URL string', function(done){
		request('https://www.google.com', function(err,resp,body){
			should(err).be.null;
			should(resp).be.an.object;
			should(body).be.a.string;
			should(request.getLastURL()).be.eql('https://www.google.com');
			done();
		});
	});

	it('should request with URL in object', function(done){
		request({url:'https://www.google.com'}, function(err,resp,body){
			should(err).be.null;
			should(resp).be.an.object;
			should(body).be.a.string;
			should(request.getLastURL()).be.eql('https://www.google.com');
			done();
		});
	});

	it('should request with URI in object', function(done){
		request({uri:'https://www.google.com'}, function(err,resp,body){
			should(err).be.null;
			should(resp).be.an.object;
			should(body).be.a.string;
			should(request.getLastURL()).be.eql('https://www.google.com');
			done();
		});
	});

	it('should send error if no callback specified', function(done){
		var req = request('https://www.yahoo.com');
		req.on('error', function(e){
			should(e).be.an.object;
			should(e.message).be.eql('SSL authorization failed. URL: www.yahoo.com does not have a valid fingerprint which can be used to verify the SSL certificate.');
			done();
		});
	});

	it('should skip for non-SSL', function(done){
		var req = request('http://www.google.com');
		req.on('error',done);
		req.on('end', function(){
			should(request.getLastURL()).be.null;
			done();
		});
	});

	it('should remove all fingerprints',function(done){
		request.removeAllFingerprints();
		var req = request('https://www.google.com');
		req.on('error', function(e){
			should(e).be.an.object;
			should(e.message).be.eql('SSL authorization failed. URL: www.google.com does not have a valid fingerprint which can be used to verify the SSL certificate.');
			done();
		});
	});

	it('should fail is adding fingerprint without no domain',function(){
		(function(){
			request.addFingerprint();
		}).should.throw('missing name');
	});

	it('should fail is adding fingerprint without no fingerprint',function(){
		(function(){
			request.addFingerprint('name');
		}).should.throw('missing fingerprint');
	});

	it('should support getting the request library itself',function(){
		should(request.request).be.an.object;
	});

});