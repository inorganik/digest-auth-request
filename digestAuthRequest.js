// digest auth request v0.3.0
// by Jamie Perkins

// dependent upon CryptoJS MD5 hashing:
// http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/md5.js

function digestAuthRequest(method, url, username, password) {

	var self = this;

	this.nonce = null; // server issued nonce
	this.realm = null; // server issued realm
	this.qop = null; // "quality of protection" - '' or 'auth' or 'auth-int'
	this.response = null; // hashed response to server challenge
	this.nc = 1; // nonce count - increments with each request used with the same nonce
	this.cnonce = null; // client nonce

	// requests
	this.firstRequest;
	this.request;

	// settings
	this.timeout = 6000;

	// determine if a post
	this.post = false;
	if (method.toLowerCase() == 'post') this.post = true;

	// start here
	// successFn - will be passed JSON data
	// errorFn - will be passed error status code
	// data - optional, for POSTS
	this.request = function(successFn, errorFn, data) {
		// posts data as JSON if there is any
		if (data) self.data = JSON.stringify(data);
		self.successFn = successFn;
		self.errorFn = errorFn;

		if (self.nonce == null) {
			self.unauthenticatedRequest(self.data);
		} else {
			self.authenticatedRequest();
		}		
	}
	this.unauthenticatedRequest = function(data) {
		firstRequest = new XMLHttpRequest();
		firstRequest.open(method, url, true);
		firstRequest.timeout = self.timeout;
		// if we are posting, add appropriate headers
		if (self.post) {
			firstRequest.setRequestHeader('Content-type', 'application/json');
			firstRequest.setRequestHeader('Content-length', data.length);
			firstRequest.setRequestHeader('Connection', 'close');
		}
		firstRequest.onreadystatechange = function() {

			// 2: received headers,  3: loading, 4: done
			if (firstRequest.readyState == 2) { 

				var responseHeaders = firstRequest.getAllResponseHeaders();
				responseHeaders = responseHeaders.split('\n');
				// get authenticate header
				var digestHeaders;
				for(var i = 0; i < responseHeaders.length; i++) {
					if (responseHeaders[i].match(/www-authenticate/i) != null) {
						digestHeaders = responseHeaders[i];
					}
				}
				if (digestHeaders != null) {
					// parse auth header and get digest auth keys
					digestHeaders = digestHeaders.split(':')[1];
					digestHeaders = digestHeaders.split(',');
					for(var i = 0; i < digestHeaders.length; i++) {
						var keyVal = digestHeaders[i].split('=');
						var key = keyVal[0];
						var val = keyVal[1].replace(/\"/g, '').trim();
						// find realm
						if (key.match(/realm/i) != null) {
							self.realm = val;
						}
						// find nonce
						if (key.match(/nonce/i) != null) {
							self.nonce = val;
						}
						// find QOP
						if (key.match(/qop/i) != null) {
							self.qop = val;
						}
					}
					// client generated keys
					self.cnonce = self.generateCnonce();
					self.nc++;
					// now we can make an authenticated request
					self.authenticatedRequest();
				}
			}
			if (firstRequest.readyState == 4) {
				if (firstRequest.status == 200) {
					self.successFn(JSON.parse(firstRequest.responseText));
				}
			}
		}
		// send
		if (self.post) {
			// in case digest auth not required
			firstRequest.send(self.data);
		} else {
			firstRequest.send();
		}
	}
	this.authenticatedRequest = function() {

		self.response = self.formulateResponse();

		request = new XMLHttpRequest();
		request.open(method, url, true);
		request.timeout = self.timeout;
		var digestAuthHeader =
			'X-Digest username="'+username+'", '+
			'realm="'+self.realm+'", '+
			'nonce="'+self.nonce+'", '+
			'uri="'+url+'", '+
			'response="'+self.response+'", '+
			'qop='+self.qop+', '+
			'nc='+('00000000' + self.nc).slice(-8)+', '+
			'cnonce="'+self.cnonce+'"';
		request.setRequestHeader('Authorization', digestAuthHeader);
		// if we are posting, add appropriate headers
		if (self.post) {
			request.setRequestHeader('Content-type', 'application/json');
			request.setRequestHeader('Content-length', data.length);
			request.setRequestHeader('Connection', 'close');
		}
		request.onload = function() {
			// success
  			if (request.status >= 200 && request.status < 400) {
  				// increment nonce count
				self.nc++;
				// return JSON
				self.successFn(JSON.parse(request.responseText));
			}
			// failure
			else {
				self.nonce = null;
				self.errorFn(request.status);
			}
		}
		request.onerror = function() { 
			console.log('request error');
			self.nonce = null;
			self.errorFn(request.status);
		};
		// send
		if (self.post) {
			request.send(self.data);
		} else {
			request.send();
		}
	}
	// hash response based on server challenge
	this.formulateResponse = function() {
		var HA1 = CryptoJS.MD5(username+':'+self.realm+':'+password).toString();
		var HA2 = CryptoJS.MD5(method+':'+url).toString();
		var response = CryptoJS.MD5(HA1+':'+
			self.nonce+':'+
			('00000000' + self.nc).slice(-8)+':'+
			self.cnonce+':'+
			self.qop+':'+
			HA2).toString();
		return response;
	}
	// generate 16 char client nonce
	this.generateCnonce = function() {
		var characters = 'abcdef0123456789';
		var token = '';
		for (var i = 0; i < 16; i++) {
			var randNum = Math.round(Math.random() * characters.length);
			token += characters.substr(randNum, 1);
		}
		return token;
	}
	this.abort = function() {
		if (self.firstRequest != null) {
			if (self.firstRequest.readyState != 4) self.firstRequest.abort();
		}
		if (self.request != null) {
			if (self.request.readyState != 4) self.request.abort();
		}
	}
}