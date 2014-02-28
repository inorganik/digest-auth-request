// digest auth request v0.1.0
// by Jamie Perkins

// dependent upon CryptoJS MD5 hashing:
// http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/md5.js
// see example in index.html

// Params:
// method - GET, POST, etc (string)
// request url (string)
// username of registered user (string)
// password of registered user (string)

function digestAuthRequest(method, url, username, password) {

	var self = this;

	this.nonce = null; // server issued nonce
	this.realm = null; // server issued realm
	this.qop = null; // "quality of protection" - '' or 'auth' or 'auth-int'
	this.response = null; // hashed response to server challenge
	this.nc = 1; // nonce count - increments with each request used with the same nonce
	this.cnonce = null; // client nonce

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
			self.unauthenticatedRequest();
		} else {
			self.authenticatedRequest();
		}		
	}
	this.unauthenticatedRequest = function() {
		var firstRequest = new XMLHttpRequest();
		firstRequest.open('GET', url, true);
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
		firstRequest.send();
	}
	this.authenticatedRequest = function() {

		self.response = self.formulateResponse();

		var request = new XMLHttpRequest();
		request.open(method, url, true);
		var digestAuthHeader =
			'X-Digest username="'+username+'", '+
			'realm="'+self.realm+'", '+
			'nonce="'+self.nonce+'", '+
			'uri="'+url+'", '+
			'response="'+self.response+'", '+
			'qop='+self.qop+', '+
			'nc='+('00000000' + self.nc).slice(-8)+', '+
			'cnonce="'+self.cnonce+'"';
		console.log(digestAuthHeader);
		request.setRequestHeader('Authorization', digestAuthHeader);

		request.onload = function() {
			// success
  			if (request.status >= 200 && request.status < 400) {
  				// increment nonce count
				self.nc++;
				// return JSON
				var data = JSON.parse(request.responseText)
				self.successFn(data);
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

		if (self.data != null) {
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
}