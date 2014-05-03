// digest auth request v0.4.1
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

	// determine if a post, so that request will send data 
	this.post = false;
	if (method.toLowerCase() == 'post' || method.toLowerCase() == 'put') this.post = true;

	// start here
	// successFn - will be passed JSON data
	// errorFn - will be passed error status code
	// data - optional, for POSTS
	this.request = function(successFn, errorFn, data) {
		// posts data as JSON if there is any
		if (data !== null) self.data = JSON.stringify(data);
		self.successFn = successFn;
		self.errorFn = errorFn;

		if (self.nonce == null) {
			self.unauthenticatedRequest(self.data);
		} else {
			self.authenticatedRequest();
		}		
	}
	this.unauthenticatedRequest = function(data) {		
		self.firstRequest = new XMLHttpRequest();
		self.firstRequest.open(method, url, true);
		self.firstRequest.timeout = self.timeout;
		// if we are posting, add appropriate headers
		if (self.post) {
			self.firstRequest.setRequestHeader('Content-type', 'application/json');
			self.firstRequest.setRequestHeader('Content-length', self.data.length);
			self.firstRequest.setRequestHeader('Connection', 'close');
		}
		self.firstRequest.onreadystatechange = function() {

			// 2: received headers,  3: loading, 4: done
			if (self.firstRequest.readyState == 2) { 

				var responseHeaders = self.firstRequest.getAllResponseHeaders();
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
			if (self.firstRequest.readyState == 4) {
				if (self.firstRequest.status == 200) {
					if (self.firstRequest.responseText !== 'undefined') {
						if (self.firstRequest.responseText.length > 0) {
							self.successFn(JSON.parse(self.firstRequest.responseText));
						}
					} else {
						self.successFn();
					}
				}
			}
		}
		// send
		if (self.post) {
			// in case digest auth not required
			self.firstRequest.send(self.data);
		} else {
			self.firstRequest.send();
		}
		console.log('[digestAuthRequest] Unauthenticated request to '+url);
	}
	this.authenticatedRequest = function() {

		self.response = self.formulateResponse();

		self.request = new XMLHttpRequest();
		self.request.open(method, url, true);
		self.request.timeout = self.timeout;
		var digestAuthHeader =
			'X-Digest username="'+username+'", '+
			'realm="'+self.realm+'", '+
			'nonce="'+self.nonce+'", '+
			'uri="'+url+'", '+
			'response="'+self.response+'", '+
			'qop='+self.qop+', '+
			'nc='+('00000000' + self.nc).slice(-8)+', '+
			'cnonce="'+self.cnonce+'"';
		self.request.setRequestHeader('Authorization', digestAuthHeader);
		// if we are posting, add appropriate headers
		if (self.post) {
			self.request.setRequestHeader('Content-type', 'application/json');
			self.request.setRequestHeader('Content-length', data.length);
			self.request.setRequestHeader('Connection', 'close');
		}
		self.request.onload = function() {
			
			// success
  			if (self.request.status >= 200 && self.request.status < 400) {
  				// increment nonce count
				self.nc++;
				// return JSON
				if (self.request.responseText !== 'undefined') {					
					if (self.request.responseText.length > 0) {
						self.successFn(JSON.parse(self.request.responseText));
					}
				} else {
					self.successFn();
				}
			}
			// failure
			else {
				self.nonce = null;
				self.errorFn(self.request.status);
			}
		}
		self.request.onerror = function() { 
			console.log('request error');
			self.nonce = null;
			self.errorFn(self.request.status);
		};
		// send
		if (self.post) {
			self.request.send(self.data);
		} else {
			self.request.send();
		}
		console.log('[digestAuthRequest] Authenticated request to '+url);
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