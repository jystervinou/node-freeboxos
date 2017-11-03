/*jslint node: true, esversion: 6, sub: true */
"use strict";

const http = require('http');
const request = require('request');
const crypto = require('crypto');
const EventEmitter = require('events');
const debug = require('debug')('node-freeboxos');
const fs = require('fs');
const async = require('async');

const app = {
	app_id: "testApp1",
	app_name: "Test Node App",
	app_version: '0.0.1',
	device_name: "NodeJS",

	app_token: '',
	track_id: '',

	status: '',
	logged_in: false,

	challenge: null,
	password: null,
	session_token: null,

	permissions: {}
};

const defaultFreebox = {
	ip: 'mafreebox.freebox.fr', // default
	port: 80, // default

	url: '',

	uid: '', // freebox id
	deviceName: '',
	deviceType: '',

	apiCode: '',
	apiVersion: '',
	apiBaseUrl: ''
};


/*
 * CONNECTION & INFORMATIONS
 */

class Freebox extends EventEmitter {

	/**
	 *
	 * @param {Object} [configuration] - Configurations
	 * @param {Object} [configuration.app] - Application configurations
	 */
	constructor(configuration) {
		super();
		configuration = configuration || {};
		this._configuration = configuration;

		var app = configuration.app || {};

		if (configuration.jsonPath) {
			var jcontent = fs.readFileSync(configuration.jsonPath, {encoding: 'utf8'});
			// debug("constructor", "jsonContent=", jcontent);
			var content = JSON.parse(jcontent);
			debug("constructor", "JSON=", content);
			Object.assign(app, content);

			if (configuration.jsonAutoSave) {
				this.on('app', (app)=> {
					var jcontent = JSON.stringify(app, null, '\t');

					debug("constructor", "App changed: Save jcontent=", jcontent);
					fs.writeFileSync(configuration.jsonPath, jcontent);
				});
			}
		}

		debug("constructor", "app=", app);

		if (!app.app_id) {
			throw new Error("app_id must be defined in the app object");
		}
		if (!app.app_name) {
			throw new Error("app_name must be defined in the app object");
		}
		if (!app.app_version) {
			throw new Error("app_version must be defined in the app object");
		}
		if (!app.device_name) {
			throw new Error("device_name must be defined in the app object");
		}

		if (app.session_token) {
			app.logged_in = true;
		}

		this._app = app;

		this._freebox = Object.assign({}, defaultFreebox, configuration.freebox || {});

		this._baseURL = configuration.baseURL;
		if (!this._baseURL) {
			this._baseURL = 'http://' + this._freebox.ip + ':' + this._freebox.port;
		}

		debug("constructor", "Freebox url=", this._baseURL);
	}


	/**
	 * Save connection information into a file
	 *
	 * @param {string} path - The path of the file
	 * @param {function} [callback] - Callback which was called for result
	 * @returns Promise
	 */
	saveJSON(path, callback) {
		return P((callback) => this._saveJSON(path, callback), callback);
	}

	/**
	 * @private
	 */
	_saveJSON(path, callback) {
		var app = this._app;

		var json = JSON.stringify(app);

                fs.writeFile(path, json, callback);
	}


	/**
	 * Request for freebox OS version
	 *
	 * To get the result, you can use Callback method or Promise object.
	 *
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	version(callback) {

		return P((callback) => this._version(callback), callback);
	}

	/**
	 * @private
	 */
	_version(callback) {
		var freebox = this._freebox;

		debug("_version", "get version of freebox host=", freebox.ip);

		var options = {
			url: this._baseURL + '/api_version',
			json: true
		};

		request(options, (error, response, body) => {
			if (error) {
				debug("_version", "Can not get api_version", error);

				this.emit("connect:failed", error, response);
				return callback(error);
			}

			if (response.statusCode !== 200) {
				debug("_version", "Unsupported status code ! (" + response.statusCode + ")");

				this.emit("connect:failed", error, response);
				return callback(error);
			}

			var jbody = body;

			// debug("version","response="+jbody);

			freebox.uid = jbody.uid;
			freebox.deviceName = jbody.device_name;
			freebox.deviceType = jbody.device_type;

			freebox.apiVersion = jbody.api_version;
			freebox.apiCode = 'v' + jbody.api_version.substr(0, 1);
			freebox.apiBaseUrl = jbody.api_base_url;

			freebox.url = this._baseURL + freebox.apiBaseUrl + freebox.apiCode + '/';

			debug("_version", "freebox=", freebox);

			this.emit("freebox", freebox);

			callback(null, freebox, jbody);
		});
	}


	/**
	 * Ask an authorize token
	 *
	 * To get the result, you can use Callback method or Promise object.
	 *
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	authorize(callback) {

		return P((callback) => this._authorize(callback), callback);
	}

	/**
	 * @private
	 */
	_authorize(callback) {

		var freebox = this._freebox;

		var app = this._app;

		// Asking for an app token

		if (!freebox.url) {
			return callback(new Error("Freebox URL must be defined"));
		}

		var json = {
			"app_id": app.app_id,
			"app_name": app.app_name,
			"app_version": app.app_version,
			"device_name": app.device_name
		};

		debug("_authorize", "Request authorisation json=", json);

		var options = {
			url: freebox.url + 'login/authorize/',
			method: 'POST',
			json: json,
			encode: 'utf-8'
		};

		request(options, (error, response, body) => {
			debug("_authorize", "Request login/authorize response=", body, "error=", error);

			if (error) {
				debug("_authorize", "Can not login/authorize", error);

				return callback(error);
			}

			var oldAppToken = app.app_token;
			var oldTrackId = app.track_id;

			if (response.statusCode !== 200) {
				debug("_authorize", "Unsupported status code ! (" + response.statusCode + ")");
				error = new Error("Unsupported status code");
				error.response = response;
				app.app_token = null;
				app.track_id = null;

			} else if (!body || body.success !== true) {
				debug("_authorize", "Unauthorized response=", body);
				error = new Error("Unauthorized response");
				error.body = body;
				app.app_token = null;
				app.track_id = null;

			} else {
				app.app_token = body.result.app_token;
				app.track_id = body.result.track_id;

				debug("_authorize", "App_token=", app.app_token, "track_id=", app.track_id);
			}

			var appChanged = false;
			if (oldAppToken !== app.app_token) {
				this.emit("app_token", app.app_token);
				appChanged = true;

			}
			if (oldTrackId !== app.track_id) {
				this.emit("track_id", app.track_id);
				appChanged = true;

			}
			if (appChanged) {
				this.emit("app", app);
			}

			callback(error, app, body);
		});
	}

	/**
	 * Return authorize status
	 *
	 * To get the result, you can use Callback method or Promise object.
	 *
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	getAuthorizeStatus(callback) {

		return P((callback) => this._getAuthorizeStatus(callback), callback);
	}

	/**
	 * @private
	 */
	_getAuthorizeStatus(callback) {
		// Track authorization progress
		var freebox = this._freebox;
		var app = this._app;

		if (!freebox.url) {
			return callback(new Error("Freebox URL must be defined"));
		}

		if (!app.track_id) {
			return callback(new Error("Application track id must be defined"));
		}

		var options = {
			url: freebox.url + 'login/authorize/' + app.track_id,
			json: true
		};

		request(options, (error, response, body) => {
			debug("_getAuthorizeStatus", "Request login/authorize status trackId=", app.track_id, "response=", body, "error=", error);

			if (error) {
				debug("_getAuthorizeStatus", "Can not login/authorize", error);

				return callback(error);
			}


			var oldStatus = app.status;
			var oldChallenge = app.challenge;
			var oldPassword = app.password;

			if (response.statusCode !== 200) {
				debug("_getAuthorizeStatus", "Unsupported status code ! (" + response.statusCode + ")");
				error = new Error("Unsupported status code");
				error.response = response;
				app.status = null;
				app.challenge = null;
				app.password = null;

			} else if (!body || body.success !== true) {
				debug("_getAuthorizeStatus", "getTrackStatus response=", body.result);
				error = new Error("Invalid response");
				error.body = body;
				app.status = null;
				app.challenge = null;
				app.password = null;

			} else {
				app.status = body.result.status; // Normaly 'pending'
				app.challenge = body.result.challenge;

				debug("_getAuthorizeStatus", "status=", app.status, "challenge=", app.challenge);
			}

			var appChanged = false;
			if (oldStatus != app.status) {
				this.emit("status", app.status);
				app.password = null;
				appChanged = true;
			}
			if (oldChallenge != app.challenge) {
				this.emit("challenge", app.challenge);
				app.password = null;
				appChanged = true;
			}
			if (oldPassword != app.password) {
				this.emit("password", app.password);
				appChanged = true;
			}
			if (appChanged) {
				this.emit("app", app);
			}

			callback(error, app, body.result);
		});
	}

	/**
	 * Wait for the application's grant by the user. This method could request Version and Authorize token if needed.
	 *
	 * To get the result, you can use Callback method or Promise object.
	 *
	 * @param {number} [delay] - Delay in milliseconds
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	waitApplicationGranted(delay, callback) {
		if (arguments.length == 1 && typeof(delay) === "function") {
			callback = delay;
			delay = undefined;
		}

		return P((callback) => this._waitApplicationGranted(delay, callback), callback);
	}

	/**
	 * @private
	 */
	_waitApplicationGranted(delay, callback) {
		debug("_waitApplicationGranted", "delay=", delay);

		var freebox = this._freebox;
		var app = this._app;

		var retryCb = (error) => {
			if (error) {
				return callback(error);
			}

			setImmediate(() => this._waitApplicationGranted(delay, callback));
		};

		if (!freebox.url) {
			this._version(retryCb);
			return;
		}

                if (!app.track_id) {
			this._authorize(retryCb);
			return;
		}

		if (!app.password) {
			this._login(retryCb);
			return;
		}

		this._waitStatusGranted(delay, callback);
	}


	/**
	 * Wait for the application grant.
	 *
	 * To get the result, you can use Callback method or Promise object.
	 *
	 * @param {number|undefined} [delay] - Delay in milliseconds
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	waitStatusGranted(delay, callback) {
		if (arguments.length == 1 && typeof(delay) === "function") {
			callback = delay;
			delay = undefined;
		}


		return P((callback) => this._waitStatusGranted(delay, callback), callback);
	}

	/**
	 * @private
	 */
	_waitStatusGranted(delay, callback) {
		if (typeof(delay) === "function") {
			callback = delay;
			delay = undefined;
		}

		debug("_waitStatusGranted", "delay=", delay);

		var app = this._app;

		debug("_waitSatusGranted", "App status=", app.status, "delay=", delay);

		this._getAuthorizeStatus((error, app) => {
			if (error) {
				debug("_waitSatusGranted", "getAuthorize status returns error=", error);
				return callback(error);
			}

			debug("_waitSatusGranted", "new app=", app);

			if (app.status === 'granted') {
				return callback(null, app);
			}

			if (app.status !== 'pending') { // If the app is denied or timeout or revoked
				var ex = new Error("The app is not accepted. You must register it.");
				ex.status = app.status;
				return callback(ex);
			}

			debug("waitStatusGranted", "delay=", delay);

			if (delay > 0) {
				delay -= 1000;

				setTimeout(() => {
					this._waitStatusGranted(delay, callback);

				}, 1000);
				this.emit("wait", app);
				return;
			}

			var error2 = new Error("Waiting for user timeout");
			error2.code = 'waiting';
			error2.status = app.status;
			callback(error2);
		});
	}

	/**
	 * Login the application
	 *
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	login(callback) {
		return P((callback) => this._login(callback), callback);
	}

	/**
	 * @private
	 */
	_login(callback) {
		debug("_login", "Start login");
		// Asking a new challenge

		var app = this._app;
		var freebox = this._freebox;

		if (!freebox.url) {
			return callback(new Error("Freebox URL must be defined"));
		}

		var options = {
			url: freebox.url + 'login',
			json: true
		};

		request(options, (error, response, body) => {
			debug("_login", "Login response=", body, "error=", error);
			if (error) {
				debug("_login", "Can not login", error);
				return callback(error);
			}

			var oldLoggedIn = app.logged_in;
			var oldChallenge = app.challenge;
			var oldPassword = app.password;

			if (response.statusCode !== 200) {
				debug("_login", "Unsupported status code ! (" + response.statusCode + ")");
				error = new Error("Unsupported status code");
				error.response = response;
				app.logged_in = false;
				app.challenge = null;
				app.password = null;

			} else if (!body.result || body.success !== true) {
				debug("_login", "getTrackStatus response=", body.result);
				error = new Error("Invalid response");
				error.body = body;
				app.logged_in = false;
				app.challenge = null;
				app.password = null;

			} else {
				debug("_login", "Response body=", body.result);

				app.logged_in = body.result.logged_in; // Update login status
				app.challenge = body.result.challenge; // Update challenge
				app.password = crypto.createHmac('sha1', app.app_token).update(app.challenge).digest('hex');
			}

			var appChanged = false;
			if (oldLoggedIn !== app.logged_in) {
				this.emit("logged_in", app.logged_in);
				appChanged = true;
			}
			if (oldChallenge != app.challenge) {
				this.emit("challenge", app.challenge);
				appChanged = true;
			}
			if (oldPassword != app.password) {
				this.emit("password", app.password);
				appChanged = true;
			}
			if (appChanged) {
				this.emit("app");
			}

			// If we're not logged_in
			if (!app.logged_in) {
// error=new Error("Not logged");
// error.response=body.result;
			}

			callback(error, app, body.result);
		});
	}

	/**
	 * Start a session
	 *
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	startSession(callback) {
		return P((callback) => this._session(callback), callback);
	}

	/**
	 * @private
	 */
	_session(callback) {
		debug("_session", "Start session");

		var freebox = this._freebox;
		var app = this._app;

		if (!freebox.url) {
			return callback(new Error("Freebox URL must be defined"));
		}

		if (!app.password) {
			return callback(new Error("Application password must be defined"));
		}

		// POST app_id & password
		var options = {
			url: freebox.url + 'login/session/',
			method: 'POST',
			json: {
				"app_id": app.app_id,
				"app_version": app.app_version,
				"password": app.password,
			},
			encode: 'utf-8'
		};

		request(options, (error, response, body) => {
			if (error) {
				debug("_session", "Can not login session", error);
				return callback(error);
			}

			var oldChallenge = app.challenge;
			var oldSessionToken = app.session_token;
			var oldLoggedIn = app.logged_in;
			var oldPermissions = app.permissions;

			debug("_session", "Request response statusCode=", response.statusCode, body);

			if (response.statusCode == 200) { // OK
				app.challenge = body.result.challenge; // Update challenge
				app.session_token = body.result.session_token; // Save session token
				app.logged_in = true; // Update login status
				app.permissions = body.result.permissions;

			} else if (response.statusCode == 403) { // Forbidden
				app.challenge = body.result.challenge; // Update challenge
				app.logged_in = false;
				app.session_token = null;
				app.password = null;

				error = new Error("Session failed !");
				error.code = "failed";
				error.serverErrorCode = body && body.error_code;
				error.response = body;
				error.statusCode = response.statusCode;

				if (body && body.error_code == "invalid_token") {
					error.canRetry = true;
				}

			} else {
				error = new Error("Unsupported status code (" + response.statusCode + ")");
				error.code = "unsupported";
				error.response = response;
				error.statusCode = response.statusCode;
			}

			var appChanged = false;
			if (oldLoggedIn !== app.logged_in) {
				this.emit("logged_in", app.logged_in);
				appChanged = true;
			}
			if (oldChallenge !== app.challenge) {
				this.emit("challenge", app.challenge);
				appChanged = true;
			}
			if (oldSessionToken !== app.session_token) {
				this.emit("session_token", app.session_token);
				appChanged = true;
			}
			if (JSON.stringify(oldPermissions) !== JSON.stringify(app.permissions)) {
				this.emit("permissions", app.permissions);
				appChanged = true;
			}
			if (appChanged) {
				this.emit("app", app);
			}

			callback(error, app, body.result);
		});
	}

	/**
	 * Logout the application
	 *
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	logout(callback) {
		return P((callback) => this._logout(callback), callback);
	}

	/**
	 * @private
	 */
	_logout(callback) {
		debug("_logout", "Start opening session");
		// Asking a new challenge

		var app = this._app;

		request(freebox.url + 'login/logout/', (error, response, body) => {
			if (error) {
				debug("_logout", "Can not logout", error);
				return callback(error);
			}

			app.session_token = null;
			app.challenge = null;
			app.logged_in = false;

			this.emit("logged_in", false);
			this.emit("challenge", null);
			this.emit("session_token", null);
			this.emit("app", app);

			callback(null, app);
		});
	}

	/**
	 *
	 * @param {Function} [callback]
	 * @returns {Promise|undefined}
	 */
	openSession(callback) {
		return P((callback) => this._getSession(callback), callback);
	}

	/**
	 * @param {Function} callback
	 * @private
	 */
	_getSession(callback) {
		var freebox = this._freebox;
		var app = this._app;

		debug("_getSession", "apiVersion=", freebox.apiVersion, "appStatus=", app.status, "appLoggedIn=", app.logged_in, "appSessionToken=", app.session_token);

		var retryCb = (error) => {
			if (error) {
				debug("_getSession", "Retry CB error=", error);

				if (!error.canRetry) {
					return callback(error);
				}
			}

			setImmediate(() => this._getSession(callback));
		};

		if (!freebox.url) {
			this._version(retryCb);
			return;
		}

		if (!app.app_token || typeof(app.track_id) !== "number") {
			this._authorize(retryCb);
			return;
		}

		if (!app.password) {
			this._login(retryCb);
			return;
		}

		if (app.status !== 'granted') {
			this._waitStatusGranted(this._configuration.registerDelayMs, retryCb);
			return;
		}

		if (!app.challenge) {
			this._login(retryCb);
			return;
		}

		if (!app.session_token) {
			this._session(retryCb);
			return;
		}

		callback(null, app);
	}

	/**
	 * stats method
	 *
	 * Return some stats about the box.
	 *
	 * @see http://dev.freebox.fr/sdk/os/rrd/ for all the options
	 *
	 * @param {string} db - net, temp, dsl, switch
	 * @param {timestamp} [date_start] - The requested start timestamp of the stats to get (optional)
	 * @param {timestamp} [date_end] The requested end timestamp of the stats to get (optional)
	 * @param {number} [precision] - Precision
	 * @param {object} [fields] - For just getting some fields (optional) ex : ['tx_1', 'tx_2']
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */

	stats(db, date_start, date_end, precision, fields, callback) {
		switch (arguments.length) {
			case 2:
				callback = date_start;
				date_start = undefined;
				break;
			case 3:
				callback = date_end;
				date_end = undefined;
				break;
			case 4:
				callback = precision;
				precision = undefined;
				break;
			case 5:
				callback = fields;
				fields = undefined;
				break;
		}

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._stats(app, db, date_start, date_end, precision, fields, callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_stats(app, db, date_start, date_end, precision, fields, callback) {

		if (!app.permissions.settings) {
			var ex = new Error("No settings permission");
			ex.permissions = app.permissions;
			return callback(ex);
		}

		var json = {db: db};

		if (date_start) {
			json.date_start = date_start;
		}
		if (date_end) {
			json.date_end = date_end;
		}
		if (precision) {
			json.precision = precision;
		}
		if (fields) {
			json.fields = fields;
		}

		var freebox = this._freebox;

		var options = {
			url: freebox.url + 'rrd',
			json: json,
			method: 'POST'
		};

		this._returnJSON("_stats", app, options, 0, callback);
	}

	/**
	 *
	 * @param debugName
	 * @param app
	 * @param options
	 * @param retry
	 * @param callback
	 * @private
	 */
	_returnJSON(debugName, app, options, retry, callback) {
		options.headers = options.headers || {};
		options.headers['X-Fbx-App-Auth'] = app.session_token;

		debug("_returnJSON", "Send request options=", options);

		request(options, (error, response, body) => {
			if (error) {
				debug(debugName, "Request error", error);
				return callback(error);
			}

			debug(debugName, "Request statusCode=", response.statusCode, " result=", body.result);

			if (response.statusCode === 403 && retry < 2) {
				this._session((error, app) => {
					if (error) {
						return callback(error);
					}

					this._returnJSON(debugName, app, options, retry + 1, callback);
				});
				return;
			}

			if (response.statusCode != 200) {
				var ex = new Error("Invalid response", error);
				ex.response = response;
				ex.statusCode = response.statusCode;
				return callback(ex);
			}

			callback(null, body.result, body); // return stats
		});
	}

	/**
	 * downloadsStats method
	 *
	 * Return the download stats
	 *
	 * Example :
	 *
	 * freebox.downloadsStats(function(msg){ console.log(msg); });
	 *
	 * @see http://dev.freebox.fr/sdk/os/download/#get-the-download-stats
	 *
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	downloadsStats(callback) {
		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._stats(app, callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_downloadsStats(app, callback) {

		if (!app.permissions.downloader) {
			var ex = new Error("No settings permission");
			ex.permissions = app.permissions;
			return callback(ex);
		}

		var freebox = this._freebox;

		var options = {
			url: freebox.url + 'downloads/stats'
		};

		this._returnJSON("_downloadsStats", app, options, 0, callback);
	}


	/**
	 * downloads method
	 *
	 * Manage downloads.
	 *
	 * With no id submitted it returns the entire downloads list. With an id you can manage the selected download.
	 *
	 * Example :
	 *
	 * freebox.downloads(2, udpate, {"io_priority": "high","status": "stopped"}, (msg) => { console.log(msg); });
	 *
	 * @see http://dev.freebox.fr/sdk/os/download/#download-api
	 *
	 * @param {int} id - The id of the download. If null, it will return the entire download list
	 * @param {string} action - The action to do if and id is submited. Could be read, log, udpate, delete and deleteAndErase - delete
	 *            the download and erase the files downloaded. If null, it's set to read.
	 * @param {json} [params] - If action update, the item to update.
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	downloads(id, action, params, callback) {
		switch (arguments.length) {
			case 3:
				callback = params;
				params = undefined;
				break;
		}

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._downloads(app, id, action, params, callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_downloads(app, id, action, params, next, callback) {

		if (!app.permissions.downloader) {
			var ex = new Error("No settings permission");
			ex.permissions = app.permissions;
			return callback(ex);
		}

		var freebox = this._freebox;

		// All the download list
		if (!id) {
			var options2 = {
				url: freebox.url + 'downloads/'
			};

			this._returnJSON("_downloads", app, options2, 0, callback);
			return;
		}

		var options = {
			url: freebox.url + 'downloads/' + id,
			json: {}
		};

		// What to do ?

		action = action || 'read';

		switch (action) {
			case 'delete' :
				options.method = 'DELETE';
				break;

			case 'deleteAndErase' :
				options.url += '/erase';
				options.method = 'DELETE';
				break;

			case 'update' :
				options.method = 'PUT';
				options.json = params;
				break;

			case 'log' :
				options.url += '/log';
				options.method = 'GET';
				break;

			case 'read' :
				options.method = 'GET';
				break;

			default :
				return callback('This action doesn\'t exist. Try read, log, update, delete or deleteAndErase.');
		}

		this._returnJSON("_downloads:" + action, app, options, 0, callback);
	}


	/**
	 * addDownloads method
	 *
	 * Add one or multiple download(s) to the queue.
	 *
	 * Example :
	 *
	 * freebox.addDownloads(
	 * "http://blog.baillet.eu/public/ciel-bleu-sans-avion-20100417-imgis5346.jpg\nhttp://www.8alamaison.com/wp-content/uploads/2013/04/z2354-carton-rouge3.gif",
	 * null, false, null, null, null, function(msg) { console.log(msg); } );
	 *
	 * @param {string} url - Url(s) to download. If multiple, separated by a new line delimiter "\n"
	 * @param {string} [dir] - The download destination directory
	 * @param {bool} [recursive] - If true the download will be recursive. See http://dev.freebox.fr/sdk/os/download/#adding-by-url
	 * @param {string} [username] - Username
	 * @param {string} [password] - Password
	 * @param {string} [archive_password] - Password to decompress the archive if encrypted.
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	addDownloads(url, dir, recursive, username, password, archive_password, callback) {
		switch (arguments.length) {
			case 6:
				callback = archive_password;
				archive_password = undefined;
				break;
			case 5:
				callback = password;
				password = undefined;
				break;
			case 4:
				callback = username;
				username = undefined;
				break;
			case 3:
				callback = recursive;
				recursive = undefined;
				break;
			case 2:
				callback = dir;
				dir = undefined;
				break;
		}

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._downloads(app, url, dir, recursive, username, password, archive_password, callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_addDownloads(app, url, dir, recursive, username, password, archive_password, callback) {

		if (!app.permissions.downloader) {
			var ex = new Error("No settings permission");
			ex.permissions = app.permissions;
			return callback(ex);
		}

		// Form to submit

		var form = {
			'download_url_list': url,
			'recursive': recursive
		};

		if (dir) {
			form.download_dir = dir;
		}

		if (username && password) {
			form.username = username;
			form.password = password;
		}

		if (archive_password) {
			form.archive_password = archive_password;
		}

		var options = {
			url: freebox.url + 'downloads/add',
			form: form,
			method: 'POST'
		};

		this._returnJSON("_addDownloads", app, options, 0, callback);
	}

	/**
	 * Return all the calls.
	 *
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	calls(callback) {
		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._calls(app, callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_calls(app, callback) {

		if (!app.permissions.calls) {
			return callback(new Error("No call permission"));
		}

		var options = {
			url: this._freebox.url + 'call/log/',
			json: true
		};

		this._returnJSON("_calls", app, options, 0, callback);
	}

	/**
	 * Manage a call.
	 *
	 * @param {int} id - Call id
	 * @param {string} [action=Read] - The action to do. Read (default), update, delete.
	 * @param {Object} [params] - If update, params to update.
	 * @param {Function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	call(id, action, params, callback) {
		switch (arguments.length) {
			case 3:
				callback = params;
				params = undefined;
				break;
			case 2:
				callback = action;
				action = undefined;
				break;
		}

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._call(app, id, action, params, callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_call(id, action, params, callback) {


		if (!app.permissions.calls) {
			return callback(new Error("No call permission"));
		}

		var options = {
			url: freebox.url + 'call/log/' + id,
			json: {}
		};

		switch (action) {
			case null :
			case 'read' :
				break;

			case 'update' :
				options.method = "PUT";
				options.json = params;
				break;

			case 'delete' :
				options.method = "DELETE";
				break;
		}

		this._returnJSON("_call", app, options, 0, callback);
	}


	/**
	 * Return all detected hosts.
	 *
	 * @param {function} [callback] - Callback which was called for result
	 * @returns {Promise|undefined}
	 */
	lanBrowser(callback) {

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._lanBrowser(app, callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_lanBrowser(app, callback) {

		if (!app.permissions.calls) {
			return callback(new Error("No call permission"));
		}

		var options = {
			url: this._freebox.url + 'lan/browser/interfaces/',
			json: true
		};

		this._returnJSON("_lanBrowser", app, options, 0, (error, result) => {
			if (error) {
				return callback(error);
			}

			var ret = [];

			async.forEach(result, (inte, callback) => {

				var options = {
					url: this._freebox.url + 'lan/browser/' + inte.name + '/',
					json: true
				};

				this._returnJSON("_lanBrowser:list", app, options, 0, (error, result) => {
					if (error) {
						return callback(error);
					}


					debug("_lanBrowser", "list of interface=", inte, "=>", result);


					result.forEach((r) => {
						r.$interface = inte.name;
						ret.push(r);
					});

					callback(null, result);
				});
			}, (error) => {
				if (error) {
					return callback(error);
				}

				debug("_lanBrowser", "finalList=", ret);

				callback(null, ret);
			});
		});
	}

	/**
	 *
	 * @param {boolean} [state] Requested state
	 * @param {Function} [callback]
	 * @returns {Promise|*}
	 */
	setWifiState(state, callback) {
		if (arguments.length === 1 && typeof(callback) === "function") {
			callback = state;
			state = undefined;
		}

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}

			if (state === undefined) {
				this._getWifiConfig((error, state) => {
					if (error) {
						return callback(error);
					}

					this._setWifiConfig({enabled: !state.enabled}, callback);
				});
				return;
			}

			this._setWifiConfig(state, callback);
		}), callback);
	}

	/**
	 *
	 * @param {Object} config - Wifi configuration
	 * @param {Function} [callback]
	 * @returns {Promise|*}
	 */
	setWifiConfig(config, callback) {

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._setWifiConfig(config, callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_setWifiConfig(json, callback) {
		var app = this._app;

		var options = {
			url: this._freebox.url + 'wifi/config/',
			json: json,
			method: "PUT"
		};

		this._returnJSON("_setWifiConfig", app, options, 0, (error, result, body) => {
			if (error) {
				return callback(error);
			}

			if (body.success !== true) {
				error = new Error("Request failed");
				error.result = result;

				return callback(error);
			}

			callback(null, body.result.enabled);
		});
	}

	/**
	 * @param {Function} [callback]
	 * @returns {Promise|*}
	 */
	getWifiState(callback) {

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._getWifiConfig((error, config) => {
				if (error) {
					return callback(error);
				}

				callback(null, config.enabled);
			});
		}), callback);
	}

	/**
	 * @param {Function} [callback]
	 * @returns {Promise|*}
	 */
	getWifiConfig(callback) {

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._getWifiConfig(callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_getWifiConfig(callback) {
		var app = this._app;

		var options = {
			url: this._freebox.url + 'wifi/config/',
			json: true
		};

		this._returnJSON("_getWifiConfig", app, options, 0, (error, result, body) => {
			if (error) {
				return callback(error);
			}

			if (body.success !== true) {
				error = new Error("Request failed");
				error.result = result;

				return callback(error);
			}

			callback(null, body.result);
		});
	}

	/**
	 * @param {Function} [callback]
	 * @returns {Promise|*}
	 */
	getWifiPlanning(callback) {

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._getWifiPlanning(callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_getWifiPlanning(callback) {
		var app = this._app;

		var options = {
			url: this._freebox.url + 'wifi/planning/',
			json: true
		};

		this._returnJSON("_getWifiPlanning", app, options, 0, (error, result, body) => {
			if (error) {
				return callback(error);
			}

			if (body.success !== true) {
				error = new Error("Request failed");
				error.result = result;

				return callback(error);
			}

			callback(null, body.result);
		});
	}


	/**
	 * @param {Object} config - Planning configuration
	 * @param {Function} [callback]
	 * @returns {Promise|*}
	 */
	setWifiPlanning(config, callback) {

		return P((callback) => this._getSession((error, app) => {
			if (error) {
				return callback(error);
			}
			this._setWifiPlanning(config, callback);
		}), callback);
	}

	/**
	 * @private
	 */
	_setWifiPlanning(config, callback) {
		var app = this._app;

		var options = {
			url: this._freebox.url + 'wifi/planning/',
			json: config,
			method: "PUT"
		};

		this._returnJSON("_setWifiPlanning", app, options, 0, (error, result, body) => {
			if (error) {
				return callback(error);
			}

			if (body.success !== true) {
				error = new Error("Request failed");
				error.result = result;

				return callback(error);
			}

			callback(null, body.result);
		});
	}
}

function P(func, callback) {
	if (typeof(callback) === "function") {
		func(callback);
		return;
	}

	return new Promise((resolve, reject) => {

		func((error, value) => {
			// debug("P", "Returns error=",error,"value=",value);

			if (error) {
				return reject(error);
			}

			resolve(value);
		});
	});
}

module.exports = Freebox;
