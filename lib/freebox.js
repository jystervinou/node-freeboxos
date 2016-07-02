/*jslint node: true, esversion: 6, sub: true */

const http         = require('http');
const request      = require('request');
const parseString  = require('xml2js').parseString;
const crypto       = require('crypto');
const EventEmitter = require('events');
const debug = require('debug')('freeboxos');
const fs = require('fs');
const async = require('async');

var app = {
    app_id        : "testApp1", 
    app_name      : "Test Node App",
    app_version   : '0.0.1',
    device_name   : "NodeJS",

    app_token     : '', 
    track_id      : '',

    status        : 'granted',
    logged_in     : false,

    challenge     : null,
    password      : null,
    session_token : null,

    permissions   : {}
};

const defaultFreebox = {
    ip         : 'mafreebox.freebox.fr', // default
    port       : 80, // default

    url        : '',

    uid        : '', // freebox id
    deviceName : '',
    deviceType : '',

    apiCode    : '',
    apiVersion : '',
    apiBaseUrl : ''
};


/*
 * CONNECTION & INFORMATIONS
 */

class Freebox extends EventEmitter {
  constructor(configuration) {
    super();
    configuration=configuration || {};

    var app=configuration.app || {};

    if (configuration.jsonPath) {
      var content=fs.readFileSync(jsonPath);
      Object.assign(app, content);
    }

    debug("freebox", "app=",app);

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
      app.logged_in=true;
    }

    this._app=app;

    this._freebox = Object.assign({}, defaultFreebox, configuration.freebox || {});
  }

  saveJSON(path, callback) {
    var app=this._app;

    var json=JSON.stringify(app);

    fs.createWriteStream(path, json, callback);
  }

  /**
   * connect method
   * 
   * Example :
   * 
   * freebox.version({ 'ip'! : 'mafreebox.freebox.fr', (optional) 'port' : 80, (optional) 'app_token' : '012345', (optional)
   * 'track_id' : '12', (optional) });
   * 
   * Update freebox information
   * 
   * @return void
   */
  version(callback) {
    var freebox=this._freebox;

    debug("version","get version of freebox host=",freebox.ip);

    var options= {
        url: 'http://'+freebox.ip+'/api_version',
        json: true
    };

    request(options, (error, response, body) => {
      if (error) {
        debug("version", "Can not get api_version", error);

        this.emit("connect:failed", error, response);
        return callback(error);
      }

      if (response.statusCode !== 200) {
        debug("version", "Unsupported status code ! ("+response.statusCode+")");

        this.emit("connect:failed", error, response);
        return callback(error);
      } 

      var jbody=body;

      //debug("version","response="+jbody);

      freebox.uid        = jbody.uid;
      freebox.deviceName = jbody.device_name;
      freebox.deviceType = jbody.device_type;

      freebox.apiVersion = jbody.api_version;
      freebox.apiCode    = 'v'+jbody.api_version.substr(0,1);
      freebox.apiBaseUrl = jbody.api_base_url;

      freebox.url = 'http://'+freebox.ip+':'+freebox.port+freebox.apiBaseUrl+freebox.apiCode+'/';

      debug("version", "freebox=",freebox);

      this.emit("freebox", freebox);

      callback(null, freebox, jbody);
    });
  }

  /**
   * 
   */
  authorize(callback) {

    var freebox=this._freebox;

    var app=this._app;

    // Asking for an app token

    if (!freebox.url) {
      return callback(new Error("Freebox URL must be defined"));
    }

    var options = {
        url    : freebox.url+'login/authorize/',
        method : 'POST',
        json   : {
          "app_id"      : app.app_id,
          "app_name"    : app.app_name,
          "app_version" : app.app_version,
          "device_name" : app.device_name
        },
        encode : 'utf-8'
    };

    request(options, (error, response, body) => {
      debug("authorize", "Request login/authorize response=",body,"error=",error);

      if (error) {
        debug("authorize", "Can not login/authorize", error);

        return callback(error);
      }

      var oldAppToken=body.app_token;
      var oldTrackId=body.track_id;

      if (response.statusCode !== 200) {
        debug("authorize", "Unsupported status code ! ("+response.statusCode+")");
        error=new Error("Unsupported status code");
        error.response=response;
        app.app_token = null;
        app.track_id  = null;

      }  else if (!body || body.success!==true) {
        debug("authorize", "Unauthorized response=",body);
        error=new Error("Unauthorized response");
        error.body=body;
        app.app_token = null;
        app.track_id  = null;

      } else {
        app.app_token = body.result.app_token;
        app.track_id  = body.result.track_id;

        debug("authorize", "App_token=",app.app_token, "track_id=",app.track_id);
      }

      var appChanged=false;
      if (oldAppToken!==app.app_token) {
        this.emit("app_token", app.app_token);
        appChanged=true;

      }
      if (oldTrackId!==app.track_id) {
        this.emit("track_id", app.track_id);
        appChanged=true;

      }
      if (appChanged) {
        this.emit("app", app);
      }

      callback(error, app, body);
    });
  }

  getAuthorizeStatus(callback) {
    // Track authorization progress
    var freebox=this._freebox;
    var app=this._app;

    if (!freebox.url) {
      return callback(new Error("Freebox URL must be defined"));
    }

    if (!app.track_id) {
      return callback(new Error("Application track id must be defined"));
    }

    var options = {
        url: freebox.url+'login/authorize/'+app.track_id,
        json: true
    };

    request(options, (error, response, body) => {
      debug("getAuthorizeStatus", "Request login/authorize status trackId=",app.track_id,"response=",body,"error=",error);

      if (error) {
        debug("getAuthorizeStatus", "Can not login/authorize", error);

        return callback(error);
      }


      var oldStatus=app.status;
      var oldChallenge=app.challenge;
      var oldPassword=app.password;

      if (response.statusCode !== 200) {
        debug("getAuthorizeStatus", "Unsupported status code ! ("+response.statusCode+")");
        error=new Error("Unsupported status code");
        error.response=response;
        app.status    = null;
        app.challenge = null;
        app.password = null;

      } else if (!body || body.success!==true) {
        debug("getAuthorizeStatus", "getTrackStatus response=",body.result);
        error=new Error("Invalid response");
        error.body=body;
        app.status    = null;
        app.challenge = null;
        app.password = null;

      } else { 
        app.status    = body.result.status; // Normaly 'pending'
        app.challenge = body.result.challenge;

        debug("getAuthorizeStatus", "status=",app.status,"challenge=",app.challenge);
      }

      var appChanged=false;
      if (oldStatus!=app.status) {
        this.emit("status", app.status);
        app.password = null;
        appChanged=true;
      }
      if (oldChallenge!=app.challenge) {
        this.emit("challenge", app.challenge);
        app.password = null;
        appChanged=true;
      }
      if (oldPassword!=app.password) {
        this.emit("password", app.password);
        appChanged=true;
      }
      if (appChanged) {
        this.emit("app", app);
      }

      callback(error, app, body.result);
    });
  }

  waitApplicationGranted(delay, callback) {
    if (typeof(delay)==="function") {
      callback=delay;
      delay=undefined;
    }

    var freebox = this._freebox;
    var app=this._app;

    var retryCb = (error) => {
      if (error) {
        return callback(error);
      }

      setImmediate(() => this.waitStatusGranted(delay, callback));
    };

    if (!freebox.url) {
      this.version(retryCb);
      return;
    }

    if (!app.password) {
      this.authorize(retryCb);
      return;
    }    

    this._waitStatusGranted(delay, callback);
  }

  waitStatusGranted(delay, callback) {
    if (typeof(delay)==="function") {
      callback=delay;
      delay=undefined;
    }

    var app=this._app;

    debug("waitStatusGranted", "App status=",app.status,"delay=",delay);

    this.getAuthorizeStatus((error, app) => {
      if (error) {
        return callback(error);
      }

      if (app.status === 'granted') {
        return callback(null, app);
      }

      if (app.status !== 'pending') { // If the app is denied or timeout or revoked
        var ex=new Error("The app is not accepted. You must register it.");
        ex.status=app.status;
        return callback(ex);
      }

      debug("waitStatusGranted", "delay=",delay);

      if (delay>0) {
        delay-=1000;

        setTimeout(() => {
          this.waitStatusGranted(delay, callback);

        }, 1000);
        this.emit("wait",app);
        return;
      }

      var error2=new Error("Waiting for user timeout");
      error2.code='waiting';
      error2.status=app.status;
      callback(error2);
    });
  }

  /**
   * sessionApp method
   * 
   * Update login status and challenge. If needed log the app = Ask for a session token.
   * 
   * @param next
   * @return void
   */
  login(callback) {
    debug("login", "Start login");
    // Asking a new challenge

    var app=this._app;
    var freebox=this._freebox;

    if (!freebox.url) {
      return callback(new Error("Freebox URL must be defined"));
    }

    var options= {
        url: freebox.url+'login',
        json: true
    };

    request(options, (error, response, body) => {
      debug("login", "Login response=",body,"error=",error);
      if (error) {
        debug("login", "Can not login", error);
        return callback(error);
      }

      var oldLoggedIn=app.logged_in;
      var oldChallenge=app.challenge;
      var oldPassword=app.password;

      if (response.statusCode !== 200) {
        debug("getAuthorizeStatus", "Unsupported status code ! ("+response.statusCode+")");
        error=new Error("Unsupported status code");
        error.response=response;
        app.logged_in    = false;
        app.challenge = null;
        app.password = null;

      } else if (!body.result || body.success!==true) {
        debug("getAuthorizeStatus", "getTrackStatus response=",body.result);
        error=new Error("Invalid response");
        error.body=body;
        app.logged_in    = false;
        app.challenge = null;
        app.password = null;

      } else { 
        debug("login", "Response body=",body.result);

        app.logged_in = body.result.logged_in; // Update login status
        app.challenge = body.result.challenge; // Update challenge
        app.password = crypto.createHmac('sha1', app.app_token).update(app.challenge).digest('hex'); 
      }

      var appChanged=false;
      if (oldLoggedIn!==app.logged_in) {
        this.emit("logged_in", app.logged_in);
        appChanged=true;
      }
      if (oldChallenge!=app.challenge) {
        this.emit("challenge", app.challenge);
        appChanged=true;
      }
      if (oldPassword!=app.password) {
        this.emit("password", app.password);
        appChanged=true;
      }
      if (appChanged) {
        this.emit("app");
      }

      // If we're not logged_in
      if (!app.logged_in) {
//      error=new Error("Not logged");
//      error.response=body.result;
      }

      callback(error, app, body.result);
    });
  }

  session(callback) {
    debug("session", "Start session");

    var freebox=this._freebox;
    var app=this._app;

    if (!freebox.url) {
      return callback(new Error("Freebox URL must be defined"));
    }

    if (!app.password) {
      return callback(new Error("Application password must be defined"));
    }

    // POST app_id & password
    var options = {
        url    : freebox.url+'login/session/',
        method : 'POST',
        json   : {
          "app_id"      : app.app_id,
          "app_version" : app.app_version,
          "password"    : app.password,
        },
        encode : 'utf-8'
    };

    request(options, (error, response, body) => {
      if (error) {
        debug("session", "Can not login session", error);
        return callback(error);
      }

      var oldChallenge=app.challenge;
      var oldSessionToken = app.session_token;
      var oldLoggedIn = app.logged_in;
      var oldPermissions = app.permissions;

      if (response.statusCode == 200) { // OK
        app.challenge = body.result.challenge; // Update challenge
        app.session_token = body.result.session_token; // Save session token
        app.logged_in   = true; // Update login status
        app.permissions = body.result.permissions;

      } else if(response.statusCode == 403) { // Forbidden
        app.challenge = body.result.challenge; // Update challenge

        error=new Error("Session failed !");
        error.code="failed";
        error.response=response;
        error.statusCode=response.statusCode;

      } else {
        error=new Error("Unsupported status code ("+response.statusCode+")");
        error.code="unsupported";
        error.response=response;
        error.statusCode=response.statusCode;
      }

      var appChanged=false;
      if (oldLoggedIn!==app.logged_in) {
        this.emit("logged_in", app.logged_in);
        appChanged=true;
      }
      if (oldChallenge!=app.challenge) {
        this.emit("challenge", app.challenge);
        appChanged=true;
      }
      if (oldSessionToken!=app.session_token) {
        this.emit("session_token", app.session_token);
        appChanged=true;
      }
      if (JSON.stringify(oldPermissions)!=JSON.stringify(app.permissions)) {
        this.emit("permissions", app.permissions);
        appChanged=true;
      }
      if (appChanged) {
        this.emit("app", app);
      }

      callback(error, app, body.result);
    });
  }

  logout(callback) {
    debug("login", "Start opening session");
    // Asking a new challenge

    var app=this._app;

    request(freebox.url+'login/logout/', (error, response, body) => {
      if (error) {
        debug("lgout", "Can not logout", error);
        return callback(error);
      }

      app.session_token=null;
      app.challenge=null;
      app.logged_in=false;

      this.emit("logged_in", false);
      this.emit("challenge", null);
      this.emit("session_token", null);
      this.emit("app", app);

      callback(null, app);
    });
  }

  _getSession(callback) {
    var freebox=this._freebox;
    var app=this._app;

    debug("_getSession", "apiVersion=",freebox.apiVersion,"appStatus=",app.status,"appLoggedIn=",app.logged_in,"appSessionToken=",app.session_token);

    var retryCb = (error) => {
      if (error) {
        return callback(error);
      }

      setImmediate(() => this._getSession(callback));
    };

    if (!freebox.url) {
      this.version(retryCb);
      return;
    }

    if (!app.password) {
      this.login(retryCb);
      return;
    }

    if (app.status !== 'granted') {
      this.waitStatusGranted(app.registerDelayMs, retryCb);
      return;
    }

    if (!app.challenge) {
      this.login(retryCb);
      return;
    }

    if (!app.session_token) {
      this.session(retryCb);
      return;
    }

    callback(null, app);
  }

  /*
   * STATS
   */

  /**
   * stats method
   * 
   * Return some stats about the box.
   * 
   * @see http://dev.freebox.fr/sdk/os/rrd/ for all the options
   * 
   * @param {string}
   *            db net, temp, dsl, switch
   * @param {timestamp}
   *            date_start The requested start timestamp of the stats to get (optional)
   * @param {timestamp}
   *            date_end The requested end timestamp of the stats to get (optional)
   * @param {int}
   *            precision (optional)
   * @param {object}
   *            fields For just getting some fields (optional) ex : ['tx_1', 'tx_2']
   */

  stats(db, date_start, date_end, precision, fields, callback) {
    switch(arguments.length) {
    case 2:
      callback=date_start;
      date_start=undefined;
      break;
    case 3:
      callback=date_end;
      date_end=undefined;
      break;
    case 4:
      callback=precision;
      precision=undefined;
      break;
    case 5:
      callback=fields;
      fields=undefined;
      break;
    }

    return P((callback) => this._getSession((error, app) => {
      if (error) {
        return callback(error);
      }
      this._stats(app, db, date_start, date_end, precision, fields, callback);
    }), callback);
  }

  _stats(app, db, date_start, date_end, precision, fields, callback) {

    if (!app.permissions.settings) {
      var ex=new Error("No settings permission");
      ex.permissions=app.permissions;
      return callback(ex);
    }

    var json = { db : db };

    if( date_start ) {
      json.date_start = date_start;
    }
    if( date_end ) {
      json.date_end = date_end;
    }
    if( precision ) {
      json.precision = precision;
    }
    if( fields ) {
      json.fields = fields;
    }

    var freebox=this._freebox;

    var options = {
        url : freebox.url+'rrd',
        json : json,
        method : 'POST'
    };

    this._returnJSON("_stats", app, options, 0, callback);
  }

  _returnJSON(debugName, app, options, retry, callback) {
    options.headers=options.headers||{};
    options.headers['X-Fbx-App-Auth']=app.session_token;

    request(options, (error, response, body) => {
      if (error) {
        debug(debugName, "Request error", error);
        return callback(error);
      }

      debug(debugName, "Request result=",body.result);

      if (response.statusCode === 403 && retry<2) {
        this.session((error, app) => {
          if (error) {
            return callback(error);
          }

          this._returnJSON(debugName, app, options, retry+1, callback);
        });
        return;
      }

      if (response.statusCode != 200) {
        var ex=new Error("Invalid response", error);
        ex.response=response;
        ex.statusCode=response.statusCode;
        return callback(ex);
      }

      callback(null, body.result); // return stats
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
   */
  downloadsStats(callback) {
    return P((callback) => this._getSession((error, app) => {
      if (error) {
        return callback(error);
      }
      this._stats(app, callback);
    }), callback);
  }

  _downloadsStats(app, callback) {

    if(!app.permissions.downloader) {
      var ex=new Error("No settings permission");
      ex.permissions=app.permissions;
      return callback(ex);
    }

    var freebox=this._freebox;

    var options = {
        url : freebox.url+'downloads/stats',
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
   * freebox.downloads(2, udpate, {"io_priority": "high","status": "stopped"}, function(msg){ console.log(msg); });
   * 
   * @see http://dev.freebox.fr/sdk/os/download/#download-api
   * 
   * @param {int}
   *            id The id of the download. If null, it will return the entire download list
   * @param {string}
   *            action The action to do if and id is submited. Could be read, log, udpate, delete and deleteAndErase - delete
   *            the download and erase the files downloaded. If null, it's set to read.
   * @params {json} params If action update, the item to update.
   * 
   */
  downloads(id, action, params, callback) {
    switch(arguments.length) {
    case 3:
      callback=params;
      params=undefined;
      break;
    }

    return P((callback) => this._getSession((error, app) => {
      if (error) {
        return callback(error);
      }
      this._downloads(app, id, action, params, callback);
    }), callback);
  }

  _downloads(app, id, action, params, next) {    

    if(!app.permissions.downloader) {
      var ex=new Error("No settings permission");
      ex.permissions=app.permissions;
      return callback(ex);
    }

    // All the download list
    if(!id) {
      var options2 = {
          url : freebox.url+'downloads/'
      };

      this._returnJSON("_downloads", app, options2, 0, callback);
      return;
    }

    var options = {
        url : freebox.url+'downloads/'+id,
        json : {}
    };

    // What to do ?

    action=action || 'read';

    switch(action) {
    case 'delete' :
      options.method = 'DELETE';
      break;

    case 'deleteAndErase' :
      options.url    += '/erase';
      options.method = 'DELETE';
      break;

    case 'update' :
      options.method = 'PUT';
      options.json   = params;
      break;

    case 'log' : 
      options.url    += '/log';
      options.method = 'GET';
      break;

    case 'read' : 
      options.method = 'GET';
      break;

    default :
      return callback('This action doesn\'t exist. Try read, log, update, delete or deleteAndErase.');
    }

    this._returnJSON("_downloads:"+action, app, options, 0, callback);
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
   * @param {string}
   *            url Url(s) to download. If multiple, separated by a new line delimiter "\n"
   * @param {string}
   *            dir The download destination directory (optional)
   * @param {bool}
   *            recursive If true the download will be recursive. See http://dev.freebox.fr/sdk/os/download/#adding-by-url
   * @param {string}
   *            username (optional)
   * @param {string}
   *            password (optional)
   * @param {string}
   *            archive_password Pasword to decompress the erchive if nzb.
   * 
   */
  addDownloads(url, dir, recursive, username, password, archive_password, callback) {
    switch(arguments.length) {
    case 6:
      callback=archive_password;
      archive_password=undefined;
      break;
    case 5:
      callback=password;
      password=undefined;
      break;
    case 4:
      callback=username;
      username=undefined;
      break;
    case 3:
      callback=recursive;
      recursive=undefined;
      break;
    case 2:
      callback=dir;
      dir=undefined;
      break;
    }

    return P((callback) => this._getSession((error, app) => {
      if (error) {
        return callback(error);
      }
      this._downloads(app, url, dir, recursive, username, password, archive_password, callback);
    }), callback);
  }

  _addDownloads(app, url, dir, recursive, username, password, archive_password, callback) {

    if(!app.permissions.downloader) {
      var ex=new Error("No settings permission");
      ex.permissions=app.permissions;
      return callback(ex);
    }

    // Form to submit

    var form = {
        'download_url_list' : url,
        'recursive'         : recursive,
    };

    if (dir) {
      form.download_dir = dir;
    }

    if(username && password) {
      form.username = username;
      form.password = password;
    }

    if(archive_password) {
      form.archive_password = archive_password;
    }

    var options = {
        url : freebox.url+'downloads/add',       
        form : form,
        method : 'POST'
    };

    this._returnJSON("_addDownloads", app, options, 0, callback);
  }

  /**
   * calls method
   * 
   * Return all the calls.
   */
  calls(callback) {
    return P((callback) => this._getSession((error, app) => {
      if (error) {
        return callback(error);
      }
      this._calls(app, callback);
    }), callback);
  }

  _calls(app, callback) {

    if(!app.permissions.calls) {
      return callback(new Error("No call permission"));
    }

    var options = {
        url : this._freebox.url+'call/log/',
        json: true
    };

    this._returnJSON("_calls", app, options, 0, callback);
  }

  /**
   * call method
   * 
   * Manage a call.
   * 
   * @param {int}
   *            id Call id
   * @param {string}
   *            action The action to do. Read (default), update, delete.
   * @param {json}
   *            params If update, params to update.
   */
  call(id, action, params, callback) {
    switch(arguments.length) {
    case 3:
      callback=params;
      params=undefined;
      break;
    case 2:
      callback=action;
      action=undefined;
      break;
    }

    return P((callback) => this._getSession((error, app) => {
      if (error) {
        return callback(error);
      }
      this._call(app, id, action, params, callback);
    }), callback);
  }

  _call(id, action, params, callback) {


    if(!app.permissions.calls) {
      return callback(new Error("No call permission"));
    }

    var options = {
        url : freebox.url+'call/log/'+id,
        json : {}
    };

    switch(action) {
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
   * calls method
   * 
   * Return all the calls.
   */
  lanBrowser(callback) {

    return P((callback) => this._getSession((error, app) => {
      if (error) {
        return callback(error);
      }
      this._lanBrowser(app, callback);
    }), callback);
  }

  _lanBrowser(app, callback) {

    if(!app.permissions.calls) {
      return callback(new Error("No call permission"));
    }

    var options = {
        url : this._freebox.url+'lan/browser/interfaces/',
        json: true
    };

    this._returnJSON("_lanBrowser", app, options, 0, (error, result) => {
      if (error) {
        return callback(error);
      }

      var ret=[];

      async.forEach(result, (inte, callback) => {

        var options = {
            url : this._freebox.url+'lan/browser/'+inte.name+'/',
            json: true           
        };

        this._returnJSON("_lanBrowser:list", app, options, 0, (error, result) => {
          if (error) {
            return callback(error);
          }


          debug("_lanBrowser", "list of interface=", inte, "=>", result);


          result.forEach((r) => {
            r.$interface=inte.name;
            ret.push(r);
          });

          callback(null, result);
        });
      }, (error) => {
        if (error) {
          return callback(error);
        }

        debug("_lanBrowser", "finalList=",ret);

        callback(null, ret);
      });
    });
  }
}


function P(func, callback) {
  return new Promise((resolve, reject) => {

    if (typeof(callback)!=="function") {
      callback = (error, value) => {
        if (error) {
          return reject(error);
        }

        resolve(value);
      };
    }

    func(callback);
  });
}

module.exports = Freebox;