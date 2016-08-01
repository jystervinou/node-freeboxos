/*jslint node:true, esversion:6 */

const Freebox=require('./lib/freebox');
const program = require('commander');
const fs=require('fs');

program.option("--app_id <appId>", "Application identifier");
program.option("--app_name <appName>", "Application name");
program.option("--app_version <appVersion>", "Application version");
program.option("--device_name <deviceName>", "Device name");
program.option("--authorization <path>", "Path of JSOn authorization");
program.option("--baseURL <baseURL>", "URL of freebox");

program.command('token').description("Return token").action( ()=> {
  var config=fillConfig();
  var freebox=new Freebox(config);

  freebox.waitApplicationGranted(1000*60*2, (error, app) => {
    console.error("error=",error,"app=",app);
  });
});

program.command('wifiState').description("Return wifi state").action( ()=> {
  var config=fillConfig();
  
  var freebox = new Freebox(config);

  freebox.getWifiState((error, state) => {
    if (error) {
      console.error(error);
      return;
    }

    console.log("wifiState=",state);
  });
});


program.command('setWifiState').description("Return wifi state").action( (state)=> {
  
  var reg=/^(on|enable|enabled|1)$/i.exec(state);
  state=!!reg;
  
  console.log("State=",state,reg);
  
  var config=fillConfig();
  
  var freebox = new Freebox(config);

  freebox.setWifiState(state, (error, newState) => {
    if (error) {
      console.error(error);
      return;
    }

    console.log("change wifiState to ",newState);
  });
});

program.command('calls').description("Return calls").action( ()=> {
  var config=fillConfig();
  
  var freebox = new Freebox(config);

  freebox.calls((error, calls) => {
    if (error) {
      console.error(error);
      return;
    }

    console.log("calls=",calls);
  });
});

program.command('lanBrowser').description("Browse all lan hosts").action( ()=> {
  var config=fillConfig();

  var freebox=new Freebox(config);

  freebox.lanBrowser().then((hosts) => {
    console.log("hosts=",hosts);
  }, (error) => {
    console.error(error);
  });
});

program.parse(process.argv);

function fillConfig() {

  var app = {
      app_id        : program.app_id || "freeboxos", 
      app_name      : program.app_name || "Test node app",
      app_version   : program.app_version || '0.0.1',
      device_name   : program.device_name || "NodeJs-API"
  };

  var config = {app};

  if (program.authorization) {
    config.jsonPath = program.authorization;
    config.jsonAutoSave = true;
  }
  if (program.baseURL) {
    config.baseURL=program.baseURL;
  }

  return config;
}


