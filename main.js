/*jslint node:true, esversion:6 */

const Freebox=require('./lib/freebox');
const program = require('commander');
const fs=require('fs');

program.option("--app_id <appId>", "Application identifier");
program.option("--app_name <appName>", "Application name");
program.option("--app_version <appVersion>", "Application version");
program.option("--device_name <deviceName>", "Device name");
program.option("--authorization <path>", "Path of JSOn authorization");

program.command('token').description("Return token").action( ()=> {

  var app = {
      app_id        : program.app_id || "freeboxos", 
      app_name      : program.app_name || "Test node app",
      app_version   : program.app_version || '0.0.1',
      device_name   : program.device_name || "NodeJs-API"
  };


  var freebox=new Freebox({app: app});

  freebox.waitApplicationGranted(1000*60*2, (error, app) => {
    console.error("error=",error,"app=",app);
  });
});

program.command('calls').description("Return token").action( ()=> {
  var config = {app};

  if (program.authorization) {
    config.jsonPath = program.authorization;
    config.jsonAutoSave = true;
  }

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
  var app = JSON.parse(fs.readFileSync(program.authorization));

  var freebox=new Freebox({app: app});

  freebox.lanBrowser().then((hosts) => {
    console.log("hosts=",hosts);
  }, (error) => {
    console.error(error);
  });
});

program.parse(process.argv);

