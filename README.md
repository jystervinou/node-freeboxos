FreeboxOS Api - NodeJS module
===============

A NodeJS module for the new FreeboxOS API.

Please read also the doc : http://dev.freebox.fr/sdk/os.


## Installation

```sh
npm install node-freeboxos
```

Connect & register
-------------------

### First connection & register
You can start to use the module with these lines of code :

```

  const freebox=require('node-freeboxos');

  const app = {
      app_id        : "myApplicationId", 
      app_name      : "My Application name",
      app_version   : "0.0.1",
      device_name   : "Nodejs API"
  };

  var freebox=new Freebox({app: app});

  freebox.waitApplicationGranted(1000*60*2, (error, app) => {
    if (error) {
    	console.error(error);
    	return;
    }

    console.log("granted app=",app);    
    
    freenox.saveJSON("/tmp/freebox.infos", (error) => {
    	if (error) {
    		console.error(error);
    		return;
		}
    });
  });
  
  ...or you can use Promise pattern ...
  
  freebox.waitApplicationGranted(1000*60*2).then((app) => {
    console.log("granted app=",app);
    
    return freebox.saveJSON("/tmp/freebox.json");
    
  }, (error) => {
    console.error("error=",error);
  });
  
```

### If you already have a valid token (and saved it with saveJSON)

```
  const freebox=require('freeboxos');

  var freebox=new Freebox({jsonPath: '/tmp/toto.json'});
  
```

Stats
-------
### freebox.stats(db, date_start, date_end, precision, fields, next)
Echo freebox's stats. Example :
```
freebox.stats('temp', null, null, null, null, (error, msg) => {
  console.log(msg);
});
```
date_start, date_end, precision and fields are optional.
Please see http://dev.freebox.fr/sdk/os/rrd/ for all the options.

Downloads
--------- 

### freebox.downloadsStats(next)
Echo download stats with :
```
freebox.downloadsStats((error, msg) => {
  console.log(msg);
});
```

### addDownloads(url, dir, recursive, username, password, archive_password, next)

'Url' can be multiple. In this case, they have to be separated by a new line delimiter "\n" as below.
```
freebox.addDownloads(
  "http://blog.baillet.eu/public/ciel-bleu-sans-avion-20100417-imgis5346.jpg\nhttp://www.8alamaison.com/wp-content/uploads/2013/04/z2354-carton-rouge3.gif",
  null, false, null, null, null,
  function(error, msg) {
    console.log(msg);
  }
 );
```

### downloads(id, action, params, next)
You can manage download.   
With no id submitted it returns the entire downloads list.
With an id you can manage the selected download.

Actions :
- read (default)
- log
- udpate (needs 'params', see below)
- delete
- deleteAndErase (delete the download and erase the files downloaded)   

```
freebox.downloads(2, 'udpate', {"io_priority": "high","status": "stopped"}).then((result) => {
  console.log(msg);
});
```

Calls
-----
### freebox.calls(next);
Return all the calls save in the box.
```
freebox.calls().then((msg) => {
  console.log(msg);
}, (error) => {
	console.error(error);
});
```

### freebox.call(id, action, params, next)
Manage a call.
Actions :
- Read (default)
- update
- delete

Example : read a specific call
```
freebox.call(1, 'read', null, (error, msg) => {
  console.log(msg);
});
```
Example : update a call 
```
freebox.call(1, 'update', {'new' : false}, (error, msg) => {
  console.log(msg);
});
```







