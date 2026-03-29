// === Patch 1 ===
const catchAll = {
  get: function(target, name) {
    const prop = name.toString();
    if (prop in target) {
      return target[prop];
    }
    console.log(`[MOCK PATCH] Unhandled property get: ${prop}`);
    return new Proxy(() => ({}), catchAll);
  },
  set: function(target, name, value) {
    const prop = name.toString();
    console.log(`[MOCK PATCH] Unhandled property set: ${prop} = ${value}`);
    target[prop] = value;
    return true;
  }
};

global.ActiveXObject = function(type) {
  console.log('[MOCK PATCH] new ActiveXObject: ' + type);
  const lcaseType = type.toLowerCase();

  if (lcaseType.includes('shell')) {
    return {
      Run: (cmd, style, wait) => {
        console.log(`[MOCK PATCH] WScript.Shell.Run: ${cmd}`);
        return 0; // Success
      },
      Exec: (cmd) => {
        console.log(`[MOCK PATCH] WScript.Shell.Exec: ${cmd}`);
        return new Proxy({
          StdOut: {
            AtEndOfStream: true,
            ReadAll: () => ''
          },
          StdErr: {
            AtEndOfStream: true,
            ReadAll: () => ''
          },
          Status: 0,
        }, catchAll);
      },
      ExpandEnvironmentStrings: (s) => {
        console.log(`[MOCK PATCH] WScript.Shell.ExpandEnvironmentStrings: ${s}`);
        return s.replace(/%temp%/ig, 'C:\\Users\\User\\AppData\\Local\\Temp')
          .replace(/%public%/ig, 'C:\\Users\\Public')
          .replace(/%appdata%/ig, 'C:\\Users\\User\\AppData\\Roaming');
      },
      RegRead: (key) => {
        console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
        if (key.toLowerCase().includes('aerofox') || key.toLowerCase().includes('foxmail')) {
            return 'C:\\Program Files\\Foxmail\\';
        }
        // Return empty for AV/sandbox checks to evade detection
        if (key.toLowerCase().includes('icedragon') || key.toLowerCase().includes('sbiedll')) {
            return '';
        }
        return '1'; // Default value
      },
      RegWrite: (key, val, type) => console.log(`[MOCK PATCH] WScript.Shell.RegWrite: ${key} = ${val}`),
      RegDelete: (key) => console.log(`[MOCK PATCH] WScript.Shell.RegDelete: ${key}`),
      Environment: (type) => new Proxy({
        Item: (k) => ''
      }, catchAll),
    };
  }

  if (lcaseType.includes('filesystemobject')) {
    const mockFiles = [
        'c:\\users\\public\\mands.png',
        'c:\\users\\public\\vile.png',
        'c:\\users\\public\\mock_script.url'
    ];
    return {
      FileExists: (path) => {
        console.log('[MOCK PATCH] FileSystemObject.FileExists: ' + path);
        const lcasePath = path.toLowerCase();
        const exists = mockFiles.some(f => lcasePath.endsWith(f.split('\\').pop()));
        console.log(`[MOCK PATCH] -> ${exists}`);
        return exists;
      },
      DeleteFile: (path, force) => {
        console.log('[MOCK PATCH] FileSystemObject.DeleteFile: ' + path);
      },
      GetFile: (path) => {
        console.log('[MOCK PATCH] FileSystemObject.GetFile: ' + path);
        return new Proxy({ Path: path, Name: path.split('\\').pop(), Size: 12345 }, catchAll);
      },
      OpenTextFile: (path, iomode, create) => {
        console.log(`[MOCK PATCH] FileSystemObject.OpenTextFile: ${path}`);
        return new Proxy({
            ReadAll: () => '',
            WriteLine: (text) => console.log(`[MOCK PATCH] TextStream.WriteLine: ${text}`),
            Close: () => {}
        }, catchAll);
      },
      CreateTextFile: (path, overwrite) => {
        console.log(`[MOCK PATCH] FileSystemObject.CreateTextFile: ${path}`);
         return new Proxy({
            WriteLine: (text) => console.log(`[MOCK PATCH] TextStream.WriteLine: ${text}`),
            Close: () => {}
        }, catchAll);
      }
    };
  }
  
  if (lcaseType.includes('winhttp') || lcaseType.includes('xmlhttp')) {
    return {
      open: (method, url, async) => console.log('[MOCK PATCH] HTTP open: ' + method + ' ' + url),
      send: (data) => console.log('[MOCK PATCH] HTTP send'),
      setRequestHeader: (k, v) => console.log(`[MOCK PATCH] HTTP setRequestHeader: ${k}: ${v}`),
      responseText: '{"status":"success","country":"US","org":"Some ISP","hosting":false}',
      responseBody: new Uint8Array([1, 2, 3, 4]),
      status: 200,
      statusText: 'OK',
      readyState: 4,
    };
  }
  
  return new Proxy({}, catchAll);
};

global.WScript = {
  ScriptName: 'malware.js',
  ScriptFullName: 'C:\\Users\\Public\\malware.js',
  Echo: (m) => console.log('[MOCK PATCH] WScript.Echo: ' + m),
  Sleep: (ms) => console.log('[MOCK PATCH] WScript.Sleep: ' + ms + 'ms'),
  Quit: (code) => console.log('[MOCK PATCH] WScript.Quit with code: ' + code),
  CreateObject: (t) => new ActiveXObject(t),
  Arguments: {
    length: 0,
    Item: () => ''
  },
};

// === Patch 2 ===
// CRITICAL: Define catchAll on the global scope to fix redeclaration errors
// and ensure it is available to all modules.
global.catchAll = {
  get: function(target, name) {
    const prop = target[name];
    if (typeof prop !== 'undefined') {
      return prop;
    }
    // Return a function to prevent crashes on unmocked method calls.
    return () => new Proxy({}, global.catchAll);
  },
  set: function(target, name, value) {
    console.log(`[MOCK PATCH] Unhandled property set: ${name.toString()} = ${value}`);
    target[name] = value;
    return true;
  }
};


// T1047, T1082, T1016, T1497: Implement GetObject to handle WMI queries for
// system fingerprinting and VM evasion, which is the malware's next logical step.
global.GetObject = function(path) {
  console.log('[MOCK PATCH] GetObject: ' + path);

  if (!path || !path.toLowerCase().includes('winmgmts')) {
    return new Proxy({}, global.catchAll);
  }

  // Return a mock WMI service object
  return new Proxy({
    ExecQuery: function(query) {
      console.log('[MOCK PATCH] WMI ExecQuery: ' + query);
      const lcaseQuery = query.toLowerCase();

      // T1082: System Information Discovery (Processor)
      if (lcaseQuery.includes('win32_processor')) {
        return [{
          Name: 'Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz',
          NumberOfCores: 6,
          ProcessorId: 'BFEBFBFF000906EA'
        }];
      }
      // T1082, T1497: System Info & VM Evasion (ComputerSystem)
      if (lcaseQuery.includes('win32_computersystem')) {
        return [{
          Manufacturer: 'Dell Inc.',
          Model: 'XPS 15 9570'
        }];
      }
      // T1082, T1497: System Info & VM Evasion (BaseBoard)
      if (lcaseQuery.includes('win32_baseboard')) {
        return [{
          Manufacturer: 'Dell Inc.',
          Product: '02MJVY',
          SerialNumber: 'F5K1B2X/CNCMK0086I001A/'
        }];
      }
      // T1497: VM Evasion (Video Controller check)
      if (lcaseQuery.includes('win32_videocontroller')) {
        // Return a name that does not contain 'VMware', 'VirtualBox', or 'VBox'
        return [{
          Name: 'NVIDIA GeForce GTX 1050 Ti with Max-Q Design'
        }];
      }
      // T1016, T1497: Network Config & VM Evasion (MAC address check)
      if (lcaseQuery.includes('win32_networkadapterconfiguration')) {
        // Return a MAC that doesn't match common VM vendor prefixes
        return [{
          MACAddress: '9C:B6:D0:FF:FF:FF',
          IPAddress: ['192.168.1.123']
        }];
      }

      console.log('[MOCK PATCH] WMI ExecQuery: Unhandled query, returning empty collection.');
      return []; // Return empty array for unhandled queries
    }
  }, global.catchAll);
};

// === Patch 3 ===
global.ActiveXObject = function(type) {
  console.log('[MOCK PATCH] new ActiveXObject: ' + type);
  const lcaseType = type.toLowerCase();

  // T1059.001: The malware's next step is to use WScript.Shell to launch PowerShell.
  if (lcaseType.includes('wscript.shell')) {
    return new Proxy({
      Run: (cmd, style, wait) => {
        console.log('[MOCK PATCH] WScript.Shell.Run: ' + cmd);
        if (cmd && cmd.toLowerCase().includes('-enc')) {
          console.log('[MOCK PATCH] WScript.Shell.Run called with Base64 encoded PowerShell.');
        }
        return 0; // Return 0 for success
      },
      Exec: (cmd) => {
        console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
        return new Proxy({
          StdOut: new Proxy({ ReadAll: () => '' }, global.catchAll),
          StdErr: new Proxy({ ReadAll: () => '' }, global.catchAll),
          Status: 0
        }, global.catchAll);
      },
      ExpandEnvironmentStrings: (s) => {
        console.log('[MOCK PATCH] WScript.Shell.ExpandEnvironmentStrings: ' + s);
        return s.replace(/%TEMP%/ig, 'C:\\Users\\User\\AppData\\Local\\Temp')
                .replace(/%PUBLIC%/ig, 'C:\\Users\\Public')
                .replace(/%APPDATA%/ig, 'C:\\Users\\User\\AppData\\Roaming');
      },
      // T1012: Handle registry queries for credential targets and AV/sandbox checks.
      RegRead: (key) => {
        console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
        if (key.toLowerCase().includes('aerofox\\foxmail')) return 'C:\\Program Files\\Foxmail\\';
        if (key.toLowerCase().includes('sbiedll') || key.toLowerCase().includes('snxhk')) return null;
        return '1'; // Default success value
      },
      RegWrite: (key, val, type) => console.log('[MOCK PATCH] WScript.Shell.RegWrite: ' + key + ' = ' + val),
      RegDelete: (key) => console.log('[MOCK PATCH] WScript.Shell.RegDelete: ' + key),
    }, global.catchAll);
  }

  // T1071: Pre-stub network objects for C2 and hosting checks.
  if (lcaseType.includes('xmlhttp') || lcaseType.includes('winhttp')) {
    return new Proxy({
      open: (method, url, async) => console.log('[MOCK PATCH] HTTP ' + method + ': ' + url),
      send: (data) => console.log('[MOCK PATCH] HTTP send'),
      setRequestHeader: (k, v) => {},
      responseText: '{"status":"success","country":"US","org":"Customer Network","hosting":false}',
      status: 200,
    }, global.catchAll);
  }

  // Pre-stub FileSystemObject for file artifact checks.
  if (lcaseType.includes('scripting.filesystemobject')) {
    return new Proxy({
      FileExists: (path) => {
        console.log('[MOCK PATCH] FSO.FileExists: ' + path);
        // Pretend dropper artifacts don't exist to proceed with execution.
        if (path.toLowerCase().includes('mands.png') || path.toLowerCase().includes('vile.png')) return false;
        return true;
      },
      DeleteFile: (path, force) => console.log('[MOCK PATCH] FSO.DeleteFile: ' + path),
      GetFile: (path) => new Proxy({}, global.catchAll),
      CreateTextFile: (path) => new Proxy({ Write: (t) => {}, Close: () => {} }, global.catchAll),
    }, global.catchAll);
  }

  // Fallback for any other requested object.
  console.log('[MOCK PATCH] Unhandled ActiveXObject type: ' + type);
  return new Proxy({}, global.catchAll);
};

