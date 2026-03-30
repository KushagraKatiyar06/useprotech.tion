// === Patch 1 ===
const catchAll = {
    get: function(target, prop) {
        if (prop in target) return target[prop];
        if (typeof prop === 'string' && prop.length < 100) {
            console.log('[MOCK ATTEMPT] Called: ' + target.objectType + '.' + prop);
        }
        const fn = function() { return new Proxy(target, catchAll); };
        // Allow chaining and accessing properties on the result of a function call
        return new Proxy(fn, catchAll);
    }
};

global.WScript = {
  ScriptName: 'malware.js',
  ScriptFullName: 'C:\\Users\\Public\\malware.js',
  Echo: (m) => console.log('[MOCK PATCH] WScript.Echo: ' + m),
  Sleep: (ms) => console.log('[MOCK PATCH] WScript.Sleep: ' + ms + 'ms'),
  Quit: (code) => console.log('[MOCK PATCH] WScript.Quit with code: ' + code),
  CreateObject: (t) => new ActiveXObject(t),
  Arguments: { length: 0, Item: () => '', Count: () => 0 },
  get FullName() {
    console.log('[MOCK PATCH] WScript.FullName');
    // In JScript, WScript.FullName returns the path to the interpreter (wscript.exe)
    return 'C:\\Windows\\System32\\WScript.exe';
  },
};

global.ActiveXObject = function(type) {
  console.log('[MOCK PATCH] new ActiveXObject: ' + type);
  const ltype = type.toLowerCase();

  if (ltype.includes('shell')) {
    return {
      objectType: 'WScript.Shell',
      Run: (cmd, style, wait) => {
        console.log('[MOCK PATCH] WScript.Shell.Run: ' + cmd);
        // This is a critical TTP (T1059.001) for this sample
        if (cmd.includes("powershell -enc")) {
            console.log('[MOCK PATCH] DETECTED POWERSHELL EXECUTION');
        }
        return 0; // Success
      },
      Exec: (cmd) => {
        console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
        return { StdOut: { ReadAll: () => 'Windows IP Configuration' }, StdErr: { ReadAll: () => '' }, Status: 0 };
      },
      ExpandEnvironmentStrings: (s) => {
        console.log('[MOCK PATCH] WScript.Shell.ExpandEnvironmentStrings: ' + s);
        return s.replace(/%temp%/ig, 'C:\\Users\\User\\AppData\\Local\\Temp')
                .replace(/%public%/ig, 'C:\\Users\\Public')
                .replace(/%appdata%/ig, 'C:\\Users\\User\\AppData\\Roaming');
      },
      RegRead: (key) => {
        console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
        if (key.includes('Aerofox')) return 'C:\\Program Files\\Foxmail\\';
        return null; // Simulate key not found for AV/sandbox checks
      },
      RegWrite: (key, val) => console.log('[MOCK PATCH] WScript.Shell.RegWrite: ' + key + ' = ' + val),
      Environment: (t) => new Proxy({ Item: (k) => '', objectType: 'WScript.Shell.Environment' }, catchAll),
    };
  }

  if (ltype.includes('filesystemobject')) {
    return new Proxy({
        objectType: 'FileSystemObject',
        FileExists: (path) => {
            console.log('[MOCK PATCH] FileSystemObject.FileExists: ' + path);
            // Per TTPs, it checks for these files to delete them. Return true to trigger deletion.
            if (path.includes('Mands.png') || path.includes('Vile.png')) {
                return true;
            }
            // It also checks for a stage marker. Return false to make it proceed.
            if (path.includes('mock_script.url')) {
                return false;
            }
            return false;
        },
        DeleteFile: (path, force) => {
            console.log('[MOCK PATCH] FileSystemObject.DeleteFile: ' + path);
        },
        GetSpecialFolder: (id) => {
            // 0: WindowsFolder, 1: SystemFolder, 2: TempFolder
            console.log('[MOCK PATCH] FileSystemObject.GetSpecialFolder: ' + id);
            if (id === 2) return 'C:\\Users\\User\\AppData\\Local\\Temp';
            if (id === 1) return 'C:\\Windows\\System32';
            return 'C:\\Windows';
        },
        GetTempName: () => {
             const tempName = Math.random().toString(36).substring(2, 10) + '.tmp';
             console.log('[MOCK PATCH] FileSystemObject.GetTempName: ' + tempName);
             return tempName;
        },
        CreateTextFile: (path) => {
             console.log('[MOCK PATCH] FileSystemObject.CreateTextFile: ' + path);
             return { Write: (c) => {}, Close: () => {} };
        },
        GetFile: (path) => {
            console.log('[MOCK PATCH] FileSystemObject.GetFile: ' + path);
            return { Path: path, Size: 12345, OpenAsTextStream: () => ({ ReadAll: () => '', Close: () => {} }) };
        },
        BuildPath: (path, name) => {
            console.log('[MOCK PATCH] FileSystemObject.BuildPath: ' + path + ', ' + name);
            return path + '\\' + name;
        }
    }, catchAll);
  }

  if (ltype.includes('winhttp') || ltype.includes('xmlhttp')) {
      return new Proxy({
          objectType: 'XMLHTTP',
          open: (method, url, async) => console.log('[MOCK PATCH] HTTP ' + method + ': ' + url),
          send: (data) => console.log('[MOCK PATCH] HTTP send' + (data ? ': ' + data.length + ' bytes' : '')),
          setRequestHeader: (k,v) => console.log('[MOCK PATCH] HTTP setRequestHeader: ' + k + ': ' + v),
          responseText: JSON.stringify({status: "success", country: "United States", hosting: false}),
          responseBody: new Uint8Array([80, 75, 3, 4]), // Mock PK zip header
          status: 200,
          readyState: 4,
          statusText: 'OK',
      }, catchAll);
  }

  // Default catch-all for any other ActiveXObject
  return new Proxy({ objectType: 'Unknown ActiveX: ' + type }, catchAll);
};

// === Patch 2 ===
// Mock for GetObject, primarily used for WMI access to perform system fingerprinting and VM checks.
// This is a common TTP for Agent Tesla and many other malware families.
// (TTPs: T1047, T1082, T1016, T1497)
global.GetObject = function(path) {
  console.log('[MOCK PATCH] GetObject: ' + path);
  // The malware uses WMI for fingerprinting.
  if (path && path.toLowerCase().includes('winmgmts')) {
    return new Proxy({
      objectType: 'WMI.Service',
      ExecQuery: function(query) {
        console.log('[MOCK PATCH] WMI ExecQuery: ' + query);
        const lquery = query.toLowerCase();
        let collection = [];

        if (lquery.includes('win32_processor')) {
          collection = [{
            Name: 'Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz',
            NumberOfCores: 6,
            ProcessorId: 'BFEBFBFF000906EA'
          }];
        } else if (lquery.includes('win32_videocontroller')) {
          collection = [{
            Name: 'NVIDIA GeForce GTX 1050 Ti',
            VideoProcessor: 'GeForce GTX 1050 Ti'
          }];
        } else if (lquery.includes('win32_networkadapterconfiguration')) {
          // Provide a non-VM MAC address to bypass simple checks
          collection = [{
            MACAddress: '00:1A:2B:3C:4D:5E',
            IPAddress: ['192.168.1.100']
          }];
        } else if (lquery.includes('win32_computersystem')) {
          collection = [{
            Manufacturer: 'Dell Inc.',
            Model: 'XPS 15 9570'
          }];
        } else if (lquery.includes('win32_baseboard')) {
          collection = [{
            Manufacturer: 'Dell Inc.',
            Product: '0M0D1J',
            SerialNumber: 'ABC123XYZ'
          }];
        }
        
        // Return a collection object that has a .Count property for VBS/JS compatibility
        const result = collection;
        result.Count = collection.length;
        return result;
      },
    }, catchAll);
  }

  // Fallback for other GetObject types not related to WMI.
  return new Proxy({
    objectType: 'GetObject:' + path
  }, catchAll);
};

