// === Patch 1 ===
const catchAll = {
  get: function(target, prop, receiver) {
    if (prop in target || typeof prop === 'symbol') {
      return Reflect.get(...arguments);
    }
    console.log(`[MOCK ATTEMPT] Unhandled property on ${target.constructor.name}: ${prop}`);
    const NOP = () => new Proxy({}, catchAll);
    NOP.toString = () => `[Mocked Property: ${prop}]`;
    return new Proxy(NOP, catchAll);
  },
  set: function(target, prop, value) {
    console.log(`[MOCK ATTEMPT] Setting property on ${target.constructor.name}: ${prop} = ${value}`);
    target[prop] = value;
    return true;
  },
  apply: function(target, thisArg, argumentsList) {
    console.log(`[MOCK ATTEMPT] Calling function with args: ${argumentsList.join(', ')}`);
    return new Proxy({}, catchAll);
  }
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

global.GetObject = function(path) {
  console.log('[MOCK PATCH] GetObject: ' + path);
  if (path && path.toLowerCase().includes('winmgmts:')) {
    return new Proxy({
      ExecQuery: function(query) {
        console.log('[MOCK PATCH] WMI ExecQuery: ' + query);
        if (query.toLowerCase().includes('win32_processor'))
          return [{
            Name: 'Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz',
            NumberOfCores: 10,
            ProcessorId: 'BFEBFBFF000906EA'
          }];
        if (query.toLowerCase().includes('win32_videocontroller'))
          return [{
            Name: 'NVIDIA GeForce RTX 4090',
            VideoProcessor: 'NVIDIA'
          }];
        if (query.toLowerCase().includes('win32_networkadapterconfiguration'))
          return [{
            MACAddress: '00:1A:2B:3C:4D:5E',
            IPAddress: ['192.168.1.100']
          }];
        if (query.toLowerCase().includes('win32_computersystem') || query.toLowerCase().includes('win32_baseboard'))
          return [{
            Manufacturer: 'ASUS',
            Model: 'ROG MAXIMUS Z790 HERO',
            SerialNumber: 'ABC123DEF456'
          }];
        return [new Proxy({}, catchAll)];
      },
      Get: (cls) => {
        console.log('[MOCK PATCH] WMI Get: ' + cls);
        return new Proxy({}, catchAll);
      }
    }, catchAll);
  }
  return new Proxy({}, catchAll);
};

global.ActiveXObject = function(type) {
  console.log('[MOCK PATCH] new ActiveXObject: ' + type);
  const typeLower = type.toLowerCase();

  if (typeLower.includes('wscript.shell')) {
    return {
      Run: (cmd, style, wait) => {
        console.log(`[MOCK PATCH] WScript.Shell.Run: ${cmd} (Style: ${style}, Wait: ${wait})`);
        return 0;
      },
      Exec: (cmd) => {
        console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
        const mockStd = {
          ReadAll: () => '',
          AtEndOfStream: true
        };
        return {
          StdOut: mockStd,
          StdErr: mockStd,
          Status: 0
        };
      },
      ExpandEnvironmentStrings: (s) => {
        const expanded = s.replace(/%TEMP%/ig, 'C:\\Users\\User\\AppData\\Local\\Temp').replace(/%PUBLIC%/ig, 'C:\\Users\\Public').replace(/%APPDATA%/ig, 'C:\\Users\\User\\AppData\\Roaming').replace(/%WINDIR%/ig, 'C:\\Windows');
        console.log(`[MOCK PATCH] ExpandEnvironmentStrings: ${s} -> ${expanded}`);
        return expanded;
      },
      RegRead: (key) => {
        console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
        if (key.includes('Aerofox\\Foxmail')) return 'C:\\Program Files\\Foxmail';
        if (key.includes('SbieDll.dll') || key.includes('snxhk.dll') || key.includes('SxIn.dll') || key.includes('cmdvrt32.dll')) return ''; // Anti-sandbox check
        return '1';
      },
      RegWrite: (key, val, type) => console.log(`[MOCK PATCH] WScript.Shell.RegWrite: ${key} = ${val} (Type: ${type})`),
      RegDelete: (key) => console.log('[MOCK PATCH] WScript.Shell.RegDelete: ' + key),
      Environment: (t) => new Proxy({
        Item: (k) => ''
      }, catchAll),
    };
  }

  if (typeLower.includes('scripting.filesystemobject')) {
    return {
      FileExists: (path) => {
        console.log('[MOCK PATCH] FSO.FileExists: ' + path);
        if (path.includes('Mands.png') || path.includes('Vile.png') || path.includes('mock_script.url')) {
          return true; // Dropper checks for these to clean up or as markers
        }
        return false;
      },
      DeleteFile: (path, force) => console.log(`[MOCK PATCH] FSO.DeleteFile: ${path} (Force: ${force})`),
      CreateTextFile: (path) => {
        console.log('[MOCK PATCH] FSO.CreateTextFile: ' + path);
        return {
          WriteLine: (t) => console.log('[MOCK PATCH] FSO.Stream.WriteLine'),
          Write: (t) => console.log('[MOCK PATCH] FSO.Stream.Write'),
          Close: () => {}
        };
      },
      OpenTextFile: (path) => ({
        ReadAll: () => 'mock data',
        Close: () => {}
      }),
      GetSpecialFolder: (id) => {
        console.log('[MOCK PATCH] FSO.GetSpecialFolder: ' + id);
        if (id === 2) return 'C:\\Users\\User\\AppData\\Local\\Temp';
        return 'C:\\';
      },
      BuildPath: (p1, p2) => `${p1}\\${p2}`,
    };
  }

  if (typeLower.includes('winhttp') || typeLower.includes('xmlhttp')) {
    return {
      open: (method, url, async) => console.log(`[MOCK PATCH] HTTP ${method}: ${url}`),
      send: (data) => console.log('[MOCK PATCH] HTTP send: ' + (data ? data.length + ' bytes' : 'empty')),
      setRequestHeader: (k, v) => console.log(`[MOCK PATCH] HTTP setRequestHeader: ${k}: ${v}`),
      responseText: '{"status":"success","country":"US","org":"Some ISP","hosting":false}',
      responseBody: new Uint8Array([0x50, 0x4B, 0x03, 0x04]), // Mock PE/ZIP header
      status: 200,
      statusText: 'OK',
    };
  }

  if (typeLower.includes('adodb.stream')) {
    return {
      Open: () => console.log('[MOCK PATCH] ADODB.Stream.Open'),
      Write: (d) => console.log('[MOCK PATCH] ADODB.Stream.Write: ' + (d ? d.length : 0) + ' bytes'),
      SaveToFile: (p, mode) => console.log(`[MOCK PATCH] ADODB.Stream.SaveToFile: ${p} (Mode: ${mode})`),
      LoadFromFile: (p) => console.log('[MOCK PATCH] ADODB.Stream.LoadFromFile: ' + p),
      Read: (n) => new Uint8Array(0),
      Close: () => {},
      Position: 0,
      Size: 0,
      Type: 1,
      Charset: 'utf-8',
    };
  }

  if (typeLower.includes('xmldom') || typeLower.includes('domdocument')) {
    return {
      createElement: (tag) => {
        console.log('[MOCK PATCH] XMLDOM.createElement: ' + tag);
        return new Proxy({
          text: 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAFY3iGMAAAAAAAAAAOAAIgALATgAAAACAAAABgAAAA==', // Base64 PE header
          dataType: 'bin.base64',
          nodeTypedValue: new Uint8Array([77, 90]),
          appendChild: () => {},
        }, catchAll);
      },
      loadXML: (xml) => {
        console.log('[MOCK PATCH] XMLDOM.loadXML');
        return true;
      },
      getElementsByTagName: (tag) => {
        console.log('[MOCK PATCH] XMLDOM.getElementsByTagName: ' + tag);
        return [new Proxy({}, catchAll)];
      },
      documentElement: new Proxy({}, catchAll),
      async: false,
    };
  }

  return new Proxy({}, catchAll);
};

// === Patch 2 ===
global.catchAll = {
  get: function(target, name) {
    console.log(`[MOCK PATCH] Unhandled property get: ${String(name)}`);
    return (...args) => new Proxy({}, global.catchAll);
  },
  set: function(target, name, value) {
    console.log(`[MOCK PATCH] Unhandled property set: ${String(name)} = ${value}`);
    return true;
  }
};

global.WScript = new Proxy({
  _mock_name: 'WScript',
  ScriptName: 'dropper.js',
  ScriptFullName: 'C:\\Users\\Public\\dropper.js',
  Echo: (m) => console.log('[MOCK PATCH] WScript.Echo: ' + m),
  Sleep: (ms) => console.log('[MOCK PATCH] WScript.Sleep: ' + ms + 'ms'),
  Quit: (code) => console.log('[MOCK PATCH] WScript.Quit with code ' + code),
  CreateObject: (t) => new ActiveXObject(t),
  Arguments: {
    length: 0,
    Item: (i) => '',
    Count: () => 0
  },
}, global.catchAll);

global.GetObject = function(path) {
  console.log('[MOCK PATCH] GetObject: ' + path);
  return new Proxy({
    ExecQuery: function(query) {
      console.log('[MOCK PATCH] WMI ExecQuery: ' + query);
      const qLower = query.toLowerCase();
      if (qLower.includes('win32_processor'))
        return [{
          Name: 'Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz',
          NumberOfCores: 6
        }];
      if (qLower.includes('win32_computersystem'))
        return [{
          Manufacturer: 'Dell Inc.',
          Model: 'OptiPlex 7090'
        }];
      if (qLower.includes('win32_baseboard'))
        return [{
          Manufacturer: 'Intel Corporation',
          Product: '440BX Desktop Reference Platform'
        }]; // Common VM indicator
      if (qLower.includes('win32_videocontroller'))
        return [{
          Name: 'NVIDIA GeForce GTX 1080'
        }];
      if (qLower.includes('win32_networkadapterconfiguration'))
        return [{
          MACAddress: '00:1A:2B:3C:4D:5E',
          IPAddress: ['192.168.1.101']
        }];
      return [new Proxy({}, global.catchAll)];
    },
  }, global.catchAll);
};

if (typeof ActiveXObject !== 'undefined') {
  const originalActiveXObject = ActiveXObject;
  global.ActiveXObject = function(type) {
    const typeLower = type.toLowerCase();

    if (typeLower.includes('wscript.shell')) {
      console.log('[MOCK PATCH] Created ActiveXObject: WScript.Shell');
      return {
        Run: (cmd, style, wait) => {
          console.log(`[MOCK PATCH] WScript.Shell.Run: "${cmd}"`);
          if (cmd.toLowerCase().includes('powershell') && cmd.toLowerCase().includes('-enc')) {
            const parts = cmd.split(' ');
            const encodedPart = parts.find(p => p.length > 100);
            if (encodedPart) {
              try {
                const decoded = Buffer.from(encodedPart, 'base64').toString('utf16le');
                console.log(`[MOCK PATCH] DECODED POWERSHELL: ${decoded.substring(0, 250)}...`);
              } catch (e) {
                console.log('[MOCK PATCH] Failed to decode suspected PowerShell command.');
              }
            }
          }
          return 0;
        },
        Exec: (cmd) => {
          console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
          return {
            StdOut: {
              ReadAll: () => ''
            },
            StdErr: {
              ReadAll: () => ''
            },
            Status: 0
          };
        },
        RegRead: (key) => {
          console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
          if (key.includes('Aerofox\\Foxmail')) return 'C:\\Program Files\\Foxmail\\';
          if (key.includes('Comodo\\IceDragon')) return '';
          return '1';
        },
        ExpandEnvironmentStrings: (s) => {
          console.log('[MOCK PATCH] WScript.Shell.ExpandEnvironmentStrings: ' + s);
          return s.replace(/%PUBLIC%/g, 'C:\\Users\\Public').replace(/%TEMP%/g, 'C:\\Users\\User\\AppData\\Local\\Temp');
        },
        RegWrite: (key, val, type) => console.log(`[MOCK PATCH] WScript.Shell.RegWrite: ${key} = ${val}`),
        RegDelete: (key) => console.log('[MOCK PATCH] WScript.Shell.RegDelete: ' + key),
        Environment: (type) => new Proxy({ Item: (k) => '' }, global.catchAll),
      };
    }
    return originalActiveXObject(type);
  };
}

// === Patch 3 ===
if (typeof ActiveXObject !== 'undefined') {
    const originalActiveXObject = global.ActiveXObject_Original || global.ActiveXObject;
    // Prevent re-capturing an already-patched version in case this patch runs multiple times
    if (typeof global.ActiveXObject_Original === 'undefined') {
        global.ActiveXObject_Original = originalActiveXObject;
    }

    global.ActiveXObject = function(type) {
        const typeLower = (type || '').toLowerCase();

        if (typeLower.includes('wscript.shell')) {
            console.log('[MOCK PATCH] Created ActiveXObject: WScript.Shell');
            return {
                Run: (cmd, style, wait) => {
                    console.log(`[MOCK PATCH] WScript.Shell.Run: "${cmd}"`);
                    if (cmd.toLowerCase().includes('powershell') && cmd.toLowerCase().includes('-enc')) {
                        const parts = cmd.split(' ');
                        const encodedPart = parts.find(p => p.length > 100);
                        if (encodedPart) {
                            try {
                                const decoded = Buffer.from(encodedPart, 'base64').toString('utf16le');
                                console.log(`[MOCK PATCH] DECODED POWERSHELL: ${decoded.substring(0, 250)}...`);
                            } catch (e) {
                                console.log('[MOCK PATCH] Failed to decode suspected PowerShell command.');
                            }
                        }
                    }
                    return 0;
                },
                Exec: (cmd) => {
                    console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
                    return { StdOut: { ReadAll: () => '' }, StdErr: { ReadAll: () => '' }, Status: 0 };
                },
                RegRead: (key) => {
                    console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
                    if (key.includes('Aerofox\\Foxmail')) return 'C:\\Program Files\\Foxmail\\';
                    if (key.includes('Comodo\\IceDragon')) return '';
                    return '1';
                },
                ExpandEnvironmentStrings: (s) => {
                    console.log('[MOCK PATCH] WScript.Shell.ExpandEnvironmentStrings: ' + s);
                    return s.replace(/%PUBLIC%/g, 'C:\\Users\\Public').replace(/%TEMP%/g, 'C:\\Users\\User\\AppData\\Local\\Temp');
                },
                RegWrite: (key, val, type) => console.log(`[MOCK PATCH] WScript.Shell.RegWrite: ${key} = ${val}`),
                RegDelete: (key) => console.log('[MOCK PATCH] WScript.Shell.RegDelete: ' + key),
                Environment: (type) => new Proxy({ Item: (k) => '' }, global.catchAll),
            };
        } else if (typeLower.includes('scripting.filesystemobject')) {
            console.log('[MOCK PATCH] Created ActiveXObject: Scripting.FileSystemObject');
            return {
                FileExists: (path) => {
                    const pLower = (path || '').toLowerCase();
                    console.log('[MOCK PATCH] FileSystemObject.FileExists: ' + path);
                    // TTP: Dropper cleanup artifacts
                    if (pLower.endsWith('mands.png') || pLower.endsWith('vile.png') || pLower.endsWith('mock_script.url')) {
                        return true;
                    }
                    // TTP: T1497 VM Evasion via file checks
                    if (pLower.includes('sbiedll.dll') || pLower.includes('snxhk.dll') || pLower.includes('sxln.dll') || pLower.includes('cmdvrt32.dll')) {
                        console.log('[MOCK PATCH] Anti-VM file check detected: ' + path);
                        return true;
                    }
                    return false;
                },
                DeleteFile: (path, force) => {
                    console.log('[MOCK PATCH] FileSystemObject.DeleteFile: ' + path);
                },
                GetSpecialFolder: (id) => {
                    console.log('[MOCK PATCH] FileSystemObject.GetSpecialFolder: ' + id);
                    // 2 = TemporaryFolder, commonly used for staging
                    if (id === 2) return 'C:\\Users\\User\\AppData\\Local\\Temp';
                    return 'C:\\Windows\\System32';
                },
            };
        }

        try {
            return new originalActiveXObject(type);
        } catch (e) {
            console.log(`[MOCK PATCH] Original ActiveXObject failed for "${type}", returning empty proxy.`);
            return new Proxy({}, global.catchAll);
        }
    };
}

