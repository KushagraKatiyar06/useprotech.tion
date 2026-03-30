// === Patch 1 ===
const catchAll = {
    get: function(target, prop) {
        const propStr = String(prop);
        if (prop in target) {
            return target[prop];
        }
        if (typeof prop === 'symbol' || propStr.startsWith('_') || propStr === 'inspect') {
            return undefined;
        }
        console.log(`[MOCK STUB] Unhandled call: ${target._COM_TYPE || 'Unknown COM'}.${propStr}`);
        const newFunc = (...args) => {
            if (args.length > 0) {
                 console.log(`[MOCK STUB] Args for ${propStr}: ${JSON.stringify(args).slice(0, 100)}`);
            }
            return new Proxy({}, catchAll);
        };
        newFunc.toString = () => `function ${propStr}() { [native code] }`;
        return newFunc;
    },
    set: function(target, prop, value) {
        const propStr = String(prop);
        console.log(`[MOCK STUB] Set: ${target._COM_TYPE || 'Unknown COM'}.${propStr} = ${value}`);
        target[prop] = value;
        return true;
    }
};

global.WScript = {
  ScriptName: 'dropper.js',
  ScriptFullName: 'C:\\Users\\Public\\dropper.js',
  Echo: (m) => console.log('[MOCK PATCH] WScript.Echo: ' + m),
  Sleep: (ms) => console.log('[MOCK PATCH] WScript.Sleep: ' + ms + 'ms'),
  Quit: (code) => console.log('[MOCK PATCH] WScript.Quit: ' + code),
  CreateObject: (t) => new ActiveXObject(t),
  Arguments: {
    length: 0,
    Item: () => ''
  },
};

global.ActiveXObject = function(type) {
  console.log('[MOCK PATCH] new ActiveXObject: ' + type);
  const lcaseType = type.toLowerCase();

  if (lcaseType.includes('scripting.filesystemobject')) {
    return new Proxy({
      _COM_TYPE: 'FileSystemObject',
      FileExists: (path) => {
        console.log('[MOCK PATCH] FileSystemObject.FileExists: ' + path);
        // TTP: Dropper cleans up these artifacts. Return true to exercise the DeleteFile path.
        if (path.toLowerCase().includes('mands.png') || path.toLowerCase().includes('vile.png')) {
          return true;
        }
        // TTP: Dropper checks for a marker file; it won't exist on first run.
        if (path.toLowerCase().includes('.url')) {
          return false;
        }
        return false;
      },
      DeleteFile: (path) => {
        console.log('[MOCK PATCH] FileSystemObject.DeleteFile: ' + path);
      },
      CreateTextFile: (path, overwrite) => {
        console.log('[MOCK PATCH] FileSystemObject.CreateTextFile: ' + path);
        return {
          Write: (s) => { console.log('[MOCK PATCH] TextStream.Write: ' + s.substring(0, 80) + '...'); },
          Close: () => { console.log('[MOCK PATCH] TextStream.Close'); }
        };
      },
      GetSpecialFolder: (id) => {
        console.log('[MOCK PATCH] FileSystemObject.GetSpecialFolder: ' + id);
        if (id === 2) return 'C:\\Users\\User\\AppData\\Local\\Temp';
        return 'C:\\Users\\Public';
      }
    }, catchAll);
  }

  if (lcaseType.includes('wscript.shell')) {
    // Proactive stub based on TTP: Next step is PowerShell execution.
    return new Proxy({
      _COM_TYPE: 'WScript.Shell',
      Run: (cmd, style, wait) => {
        console.log('[MOCK PATCH] WScript.Shell.Run: ' + cmd);
        if (cmd.toLowerCase().includes("powershell")) {
            console.log('[MOCK TTP] T1059.001 PowerShell Execution Detected');
        }
        return 0;
      },
      Exec: (cmd) => {
        console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
        return {
          StdOut: { ReadAll: () => '' },
          StdErr: { ReadAll: () => '' },
          Status: 0
        };
      },
      ExpandEnvironmentStrings: (s) => {
          console.log('[MOCK PATCH] WScript.Shell.ExpandEnvironmentStrings: ' + s);
          return s.replace(/%temp%/ig, 'C:\\Users\\User\\AppData\\Local\\Temp')
                  .replace(/%public%/ig, 'C:\\Users\\Public')
                  .replace(/%appdata%/ig, 'C:\\Users\\User\\AppData\\Roaming')
                  .replace(/%windir%/ig, 'C:\\Windows');
      },
      RegRead: (key) => {
        console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
        return '1';
      },
    }, catchAll);
  }

  // Default for unhandled COM objects
  return new Proxy({ _COM_TYPE: type }, catchAll);
};

// === Patch 2 ===
const catchAll = {
    get: function(target, prop, receiver) {
        const comType = target._COM_TYPE || 'Unknown';
        if (prop in target || typeof prop === 'symbol') {
            return Reflect.get(...arguments);
        }
        console.log(`[MOCK PATCH] catchAll GET: ${comType}.${String(prop)} (stubbed)`);
        return (...args) => {
            console.log(`[MOCK PATCH] catchAll CALL: ${comType}.${String(prop)}()`);
            if (String(prop).toLowerCase() === 'item') return new Proxy({ _COM_TYPE: `${comType}.Item` }, catchAll);
            return new Proxy({ _COM_TYPE: `${comType}.${String(prop)}` }, catchAll);
        };
    },
    set: function(target, prop, value) {
        const comType = target._COM_TYPE || 'Unknown';
        console.log(`[MOCK PATCH] catchAll SET: ${comType}.${String(prop)} = ${value}`);
        target[prop] = value;
        return true;
    }
};
global.catchAll = catchAll;

global.GetObject = function(path) {
    console.log('[MOCK PATCH] GetObject: ' + path);
    if (path.toLowerCase().includes('winmgmts')) {
        return new Proxy({
            _COM_TYPE: 'WMI',
            ExecQuery: function(query) {
                console.log('[MOCK PATCH] WMI ExecQuery: ' + query);
                const lq = query.toLowerCase();
                if (lq.includes('win32_processor')) {
                    console.log('[MOCK TTP] T1082 System Info Discovery: Processor');
                    return [{ Name: 'Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz', NumberOfCores: 6 }];
                }
                if (lq.includes('win32_computersystem') || lq.includes('win32_baseboard')) {
                    console.log('[MOCK TTP] T1082 System Info Discovery: System/Board');
                    return [{ Manufacturer: 'Dell Inc.', Model: 'XPS 15 9570' }];
                }
                if (lq.includes('win32_videocontroller')) {
                    console.log('[MOCK TTP] T1497 VM Evasion: Video Controller Check');
                    return [{ Name: 'NVIDIA GeForce GTX 1050 Ti' }];
                }
                if (lq.includes('win32_networkadapterconfiguration')) {
                    console.log('[MOCK TTP] T1016 Network Config Discovery: MAC Address');
                    return [{ MACAddress: '00:1A:2B:3C:4D:5E', IPEnabled: true }];
                }
                // Return a generic collection with one item to prevent crashes on iteration
                return [new Proxy({ _COM_TYPE: 'WMI.Item' }, catchAll)];
            }
        }, catchAll);
    }
    return new Proxy({ _COM_TYPE: 'GetObject.' + path }, catchAll);
};

if (typeof global.ActiveXObject === 'function') {
    const originalActiveXObject = global.ActiveXObject;
    global.ActiveXObject = function(type) {
        console.log('[MOCK PATCH] new ActiveXObject: ' + type);
        const lcaseType = type.toLowerCase();

        if (lcaseType.includes('msxml2.xmlhttp') || lcaseType.includes('winhttp')) {
            console.log('[MOCK TTP] T1071 Web Protocols Detected');
            return new Proxy({
                _COM_TYPE: 'XMLHTTP',
                open: (method, url, async) => console.log(`[MOCK PATCH] HTTP ${method}: ${url}`),
                send: (data) => console.log('[MOCK PATCH] HTTP send'),
                setRequestHeader: (k, v) => console.log(`[MOCK PATCH] HTTP SetHeader: ${k}: ${v}`),
                responseText: '{"status":"success","country":"US","hosting":false}',
                responseBody: new Uint8Array([0x4d, 0x5a]), // MZ header
                status: 200,
            }, catchAll);
        }

        if (lcaseType.includes('wscript.shell')) {
            const shell = originalActiveXObject(type);
            shell.RegRead = (key) => {
                console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
                const lkey = key.toLowerCase();
                if (lkey.includes('aerofox') || lkey.includes('foxmail')) {
                    console.log('[MOCK TTP] T1555 Credential Access: Foxmail Registry Key');
                    return 'C:\\Program Files\\Foxmail\\';
                }
                if (lkey.includes('comodo') || lkey.includes('icedragon')) {
                    console.log('[MOCK TTP] T1497 VM Evasion: Sandbox Registry Key Check');
                    return ''; // Return empty string to indicate not found
                }
                return '1';
            };
            return shell;
        }

        return originalActiveXObject(type);
    };
}

// === Patch 3 ===
if (typeof global.catchAll === 'undefined') {
    global.catchAll = {
        get: function(target, name, receiver) {
            if (name === 'then' || typeof name === 'symbol') return undefined;
            const identifier = target._COM_TYPE ? `${target._COM_TYPE}.${String(name)}` : `Unknown.${String(name)}`;
            console.log(`[MOCK STUB] Unhandled GET: ${identifier}`);
            const prop = Reflect.get(target, name, receiver);
            if (typeof prop === 'function') {
                return (...args) => {
                    console.log(`[MOCK STUB] Unhandled CALL: ${identifier}()`);
                    return new Proxy({ _COM_TYPE: `${identifier}()` }, global.catchAll);
                };
            }
            return new Proxy({ _COM_TYPE: identifier }, global.catchAll);
        },
        set: function(target, name, value) {
            const identifier = target._COM_TYPE || 'Unknown';
            console.log(`[MOCK STUB] Unhandled SET: ${identifier}.${String(name)} = ${value}`);
            return Reflect.set(target, name, value);
        }
    };
}


const existingActiveX = global.ActiveXObject;

global.ActiveXObject = function(type) {
    console.log('[MOCK PATCH] new ActiveXObject: ' + type);
    const lcaseType = type.toLowerCase();

    if (lcaseType.includes('scripting.filesystemobject')) {
        console.log('[MOCK TTP] T1059.007 JavaScript File System Operations Detected');
        return {
            _COM_TYPE: 'FileSystemObject',
            FileExists: (path) => {
                console.log('[MOCK PATCH] FileSystemObject.FileExists: ' + path);
                const lpath = path.toLowerCase();
                if (lpath.endsWith('mands.png') || lpath.endsWith('vile.png') || lpath.endsWith('mock_script.url')) {
                    console.log('[MOCK TTP] AgentTesla dropper file artifact check.');
                    return true;
                }
                if (lpath.endsWith('sbiedll.dll') || lpath.endsWith('snxhk.dll') || lpath.endsWith('sxin.dll') || lpath.endsWith('cmdvrt32.dll')) {
                    console.log('[MOCK TTP] T1497 VM Evasion: Sandbox-related DLL check.');
                    return true;
                }
                return false;
            },
            DeleteFile: (path) => {
                console.log('[MOCK PATCH] FileSystemObject.DeleteFile: ' + path);
            },
            GetFile: (path) => {
                console.log('[MOCK PATCH] FileSystemObject.GetFile: ' + path);
                return new Proxy({ _COM_TYPE: 'File', Path: path, Size: 12345 }, global.catchAll);
            },
            BuildPath: (path, name) => {
                console.log(`[MOCK PATCH] FileSystemObject.BuildPath: ${path}\\${name}`);
                return `${path}\\${name}`;
            },
            GetSpecialFolder: (id) => {
                // 0=WindowsFolder, 1=SystemFolder, 2=TemporaryFolder
                if (id === 2) return 'C:\\Users\\Admin\\AppData\\Local\\Temp';
                if (id === 1) return 'C:\\Windows\\System32';
                return 'C:\\Windows';
            }
        };
    }

    if (typeof existingActiveX === 'function') {
        try {
            return existingActiveX(type);
        } catch (e) {
            console.log(`[MOCK STUB] existingActiveX handler for "${type}" failed. Providing generic mock.`);
        }
    }

    return new Proxy({ _COM_TYPE: type }, global.catchAll);
};

