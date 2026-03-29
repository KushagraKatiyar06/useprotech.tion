// === Patch 1 ===
const catchAll = {
    get: function(target, prop, receiver) {
        if (prop in target) {
            return target[prop];
        }
        const knownMethods = ['toString', 'valueOf', Symbol.toPrimitive];
        if (typeof prop === 'symbol' || knownMethods.includes(prop)) {
             return () => '[ProxyObject]';
        }
        console.log(`[MOCK CATCH] Unhandled property: ${prop.toString()}`);
        return new Proxy(function() {}, catchAll);
    }
};

global.ActiveXObject = function(type) {
    console.log('[MOCK PATCH] new ActiveXObject: ' + type);
    const ltype = type.toLowerCase();

    if (ltype.includes('scripting.filesystemobject')) {
        return {
            FileExists: (path) => {
                console.log('[MOCK PATCH] FileSystemObject.FileExists: ' + path);
                const lpath = path.toLowerCase();
                if (lpath.includes('mands.png') || lpath.includes('vile.png')) {
                    return true; // Return true so dropper executes its cleanup logic
                }
                if (lpath.includes('mock_script.url')) {
                    return false; // Return false so dropper proceeds (doesn't think it's already run)
                }
                return false;
            },
            DeleteFile: (path) => {
                console.log('[MOCK PATCH] FileSystemObject.DeleteFile: ' + path);
            },
            CreateTextFile: (path) => {
                console.log('[MOCK PATCH] FileSystemObject.CreateTextFile: ' + path);
                return new Proxy({ Write: () => {}, Close: () => {} }, catchAll);
            },
            BuildPath: (p, n) => `${p}\\${n}`,
            GetFile: (p) => new Proxy({ Path: p, Size: 123 }, catchAll),
            GetFolder: (p) => new Proxy({ Path: p }, catchAll),
        };
    }

    if (ltype.includes('wscript.shell')) {
        return {
            Run: (cmd, style, wait) => {
                console.log('[MOCK PATCH] WScript.Shell.Run: ' + cmd);
                return 0; // Success
            },
            Exec: (cmd) => {
                console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
                return { StdOut: { ReadAll: () => '' }, StdErr: { ReadAll: () => '' }, Status: 0 };
            },
            ExpandEnvironmentStrings: (s) => s.replace(/%[a-zA-Z]+%/g, (match) => {
                const env = {
                    '%TEMP%': 'C:\\Users\\User\\AppData\\Local\\Temp',
                    '%PUBLIC%': 'C:\\Users\\Public',
                    '%APPDATA%': 'C:\\Users\\User\\AppData\\Roaming'
                };
                return env[match.toUpperCase()] || match;
            }),
        };
    }

    return new Proxy({}, catchAll);
};

global.WScript = {
    ScriptName: 'malware.js',
    ScriptFullName: 'C:\\Users\\Public\\malware.js',
    Echo: (m) => console.log('[MOCK PATCH] WScript.Echo: ' + m),
    Sleep: (ms) => console.log('[MOCK PATCH] WScript.Sleep: ' + ms + 'ms'),
    Quit: (code) => console.log('[MOCK PATCH] WScript.Quit: ' + code),
    CreateObject: (t) => new global.ActiveXObject(t),
    Arguments: {
        length: 0,
        Item: () => ''
    },
};

// === Patch 2 ===
global.GetObject = function(path) {
    console.log('[MOCK PATCH] GetObject: ' + path);
    if (!path.toLowerCase().includes('winmgmts')) {
        return new Proxy({}, catchAll);
    }
    return new Proxy({
        ExecQuery: function(query) {
            console.log('[MOCK PATCH] WMI ExecQuery: ' + query);
            const lquery = query.toLowerCase();
            if (lquery.includes('win32_processor'))
                return [{
                    Name: 'Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz',
                    NumberOfCores: 6,
                    ProcessorId: 'BFEBFBFF000906EA'
                }];
            if (lquery.includes('win32_videocontroller'))
                return [{
                    Name: 'VMware SVGA II Adapter',
                    VideoProcessor: 'VMware'
                }];
            if (lquery.includes('win32_networkadapterconfiguration'))
                return [{
                    MACAddress: '00:0C:29:1A:2B:3C',
                    IPAddress: ['192.168.1.101']
                }];
            if (lquery.includes('win32_computersystem') || lquery.includes('win32_baseboard'))
                return [{
                    Manufacturer: 'VMware, Inc.',
                    Model: 'VMware Virtual Platform',
                    SerialNumber: 'VMware-12 34 56 78 90 ab cd ef-ba 98 76 54 32 10 fe dc'
                }];
            return [new Proxy({}, catchAll)];
        },
        Get: (cls) => {
            console.log('[MOCK PATCH] WMI Get: ' + cls);
            return new Proxy({}, catchAll);
        }
    }, catchAll);
};

if (typeof global.ActiveXObject !== 'undefined') {
    const originalActiveXObject = global.ActiveXObject;

    global.ActiveXObject = function(type) {
        const ltype = type.toLowerCase();

        if (ltype.includes('wscript.shell')) {
            const shell = originalActiveXObject(type);
            shell.RegRead = (key) => {
                console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
                const lkey = key.toLowerCase();
                if (lkey.includes('aerofox\\foxmail')) return 'C:\\Program Files\\Foxmail';
                if (lkey.includes('icedragon') || lkey.includes('comodo') || lkey.includes('sandbox')) return '';
                return '1';
            };
            shell.RegWrite = (key, val) => console.log('[MOCK PATCH] WScript.Shell.RegWrite: ' + key + ' = ' + val);
            shell.RegDelete = (key) => console.log('[MOCK PATCH] WScript.Shell.RegDelete: ' + key);
            shell.Environment = (t) => new Proxy({ Item: (k) => '' }, catchAll);
            return shell;
        }

        if (ltype.includes('winhttp') || ltype.includes('xmlhttp')) {
            console.log('[MOCK PATCH] new ActiveXObject: ' + type);
            return {
                open: (method, url, async) => console.log('[MOCK PATCH] HTTP open: ' + method + ' ' + url),
                send: (data) => console.log('[MOCK PATCH] HTTP send'),
                setRequestHeader: (k, v) => {},
                responseText: '{"status":"success","country":"US","org":"Contoso","hosting":false}',
                responseBody: new Uint8Array(0),
                status: 200,
                statusText: 'OK',
            };
        }

        return originalActiveXObject(type);
    };
}

// === Patch 3 ===
global.FileSystemObject = function() {
    console.log('[MOCK PATCH] new FileSystemObject');
    this.FileExists = (path) => {
        const lpath = path.toLowerCase();
        console.log('[MOCK PATCH] FileSystemObject.FileExists: ' + path);
        // TTP: Dropper cleanup checks
        if (lpath.includes('mands.png') || lpath.includes('vile.png') || lpath.includes('mock_script.url')) {
            return true;
        }
        // TTP: Anti-VM/sandbox file checks
        if (lpath.includes('sbiedll.dll') || lpath.includes('snxhk.dll') || lpath.includes('sxln.dll') || lpath.includes('cmdvrt32.dll')) {
            console.log('[MOCK PATCH] Anti-VM file check positive for: ' + path);
            return true;
        }
        return false;
    };
    this.DeleteFile = (path) => {
        console.log('[MOCK PATCH] FileSystemObject.DeleteFile: ' + path);
    };
    this.GetSpecialFolder = (id) => {
        console.log('[MOCK PATCH] FileSystemObject.GetSpecialFolder: ' + id);
        if (id === 2) return 'C:\\Users\\User\\AppData\\Local\\Temp'; // TempFolder
        return 'C:\\Users\\Public';
    };
    this.BuildPath = (p1, p2) => p1 + '\\' + p2;
    this.GetFile = (path) => {
        console.log('[MOCK PATCH] FileSystemObject.GetFile: ' + path);
        return new Proxy({ Path: path, Size: 12345 }, catchAll);
    };
    return new Proxy(this, catchAll);
};

if (typeof global.ActiveXObject !== 'undefined') {
    const originalActiveXObject = global.ActiveXObject;

    global.ActiveXObject = function(type) {
        console.log('[MOCK PATCH] new ActiveXObject: ' + type);
        const ltype = type.toLowerCase();

        if (ltype.includes('wscript.shell')) {
            return {
                Run: (cmd, style, wait) => {
                    console.log(`[MOCK PATCH] WScript.Shell.Run: cmd="${cmd}", style=${style}, wait=${wait}`);
                    return 0; // Success
                },
                Exec: (cmd) => {
                    console.log(`[MOCK PATCH] WScript.Shell.Exec: "${cmd}"`);
                    return { StdOut: { ReadAll: () => '' }, StdErr: { ReadAll: () => '' }, Status: 0 };
                },
                RegRead: (key) => {
                    console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
                    const lkey = key.toLowerCase();
                    if (lkey.includes('aerofox\\foxmail')) return 'C:\\Program Files\\Foxmail';
                    if (lkey.includes('icedragon') || lkey.includes('comodo') || lkey.includes('sandbox')) return '';
                    return '1';
                },
                RegWrite: (key, val) => console.log('[MOCK PATCH] WScript.Shell.RegWrite: ' + key + ' = ' + val),
                RegDelete: (key) => console.log('[MOCK PATCH] WScript.Shell.RegDelete: ' + key),
                Environment: (t) => new Proxy({ Item: (k) => '' }, catchAll),
                ExpandEnvironmentStrings: (s) => s.replace(/%PUBLIC%/gi, 'C:\\Users\\Public').replace(/%TEMP%/gi, 'C:\\Users\\User\\AppData\\Local\\Temp'),
            };
        }

        if (ltype.includes('scripting.filesystemobject')) {
            return new global.FileSystemObject();
        }

        if (ltype.includes('adodb.stream')) {
            return {
                Open: () => console.log('[MOCK PATCH] ADODB.Stream.Open'),
                Write: (d) => console.log('[MOCK PATCH] ADODB.Stream.Write: ' + (d ? d.length : 0) + ' bytes'),
                SaveToFile: (p, mode) => console.log('[MOCK PATCH] ADODB.Stream.SaveToFile: ' + p + ' (Mode: ' + mode + ')'),
                Close: () => console.log('[MOCK PATCH] ADODB.Stream.Close'),
                Position: 0,
                Size: 0,
                Type: 1, // 1=binary, 2=text
            };
        }

        if (ltype.includes('winhttp') || ltype.includes('xmlhttp')) {
            return {
                open: (method, url, async) => console.log('[MOCK PATCH] HTTP open: ' + method + ' ' + url),
                send: (data) => console.log('[MOCK PATCH] HTTP send'),
                setRequestHeader: (k, v) => {},
                responseText: '{"status":"success","country":"US","org":"Contoso","hosting":false}',
                responseBody: new Uint8Array(0),
                status: 200,
                statusText: 'OK',
            };
        }

        return originalActiveXObject(type);
    };
}

