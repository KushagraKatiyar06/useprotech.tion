// === Patch 1 ===
const catchAll = {
    get: function(target, prop) {
        if (prop in target) return target[prop];
        if (typeof prop === 'string' && prop.length < 100) {
            console.log('[MOCK ATTEMPT] Called on mock object: ' + prop);
        }
        const P = new Proxy(function() {}, catchAll);
        return P;
    }
};

global.ActiveXObject = function(type) {
    console.log('[MOCK PATCH] new ActiveXObject: ' + type);

    if (type.toLowerCase().includes('shell')) {
        return {
            Run: (cmd, style, wait) => {
                console.log('[MOCK PATCH] WScript.Shell.Run: ' + cmd);
                return 0; // Success
            },
            Exec: (cmd) => {
                console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
                return new Proxy({
                    StdOut: { ReadAll: () => 'Microsoft Windows [Version 10.0.19045.2846]' },
                    StdErr: { ReadAll: () => '' },
                    Status: 0
                }, catchAll);
            },
            ExpandEnvironmentStrings: (s) => {
                console.log('[MOCK PATCH] WScript.Shell.ExpandEnvironmentStrings: ' + s);
                return s.replace(/%temp%/ig, 'C:\\Users\\User\\AppData\\Local\\Temp')
                        .replace(/%public%/ig, 'C:\\Users\\Public')
                        .replace(/%appdata%/ig, 'C:\\Users\\User\\AppData\\Roaming');
            },
            RegRead: (key) => {
                console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
                // Based on TTPs for credential theft targets and AV checks
                if (key.toLowerCase().includes('aerofox\\foxmail')) return 'C:\\Program Files\\Foxmail\\';
                if (key.toLowerCase().includes('icedragon') || key.toLowerCase().includes('sbiedll')) return null;
                return '1';
            },
            RegWrite: (key, val, type) => console.log(`[MOCK PATCH] WScript.Shell.RegWrite: ${key} = ${val}`),
            RegDelete: (key) => console.log(`[MOCK PATCH] WScript.Shell.RegDelete: ${key}`),
            Environment: (proc) => new Proxy({ Item: (k) => '' }, catchAll)
        };
    }

    if (type.toLowerCase().includes('filesystemobject')) {
        return {
            FileExists: (path) => {
                console.log('[MOCK PATCH] FileSystemObject.FileExists: ' + path);
                // Per TTPs, these files are checked before deletion. Return true to allow deletion logic to run.
                if (path.toLowerCase().includes('mands.png') || path.toLowerCase().includes('vile.png') || path.toLowerCase().includes('mock_script.url')) {
                    return true;
                }
                return false;
            },
            DeleteFile: (path, force) => {
                console.log('[MOCK PATCH] FileSystemObject.DeleteFile: ' + path);
            },
            GetSpecialFolder: (id) => {
                console.log('[MOCK PATCH] FileSystemObject.GetSpecialFolder: ' + id);
                if (id === 2) return 'C:\\Users\\User\\AppData\\Local\\Temp'; // TempFolder
                return 'C:\\Users\\Public';
            },
            BuildPath: (path, name) => path + '\\' + name,
            GetTempName: () => 'rad' + Math.random().toString(36).substring(2, 8) + '.tmp',
            CreateTextFile: (path, overwrite, unicode) => new Proxy({}, catchAll),
            OpenTextFile: (path, mode, create, format) => new Proxy({ Close: ()=>{} }, catchAll),
        };
    }

    if (type.toLowerCase().includes('xmlhttp') || type.toLowerCase().includes('winhttp')) {
        return {
            open: (method, url, async) => console.log('[MOCK PATCH] HTTP ' + method + ': ' + url),
            send: (data) => console.log('[MOCK PATCH] HTTP send' + (data ? ': ' + data.length + ' bytes' : '')),
            setRequestHeader: (k, v) => {},
            status: 200,
            statusText: 'OK',
            // Per TTPs, checks for VM hosting environments
            responseText: '{"status":"success","country":"United States","org":"Some ISP","hosting":false}',
            responseBody: new Uint8Array([0x50, 0x4B, 0x03, 0x04]), // Mock PE/ZIP header
        };
    }

    return new Proxy({}, catchAll);
};

global.WScript = {
    ScriptName: 'malware.js',
    ScriptFullName: 'C:\\Users\\Public\\malware.js',
    Echo: (m) => console.log('[MOCK PATCH] WScript.Echo: ' + m),
    Sleep: (ms) => console.log('[MOCK PATCH] WScript.Sleep: ' + ms + 'ms'),
    Quit: (code) => console.log('[MOCK PATCH] WScript.Quit with code: ' + (code || 0)),
    CreateObject: (t) => new global.ActiveXObject(t),
    Arguments: new Proxy({ length: 0, Item: (i) => '' }, catchAll)
};

global.GetObject = function(path) {
    console.log('[MOCK PATCH] GetObject: ' + path);
    return new Proxy({
        ExecQuery: function(query) {
            console.log('[MOCK PATCH] WMI ExecQuery: ' + query);
            // Mock responses based on TTP fingerprinting queries
            if (query.toLowerCase().includes('win32_processor'))
                return [{ Name: 'Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz', NumberOfCores: 10, ProcessorId: 'BFEBFBFF000906EA' }];
            if (query.toLowerCase().includes('win32_computersystem'))
                return [{ Manufacturer: 'ASUSTeK COMPUTER INC.', Model: 'System Product Name', TotalPhysicalMemory: '34277203968' }];
            if (query.toLowerCase().includes('win32_baseboard'))
                return [{ Manufacturer: 'ASUSTeK COMPUTER INC.', Product: 'ROG STRIX Z490-E GAMING' }];
            if (query.toLowerCase().includes('win32_videocontroller'))
                return [{ Name: 'NVIDIA GeForce RTX 3080' }];
            if (query.toLowerCase().includes('win32_networkadapterconfiguration'))
                return [{ MACAddress: '00:DE:AD:BE:EF:00', IPAddress: ['192.168.1.101'] }];
            return [new Proxy({}, catchAll)];
        }
    }, catchAll);
};

