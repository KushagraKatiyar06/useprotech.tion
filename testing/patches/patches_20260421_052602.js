// === Patch 1 ===
global.ActiveXObject = function(type) {
    console.log('[MOCK PATCH] new ActiveXObject: ' + type);
    const ltype = type.toLowerCase();

    if (ltype.includes('filesystemobject')) {
        return new Proxy({
            FileExists: (path) => {
                console.log('[MOCK PATCH] FSO.FileExists: ' + path);
                if (path.toLowerCase().includes('mands.png') || path.toLowerCase().includes('vile.png') || path.toLowerCase().includes('mock_script.url')) {
                    return true;
                }
                return false;
            },
            DeleteFile: (path, force) => {
                console.log('[MOCK PATCH] FSO.DeleteFile: ' + path);
            },
            CreateTextFile: (path) => {
                console.log('[MOCK PATCH] FSO.CreateTextFile: ' + path);
                return new Proxy({
                    WriteLine: (s) => console.log('[MOCK PATCH] FSO.Stream.WriteLine: (length ' + s.length + ')'),
                    Close: () => console.log('[MOCK PATCH] FSO.Stream.Close')
                }, catchAll);
            },
            GetSpecialFolder: (id) => {
                console.log('[MOCK PATCH] FSO.GetSpecialFolder: ' + id);
                if (id === 2) return 'C:\\Users\\User\\AppData\\Local\\Temp';
                return 'C:\\Windows';
            },
        }, catchAll);
    }

    if (ltype.includes('shell')) {
        return new Proxy({
            Run: (cmd, style, wait) => {
                console.log(`[MOCK PATCH] WScript.Shell.Run: "${cmd}"`);
                if (cmd.toLowerCase().includes('powershell')) {
                    console.log('[MOCK PATCH] DETECTED POWERSHELL EXECUTION (T1059.001)');
                }
                return 0;
            },
            ExpandEnvironmentStrings: (s) => {
                console.log('[MOCK PATCH] WScript.Shell.ExpandEnvironmentStrings: ' + s);
                return s.replace(/%PUBLIC%/ig, 'C:\\Users\\Public').replace(/%TEMP%/ig, 'C:\\Users\\User\\AppData\\Local\\Temp');
            },
            Exec: (cmd) => {
                console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
                return {
                    StdOut: { ReadAll: () => '', atEnd: true },
                    StdErr: { ReadAll: () => '', atEnd: true },
                    Status: 0,
                    Terminate: () => {}
                };
            },
        }, catchAll);
    }
    
    console.log('[MOCK WARNING] Unhandled ActiveXObject type: ' + type);
    return new Proxy({}, catchAll);
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
        Item: () => '',
        Count: () => 0
    },
};

