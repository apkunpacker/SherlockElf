import base64
import struct
import frida

app_name = "" # Enter the name of the app to be monitored here.

js_code = """
rpc.exports = {
    findModule: function (name) {
        const libso = Process.findModuleByName(name);
        return libso !== null;
    },
    dumpSo: function (name) {
        const libso = Process.findModuleByName(name);
        if (libso === null) {
            console.log("find moduel failed");
            return '';
        }
        Memory.protect(ptr(libso.base), libso.size, 'rwx');
        const libso_buffer = ptr(libso.base).readByteArray(libso.size);
        return libso_buffer;
    },
}
"""


def main():
    device: frida.core.Device = frida.get_usb_device()
    app = device.get_frontmost_application()
    if app:
        target = app.pid
    else:
        target = app_name
    session: frida.core.Session = device.attach(target)
    script = session.create_script(js_code)
    script.load()

    # ... do more stuff


if __name__ == '__main__':
    main()