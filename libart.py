# List libart jni

import frida
import sys

app_name = "" # Enter the name of the app to be monitored here.
script_file = "hook/libart.js"  # Hook


def main():
    try:
        # Load the Frida script
        with open(script_file) as f:
            script_code = f.read()

        # Attach to the target process
        device = frida.get_usb_device()
        app = device.get_frontmost_application()
        if app and app.name == app_name:
            target = app.pid
        else:
            target = device.spawn([app_name])
            device.resume(target)

        session = device.attach(target)
        script = session.create_script(script_code)
        script.load()

        # Keep the script running
        print(f"[*] Hooking {target}. Press Ctrl+C to stop.")
        sys.stdin.read()
    except frida.ServerNotRunningError:
        print("Frida server is not running. Please start the frida-server on your device.")
    except frida.ProcessNotFoundError:
        print(f"Process '{app_name}' not found. Make sure the app is running.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
