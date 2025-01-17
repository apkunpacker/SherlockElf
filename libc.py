# Hook strlen method

import frida
import sys

app_name = "" # Enter the name of the app to be monitored here.

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[Message from SherlockElf]: {message['payload']}")
        with open("dump/strlen_dump.txt", "a") as f:
            f.write(f'{message}\n')
    elif message['type'] == 'error':
        print(f"[Error]: {message['stack']}")

def on_destroyed():
    print("[*] Script destroyed.")

def main():
    try:
        # Load the Frida script
        with open("hook/strlen.js") as f:
            script_code = f.read()

        # Attach to the target process
        device: frida.core.Device = frida.get_usb_device()
        app = device.get_frontmost_application()
        if app:
            target = app.pid
        else:
            target = app_name
        session: frida.core.Session = device.attach(target)
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.on('destroyed', on_destroyed)
        script.load()

        # Keep the script running
        print(f"[*] Hooking {target}. Press Ctrl+C to stop.")
        sys.stdin.read()
    except frida.ServerNotRunningError:
        print("Frida server is not running. Please start the frida-server on your device.")
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found. Make sure the app is running.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
