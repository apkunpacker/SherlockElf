# Hook memory

import frida
import sys

from emu.ds    import disassemble_code
from datetime           import datetime

app_name = "" # Enter the name of the app to be monitored here.

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        base = payload.get('base')
        chunk_size = payload.get('chunkSize')

        if data is None:
            print(f"[Error] Received memory dump from base address: {base} with chunk size: {chunk_size} bytes, but no data was received.")
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            print(f"Received memory dump from base address: {base} with chunk size: {chunk_size} bytes")

            # Save the received memory data to a file
            with open(f"bin/memory_dump_{base}_{timestamp}.bin", "wb") as f:
                f.write(data)
                disassemble_code(data, 0x1000)
                print(f"Memory dump saved to memory_dump_{base}_{timestamp}.bin")
    elif message['type'] == 'error':
        print(f"[Error]: {message['stack']}")


def main():
    try:
        # Load the Frida script
        with open("hook/mem.js") as f:
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
