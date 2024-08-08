# SherlockElf 🕵️‍♂️

**SherlockElf** is a powerful tool designed for both static and dynamic analysis of Android ELF binaries. It helps security researchers, developers, and reverse engineers gain insights into ELF (Executable and Linkable Format) binaries used in Android applications.

## Features ✨

- **Static Analysis**: Extracts and analyzes metadata, headers, and sections from ELF binaries.
- **Dynamic Analysis**: Executes and monitors ELF binaries to observe runtime behavior and identify potential vulnerabilities.
- **User-friendly Interface**: Intuitive command-line interface for easy interaction.
- **Comprehensive Reports**: Generates detailed analysis reports for further inspection.
- **Cross-platform Support**: Works seamlessly on multiple platforms including Windows, macOS, and Linux.

## Installation 🛠️

To get started with SherlockElf, follow these steps:

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/iamtorsten/SherlockElf.git
    cd SherlockElf
    ```

2. **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Setup Environment**:
    - Magisk or KernelSu rooted Android Phone or Tablet
    - Running Frida Server on Phone
    - Installed Frida Tools on PC

## Usage 🚀

Using SherlockElf is straightforward. Below are some common commands and their descriptions:

- **Static Analysis**:
    ```bash
    python emulate.py
    ```
    This command performs a static analysis on the specified ELF binary and outputs the results.
<br><br>
- **Dynamic Analysis**:
    ```python
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
    ```
    This command executes the ELF binary and monitors its memory behavior.

## Contributing 🤝

We welcome contributions from the community! If you'd like to contribute to SherlockElf, please follow these steps:

1. **Fork the Repository**: Click the "Fork" button at the top right of this page.
2. **Clone Your Fork**:
    ```bash
    git clone https://github.com/iamtorsten/SherlockElf.git
    ```
3. **Create a Branch**:
    ```bash
    git checkout -b feature-branch
    ```
4. **Make Your Changes** and **Commit**:
    ```bash
    git commit -am 'Add new feature'
    ```
5. **Push to Your Fork**:
    ```bash
    git push origin feature-branch
    ```
6. **Create a Pull Request**: Navigate to the original repository and submit a pull request.

## License 📜

SherlockElf is licensed under the MIT License. See the [LICENSE](https://github.com/iamtorsten/SherlockElf/blob/main/LICENSE) file for more information.

## Contact 📬

For any questions or feedback, please reach out via email at [torsten.klinger@googlemail.com](mailto:torsten.klinger@googlemail.com).

## Disclaimer ⚖️

This Project is just for personal educational purposed only. You can modify it for your personal used. But i do not take any resonsibility for issues caused by any modification of this project. All processes illustrated in the project serve only as examples. <br><br>**Use of this code must comply with applicable laws.**

## Dependencies 🗒️󠁶󠁥󠁷󠁿

- [Frida](https://github.com/frida/frida)
- [Capstone](https://www.capstone-engine.org)
- [Keystone](https://www.capstone-engine.org)
- [Unicorn](https://www.unicorn-engine.org/)
- Improved version of [ExAndroidNativeEmu](https://github.com/maiyao1988/ExAndroidNativeEmu)

