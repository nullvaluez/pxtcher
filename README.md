# pxtcher - .NET Obfuscator and Patcher
pxtcher is a tool designed to obfuscate and encrypt .NET assemblies to protect against reverse engineering and unauthorized tampering. The tool uses Mono.Cecil for assembly manipulation, BouncyCastle for encryption, and provides an option to generate a random encryption key if one is not provided. 

## Overview

This project is a .NET assembly obfuscator and encryptor designed to enhance the security of your .NET applications by protecting them from reverse engineering and tampering. It includes a launcher script (`launcher.py`) that wraps the executable using PyArmor.

## Features

- Obfuscates .NET assemblies
- Encrypts .NET assemblies
- Control flow obfuscation
- String encryption
- Anti-tamper and anti-debugging mechanisms
- Environment checks (e.g., running in a virtual machine)
- Easy to use CLI
- Includes a launcher script to wrap the executable

## Getting Started

### Prerequisites

- Python 3.x
- .NET SDK
- PyArmor (`pip install pyarmor`)
- PyInstaller (`pip install pyinstaller`)
- Mono.Cecil library for .NET (`Install-Package Mono.Cecil`)
- BouncyCastle library for .NET (`Install-Package BouncyCastle`)

### Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/yourusername/your-repo-name.git
    cd your-repo-name
    ```

2. **Install Python dependencies:**

    ```bash
    pip install pyarmor pyinstaller
    ```

3. **Install .NET dependencies:**

    ```bash
    dotnet add package Mono.Cecil
    dotnet add package BouncyCastle
    ```

4. **Build the .NET project:**

    ```bash
    dotnet build -c Release
    ```

## Usage

1. **Obfuscate and encrypt your .NET assemblies:**

    ```bash
    dotnet run --project YourProjectPath
    ```

2. **Wrap the executable using the launcher script:**

    Ensure `launcher.py` is in the root directory, then run:

    ```bash
    pyarmor gen --output dist launcher.py
    pyinstaller --onefile dist/launcher.py
    ```

    Use the generated executable to wrap your .NET executable:

    ```bash
    dist/launcher path/to/your/executable.exe
    ```

## Examples

### Obfuscating a .NET Assembly

1. **Run the tool:**

    ```bash
    dotnet run --project YourProjectPath
    ```

2. **Provide the DLL file:**

    Drag and drop the DLL file into the console and press enter.

3. **Check the output:**

    The obfuscated and encrypted DLL will be saved in the same directory with `_obfuscated` appended to the filename.

### Wrapping the Executable with PyArmor

1. **Generate the PyArmor wrapper:**

    ```bash
    pyarmor gen --output dist launcher.py
    ```

2. **Create a standalone executable:**

    ```bash
    pyinstaller --onefile dist/launcher.py
    ```

3. **Use the wrapped executable:**

    ```bash
    dist/launcher path/to/your/executable.exe
    ```

## Function Descriptions

- **EnsureSingleInstance**: Ensures that only one instance of the application is running.
- **StartProcessDetection**: Starts a background thread to detect unauthorized processes.
- **PerformTamperDetection**: Validates the assembly's integrity and adds anti-tamper mechanisms.
- **DisplayWelcomeMessage**: Displays an ASCII art welcome message.
- **GenerateSafeOutputPath**: Generates a safe output path for the obfuscated DLL.
- **ProcessAssembly**: Obfuscates and encrypts the assembly.
- **EmbedHashInAssembly**: Embeds a hash in the assembly for tamper detection.
- **GetEmbeddedHash**: Retrieves the embedded hash from the assembly.
- **ValidateHashAndResourceCreation**: Validates the hash and resource creation in the assembly.
- **GenerateRandomEncryptionKey**: Generates a random encryption key.
- **ObfuscateAndEncryptAssembly**: Applies obfuscation and encryption to the assembly.
- **InsertControlFlowObfuscation**: Inserts control flow obfuscation into the methods.
- **InsertOpaquePredicates**: Inserts opaque predicates into the methods.
- **AddAntiTamperCheck**: Adds anti-tamper checks to the methods.
- **AddEncryptedResource**: Adds an encrypted resource to the assembly.
- **EncryptData**: Encrypts data using the specified key.
- **LoadAssemblyReflectively**: Loads the assembly reflectively.
- **SwitchEncryptionAlgorithm**: Switches the encryption algorithm periodically.
- **GenerateObfuscatedName**: Generates a random obfuscated name.
- **DetectProcess**: Detects unauthorized processes and terminates the application.
- **EncryptStrings**: Encrypts string fields and properties in the assembly.
- **EncryptString**: Encrypts a string using the specified encryption key.
- **DecryptString**: Decrypts a string using the specified encryption key.
- **AntiDebugging**: Detects if a debugger is attached and terminates the application.
- **EnvironmentChecks**: Checks if the application is running in a virtual machine.

## PyArmor

The `launcher.py` script is designed to wrap your .NET executable with PyArmor, providing an additional layer of security. Here's how to use it:

1. **Ensure `launcher.py` is in the root directory.**
2. **Generate the PyArmor wrapper:**

    ```bash
    pyarmor gen --output dist launcher.py
    ```

3. **Create a standalone executable:**

    ```bash
    pyinstaller --onefile dist/launcher.py
    ```

4. **Use the wrapped executable:**

    ```bash
    dist/launcher path/to/your/executable.exe
    ```

This will protect your .NET executable with PyArmor, adding an additional layer of security to your application.

## Contributing

We welcome contributions! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.

## Contact

For any questions or concerns, please open an issue or contact the repository owner.

