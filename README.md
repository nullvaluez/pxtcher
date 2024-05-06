# pxtcher - .NET Obfuscator and Patcher
pxtcher is a tool designed to obfuscate and encrypt .NET assemblies to protect against reverse engineering and unauthorized tampering. The tool uses Mono.Cecil for assembly manipulation, BouncyCastle for encryption, and provides an option to generate a random encryption key if one is not provided. 

## Features

- **Obfuscation**: Reduces the readability of the .NET assembly for anyone trying to reverse-engineer your code.
- **Encryption**: Secures string literals and other sensitive information within the assembly.
- **Tamper Detection**: Adds an MD5 hash to the assembly as a resource to detect tampering of the assembly after it's been built.
- **Attribute-based Exclusion**: Use the `DoNotObfuscate` attribute to exclude specific classes or methods from obfuscation.
- **Dynamic Encryption Algorithm Switching**: Allows switching between AES-256-GCM and ChaCha20 encryption algorithms.

## Getting Started

### Prerequisites

- .NET Framework 4.7.2 or higher
- Visual Studio 2017 or later
- Mono.Cecil package
- BouncyCastle package
- 
## Installation

Before running the .NET Obfuscator, ensure that you have cloned the repository and built the project with all dependencies correctly configured.

## Usage

The program takes up to three command-line arguments:

1. **InputDllPath**: The path to the input .DLL file you want to obfuscate.
2. **OutputDllPath**: The path where the obfuscated and encrypted .DLL will be saved.
3. **EncryptionKey** (optional): A base64 string used as the encryption key. If not provided, a random 32-byte key will be generated.

### Installation

Clone the repository to your local machine using:

```bash
git clone https://github.com/yourusername/dotnet-obfuscator.git
```
Navigate to the project directory:

```bash
cd dotnet-obfuscator
```
Build the project using Visual Studio or via the command line:

```bash
msbuild /p:Configuration=Release
```
### Usage

Run the program via command line from the build directory:
```bash
DotNetObfuscator.exe
```
Follow the on-screen instructions to input the path to the DLL you wish to obfuscate and encrypt.

### Example with a provided EncryptionKey:
```bash
DotNetObfuscator.exe "C:\path\to\your\assembly.dll" "C:\path\to\save\obfuscated.dll" "YourBase64KeyHere"
```

## Example
Snippet from the main functionality:
```csharp
if (!ValidateHashAndResourceCreation(stream, assembly))
{
    Console.WriteLine("Validation failed.");
    return;
}

ObfuscateAndEncryptAssembly(assembly, encryptionKey);
assembly.Write(outputDllPath);
Console.WriteLine("Obfuscation and encryption completed.");
```
## Contributing
Contributions are welcome! Please feel free to submit pull requests, create issues for bugs and feature requests, and contribute to improving the documentation.

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.

The output .DLL will be saved at the specified OutputDllPath. Make sure to replace the output dll with the original input dll, e.g., ObfuscationTool.dll, replace AND rename ObfuscationTool_obfuscated.dll back to the original.

## Functions Description
GenerateRandomEncryptionKey(int keyLength): Generates a random encryption key of specified length and returns it as a base64 string.
ObfuscateAndEncryptAssembly(AssemblyDefinition assembly, string encryptionKey): Processes the provided assembly, obfuscating names and encrypting string values.
EncryptString(string plainText, string encryptionKey): Encrypts strings using the ChaCha7539Engine from BouncyCastle.
