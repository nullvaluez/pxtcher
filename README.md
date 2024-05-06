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

## Function Descriptions

This section outlines key functions and their roles within the .NET Obfuscator and Encryptor application:

### `ObfuscateAndEncryptAssembly(AssemblyDefinition assembly, string encryptionKey)`

This function handles the main obfuscation and encryption logic. It iterates over all methods in the provided assembly and applies obfuscation techniques, such as renaming non-public methods and encrypting string literals based on the provided encryption key.

### `ValidateHashAndResourceCreation(Stream stream, AssemblyDefinition assembly)`

Validates the integrity of the assembly by creating and checking an MD5 hash of the assembly's data stream. It also checks the creation of embedded resources for tamper detection.

### `GenerateRandomEncryptionKey(int keySize)`

Generates a random encryption key of specified size using a cryptographic random number generator. This key is used for the encryption of strings within the assembly.

### `EmbedHashInAssembly()`

Calculates and embeds an SHA-256 hash of the assembly's contents into the assembly itself as a resource. This is part of the tamper detection feature, verifying the integrity of the assembly at runtime.

### `GetEmbeddedHash()`

Retrieves the embedded hash from the assembly's resources, which can be used to check if the assembly has been tampered with since its creation.

### `EncryptStrings(MethodDefinition method, string encryptionKey)`

Specifically targets string literals in the provided method's IL code and encrypts them using the specified encryption key and algorithm. It replaces the original strings with their encrypted versions.

### `GenerateObfuscatedName()`

Generates a random string name which is used to rename methods and classes during obfuscation to make reverse engineering more difficult.

### `InsertDummyOperations(MethodDefinition method)`

Inserts non-operative instructions (NOPs) into the method's body to confuse decompilers and obfuscate the control flow further.

### `AddDynamicProxy(MethodDefinition originalMethod, AssemblyDefinition assembly, string encryptionKey)`

Adds a dynamic proxy method that forwards calls to an original method. This is used to obfuscate the direct calling relationship between methods.

### `SwitchEncryptionAlgorithm()`

Switches the encryption algorithm used in the obfuscator dynamically between AES-256-GCM and ChaCha20 to provide an additional layer of security complexity.

These functions are pivotal in ensuring the obfuscator not only protects your assemblies through encryption and obfuscation but also maintains integrity checks to deter and detect tampering.
