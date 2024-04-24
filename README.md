# pxtcher - .NET Obfuscator and Patcher
pxtcher is a tool designed to obfuscate and encrypt .NET assemblies to protect against reverse engineering and unauthorized tampering. The tool uses Mono.Cecil for assembly manipulation, BouncyCastle for encryption, and provides an option to generate a random encryption key if one is not provided. 

## Requirements

- .NET Framework or .NET Core installed on your machine.
- Mono.Cecil library.
- BouncyCastle library.

## Installation

Before running the .NET Obfuscator, ensure that you have cloned the repository and built the project with all dependencies correctly configured.

## Usage

The program takes up to three command-line arguments:

1. **InputDllPath**: The path to the input .DLL file you want to obfuscate.
2. **OutputDllPath**: The path where the obfuscated and encrypted .DLL will be saved.
3. **EncryptionKey** (optional): A base64 string used as the encryption key. If not provided, a random 32-byte key will be generated.

### Running the Program

Open a command prompt or terminal window and navigate to the directory containing the compiled executable. Run the program using the following syntax:

```bash
DotNetObfuscator.exe <InputDllPath> <OutputDllPath> [EncryptionKey]

```
### Example without providing an EncryptionKey:
```bash
DotNetObfuscator.exe "C:\path\to\your\assembly.dll" "C:\path\to\save\obfuscated.dll"
```
### Example with a provided EncryptionKey:
```bash
DotNetObfuscator.exe "C:\path\to\your\assembly.dll" "C:\path\to\save\obfuscated.dll" "YourBase64KeyHere"
```

## Output
After successfully running the program, the console will display:

A message confirming the generation of a random encryption key (if no key was provided).
A completion message indicating that the obfuscation and encryption process is finished.

The output .DLL will be saved at the specified OutputDllPath. Make sure to replace the output dll with the original input dll.

## Functions Description
GenerateRandomEncryptionKey(int keyLength): Generates a random encryption key of specified length and returns it as a base64 string.
ObfuscateAndEncryptAssembly(AssemblyDefinition assembly, string encryptionKey): Processes the provided assembly, obfuscating names and encrypting string values.
EncryptString(string plainText, string encryptionKey): Encrypts strings using the ChaCha7539Engine from BouncyCastle.
