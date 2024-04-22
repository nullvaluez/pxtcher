using Mono.Cecil;
using Mono.Cecil.Cil;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Reflection;

namespace DotNetObfuscator
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting obfuscation of all DLLs in the publish folder...");
            
           // Define the directory path where the DLLs are located.
            string directoryPath = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..\\..\\..\\Release\\net6.0\\win-x64"));

            // Process all DLL files in the specified directory.
            ProcessDirectory(directoryPath);

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey(); // Waits for a key press before closing
        }

static void ProcessDirectory(string directoryPath)
{
    string targetFile = Path.Combine(directoryPath, "DotNetObfuscatorAppCopy.dll");

    if (File.Exists(targetFile))
    {
        ProcessSingleFile(targetFile);
    }
    else
    {
        Console.WriteLine($"Error: The target file {targetFile} does not exist.");
    }
}

static void ProcessSingleFile(string filePath)
{
    if (!File.Exists(filePath))
    {
        Console.WriteLine($"Error: The file {filePath} does not exist.");
        return;
    }

    if (!IsValidDotNetAssembly(filePath))
    {
        Console.WriteLine("Error: The file is not a valid .NET assembly.");
        return;
    }

    // Only process DotNetObfuscatorApp.dll
    if (Path.GetFileName(filePath) != "DotNetObfuscatorApp.dll")
    {
        return;
    }

    try
    {
        var obfuscator = new ObfuscationEngine();
        obfuscator.Obfuscate(filePath);
        Console.WriteLine($"Obfuscation completed successfully for: {filePath}");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Error during obfuscation of {filePath}: {ex.Message}");
    }
}

        static bool IsValidDotNetAssembly(string filePath)
        {
            try
            {
                AssemblyDefinition.ReadAssembly(filePath, new ReaderParameters { InMemory = true });
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    public class ObfuscationEngine
    {
        private readonly byte[] key = Encoding.UTF8.GetBytes(GenerateRandomBytes(32));
        private readonly HashSet<string> usedNames = new HashSet<string>();

        public void Obfuscate(string filePath)
        {
            var assembly = AssemblyDefinition.ReadAssembly(filePath, new ReaderParameters { ReadWrite = true });
            RenameSymbols(assembly);
            EncryptStrings(assembly);
            assembly.Write(filePath.Replace(".dll", "_obfuscated.dll"));
        }

       private void RenameSymbols(AssemblyDefinition assembly)
    {
        foreach (var type in assembly.MainModule.Types)
        {
            if (!type.IsPublic)
            {
                type.Name = GenerateUniqueName();
            }

            foreach (var method in type.Methods)
            {
                method.Name = GenerateUniqueName();
            }

            foreach (var field in type.Fields)
            {
                field.Name = GenerateUniqueName();
            }
        }
    }

    private string GenerateUniqueName()
    {
        string name;
        do
        {
            name = GenerateRandomName();
        } while (usedNames.Contains(name));

        usedNames.Add(name);
        return name;
    }

        private MethodReference AddDecryptMethod(ModuleDefinition module)
        {
            var decryptMethod = new MethodDefinition(
                "DecryptString",
                Mono.Cecil.MethodAttributes.Static | Mono.Cecil.MethodAttributes.Public,
                module.ImportReference(typeof(string))
            );

            var param = new ParameterDefinition("cipherText", Mono.Cecil.ParameterAttributes.None, module.ImportReference(typeof(string)));
            decryptMethod.Parameters.Add(param);

            var il = decryptMethod.Body.GetILProcessor();
            il.Append(Instruction.Create(OpCodes.Ldarg_0));

            var decryptorMethod = typeof(AesHelper).GetMethod("Decrypt");
            il.Append(Instruction.Create(OpCodes.Call, module.ImportReference(decryptorMethod)));
            il.Append(Instruction.Create(OpCodes.Ret));

            module.Types[0].Methods.Add(decryptMethod);
            return module.ImportReference(decryptMethod);
        }

        private void EncryptStrings(AssemblyDefinition assembly)
        {
            var decryptRef = AddDecryptMethod(assembly.MainModule);

            foreach (var type in assembly.MainModule.Types)
            {
                foreach (var method in type.Methods)
                {
                    for (int i = 0; i < method.Body.Instructions.Count; i++)
                    {
                        var instruction = method.Body.Instructions[i];
                        if (instruction.OpCode == Mono.Cecil.Cil.OpCodes.Ldstr)
                        {
                            string originalString = (string)instruction.Operand;
                            var encryptedString = EncryptString(originalString);
                            instruction.OpCode = Mono.Cecil.Cil.OpCodes.Ldstr;
                            instruction.Operand = encryptedString;
                            var ilProcessor = method.Body.GetILProcessor();
                            ilProcessor.InsertAfter(instruction, Instruction.Create(OpCodes.Call, decryptRef));
                        }
                    }
                }
            }
        }

        private string EncryptString(string input)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] encryptedBytes = AesHelper.Encrypt(inputBytes, key);
            return Convert.ToBase64String(encryptedBytes);
        }

        private static string GenerateRandomName()
        {
            return Guid.NewGuid().ToString("N");
        }

        private static string GenerateRandomBytes(int length)
        {
            var randomBytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return BitConverter.ToString(randomBytes).Replace("-", "");
        }
    }

    public static class AesHelper
    {
        public static byte[] Encrypt(byte[] input, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (var memoryStream = new MemoryStream())
                {
                    memoryStream.Write(aes.IV, 0, aes.IV.Length);
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(input, 0, input.Length);
                    }
                    return memoryStream.ToArray();
                }
            }
        }

        public static byte[] Decrypt(byte[] input, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                byte[] iv = new byte[aes.BlockSize / 8];
                Array.Copy(input, iv, iv.Length);
                aes.IV = iv;
                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var memoryStream = new MemoryStream(input, iv.Length, input.Length - iv.Length))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                {
                    byte[] result = new byte[input.Length];
                    int bytesRead = cryptoStream.Read(result, 0, result.Length);
                    Array.Resize(ref result, bytesRead);
                    return result;
                }
            }
        }

        public static string Decrypt(string cipherText, byte[] key)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            byte[] decryptedBytes = Decrypt(cipherBytes, key);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}