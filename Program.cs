using System;
using System.IO;
using System.Linq;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Reflection;
using System.Security.Cryptography;

namespace DotNetObfuscator
{
    class Program
    {
        static void Main(string[] args)
        {
            string inputDllPath = args[0];
            string outputDllPath = args[1];
            string encryptionKey;
            if (args.Length == 3)
            {
                encryptionKey = args[2];
            }
            else
            {
                encryptionKey = GenerateRandomEncryptionKey(32); // Generate a 32-byte key
                Console.WriteLine($"Generated random encryption key: {encryptionKey}");
            }
            // Load the input assembly
            AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(inputDllPath);
            // Obfuscate and encrypt the assembly
            ObfuscateAndEncryptAssembly(assembly, encryptionKey);
            // Save the obfuscated and encrypted assembly
            assembly.Write(outputDllPath);
            Console.WriteLine("Obfuscation and encryption completed.");
        }

        public static string GenerateRandomEncryptionKey(int keySize)
        {
            using(var rng = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[keySize];
                rng.GetBytes(key);
                return Convert.ToBase64String(key); // Return the key as a base64 string
            }
        }

        static void ObfuscateAndEncryptAssembly(AssemblyDefinition assembly, string encryptionKey)
        {
            foreach (var type in assembly.MainModule.Types)
            {
                foreach (var method in type.Methods)
                {
                    if (method.HasBody)
                    {
                        // Obfuscate method names and parameters
                        if (!method.IsPublic)
                        {
                            method.Name = GenerateObfuscatedName();
                        }
                        // Control flow obfuscation: Insert dummy operations
                        InsertDummyOperations(method);
                        // Encrypt strings and other literals
                        EncryptStrings(method, encryptionKey);
                        // Add Dynamic Proxies
                        AddDynamicProxy(method, assembly, encryptionKey);
                    }
                }
            }
        }

        static void InsertDummyOperations(MethodDefinition method)
        {
            var processor = method.Body.GetILProcessor();
            // Create a list to store the points at which to insert the NOP instructions
            var pointsToInsert = method.Body.Instructions.ToList(); // Copy all instructions to a new list

            foreach (var instruction in pointsToInsert)
            {
            // Insert NOP before each instruction in the original list
            processor.InsertBefore(instruction, Instruction.Create(OpCodes.Nop));
            }
        }

        static void EncryptStrings(MethodDefinition method, string encryptionKey)
        {
            var instructionsCopy = method.Body.Instructions.ToList(); // Create a copy of the instructions to avoid collection modification issues
            foreach (var instr in instructionsCopy)
            {
                if (instr.OpCode == OpCodes.Ldstr)
                {
                    string plainText = (string)instr.Operand;
                    string encryptedText = EncryptString(plainText, encryptionKey);
                    method.Body.Instructions.First(i => i == instr).Operand = encryptedText; // Modify the original collection
                }
            }
        }

        static void AddDynamicProxy(MethodDefinition originalMethod, AssemblyDefinition assembly, string encryptionKey)
        {
            var proxyMethodName = "Proxy_" + GenerateObfuscatedName();
            var proxyMethod = new MethodDefinition(proxyMethodName, Mono.Cecil.MethodAttributes.Public | Mono.Cecil.MethodAttributes.Static, originalMethod.ReturnType);
        }

        static string GenerateObfuscatedName()
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            byte[] randomBytes = new byte[10];
            using(var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return new string(randomBytes.Select(b => chars[b % chars.Length]).ToArray());
        }

        static string EncryptString(string plainText, string base64EncryptionKey)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Convert.FromBase64String(base64EncryptionKey); // Ensure this is exactly 32 bytes
            if (keyBytes.Length != 32)
            {
                throw new ArgumentException("Key must be exactly 32 bytes (256 bits) long.");
            }
            byte[] iv = new byte[12]; // ChaCha20 uses a 12-byte IV
            using(var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            ChaCha7539Engine chacha20 = new ChaCha7539Engine();
            ParametersWithIV chachaParams = new ParametersWithIV(new KeyParameter(keyBytes), iv);
            chacha20.Init(true, chachaParams);
            byte[] cipherBytes = new byte[plainBytes.Length];
            chacha20.ProcessBytes(plainBytes, 0, plainBytes.Length, cipherBytes, 0);
            return Convert.ToBase64String(iv) + ":" + Convert.ToBase64String(cipherBytes);
        }

        public static string DecryptString(string encryptedText)
        {
            // Split the encrypted text into the IV and the cipher text
            string[] parts = encryptedText.Split(':');
            byte[] iv = Convert.FromBase64String(parts[0]);
            byte[] cipherBytes = Convert.FromBase64String(parts[1]);

            byte[] keyBytes = Convert.FromBase64String(parts[1]); // Mock keyBytes for placeholder

            ChaCha7539Engine chacha20 = new ChaCha7539Engine();
            ParametersWithIV chachaParams = new ParametersWithIV(new KeyParameter(keyBytes), iv);
            chacha20.Init(false, chachaParams); // false for decryption
            byte[] plainBytes = new byte[cipherBytes.Length];
            chacha20.ProcessBytes(cipherBytes, 0, cipherBytes.Length, plainBytes, 0);

            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}
