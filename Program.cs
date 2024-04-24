using System;
using System.IO;
using System.Linq;
using System.Text;
using Mono.Cecil;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Reflection.Emit;
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

        public static string GenerateRandomEncryptionKey(int keyLength)
        {
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] key = new byte[keyLength];
                rng.GetBytes(key);
                return Convert.ToBase64String(key); // Return the key as a base64 string
            }
        }

        static void ObfuscateAndEncryptAssembly(AssemblyDefinition assembly, string encryptionKey)
        {
            // Obfuscate types
            foreach (var type in assembly.MainModule.Types)
            {
                if (!type.IsPublic)
                {
                    type.Name = GenerateObfuscatedName();
                }

                // Obfuscate methods
                foreach (var method in type.Methods)
                {
                    if (!method.IsPublic)
                    {
                        method.Name = GenerateObfuscatedName();
                    }
                }

                // Obfuscate fields
                foreach (var field in type.Fields)
                {
                    if (!field.IsPublic)
                    {
                        field.Name = GenerateObfuscatedName();
                    }
                }
            }

            // Encrypt strings
            foreach (var type in assembly.MainModule.Types)
            {
                foreach (var method in type.Methods)
                {
                    if (method.Body != null)
                    {
                        for (int i = 0; i < method.Body.Instructions.Count; i++)
                        {
                            if (method.Body.Instructions[i].OpCode.Equals(OpCodes.Ldstr))
                            {
                                string plainText = (string)method.Body.Instructions[i].Operand;
                                string encryptedText = EncryptString(plainText, encryptionKey);
                                method.Body.Instructions[i].Operand = encryptedText;
                            }
                        }
                    }
                }
            }
        }

        static string GenerateObfuscatedName()
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            byte[] randomBytes = new byte[10];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return new string(randomBytes.Select(b => chars[b % chars.Length]).ToArray());
        }
        static string EncryptString(string plainText, string encryptionKey)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(encryptionKey);

            // Use ChaCha20 for encryption
            ChaCha7539Engine chacha20 = new ChaCha7539Engine();
            KeyParameter chachaKey = new KeyParameter(keyBytes);
            chacha20.Init(true, chachaKey);
            byte[] cipherBytes = new byte[plainBytes.Length];
            chacha20.ProcessBytes(plainBytes, 0, plainBytes.Length, cipherBytes, 0);
            return Convert.ToBase64String(cipherBytes); // Return the encrypted string as a base64 string
        }

    }
}
