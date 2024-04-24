using System;
using System.IO;
using System.Linq;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;
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
            foreach(var type in assembly.MainModule.Types)
            {
                foreach(var method in type.Methods)
                {
                    if (method.HasBody)
                    {
                        // Obfuscate method names and parameters
                        if (!method.IsPublic)
                        {
                            method.Name = GenerateObfuscatedName();
                        }
                        // Control flow obfuscation: Insert dummy operations
                        var processor = method.Body.GetILProcessor();
                        var instructions = method.Body.Instructions.ToList();
                        for (int i = 0; i < instructions.Count; i++)
                        {
                            processor.InsertBefore(instructions[i], Mono.Cecil.Cil.Instruction.Create(Mono.Cecil.Cil.OpCodes.Nop));
                        }
                        // Encrypt strings and other literals
                        for (int i = 0; i < method.Body.Instructions.Count; i++)
                        {
                            var instr = method.Body.Instructions[i];
                            if (instr.OpCode == Mono.Cecil.Cil.OpCodes.Ldstr)
                            {
                                string plainText = (string) instr.Operand;
                                string encryptedText = EncryptString(plainText, encryptionKey);
                                instr.Operand = encryptedText;
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
            // Check the key length
            if (keyBytes.Length != 32)
            {
                throw new ArgumentException("Key must be exactly 32 bytes (256 bits) long.");
            }
            // Generate a random IV
            byte[] iv = new byte[12]; // ChaCha20 uses a 12-byte IV
            using(var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
            // Use ChaCha20 for encryption
            ChaCha7539Engine chacha20 = new ChaCha7539Engine();
            ParametersWithIV chachaParams = new ParametersWithIV(new KeyParameter(keyBytes), iv);
            chacha20.Init(true, chachaParams);
            byte[] cipherBytes = new byte[plainBytes.Length];
            chacha20.ProcessBytes(plainBytes, 0, plainBytes.Length, cipherBytes, 0);
            // Return the encrypted string as a base64 string, along with the IV
            return Convert.ToBase64String(iv) + ":" + Convert.ToBase64String(cipherBytes);
        }
    }
}
