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
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
    public class DoNotObfuscateAttribute : Attribute
    {
    }

    class Program
    {
        static void Main(string[] args)
        {
            string asciiArt = @"
                _       _               
      _ ____  _| |_ ___| |__   ___ _ __ 
     | '_ \ \/ / __/ __| '_ \ / _ \ '__|
     | |_) >  <| || (__| | | |  __/ |   
     | .__/_/\_\\__\___|_| |_|\___|_|   
     |_|                                
            ";
            Console.WriteLine(asciiArt);
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: DotNetObfuscator <inputDllPath> <outputDllPath> [encryptionKey]");
                return;
            }

            string inputDllPath = args[0];
            string outputDllPath = args[1];
            string encryptionKey = args.Length > 2 ? args[2] : GenerateRandomEncryptionKey(32);

            try
            {
                AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(inputDllPath);
                ObfuscateAndEncryptAssembly(assembly, encryptionKey);
                assembly.Write(outputDllPath);
                Console.WriteLine("Obfuscation and encryption completed.");
                Console.WriteLine("Encryption key: " + encryptionKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error processing assembly: " + ex.Message);
            }
        }

        public static string GenerateRandomEncryptionKey(int keySize)
        {
            try
            {
                byte[] key = new byte[keySize];
                RandomNumberGenerator.Fill(key);
                return Convert.ToBase64String(key);
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                Console.WriteLine("Cryptographic error: " + ex.Message);
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to generate encryption key: " + ex.Message);
                return null;
            }
        }

        static void ObfuscateAndEncryptAssembly(AssemblyDefinition assembly, string encryptionKey)
        {
            foreach (var type in assembly.MainModule.Types)
            {
                if (type.CustomAttributes.Any(attr => attr.AttributeType.Name == "DoNotObfuscateAttribute"))
                    continue;

                foreach (var method in type.Methods)
                {
                    if (method.HasBody && !method.CustomAttributes.Any(attr => attr.AttributeType.Name == "DoNotObfuscateAttribute"))
                    {
                        if (!method.IsPublic)
                        {
                            method.Name = GenerateObfuscatedName();
                        }
                    }
                }
            }
        }

        static void InsertDummyOperations(MethodDefinition method)
        {
            var processor = method.Body.GetILProcessor();
            Instruction last = method.Body.Instructions.Last();
            // Insert NOP only at safe points (e.g., before returns or after calls)
            foreach (var instruction in method.Body.Instructions.ToList())
            {
                if (instruction.OpCode == OpCodes.Ret || instruction.OpCode == OpCodes.Call)
                {
                    processor.InsertBefore(instruction, Instruction.Create(OpCodes.Nop));
                }
            }
        }

        static void EncryptStrings(MethodDefinition method, string encryptionKey)
        {
            var instructionsCopy = method.Body.Instructions.ToList(); // Create a copy of the instructions
            foreach (var instr in instructionsCopy)
            {
                if (instr.OpCode == OpCodes.Ldstr)
                {
                    string plainText = (string)instr.Operand;
                    string encryptedText = EncryptString(plainText, encryptionKey);
                    method.Body.Instructions.First(i => i == instr).Operand = encryptedText;
                }
            }
        }

        static void AddDynamicProxy(MethodDefinition originalMethod, AssemblyDefinition assembly, string encryptionKey)
        {
            if (!originalMethod.IsPublic) return; // Only add proxies to public methods to avoid issues with access levels

            var proxyMethodName = "Proxy_" + GenerateObfuscatedName();
            var proxyMethod = new MethodDefinition(proxyMethodName, Mono.Cecil.MethodAttributes.Public | Mono.Cecil.MethodAttributes.Static, originalMethod.ReturnType);

            foreach (var parameter in originalMethod.Parameters)
            {
                proxyMethod.Parameters.Add(new ParameterDefinition(parameter.ParameterType));
            }

            var proxyMethodBody = proxyMethod.Body;
            var proxyMethodProcessor = proxyMethodBody.GetILProcessor();

            // Forward all parameters to the original method
            for (int i = 0; i < originalMethod.Parameters.Count; i++)
            {
                proxyMethodProcessor.Emit(OpCodes.Ldarg, i);
            }

            // Call the original method
            proxyMethodProcessor.Emit(OpCodes.Call, originalMethod);
            proxyMethodProcessor.Emit(OpCodes.Ret);

            originalMethod.DeclaringType.Methods.Add(proxyMethod);
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

        static string EncryptString(string plainText, string base64EncryptionKey)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Convert.FromBase64String(base64EncryptionKey);
            if (keyBytes.Length != 32)
            {
                throw new ArgumentException("Key must be exactly 32 bytes (256 bits) long.");
            }
            byte[] iv = new byte[12];
            using (var rng = RandomNumberGenerator.Create())
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

        public static string DecryptString(string encryptedText, string base64EncryptionKey)
        {
            // Split the encrypted text into the IV and the cipher text
            string[] parts = encryptedText.Split(':');
            byte[] iv = Convert.FromBase64String(parts[0]);
            byte[] cipherBytes = Convert.FromBase64String(parts[1]);

            byte[] keyBytes = Convert.FromBase64String(base64EncryptionKey); // Use the provided encryption key

            ChaCha7539Engine chacha20 = new ChaCha7539Engine();
            ParametersWithIV chachaParams = new ParametersWithIV(new KeyParameter(keyBytes), iv);
            chacha20.Init(false, chachaParams); // false for decryption
            byte[] plainBytes = new byte[cipherBytes.Length];
            chacha20.ProcessBytes(cipherBytes, 0, cipherBytes.Length, plainBytes, 0);

            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}
