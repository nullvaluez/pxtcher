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
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DotNetObfuscator
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
    public class DoNotObfuscateAttribute : Attribute
    {
    }

    class Program
    {
        static EncryptionAlgorithm currentAlgorithm = EncryptionAlgorithm.AES256GCM;

        static void Main(string[] args)
        {
            Thread detectProcessThread = new Thread(new ThreadStart(DetectProcess));
            detectProcessThread.Start();
            // tamper detection
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(Assembly.GetExecutingAssembly().Location))
                {
                    AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(Assembly.GetExecutingAssembly().Location);
                    if (!ValidateHashAndResourceCreation(stream, assembly))
                    {
                        Console.WriteLine("Validation failed.");
                        return;
                    }
                    
                    var hash = md5.ComputeHash(stream);
                    var hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    // Add the hash as a resource
                    var resource = new EmbeddedResource("MD5Hash", Mono.Cecil.ManifestResourceAttributes.Private, Encoding.UTF8.GetBytes(hashString));
                    string modifiedFilePath = "C:/Users/ByronFecho/ObfuscationTool/bin/Debug/net8.0/ObfuscationTool.dll.modified"; // Replace "path/to/modified/file.dll" with the actual file path
                    assembly.Write(modifiedFilePath);
                    EmbedHashInAssembly();
                    GetEmbeddedHash(); // This will trigger the tamper detection
                    SwitchEncryptionAlgorithm(); // Switch the encryption algorithm
                    Console.WriteLine("MD5 hash: " + hashString);
                    Console.WriteLine("Tamper detection added.");
                    Console.WriteLine($"Switched encryption to {currentAlgorithm}");

                    // Delete the intermediate file
                    File.Delete(modifiedFilePath);
                }
                
            }

            string asciiArt = @"
                _       _               
      _ ____  _| |_ ___| |__   ___ _ __ 
     | '_ \ \/ / __/ __| '_ \ / _ \ '__|
     | |_) >  <| || (__| | | |  __/ |   
     | .__/_/\_\\__\___|_| |_|\___|_|   
     |_|

     .NET Obfuscator and Encryptor by @nullvaluez
                                
            ";
            Console.WriteLine(asciiArt);
            Console.WriteLine("Please drag and drop the DLL file here and press enter:");

            string inputDllPath = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(inputDllPath))
            {
                Console.WriteLine("No DLL file provided.");
                return;
            }

            string outputDllPath = inputDllPath.Replace(".dll", "_obfuscated.dll");
            string encryptionKey = GenerateRandomEncryptionKey(32);

            try
            {
                AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(inputDllPath);
                var resourceData = Encoding.UTF8.GetBytes("This is a test resource.");
                AddEncryptedResource(assembly, "EncryptedResource", resourceData);
                ObfuscateAndEncryptAssembly(assembly, encryptionKey);
                assembly.Write(outputDllPath);
                LoadAssemblyReflectively(outputDllPath);
                Console.WriteLine("Obfuscation and encryption completed.");
                Console.WriteLine("Encryption key: " + encryptionKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error processing assembly: " + ex.Message);
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        static void EmbedHashInAssembly()
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(Assembly.GetExecutingAssembly().Location))
                {
                    var hash = sha256.ComputeHash(stream);
                    var hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(Assembly.GetExecutingAssembly().Location);
                    var resource = new EmbeddedResource("SHA256Hash", Mono.Cecil.ManifestResourceAttributes.Private, hash);
                    assembly.MainModule.Resources.Add(resource);
                    assembly.Write(Assembly.GetExecutingAssembly().Location + ".modified");
                    Console.WriteLine("SHA256 hash: " + hashString);
                }
            }
        }

        static byte[] GetEmbeddedHash()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            var resourceName = "MD5 hash";
            using (Stream resourceStream = assembly.GetManifestResourceStream(resourceName))
            {
                if (resourceStream == null) return null;
                byte[] hash = new byte[resourceStream.Length];
                resourceStream.Read(hash, 0, hash.Length);
                return hash;
            }
        }
        static bool ValidateHashAndResourceCreation(Stream stream, AssemblyDefinition assembly)
{
        using (var md5 = MD5.Create())
        {
            var hash = md5.ComputeHash(stream);
            var hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();

            // Validate the hash
            if (string.IsNullOrEmpty(hashString))
            {
                Console.WriteLine("Failed to compute MD5 hash.");
                return false;
            }

            // Validate the creation of the EmbeddedResource
            var resource = new EmbeddedResource("MD5Hash", Mono.Cecil.ManifestResourceAttributes.Private, Encoding.UTF8.GetBytes(hashString));
            if (resource == null)
            {
                Console.WriteLine("Failed to create EmbeddedResource.");
             return false;
            }

            assembly.MainModule.Resources.Add(resource);
        }

        return true;
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

                        InsertControlFlowObfuscation(method);
                        InsertOpaquePredicates(method);
                        AddAntiTamperCheck(method);
                    }
                }
            }
        }

        static void InsertControlFlowObfuscation(MethodDefinition method)
        {
            var processor = method.Body.GetILProcessor();
            var instructions = method.Body.Instructions.ToList();
            if (instructions.Count < 1)
            {
                for (int i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i].OpCode == OpCodes.Br)
                    {
                        
                        processor.InsertBefore(instructions[i], Instruction.Create(OpCodes.Br_S, instructions[i]));
                        processor.InsertBefore(instructions[i], Instruction.Create(OpCodes.Nop));
                    }
                }
            } 
        }

    static void LoadAssemblyReflectively(string assemblyPath)
    {
        byte[] assemblyData = File.ReadAllBytes(assemblyPath);
        Assembly loadedAssembly = Assembly.Load(assemblyData);
        Console.WriteLine($"Loaded {loadedAssembly.FullName} reflectively.");
    }
        public enum EncryptionAlgorithm
        {
            AES256GCM,
            AES,
            ChaCha20
        }

        static void EncryptStrings(MethodDefinition method)
        {
            var instructions = method.Body.Instructions.Where(instr => instr.OpCode == OpCodes.Ldstr).ToList();
            foreach (var instr in instructions)
            {
                string plainText = (string)instr.Operand;
                var key = GenerateRandomEncryptionKey(32);
                string encryptedText = EncryptString(plainText, key); // Encrypt using a new key each time
                instr.Operand = encryptedText;
            }
        }

        private static string EncryptString(string plainText, string encryptionKey, EncryptionAlgorithm currentAlgorithm)
        {
            throw new NotImplementedException();
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

        static void SwitchEncryptionAlgorithm()
        {
            System.Timers.Timer timer = new System.Timers.Timer(10000); // Set the interval to 10 seconds
            timer.Elapsed += (sender, e) => 
            {
                Random rng = new Random();
                currentAlgorithm = rng.Next(2) == 0 ? EncryptionAlgorithm.ChaCha20 : EncryptionAlgorithm.AES256GCM;
                Console.WriteLine($"Switched to {currentAlgorithm}");
            };
            timer.Start();
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

        static void AddAntiTamperCheck(MethodDefinition method)
        {
            var processor = method.Body.GetILProcessor();
            var instructions = method.Body.Instructions.ToList();
            if (instructions.Count < 1)
            {
                for (int i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i].OpCode == OpCodes.Br)
                    {
                        
                        processor.InsertBefore(instructions[i], Instruction.Create(OpCodes.Br_S, instructions[i]));
                        processor.InsertBefore(instructions[i], Instruction.Create(OpCodes.Nop));
                    }
                }
            } 
        }

        static void AddEncryptedResource(AssemblyDefinition assembly, string resourceName, byte[] data)
        {
            var encryptionKey = GenerateRandomEncryptionKey(32);
            var encryptedData = EncryptData(data, Convert.FromBase64String(encryptionKey));
            var encryptedResource = new EmbeddedResource(resourceName, Mono.Cecil.ManifestResourceAttributes.Private, encryptedData);
            assembly.MainModule.Resources.Add(encryptedResource);
            Console.WriteLine($"Resource {resourceName} encrypted and added.");
        }

        static byte[] EncryptData(byte[] data, byte[] key)
{
            // Using AES for simplicity here
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.GenerateIV();
                aesAlg.Mode = CipherMode.CBC;

                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                {
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(data, 0, data.Length);
                    }
                    // Prepend IV to the data
                    return aesAlg.IV.Concat(msEncrypt.ToArray()).ToArray();
                }
            }
        }
    }

        static void InsertOpaquePredicates(MethodDefinition method)
        {
            var processor = method.Body.GetILProcessor();
            var firstInstruction = method.Body.Instructions.First();

            var trueInstruction = Instruction.Create(OpCodes.Ldc_I4_1);
            var branchInstruction = Instruction.Create(OpCodes.Brtrue, firstInstruction);


            // Example of an opaque predicate
            processor.InsertBefore(firstInstruction, trueInstruction);
            processor.InsertBefore(firstInstruction, branchInstruction);
        } 

        // detect if certain .exe files are running
        static void DetectProcess()
        {
            while (true)
            {
                string[] processNames = { "ida", "ollydbg", "x64dbg", "windbg", "dbg", "cheat", "hack", "injector", "de4dot", "dnspy", "de4dot-x64", "ilspy", "dotpeek" };

                foreach (var processName in processNames)
                {

                    Process[] processes = Process.GetProcessesByName(processName);
                    if (processes.Length > 0)
                    {
                        Console.WriteLine($"Detected process: {processName}");
                        Environment.Exit(0);
                    }
                }
                 Thread.Sleep(5000);
            }
        }

        static string EncryptString(string plainText, string base64EncryptionKey)
        {
            // Encryption logic adjusted to handle polymorphic switching
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Convert.FromBase64String(base64EncryptionKey);
            byte[] iv = new byte[12];
            new Random().NextBytes(iv);
            byte[] cipherBytes = new byte[plainBytes.Length];

            Console.WriteLine($"Encrypting using {currentAlgorithm}");
            switch (currentAlgorithm)
            {
                case EncryptionAlgorithm.ChaCha20:
                    ChaCha7539Engine chacha20 = new ChaCha7539Engine();
                    ParametersWithIV chachaParams = new ParametersWithIV(new KeyParameter(keyBytes), iv);
                    chacha20.Init(true, chachaParams);
                    chacha20.ProcessBytes(plainBytes, 0, plainBytes.Length, cipherBytes, 0);
                    break;
                case EncryptionAlgorithm.AES256GCM:
                    using (var aes = new AesGcm(keyBytes))
                    {
                        aes.Encrypt(iv, plainBytes, cipherBytes, null);
                    }
                    break;
            }

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

