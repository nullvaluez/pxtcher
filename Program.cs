using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Timers;
using System.Runtime.InteropServices;
using System.Management;

namespace DotNetObfuscator
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
    public class DoNotObfuscateAttribute : Attribute
    {
    }

    public class Program
    {
        static EncryptionAlgorithm currentAlgorithm = EncryptionAlgorithm.AES256GCM;
        static System.Timers.Timer? encryptionAlgorithmTimer;

        static void Main(string[] args)
        {
            EnsureSingleInstance();
            StartProcessDetection();
            PerformTamperDetection();
            DisplayWelcomeMessage();
            

            // Run Environment Checks and Anti-Debugging in separate threads
            Thread environmentCheckThread = new Thread(new ThreadStart(EnvironmentChecks))
            {
                IsBackground = true
            };
            environmentCheckThread.Start();

            Thread antiDebuggingThread = new Thread(new ThreadStart(AntiDebugging))
            {
                IsBackground = true
            };
            antiDebuggingThread.Start();

            Thread memoryCheckThread = new Thread(new ThreadStart(MemoryScanning))
            {
                IsBackground = true
            };

            Console.WriteLine("Please drag and drop the DLL file here and press enter:");

            string inputDllPath = Console.ReadLine()?.Trim('"');
            if (string.IsNullOrWhiteSpace(inputDllPath) || !File.Exists(inputDllPath))
            {
                Console.WriteLine("No valid DLL file provided.");
                return;
            }

            string outputDllPath = GenerateSafeOutputPath(inputDllPath);
            string encryptionKey = GenerateRandomEncryptionKey(32) ?? string.Empty;

            ProcessAssembly(inputDllPath, outputDllPath, encryptionKey);

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();

            // Cleanup
            encryptionAlgorithmTimer?.Stop();
            encryptionAlgorithmTimer?.Dispose();
            Environment.Exit(0);
        }

        static void EnsureSingleInstance()
        {
            var current = Process.GetCurrentProcess();
            foreach (var process in Process.GetProcessesByName(current.ProcessName))
            {
                if (process.Id != current.Id)
                {
                    process.Kill();
                }
            }
        }

        static void StartProcessDetection()
        {
            Thread detectProcessThread = new Thread(new ThreadStart(DetectProcess))
            {
                IsBackground = true
            };
            detectProcessThread.Start();
        }

        static void PerformTamperDetection()
        {
            using (var md5 = MD5.Create())
            using (var stream = File.OpenRead(Assembly.GetExecutingAssembly().Location))
            {
                AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(Assembly.GetExecutingAssembly().Location);
                if (!ValidateHashAndResourceCreation(stream, assembly))
                {
                    Console.WriteLine("Validation failed.");
                    return;
                }

                var hashString = ComputeMd5Hash(md5, stream);
                AddMd5HashResource(assembly, hashString);
                string modifiedFilePath = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "ObfuscationTool.dll.modified");
                assembly.Write(modifiedFilePath);

                EmbedHashInAssembly();
                GetEmbeddedHash();
                SwitchEncryptionAlgorithm();
                

                Console.WriteLine($"MD5 hash: {hashString}");
                Console.WriteLine("Tamper detection added.");
                Console.WriteLine("Mutex acquired.");
                Console.WriteLine($"Switched encryption to {currentAlgorithm}");

                File.Delete(modifiedFilePath);
            }
        }

        static string ComputeMd5Hash(MD5 md5, Stream stream)
        {
            var hash = md5.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        static void AddMd5HashResource(AssemblyDefinition assembly, string hashString)
        {
            var resource = new EmbeddedResource("MD5Hash", Mono.Cecil.ManifestResourceAttributes.Private, Encoding.UTF8.GetBytes(hashString));
            assembly.MainModule.Resources.Add(resource);
        }

        static void DisplayWelcomeMessage()
        {
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
        }

        static string GenerateSafeOutputPath(string inputDllPath)
        {
            string directory = Path.GetDirectoryName(inputDllPath) ?? string.Empty;
            string fileName = Path.GetFileNameWithoutExtension(inputDllPath) + "_new.dll";
            return Path.Combine(directory, fileName);
        }

        static void ProcessAssembly(string inputDllPath, string outputDllPath, string encryptionKey)
        {
            try
            {
                AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(inputDllPath);
                AddEncryptedResource(assembly, "EncryptedResource", Encoding.UTF8.GetBytes("This is a test resource."));
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
        }

        static void EmbedHashInAssembly()
        {
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(Assembly.GetExecutingAssembly().Location))
            {
                var hash = sha256.ComputeHash(stream);
                var hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(Assembly.GetExecutingAssembly().Location);
                var resource = new EmbeddedResource("SHA256Hash", Mono.Cecil.ManifestResourceAttributes.Private, hash);
                assembly.MainModule.Resources.Add(resource);
                string modifiedFilePath = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "ObfuscationTool.dll.modified");
                assembly.Write(modifiedFilePath);

                Console.WriteLine("SHA256 hash: " + hashString);
            }
        }

        static byte[]? GetEmbeddedHash()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            var resourceName = "MD5Hash";
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
                var hashString = ComputeMd5Hash(md5, stream);

                if (string.IsNullOrEmpty(hashString))
                {
                    Console.WriteLine("Failed to compute MD5 hash.");
                    return false;
                }

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

        public static string? GenerateRandomEncryptionKey(int keySize)
        {
            try
            {
                byte[] key = new byte[keySize];
                RandomNumberGenerator.Fill(key);
                return Convert.ToBase64String(key);
            }
            catch (CryptographicException ex)
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
                            method.Name = GenerateObfuscatedName();

                        InsertControlFlowObfuscation(method);
                        InsertOpaquePredicates(method);
                        AddAntiTamperCheck(method);
                        EncryptStrings(type);
                       
                    }
                }
            }
        }

        static void InsertControlFlowObfuscation(MethodDefinition method)
        {
            var processor = method.Body.GetILProcessor();
            var instructions = method.Body.Instructions.ToList();

            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode == OpCodes.Br)
                {
                    processor.InsertBefore(instructions[i], Instruction.Create(OpCodes.Br_S, instructions[i]));
                    processor.InsertBefore(instructions[i], Instruction.Create(OpCodes.Nop));
                }
            }
        }

        static void InsertOpaquePredicates(MethodDefinition method)
        {
            var processor = method.Body.GetILProcessor();
            var firstInstruction = method.Body.Instructions.First();

            var trueInstruction = Instruction.Create(OpCodes.Ldc_I4_1);
            var branchInstruction = Instruction.Create(OpCodes.Brtrue, firstInstruction);

            processor.InsertBefore(firstInstruction, trueInstruction);
            processor.InsertBefore(firstInstruction, branchInstruction);
        }

        static void AddAntiTamperCheck(MethodDefinition method)
        {
            var processor = method.Body.GetILProcessor();
            var instructions = method.Body.Instructions.ToList();

            for (int i = 0; i < instructions.Count; i++)
            {
                if (instructions[i].OpCode == OpCodes.Br)
                {
                    processor.InsertBefore(instructions[i], Instruction.Create(OpCodes.Br_S, instructions[i]));
                    processor.InsertBefore(instructions[i], Instruction.Create(OpCodes.Nop));
                }
            }
        }

        static void AddEncryptedResource(AssemblyDefinition assembly, string resourceName, byte[] data)
        {
            var encryptionKey = GenerateRandomEncryptionKey(32) ?? string.Empty;
            var encryptedData = EncryptData(data, Convert.FromBase64String(encryptionKey));
            var encryptedResource = new EmbeddedResource(resourceName, Mono.Cecil.ManifestResourceAttributes.Private, encryptedData);
            assembly.MainModule.Resources.Add(encryptedResource);
            Console.WriteLine($"Resource {resourceName} encrypted and added.");
        }

        static byte[] EncryptData(byte[] data, byte[] key)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.GenerateIV();
                aesAlg.Mode = CipherMode.CBC;

                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(data, 0, data.Length);
                    }

                    return aesAlg.IV.Concat(msEncrypt.ToArray()).ToArray();
                }
            }
        }

        static void LoadAssemblyReflectively(string assemblyPath)
        {
            byte[] assemblyData = File.ReadAllBytes(assemblyPath);
            Assembly loadedAssembly = Assembly.Load(assemblyData);
            Console.WriteLine($"Loaded {loadedAssembly.FullName} reflectively.");
        }

        static void SwitchEncryptionAlgorithm()
        {
            encryptionAlgorithmTimer = new System.Timers.Timer(10000);
            encryptionAlgorithmTimer.Elapsed += (sender, e) =>
            {
                Random rng = new Random();
                currentAlgorithm = rng.Next(2) == 0 ? EncryptionAlgorithm.ChaCha20 : EncryptionAlgorithm.AES256GCM;
                Console.WriteLine($"Switched to {currentAlgorithm}");
            };
            encryptionAlgorithmTimer.Start();
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

        static void DetectProcess()
        {
            while (true)
            {
                string[] processNames = { "ida", "ollydbg", "x64dbg", "windbg", "dbg", "cheat", "hack", "injector", "de4dot", "dnspy", "de4dot-x64", "ilspy", "dotpeek", "dotpeek64" };

                foreach (var processName in processNames)
                {
                    if (Process.GetProcessesByName(processName).Length > 0)
                    {
                        Console.WriteLine($"Detected process: {processName}");
                        Environment.Exit(0);
                    }
                }
                Thread.Sleep(5000);
            }
        }

        public static void EncryptStrings(TypeDefinition type)
        {
            foreach (var field in type.Fields)
            {
                if (field.IsPublic && field.FieldType.FullName == "System.String")
                {
                    string plainText = (string)field.Constant;
                    var key = GenerateRandomEncryptionKey(32) ?? string.Empty;
                    string encryptedText = EncryptString(plainText, key);
                    field.Constant = encryptedText;
                }
            }

            foreach (var property in type.Properties)
            {
                if (property.GetMethod.IsPublic && property.PropertyType.FullName == "System.String")
                {
                    // This assumes that the property has a backing field
                    string plainText = (string)property.GetMethod.Body.Instructions
                        .First(instr => instr.OpCode == OpCodes.Ldstr).Operand;
                    var key = GenerateRandomEncryptionKey(32) ?? string.Empty;
                    string encryptedText = EncryptString(plainText, key);
                    property.GetMethod.Body.Instructions
                        .First(instr => instr.OpCode == OpCodes.Ldstr).Operand = encryptedText;
                }
            }
        }

        static string EncryptString(string plainText, string base64EncryptionKey)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Convert.FromBase64String(base64EncryptionKey);
            byte[] iv = new byte[12];
            new Random().NextBytes(iv);
            byte[] cipherBytes = new byte[plainBytes.Length];
            byte[] tag = new byte[16];

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
                        aes.Encrypt(iv, plainBytes, cipherBytes, tag);
                    }
                    break;
            }

            return $"{Convert.ToBase64String(iv)}:{Convert.ToBase64String(cipherBytes)}:{Convert.ToBase64String(tag)}";
        }

        public static string DecryptString(string encryptedText, string base64EncryptionKey)
        {
            string[] parts = encryptedText.Split(':');
            byte[] iv = Convert.FromBase64String(parts[0]);
            byte[] cipherBytes = Convert.FromBase64String(parts[1]);
            byte[] keyBytes = Convert.FromBase64String(base64EncryptionKey);
            byte[] tag = Convert.FromBase64String(parts[2]);

            byte[] plainBytes = new byte[cipherBytes.Length];

            switch (currentAlgorithm)
            {
                case EncryptionAlgorithm.ChaCha20:
                    ChaCha7539Engine chacha20 = new ChaCha7539Engine();
                    ParametersWithIV chachaParams = new ParametersWithIV(new KeyParameter(keyBytes), iv);
                    chacha20.Init(false, chachaParams);
                    chacha20.ProcessBytes(cipherBytes, 0, cipherBytes.Length, plainBytes, 0);
                    break;
                case EncryptionAlgorithm.AES256GCM:
                    using (var aes = new AesGcm(keyBytes))
                    {
                        aes.Decrypt(iv, cipherBytes, tag, plainBytes);
                    }
                    break;
            }

            return Encoding.UTF8.GetString(plainBytes);
        }

        public enum EncryptionAlgorithm
        {
            AES256GCM,
            AES,
            ChaCha20
        }

        // Anti-Debugging Techniques
        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        private static void AntiDebugging()
        {
            try
            {
                if (IsDebuggerPresent())
                {
                    Console.WriteLine("Debugger detected!");
                    Environment.Exit(0);
                }

                while (true)
                {
                    if (Debugger.IsAttached)
                    {
                        Console.WriteLine("Debugger attached!");
                        Environment.Exit(0);
                    }
                    Thread.Sleep(1000);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("AntiDebugging error: " + ex.Message);
            }
        }

        // Environment Checks
        private static void EnvironmentChecks()
        {
            try
            {
                if (IsRunningInVirtualMachine())
                {
                    Console.WriteLine("Running in a virtual machine!");
                    Environment.Exit(0);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("EnvironmentChecks error: " + ex.Message);
            }
        }

        // Memory Scanning
        static void MemoryScanning()
        {
            while (true)
            {
                var suspiciousPatterns = new List<byte[]> 
                {
                    new byte[] { 0x90, 0x90, 0x90 }, // NOP sleds, commonly found in shellcode
                    new byte[] { 0xCC, 0xCC, 0xCC }  // INT3 instructions, used by debuggers
                };

                foreach (var pattern in suspiciousPatterns)
                {
                    if (ScanMemory(pattern))
                    {
                        Console.WriteLine("Suspicious memory pattern detected!");
                        Environment.Exit(0);
                    }
                }

                Thread.Sleep(5000);
            }
        }

        static bool ScanMemory(byte[] pattern)
        {
            // Implementation of memory scanning based on pattern
            // This is platform-specific and requires advanced knowledge of memory management
            return false;
        }

        private static bool IsRunningInVirtualMachine()
        {
            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
            {
                foreach (var item in searcher.Get())
                {
                    string manufacturer = item["Manufacturer"].ToString().ToLower();
                    if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL"))
                        || manufacturer.Contains("vmware")
                        || item["Model"].ToString() == "VirtualBox")
                    {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
