using System;

namespace DotNetObfuscator
{
    public class CLIHandler
    {
        private string[] args;

        public CLIHandler(string[] args)
        {
            this.args = args;
        }

        public void Execute()
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "--help")
            {
                ShowHelp();
                return;
            }

            if (args.Length < 1)
            {
                Console.WriteLine("Error: No assembly path provided.");
                ShowHelp();
                return;
            }

            string assemblyPath = args[0];
            try
            {
                var obfuscator = new ObfuscationEngine();
                obfuscator.Obfuscate(assemblyPath);
                Console.WriteLine($"Obfuscation completed successfully. Output file: {assemblyPath.Replace(".dll", "_obfuscated.dll")}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error during obfuscation: {ex.Message}");
            }
        }

        private void ShowHelp()
        {
            Console.WriteLine("Usage: DotNetObfuscator <assemblyPath>");
            Console.WriteLine("Options:");
            Console.WriteLine("  -h, --help       Show this help message and exit.");
            Console.WriteLine(" -v, --version    Show version information and exit.");
            // Additional help info can be added here.
        }
    }
}
