import subprocess
import sys
import os
import os.path
import distutils

def main():
    # Path to the .NET executable
    exe_path = os.path.join(os.path.dirname(__file__), 'bin', 'release', 'ObfuscationTool.exe')
    
    # Call the .NET executable with forwarded arguments
    subprocess.run([exe_path] + sys.argv[1:])

if __name__ == "__main__":
    main()
