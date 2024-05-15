import subprocess
import sys
import os

# Path to your executable
exe_path = os.path.join(os.path.dirname(__file__), "path_to_your.exe")

# Function to launch the executable
def launch_exe():
    try:
        subprocess.run([exe_path] + sys.argv[1:], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error launching executable: {e}")
        sys.exit(1)

if __name__ == "__main__":
    launch_exe()
