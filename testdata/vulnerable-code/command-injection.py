# Command injection vulnerability example
import os
import subprocess

def ping_host(hostname):
    # Vulnerable: command injection
    os.system("ping -c 1 " + hostname)

def list_files(directory):
    # Vulnerable: command injection
    subprocess.call("ls " + directory, shell=True)

def ping_host_safe(hostname):
    # Safe: no shell, parameterized
    subprocess.run(["ping", "-c", "1", hostname], shell=False)
