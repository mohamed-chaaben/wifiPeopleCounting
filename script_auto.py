import time
import subprocess

launch_interval = 300

while True:
    subprocess.run(['sudo', 'python3', 'sniffing_v2.py'])
    time.sleep(launch_interval)



