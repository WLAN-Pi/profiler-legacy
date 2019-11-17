#! /bin/bash
#
# Set file ownership & permissions correctly when copying files from Win machine 
sudo chown -R wlanpi:wlanpi /home/wlanpi/profiler
sudo chmod -R 755 /home/wlanpi/profiler/profiler.py

