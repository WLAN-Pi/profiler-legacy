# This project has been deprecated and it is being replaced by [profiler](https://github.com/WLAN-Pi/profiler)

---

# Profiler-legacy

A Python script to check wireless (802.11) capabilities based on association request frame contents. It has been developed to be specifically used with the WLAN Pi platform. 

The script performs two functions:

- Create a "fake" access point that will broadcast an SSID of your choosing
- As clients attempt to join the SSID broadcast by the fake AP, it will analyze the association frames generated by clients to determine their 802.11 capabilities.

Understanding client capabilities is an important aspect of Wireless LAN design. It helps a network designer understand the features that may be enabled on a WLAN to optimize the design.

The capabilities supported by each client type may vary enormously, depending on factors such as the client wireless chipset, number of antennas, age of the client etc. Each client supplies details of its capabilities as it sends an 802.11 association frame to an access point. By capturing this frame, it is possible to decode and report on the client capabilities. On caveat, however, is that the client will match the capabilities advertised by an access point. For instance, if a 3 stream client detects that the access point supports only 2 streams, it will report that it (the client) only support 2 streams also. 

To get around this shortcoming when trying to determine client capabilities, this script uses the Python FakeAP module to create a fake AP that advertises that it has the highest levels of feature sets enabled. This fools the client in to revealing its full capabilities, which are then analyzed from the association frame that it uses as it attempts to join the fake AP. It then uses the Scapy Python module to capture and  analyze the association frames from each client to determine its capabilities.

A textual report is dumped in real-time to stdout and a text file copy is also dumped in to a directory of the WLANPi web server to allow browsing of reports. In addition, a copy of the association frame is dumped in PCAP file format in to the directory . Each result is also added to a summary CSV report file that is created for each analysis session when the script is run.

Report files are dumped in the following web directories for browsing:

- http://<wlanpi_ip_address>/profiler/clients (on directory per client, with PCAP and text capability report dumped in the directory)
- http://<wlanpi_ip_address>/profiler/reports (contains a CSV report of all clients for each session when the script is run)



## Running the Script (Front Panel Menu System)

From version v0.21 of the WLANPi FPMS, it is possible to launch the profiler script using the front panel keys of the WLANPi, so that no CLI interaction is required - all that is required is to start the Profiler process via the buttons, then view the web reports as clients are detected. The required option can be found on the front panel menu system at : Home -> 3.Apps -> 3.Profiler

Options are provided to start, stop and view the status of the profiler. Once the profiler has been started, the Profiler status option will show the channel, SSID and client count of detected clients. The status screen also shows a truncated copy of the manufacturer name of the last detected client, which, together with the detected clients counter, can be useful in indicating whether clients have triggered the Profiler analysis process. 

The reporting operation is as per the CLI mode of operation described in the previous section, with reports being generated and visible from the WLANPi web GUI.

Note: there is also an option to start the profiler with no 802.11r information elements being included in beacons. This will help with clients that are sensitive to 802.11r and will not attempt to associate when they see the 802.11r IEs

![Screenshot](https://github.com/WLAN-Pi/Profiler/blob/master/images/profiler_status.jpg)

A "Purge" option is also provided via the menu system. This will delete all old summary reports from the WLANPi (but not individual client reports)

## Running the Script (CLI)

The Profiler script can be run from the CLI of the WLANPi. To run the profiler, SSH to the WLANPi and run the script, for example:

```
 cd /home/wlanpi/profiler
 sudo ./profiler.py -c 36 (enter the root password when prompted)
```

The script will run continuously, listening for association requests, analyzing the client capabilities in real-time. To end the script, hit "Ctrl-c". Leave the script running while testing clients.

To trigger client profiling when the script is running:

- Fire up the client(s) to test
- Search for the SSID configured on the fake AP ("WLAN Pi" by default)
- Attempt to join the fake AP SSID from the test client
- When prompted, enter a random PSK on the client under test (any string of 8 or more characters will do)
- After a few seconds, a textual report will (hopefully) be displayed in the SSH session already established to the WLAN Pi as it tries to associate. (Note that the client will not actually join the fake AP SSID.)
- Once clients have been tested and successfully triggered a client report, the captured association frame is dumped in to a PCAP file for your reference (browse to "http://<ip_address_of_wlanpi>/profiler" to see PCAP dumps and text reports)

(Note: From verion 0.06, it is possible to run on the CLI with the "--NoAP" option to just listen to association requests and not fire up the fake AP. In this instance, you will
need to have an AP on your own running on the channel you wish to test on.)

## Configuration

To change the default operation of the script (v0.4 and later), a "config.ini" can be found in the same directory as the profiler script (/home/wlanpi/profiler). This can be used as an easy way to modify the channel, SSID and interface adapter used by the Profiler script.

By editing the parameters in this file, the operation of the fake AP created by the script is modified. Note that if any changes are made, the Profiler process will need to be stopped & started for the new settings to take effect. 

The configuration file may be updated by opening an SSH session to the WLANPi, then launching the nano editor:

```
 nano /home/wlanpi/profiler/config.ini
```

Once changes have been made, hit Ctrl-X to exit the editor & save the changes.

Note that this configuration file has been provided to make it easier to change the behavior of the Profiler now that front panel menu operation is now possible. Command line parameters are obviously not passed at run-time as they were when operation was initiated only via the CLI. When running from the CLI, parameters may be set in the configuration file as a convenience, but may still be over-ridden by parameters passed via the CLI at run-time.

## Usage

```
 Usage:

    profiler.py
    profiler.py [ -c <channel num> ] [ -s "SSID Name" ] [ -i interface_name ] [ --no11r ]
    profiler.py --noAP -c <channel num>
    profiler.py -f <pcap filename>
    profiler.py -h
    profiler.py -v
    profiler.py --help
    profiler.py --clean  (Clean out old CSV reports)

 Command line options:

    -h       Shows help
    -c       Sets channel for fake AP
    -s       Sets name of fake AP SSID
    -i       Sets name of fake AP wireless interface on WLANPi
    -f       Read pcap file of assoc frame
    -h       Prints help page
   --no11r   Disables 802.111r information elements
   --noAP    Disables fake AP and just listens for assoc req frames
   --help    Prints help page
   --clean   Cleans out all CSV report files
 
 ```
### Examples (Launching profiler from the CLI):

```
# capture frames on channel 48 using the default SSID
wlanpi@wlanpi:/home/wlanpi/profiler# sudo python ./profiler.py -c 48

```

```
# capture frames on channel 36 using an SSID called 'JOIN ME'
wlanpi@wlanpi:/home/wlanpi/profiler# sudo python ./profiler.py -c 36 -s "JOIN ME"

```

```
# capture frames on channel 100 using an SSID called 'Profiler' with 802.11r disabled for clients that don't like 11r
wlanpi@wlanpi:/home/wlanpi/profiler# sudo python ./profiler.py -c 100 -s "Profiler" --no11r
```

```
# capture frames on channel 100 without the fake AP running
wlanpi@wlanpi:/home/wlanpi/profiler# sudo python ./profiler.py --noAP -c 100

```

```
# analyze a association request in a previously captured PCAP file (must be only frame in file)
wlanpi@wlanpi:/home/wlanpi/profiler# sudo python ./profiler.py -f assoc_frame.pcap

```

## Screenshot

![Screenshot](https://github.com/WLAN-Pi/Profiler/blob/master/images/screenshot1.png)

## Caveats
- Note that this is work in progress and is not guaranteed to report accurate info (despite our best efforts). **You have been warned**
- A client will generally only report the capabilities it has that match the network it associates to. If you want the client to report all of its capabilities, it **must** be associating with a network that supports those capabilities (e,g, a 3 stream client will not report it supports 3 streams if the AP is associates with supports only one stream). The fake AP in this script attempts to provide a simulate a fully featured AP, but this is obviously a simulated AP, so there may be cases when it does not behave as expected. 
- Reporting of 802.11k capabilities is very poor among clients I have tested - treat with extreme caution (check for neighbor report requests from a WLC/AP debug to be sure)

## Credits
Thanks to Kobe Watkins for the code to add 802.11w support to the profiler in version 0.03. Much appreciated! :)
Thanks also to Philipp Ebbecke for spotting the 11ac capabilities bug which got fixed in v0.06.

## Release Notes

- V0.06 (Oct 2019): 
   - Fixed VHT beamformee capabilities bug (spotted by Philipp Ebbecke) 
   - Added '--noAP' option to run without the fake AP
   - Added '-f' option to analyze a previously captured association frame in a pcap file
   - Added basic 11ax detection
- v0.05 (Aug 2019):
   - Fixed issue with profiler not running when no SSH session established to WLANPi
- v0.04 (Aug 2019):
   - Added support for front panel menu system
   - Added external config file support
- v0.03 (July 2019):
   - Added 11w support (Thanks Kobe!)
   - Added MAC OUI lookup support

# Developer Information

## Installing The Script From Scratch

(Note that the script is part of standard WLANPi image, so you will generally not need these instructions unless a new script version becomes available. To check your current script version, SSH to your WLANPi and run the command "sudo /home/wlanpi/profiler/profiler.py -v")

### Pre-requisites

The Profiler script can be run from the CLI of the WLANPi using the steps outline in the next section. However, if you would like to also take advantage of using the front panel menu controls, you will need to also install the files from the following project:

- [wlanpi-nanohat-oled](https://github.com/WLAN-Pi/wlanpi-nanohat-oled) (v0.21 or better)

Each project has its own install instructions, but is generally just a simple file copy operation. (Apologies if this seems a but clunky - it is. We'll consolidate this at some point in the near future to make things easier)

### Script installation

To install the profiler script itself on the WLANPi perform the following steps:

- Download the profiler.py and config.ini file from the github repo: https://github.com/WLAN-Pi/profiler
- Open an SSH session to the WLANPi using the 'wlanpi' username - this will drop you in to the /home/wlan directory (verify with 'pwd')
- If required, create a new Profiler directory using the command : mkdir profiler (this will generally already exist if you had a previous WLANPi image on your device)
- Change directory to the Profiler directory: 
```
 cd ./profiler
```
- Transfer the "profiler.py" script and "config.ini" files in to the profiler directory on the WLANPi (e.g. using SFTP)
- Make the Proflier script executable with the command 
```
 chmod a+x profiler.py"
```
- Install the 'manuf' Python module to provide us with MAC OUI lookup capabilities, then update its OUI lookup file: 
```
 sudo pip install manuf
 cd /usr/local/lib/python2.7/dist-packages/manuf
 sudo python manuf.py --update
```
- Reboot the WLANPi: 
```
 sudo reboot
```
- Ensure that a USB wireless adapter that support monitor mode (e.g. Comfast CF-912AC) is plugged in to the WLANPi

### MAC OUI Database Update

From version 0.03 of the script, a MAC OUI lookup is included in the reports to show the manufacturer of the client based on the 6-byte MAC OUI. This feature is provided by a Python module called "manuf". It uses a local MAC OUI database file to lookup OUI information. An OUI lookup file is provided with the module, though it may be quite old, depending on the date of the last update of the module code.

If you find some devices are not reporting a manufacturer, the OUI DB file may need an update. To update the manuf OUI DB file, perform the following steps from the CLI of the WLANPi:

- Ensure the WLANPi is connected to a network with Internet access
- SSH to the WLANPi
- Perform the following commands:

```
 cd /usr/local/lib/python2.7/dist-packages/manuf
 python manuf.py --update
```

There are no outputs provided to indicate when/if the update has been successful, so I suggest only performing this step if absolutely necessary. If errors reported by the profiler script after running the update, try running the update again, as this operation seems a little "variable" in its success rate.
