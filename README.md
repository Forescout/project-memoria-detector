# project-memoria-detector

The `project-memoria-detector` tool aims to determine whether a target network device runs a vulnerable TCP/IP stack. 

Currently, the tool supports fingerprints for four embedded TCP/IP stacks (and their variations) that were found vulnerable during the AMNESIA:33 research (see https://www.forescout.com/research-labs/amnesia33/):
- [uIP](https://github.com/adamdunkels/uip), [Contiki](https://github.com/contiki-os/contiki) or [Contiki-NG](https://github.com/contiki-ng/contiki-ng)
- [picoTCP](https://github.com/tass-belgium/picotcp) or [picoTCP-NG](https://github.com/virtualsquare/picotcp)
- [Nut/Net](http://www.ethernut.de/en/software/)
- [FNET](http://fnet.sourceforge.net/)

## How does it work?

The script identifies the use of four TCP/IP stacks (uIP/Contiki, picoTCP, FNET and Nut/Net) on a target device via three active fingerprinting methods:
- ICMP probing: the script performs a malformed ICMP echo request and checks for characteristics of the reply, including changes in the Time-to-live (TTL) value and specific payload content, which varies per stack. 
- TCP options signatures: the script sends a TCP SYN packet and monitors the TCP SYN ACK response for the format of the TCP options field. Each stack replies with different values for the options, such as a Maximum Segment Size (MSS) and window scale.
- TCP Urgent flag handling: the script sends a TCP packet with the Urgent flag set and monitors the response. Each stack replies with a different set of TCP flags and a different TCP Window size value.

Although the script has been tested with the four stacks affected by AMNESIA:33 in a lab environment, we cannot guarantee its use to be safe against every possible device. Malformed ICMP packets, for instance, could crash a device that is running a different stack. Therefore, we do not recommend its use directly on live environments with mission-critical devices (such as hospitals with patient-connected devices or safety-critical industrial control systems). An ideal approach is to test devices in a lab setting or during a maintenance window.

## Dependencies

Please note that the tool has been tested only in a Linux test environment (any modern Linux distribution should work). It is assumed that the test environment is using `iptables` (https://linux.die.net/man/8/iptables) as a basic firewall.

The tool requires a recent version of Python 2.x or 3.x (see https://www.python.org/, version >= 2.7.17 or >= 3.7.7 is preferable), as well as Scapy (see https://scapy.net/, version >= 2.4.3 is preferable). 

To install Scapy together with Python and for general troubleshooting, please follow the documentation here: https://scapy.readthedocs.io/en/latest/installation.html.

## Usage

As Scapy requires root privileges to run, the tool must be run with `sudo`, e.g.:

```bash
$ sudo -E python project-memoria-detector.py [options]
```

To see the available options for running the script, run it with the `-h` option:

```bash
$ python project-memoria-detector.py -h
```

In general, the script requires at least the following three options: (1) the IP address of the target device (`-ip_dst`), an open TCP port (`-p`), and the target network interface (`-i`). For example:

```bash
$ sudo -E python project-memoria-detector.py -ip_dst 192.168.212.42 -p 80 -i eth1
```

## Interpreting the results 

After the tool is run against a target device, it will first output the IP address of the target, then it will output the result of the ICMP fingerprinting, followed by the result of the TCP fingerprinting. Each matched fingerprint is also complemented by the match confidence level in round brackets. For example: 

```bash
192.168.43.22
        ICMP fingerprint => the host 192.168.43.22 may be running the uIP/Contiki TCP/IP stack (High level of confidence)
        TCP fingerprint => the host 192.168.43.22 may be running the uIP/Contiki TCP/IP stack (Medium level of confidence) 
```

In cases when some of the fingerprints do not match (e.g., the signature is unknown), the tool produces an output similar to the following (in this example the target device did not match any of the ICMP fingerprints, but there was a match with the TCP fingerprints):

```bash
192.168.43.23
        ICMP fingerprint => failed to determine the TCP/IP stack (reason: No match)
        TCP fingerprint => the host 192.168.43.23 may be running the FNET TCP/IP stack (High level of confidence)
```

In case there is no reply to ICMP and/or TCP messages (e.g., the device is offline, and/or it does not respond to ICMP echo requests, and/or there are no open TCP ports), the output looks like this:

```bash
192.168.43.24
        ICMP fingerprint => failed to determine the TCP/IP stack (reason: No reply)
        TCP fingerprint => failed to determine the TCP/IP stack (reason: No reply)
```


## License

Copyright (C) 2020 Forescout Technologies, Inc.

Program License

"The Program" refers to any copyrightable work licensed under this License. Each licensee is addressed as "you."

All rights granted under this License are granted for the term of copyright on the Program, and are irrevocable provided the stated conditions are met. This License explicitly affirms your unlimited permission to run the unmodified Program for personal, governmental, business or non-profit use. You are prohibited from using the Program in derivative works for commercial purposes. You are prohibited from modifying the Program to be used in a commercial product or service, either alone or in conjunction with other code, either downloadable or accessed as a service. "Derivative works" shall mean any work, whether in source or object form, that is based on (or derived from) the Program and for which the editorial revisions, annotations, elaborations, or other modifications represent, as a whole, an original work of authorship.

You may convey verbatim copies of the Program's source code as you receive it, in any medium, provided that you conspicuously and appropriately publish on each copy an appropriate copyright notice; keep intact all notices stating that this License applies to the code; keep intact all notices of the absence of any warranty; give all recipients a copy of this License along with the Program; and do not financially benefit from the sale or other conveyance of the Program either alone or in conjunction with other code, downloaded or accessed as a service.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This License does not grant permission to use the trade names, trademarks, service marks, or product names of the Licensor, except as required for reasonable and customary use in describing the origin of the Program and reproducing the content of the copyright notice.
