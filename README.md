# project-memoria-detector

The `project-memoria-detector` tool aims to determine whether a target network device runs a specific embedded TCP/IP stack. 

Currently, the tool supports fingerprints for 16 embedded TCP/IP stacks (and their variations):
- [uIP](https://github.com/adamdunkels/uip), [Contiki](https://github.com/contiki-os/contiki) or [Contiki-NG](https://github.com/contiki-ng/contiki-ng)
- [picoTCP](https://github.com/tass-belgium/picotcp) or [picoTCP-NG](https://github.com/virtualsquare/picotcp)
- [Nut/Net](http://www.ethernut.de/en/software/)
- [FNET](http://fnet.sourceforge.net/)
- [Nucleus NET](https://www.prnewswire.com/news-releases/siemens-launches-new-enterprise-class-embedded-linux-solution-for-embedded-systems-development-300798756.html)
- [CycloneTCP](https://www.oryx-embedded.com/products/CycloneTCP)
- [NDKTCPIP](https://www.ti.com/tool/NDKTCPIP)
- [uC/TCP-IP](https://github.com/weston-embedded/uC-TCP-IP)
- [MPLAB Harmony Net](https://github.com/Microchip-MPLAB-Harmony/net)
- [NicheStack](https://en.wikipedia.org/wiki/NicheStack_TCP/IPv4)
- [FreeBSD](https://www.freebsd.org/)
- [Microsoft ThreadX](https://docs.microsoft.com/en-us/azure/rtos/threadx/overview-threadx)
- [CMX TCP/IP](http://www.cmx.com/tcpip.htm)
- [emNet](https://www.st.com/en/embedded-software/embos-ip.html)
- [Keil TCP/IP](https://www.keil.com/arm/rl-arm/rl-tcpnet.asp)
- [lwIP](http://www.nongnu.org/lwip/2_1_x/index.html)

Several of the above stacks were found vulnerable during the [Project Memoria](https://www.forescout.com/research-labs/) research.

## How does it work?

The script identifies the use of the 16 TCP/IP stacks on a target device via the following active fingerprinting methods:
- ICMP probing: the script performs a malformed ICMP echo request and checks for characteristics of the reply, including changes in the Time-to-live (TTL) value and specific payload content, which varies per stack. 
- TCP options signatures: the script sends a TCP SYN packet and monitors the TCP SYN ACK response for the format of the TCP options field. Each stack replies with different values for the options, such as a Maximum Segment Size (MSS) and window scale.
- TCP Urgent flag handling: the script sends a TCP packet with the Urgent flag set and monitors the response. Each stack replies with a different set of TCP flags and a different TCP Window size value.
- HTTP banners and error messages: the script performs HTTP requests to a webserver hosted on a device under the test and checks for specific HTTP headers and application-specific error messages.
- SSH banners and error messages: the script performs requests to an SSH server hosted on a device under the test and checks for specific SSH banners.
- FTP banners and error messages: the script performs requests to an FTP server hosted on a device under the test and checks for specific FTP banners.

Although the script has been tested in a lab environment, we cannot guarantee its use to be safe against every possible device. Malformed ICMP packets, for instance, could crash a device that is running a different stack. THEREFORE, WE DO NOT RECOMMEND ITS USE DIRECTLY ON LIVE ENVIRONMENTS WITH MISSION-CRITICAL DEVICES (SUCH AS HOSPITALS WITH PATIENT-CONNECTED DEVICES OR SAFETY-CRITICAL INDUSTRIAL CONTROL SYSTEMS). An ideal approach is to test devices in a lab setting or during a maintenance window.

## Dependencies

Please note that the tool has been tested only in a Linux test environment (any modern Linux distribution should work). It is assumed that the test environment is using `iptables` (https://linux.die.net/man/8/iptables) as a basic firewall.

The tool requires a recent version of Python 3.x (see https://www.python.org/, version >= 3.7.7 is preferable), as well as Scapy (see https://scapy.net/, version >= 2.4.3 is preferable). 


To install Scapy together with Python and for general troubleshooting, please follow the documentation here: https://scapy.readthedocs.io/en/latest/installation.html

If python is already installed on your machine, to install the required dependencies you can use **pip** and the provided *requirements.txt* file:

```bash
$ pip install -r requirements.txt
```

## Basic usage

As Scapy requires root privileges to run, the tool must be run with `sudo`, e.g.:

```bash
$ sudo python project-memoria-detector.py [options]
```

To see the available options for running the script, run it with the `-h` option:

```bash
$ python project-memoria-detector.py -h
```

In general, the script requires at least a single the IP address of the target device (this parameter can be explicitly specified with `-ip_dst`)

```bash
$ sudo python project-memoria-detector.py 192.168.3.1
```

The script supports scanning ranges of IP addresses. You can either specify a subnet to scan using the CIDR notation, or provide a .txt file with a set of IP addresses to scan.

The CIDR notation can be used as follows (for this example, the IP addresses from 192.168.3.1 to 192.168.3.254 will be scanned:

```bash
$ sudo python project-memoria-detector.py 192.168.3.0/24
```

You can also use a .txt file in order to specify the IP addresses of interest: each IP address in this file must start with a new line. For example, we can create a file called `input.txt` with the following contents:

```bash
$ cat input.txt
192.168.1.8
192.168.1.9
192.168.3.1
192.168.2.14
```

We can then run the script as follows:

```bash
$ sudo python project-memoria-detector.py --in-file input.txt
```

The script uses default values for ports to fingerprint different protocols such as SSH (22), FTP (21) and HTTP (80). In order to overwrite these default values, you are able to do so by setting the flags like:

```bash
$ sudo python project-memoria-detector.py -ip_dst 192.168.212.42 --tcp-port 80 --http-port 80 --ssh-port 22 --ftp-port 21 -i eth1
```

## Interpreting the results 

The script will output matches to individual fingerprints as well as degree of certainty in round brackets: 

```bash
$ sudo python project-memoria-detector.py 192.168.6.42

192.168.6.42 is alive
        ICMP => uIP/Contiki (High)
        TCP => uIP/Contiki (Medium)
        HTTP => uIP/Contiki (High)
        SSH => Unknown (No match)
        FTP => Unknown (No reply)
```

The degree of certainty of a particular fingerprint can be `High`, `Medium`, or `Low`. `No match` means that there was no match with any known fingerprints, and `No reply` means that a specific port/service is unavailable.

## License

Copyright (C) 2020 Forescout Technologies, Inc.

Program License

"The Program" refers to any copyrightable work licensed under this License. Each licensee is addressed as "you."

All rights granted under this License are granted for the term of copyright on the Program, and are irrevocable provided the stated conditions are met. This License explicitly affirms your unlimited permission to run the unmodified Program for personal, governmental, business or non-profit use. You are prohibited from using the Program in derivative works for commercial purposes. You are prohibited from modifying the Program to be used in a commercial product or service, either alone or in conjunction with other code, either downloadable or accessed as a service. "Derivative works" shall mean any work, whether in source or object form, that is based on (or derived from) the Program and for which the editorial revisions, annotations, elaborations, or other modifications represent, as a whole, an original work of authorship.

You may convey verbatim copies of the Program's source code as you receive it, in any medium, provided that you conspicuously and appropriately publish on each copy an appropriate copyright notice; keep intact all notices stating that this License applies to the code; keep intact all notices of the absence of any warranty; give all recipients a copy of this License along with the Program; and do not financially benefit from the sale or other conveyance of the Program either alone or in conjunction with other code, downloaded or accessed as a service.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This License does not grant permission to use the trade names, trademarks, service marks, or product names of the Licensor, except as required for reasonable and customary use in describing the origin of the Program and reproducing the content of the copyright notice.
