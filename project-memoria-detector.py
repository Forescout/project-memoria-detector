#!/usr/bin/python
# project-memoria-detector -- detection tool for embedded TCP/IP stacks

'''
Copyright (C) 2020 Forescout Technologies, Inc.

Program License

"The Program" refers to any copyrightable work licensed under this License. Each
licensee is addressed as "you."

All rights granted under this License are granted for the term of copyright on
the Program, and are irrevocable provided the stated conditions are met. This
License explicitly affirms your unlimited permission to run the unmodified
Program for personal, governmental, business or non-profit use. You are
prohibited from using the Program in derivative works for commercial purposes.
You are prohibited from modifying the Program to be used in a commercial product
or service, either alone or in conjunction with other code, either downloadable
or accessed as a service. "Derivative works" shall mean any work, whether in
source or object form, that is based on (or derived from) the Program and for
which the editorial revisions, annotations, elaborations, or other modifications
represent, as a whole, an original work of authorship.

You may convey verbatim copies of the Program's source code as you receive it,
in any medium, provided that you conspicuously and appropriately publish on each
copy an appropriate copyright notice; keep intact all notices stating that this
License applies to the code; keep intact all notices of the absence of any
warranty; give all recipients a copy of this License along with the Program; and
do not financially benefit from the sale or other conveyance of the Program
either alone or in conjunction with other code, downloaded or accessed as a
service.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This License does not grant permission to use the trade names, trademarks,
service marks, or product names of the Licensor, except as required for
reasonable and customary use in describing the origin of the Program and
reproducing the content of the copyright notice.
'''

import sys
import subprocess
import argparse
import time
import re
from binascii import hexlify
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import conf, send, sr1, sniff, IP, ICMP, TCP, Raw, RandShort, Padding, AsyncSniffer
import ipaddress
import csv
import os


DEFAULT_TCP_DPORT = 80
DEFAULT_HTTP_DPORT = 80
DEFAULT_SSH_DPORT = 22
DEFAULT_FTP_DPORT = 21
DEFAULT_TIMEOUT = 4

'''
TCP option signatures
'''
picotcp_tcp_opts_1 = [
    ('MSS', 1460),
    ('SAckOK', b''),
    ('WScale', 0),
    ('Timestamp', None),
    ('NOP', None),
    ('NOP', None),
    ('NOP', None),
    ('NOP', None),
    ('EOL', None),
]

picotcp_tcp_opts_2 = [
    ('WScale', 0),
    ('EOL', None),
]

fnet_tcp_opts = [
    ('MSS', 1460),
    ('WScale', 0),
    ('EOL', None),
]

uip_tcp_opts = [
    ('MSS', 1240),
]

nutnet_tcp_opts = [
    ('MSS', 536),
]

cyclone_tcp_opts = [
    ('MSS', 1430),
]

# MATCHES
MATCH_HIGH = 3
MATCH_MEDIUM = 2
MATCH_LOW = 1
MATCH_NO_MATCH = 0
MATCH_NO_REPLY = -1


def match_level_str(match_level):
    if match_level >= MATCH_HIGH:
        return 'High'
    elif match_level == MATCH_MEDIUM:
        return 'Medium'
    elif match_level == MATCH_LOW:
        return 'Low'
    elif match_level == MATCH_NO_MATCH:
        return 'No match'
    return 'No reply'


'''
This is a helper function that checks the TCP option sequences
'''

def check_tcp_options(tcp_opts, signature):
    # The signatures do not match if they have different lengths
    if len(signature) != len(tcp_opts):
        return False

    for i in range(0, len(signature)):
        # The signatures do not match if the order of the options is not exact,
        # or the option values do not match (except when it is set to 'None' in the signature)
        if (tcp_opts[i][0] != signature[i][0]):
            return False
        else:
            if (signature[i][1] != None and signature[i][1] != tcp_opts[i][1]):
                return False
    return True


'''
This is a helper function for performing a TCP 3-way handshake
'''

def tcp_handshake(dst_host, dst_port, interface, custom_tcp_opts, timeout):
    # Use the default interface if none is provided
    if interface == None:
        interface = conf.iface

    # We can use a fixed ISN
    seqn = 0
    ip = IP(version=0x4, id=0x00fb, dst=dst_host)
    src_port = int(RandShort()._fix()/2+2**15)

    syn = ip/TCP(dport=dst_port, sport=src_port, flags='S',
                 seq=seqn, ack=0, options=custom_tcp_opts)

    syn_ack = sr1(syn, timeout=timeout, iface=interface)
    if syn_ack == None or TCP not in syn_ack or 'R' in syn_ack[TCP].flags:
        return None

    seqn += 1
    ackn = syn_ack[TCP].seq + 1

    ack = ip/TCP(dport=dst_port, sport=src_port, flags='A', seq=seqn, ack=ackn)
    send(ack, iface=interface)

    return syn_ack


'''
This function attempts to actively fingerprint the usage of embedded TCP/IP stacks via ICMPv4 echo requests.
'''

def icmpv4_probe(dst_host, timeout):
    icmptype_i = 0x8
    icmptype_name_i = 'ICMP ECHO'
    icmptype_o = 0x0
    icmptype_name_o = 'ICMP ECHO_REPLY'

    stack_name = None
    match = MATCH_NO_MATCH

    ip = IP(dst=dst_host, ttl=20, proto=0x01)

    # First, check if we can reach ICMP
    std_icmp_payload = '\xcd\x69\x08\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17' \
                       '\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27' \
                       '\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37'

    reply = sr1(ip/ICMP(id=0xff, seq=1, type=icmptype_i)/Raw(load=std_icmp_payload),
                filter='icmp[icmptype] = {}'.format(icmptype_o), timeout=timeout)
    if not reply:
        return (stack_name, MATCH_NO_REPLY)

    # If there is no reply to the second ICMP packet, either the target IP cannot be reached (or ICMP is
    # disabled), or we deal with the CycloneTCP stack that will accept only ICMP packets that have at least 1 byte
    # of data. To check for CycloneTCP, we craft such a packet: we expect the 1 byte of data back (+ optional padding).
    reply = sr1(ip/ICMP(id=0xff, seq=1, type=icmptype_i), filter='icmp[icmptype] = {}'.format(icmptype_o), timeout=timeout)
    if not reply:
        reply = sr1(ip/ICMP(id=0xff, seq=1, type=icmptype_i)/Raw(load=b'\x41'), filter='icmp[icmptype] = {}'.format(icmptype_o), timeout=timeout)
        if reply and (reply.ttl >= 54 and reply.ttl <= 64):
            if Raw in reply and Padding in reply and reply[Raw].load == b'\x41':
                match = MATCH_MEDIUM
                stack_name = 'CycloneTCP'
                return (stack_name, match)

    # Next, we prepare a packet that should work with uIP/Contiki and PicoTCP
    icmp_raw = b'\x08\x01\x02'
    ipv4_probe = ip/Raw(load=icmp_raw)

    # Send the malformed ICMP packet
    # If we get the expected reply it is either PicoTCP or uIP/Contiki:
    #   - we first check that the TTL value of the echo packet is changed into 64 for the reply packet
    #   - we then check the payload sequence of the echo reply packet
    reply = sr1(ipv4_probe, filter='icmp[icmptype] = {}'.format(icmptype_o), timeout=timeout)
    if reply and (reply.ttl >= 54 and reply.ttl <= 64):
        if (hexlify(reply.load) == b'0001ff'):
            match = MATCH_HIGH
            stack_name = 'PicoTCP'
        elif (hexlify(reply.load) == b'00010a'):
            match = MATCH_HIGH
            stack_name = 'uIP/Contiki'

    else:  # we did not get a reply for the first malformed packet
        _id = 0xab
        _seq = 0xba
        # Nut/Net should reply to ICMP packets with incorrect IP and ICMP checksums
        ipv4_probe = IP(dst=dst_host, ttl=20, chksum=0xdead)/ICMP(id=_id, seq=_seq, type=icmptype_i, chksum=0xbeaf)
        reply = sr1(ipv4_probe, filter='icmp[icmptype] = {}'.format(icmptype_o), timeout=timeout)
        # TTL value must be 64 as well
        if reply and (reply.ttl >= 54 and reply.ttl <= 64):
            if (reply[ICMP].id == _id and reply[ICMP].seq == _seq and reply[ICMP].type == 0x00):
                match = MATCH_MEDIUM
                stack_name = 'Nut/Net'

    # Here we handle all other cases
    if match == MATCH_NO_MATCH:

        # NDKTCPIP should reply to an ICMP packet that has at least 4 bytes of the header and a correct ICMP checksum
        # The code (2nd byte) must be 0x00
        icmp_raw = b'\x08\x00\xf7\xff'
        ipv4_probe = ip/Raw(load=icmp_raw)
        # For some reason Scapy will not get the reply to this packet, so I had to use asynchronous sniffing
        t = AsyncSniffer(iface=interface)
        t.start()
        send(ipv4_probe)
        time.sleep(timeout)
        pkts = t.stop()

        for pkt in pkts:
            # first, let's check the source and the destination IP
            if IP in pkt and pkt[IP].src == dst_host and pkt[IP].dst == ip.src:
                # NDKTCPIP will reply with a TTL value of 255, the ICMP checksum will be 0xffff
                if ICMP in pkt and pkt[ICMP].type == 0x00 and pkt[ICMP].chksum == 0xffff:
                    # NDKTCPIP will reply with a TTL value of 255, the ICMP checksum will be 0xffff
                    if (pkt.ttl >= 245 and pkt.ttl <= 255):
                        match = MATCH_HIGH
                        stack_name = 'NDKTCPIP'
                        break

                    # Nucleus Net AND NicheStack will reply with a TTL value of 64, the ICMP checksum will be 0xffff.
                    # So far, we assume it is NicheStack.
                    elif (pkt.ttl <= 64):
                        match = MATCH_MEDIUM
                        stack_name = 'NicheStack'
                        break

    # We do an additional check for Nucleus Net: it will reply to a malformed ICMP packet that has only 1 byte in its header.
    # If we don't get a reply, NicheStack it is.
    if stack_name == 'NicheStack':
        icmp_raw = b'\x08'
        ipv4_probe = ip/Raw(load=icmp_raw)
        t = AsyncSniffer(iface=interface)
        t.start()
        send(ipv4_probe)
        time.sleep(timeout)
        pkts = t.stop()
        for pkt in pkts:
            # first, let's check the source and the destination IP
            if IP in pkt and pkt[IP].src == dst_host and pkt[IP].dst == ip.src:
                if ICMP in pkt and pkt[ICMP].type == 0x00 and pkt[ICMP].chksum == None:
                    match = MATCH_MEDIUM
                    stack_name = 'Nucleus Net'
                    break

    return (stack_name, match)


'''
This function attempts to actively fingerprint the usage of embedded TCP/IP stacks via specific HTTP signatures.
'''

def httpv4_probe(dst_host, dst_port, interface, skip_iptables, timeout):
    stack_name = None
    match_confidence = MATCH_NO_MATCH

    ip = IP(version=0x4, id=0x00fb, dst=dst_host)
    try:
        # We need to set up this rule in order to disable RST packets sent by the Linux kernel
        if skip_iptables == False:
            subprocess.check_call(['iptables', '-I', 'OUTPUT', '-p', 'tcp',
                                   '--tcp-flags', 'RST', 'RST', '-s', '%s' % ip.src, '-j', 'DROP'])

        syn_ack = tcp_handshake(dst_host, dst_port, interface, {}, timeout)
        if syn_ack == None:
            return (None, MATCH_NO_REPLY)

        seqn = syn_ack[TCP].ack
        ackn = syn_ack[TCP].seq+1

        # Check for HTTP headers
        http_data = b'\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a'     \
                    b'\x48\x6f\x73\x74\x3a\x20%s\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65'   \
                    b'\x6e\x74\x3a\x20\x63\x75\x72\x6c\x2f\x37\x2e\x35\x38\x2e\x30\x0d\x0a' \
                    b'\x41\x63\x63\x65\x70\x74\x3a\x20\x2a\x2f\x2a\x0d\x0a\x0d\x0a' % dst_host.encode('utf-8')

        http_get = ip/TCP(dport=dst_port, sport=syn_ack[TCP].dport, flags='PA', seq=seqn, ack=ackn)/Raw(load=http_data)
        send(http_get, iface=interface)
        response_pkts = sniff(filter='tcp and src %s' % dst_host, timeout=timeout*2, iface=interface)

        for pkt in response_pkts:
            if Raw in pkt:

                # uIP/Contiki
                if re.search(b'Server: Contiki/([\w._-]+)', pkt[Raw].load, re.MULTILINE | re.IGNORECASE) is not None \
                        or re.search(b'Server: uIP/([\w._-]+)', pkt[Raw].load, re.MULTILINE | re.IGNORECASE) is not None:
                    stack_name = 'uIP/Contiki'
                    match_confidence = MATCH_HIGH
                    break

                # uC/TCP-IP
                elif b'Server: uC-HTTP-server' in pkt[Raw].load or b'Server: uC-HTTPs V2.00.00' in pkt[Raw].load:
                    stack_name = 'uC/TCP-IP'
                    match_confidence = MATCH_HIGH
                    break

                # Nut/Net
                elif b'Server: Ethernut' in pkt[Raw].load:
                    stack_name = 'Nut/Net'
                    match_confidence = MATCH_HIGH
                    break

                # FNET
                elif b'Server: FNET HTTP' in pkt[Raw].load:
                    stack_name = 'FNET'
                    match_confidence = MATCH_HIGH
                    break

                # NicheStack
                elif b'Server: InterNiche Technologies WebServer' in pkt[Raw].load:
                    stack_name = 'NicheStack'
                    match_confidence = MATCH_HIGH
                    break

                # FreeBSD HTTP Servers
                elif re.search(b'Server: \w.+\/\d.*\(FreeBSD\)', pkt[Raw].load) is not None \
                        or re.search(b'Server: httpd_\d.*\/FreeBSD', pkt[Raw].load) is not None:
                    stack_name = 'FreeBSD'
                    match_confidence = MATCH_HIGH
                    break

                # FreeBSD protocol mismatch on SSH port
                elif re.search(b'OpenSSH_\d.* FreeBSD-\d.*\\r\\nProtocol mismatch\.\\n', pkt[Raw].load, re.MULTILINE | re.IGNORECASE) is not None:
                    stack_name = 'FreeBSD'
                    match_confidence = MATCH_HIGH
                    break

                # NettX
                elif re.search(b'Server: (\w.+) \(\s?ThreadX\s?\)', pkt[Raw].load, re.MULTILINE | re.IGNORECASE) is not None:
                    stack_name = 'NettX'
                    match_confidence = MATCH_HIGH
                    break

                # CMX-TCP/IP
                elif b'Server: CMX TCP\/IP - WEB' in pkt[Raw].load or b'Server: CMX Systems WebServer' in pkt[Raw].load:
                    stack_name = 'CMX-TCP/IP'
                    match_confidence = MATCH_HIGH
                    break

                # emNet
                elif b'Server: embOS/IP' in pkt[Raw].load or b'Server: CMX Systems WebServer' in pkt[Raw].load:
                    stack_name = 'emNet'
                    match_confidence = MATCH_HIGH
                    break

                # Keil TCPnet
                elif re.search(b'Server: Keil-EWEB\/\d.+', pkt[Raw].load, re.MULTILINE | re.IGNORECASE) is not None:
                    stack_name = 'Keil TCPnet'
                    match_confidence = MATCH_HIGH
                    break

                # lwIP
                elif re.search(b'Server: lwIP/([\w._-]+)', pkt[Raw].load, re.MULTILINE | re.IGNORECASE) is not None:
                    stack_name = 'lwIP'
                    match_confidence = MATCH_HIGH
                    break

        # Terminate the connection
        rst = ip/TCP(dport=dst_port, sport=syn_ack[TCP].dport, flags='R', seq=seqn, ack=ackn)
        send(rst, iface=interface)

        # If none of the banners matches, we try to get application-specific error messages
        if match_confidence == MATCH_NO_MATCH:

            # Initiate another 3-way handshake
            syn_ack = tcp_handshake(dst_host, dst_port, interface, {}, timeout)
            if syn_ack == None:
                return (None, MATCH_NO_REPLY)

            seqn = syn_ack[TCP].ack
            ackn = syn_ack[TCP].seq+1

            # Check for an implementation-specific error message from MPLAB Harmony Net
            http_data = b'\x4f\x50\x54\x49\x4f\x4e\x53\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x30\x0d\x0a\x0d\x0a'
            http_pkt = ip/TCP(dport=dst_port, sport=syn_ack[TCP].dport, flags='PA', seq=seqn, ack=ackn)/Raw(load=http_data)
            send(http_pkt, iface=interface)
            pkts = sniff(filter='tcp and src %s' % dst_host, timeout=timeout, iface=interface)

            for pkt in pkts:
                if Raw in pkt and pkt[Raw].load == b'HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n501 Not Implemented: Only GET and POST supported\r\n':
                    stack_name = 'MPLAB Harmony Net'
                    match_confidence = MATCH_HIGH
                    break

            # Terminate the connection
            rst = ip/TCP(dport=dst_port, sport=syn_ack[TCP].dport, flags='R', seq=seqn, ack=ackn)
            send(rst, iface=interface)

    except Exception as ex:
        if 'Errno 19' in '%s' % ex:
            print('\nERROR: the interface \'{}\' is invalid\n'.format(interface))
        else:
            print('\nERROR: {}\n'.format(ex))

    finally:
        # Cleanup the iptables rule
        if skip_iptables == False:
            subprocess.check_call(['iptables', '-D', 'OUTPUT', '-p', 'tcp',
                                   '--tcp-flags', 'RST', 'RST', '-s', '%s' % ip.src, '-j', 'DROP'])

    return (stack_name, match_confidence)


'''
This function attempts to actively fingerprint the usage of embedded TCP/IP stacks via specific SSH signatures.
'''

def sshv4_probe(dst_host, dst_port, interface, skip_iptables, timeout):
    stack_name = None
    match_confidence = MATCH_NO_MATCH

    ip = IP(version=0x4, id=0x00fb, dst=dst_host)

    try:
        # We need to set up this rule in order to disable RST packets sent by the Linux kernel
        if skip_iptables == False:
            subprocess.check_call(['iptables', '-I', 'OUTPUT', '-p', 'tcp',
                                   '--tcp-flags', 'RST', 'RST', '-s', '%s' % ip.src, '-j', 'DROP'])

        syn_ack = tcp_handshake(dst_host, dst_port, interface, {}, timeout)
        if syn_ack == None:
            return (None, MATCH_NO_REPLY)

        response_pkts = sniff(filter='tcp and src %s' % dst_host, timeout=timeout*2, iface=interface)

        for pkt in response_pkts:
            if Raw in pkt:

                # FreeBSD
                if re.search(b'OpenSSH_(\d.*)\sFreeBSD', pkt[Raw].load, re.IGNORECASE):
                    stack_name = 'FreeBSD'
                    match_confidence = MATCH_HIGH
                    break

    except Exception as ex:
        if 'Errno 19' in '%s' % ex:
            print('\nERROR: the interface \'{}\' is invalid\n'.format(interface))
        else:
            print('\nERROR: {}\n'.format(ex))

    finally:
        # Cleanup the iptables rule
        if skip_iptables == False:
            subprocess.check_call(['iptables', '-D', 'OUTPUT', '-p', 'tcp',
                                   '--tcp-flags', 'RST', 'RST', '-s', '%s' % ip.src, '-j', 'DROP'])

    return (stack_name, match_confidence)


'''
This function attempts to actively fingerprint the usage of embedded TCP/IP stacks via specific FTP signatures.
'''

def ftpv4_probe(dst_host, dst_port, interface, skip_iptables, timeout):
    stack_name = None
    match_confidence = MATCH_NO_MATCH

    ip = IP(version=0x4, id=0x00fb, dst=dst_host)

    try:
        # We need to set up this rule in order to disable RST packets sent by the Linux kernel
        if skip_iptables == False:
            subprocess.check_call(['iptables', '-I', 'OUTPUT', '-p', 'tcp',
                                   '--tcp-flags', 'RST', 'RST', '-s', '%s' % ip.src, '-j', 'DROP'])

        syn_ack = tcp_handshake(dst_host, dst_port, interface, {}, timeout)
        if syn_ack == None:
            return (None, MATCH_NO_REPLY)

        response_pkts = sniff(filter='tcp and src %s' % dst_host, timeout=timeout*2, iface=interface)

        for pkt in response_pkts:
            if Raw in pkt:

                # FreeBSD (low confidence, because the exact response depends on the hostname)
                if b'220 freebsd FTP server' in pkt[Raw].load:
                    stack_name = 'FreeBSD'
                    match_confidence = MATCH_LOW
                    break

                # Nucleus Net
                elif b'220 Nucleus FTP Server (Version' in pkt[Raw].load:
                    stack_name = 'Nucleus Net'
                    match_confidence = MATCH_HIGH
                    break

                # CMX-TCP/IP
                elif re.search(b'^220 CMX TCP/IP - REMOTE FTP Server \(version \w.+\) ready', pkt[Raw].load, re.IGNORECASE) is not None:
                    stack_name = 'CMX-TCP/IP'
                    match_confidence = MATCH_HIGH
                    break

                # emNet
                elif re.search(b'^220 Welcome to embOS/IP FTP server', pkt[Raw].load, re.IGNORECASE) is not None:
                    stack_name = 'emNet'
                    match_confidence = MATCH_HIGH
                    break

                # Keil TCPnet
                elif re.search(b'^220 Keil FTP server', pkt[Raw].load, re.IGNORECASE) is not None:
                    stack_name = 'Keil TCPnet'
                    match_confidence = MATCH_HIGH
                    break

    except Exception as ex:
        if 'Errno 19' in '%s' % ex:
            print('\nERROR: the interface \'{}\' is invalid\n'.format(interface))
        else:
            print('\nERROR: {}\n'.format(ex))

    finally:
        # Cleanup the iptables rule
        if skip_iptables == False:
            subprocess.check_call(['iptables', '-D', 'OUTPUT', '-p', 'tcp',
                                   '--tcp-flags', 'RST', 'RST', '-s', '%s' % ip.src, '-j', 'DROP'])

    return (stack_name, match_confidence)


'''
This function attempts to actively fingerprint the usage of embedded TCP/IP stacks via specific TCP signatures.
'''

def tcpv4_probe(dst_host, dst_port, interface, custom_tcp_opts, skip_iptables, timeout):
    stack_name = None
    stack_name_opts = None
    stack_name_urg = None

    match_confidence = MATCH_NO_MATCH
    match_confidence_opts = MATCH_NO_MATCH
    match_confidence_urg = MATCH_NO_MATCH

    ip = IP(version=0x4, id=0x00fb, dst=dst_host)

    try:
        # We need to set up this rule in order to disable RST packets sent by the Linux kernel
        if skip_iptables == False:
            subprocess.check_call(['iptables', '-I', 'OUTPUT', '-p', 'tcp',
                                   '--tcp-flags', 'RST', 'RST', '-s', '%s' % ip.src, '-j', 'DROP'])

        syn_ack = tcp_handshake(
            dst_host, dst_port, interface, custom_tcp_opts, timeout)
        if syn_ack == None:
            return (None, MATCH_NO_REPLY)

        # Find a TCP options sequence that matches the response
        uip_tcp_opts_match = check_tcp_options(syn_ack[TCP].options, uip_tcp_opts)

        fnet_tcp_opts_match = check_tcp_options(syn_ack[TCP].options, fnet_tcp_opts)

        picotcp_tcp_opts_1_match = check_tcp_options(syn_ack[TCP].options, picotcp_tcp_opts_1)

        picotcp_tcp_opts_2_match = check_tcp_options(syn_ack[TCP].options, picotcp_tcp_opts_2)

        nutnet_tcp_opts_match = check_tcp_options(syn_ack[TCP].options, nutnet_tcp_opts)

        
        cyclone_tcp_opts_match = check_tcp_options(syn_ack[TCP].options, cyclone_tcp_opts)
        timeout2 = timeout

        # Check TCP options for uIP/Contiki
        if uip_tcp_opts_match:
            match_confidence_opts = MATCH_LOW
            stack_name_opts = 'uIP/Contiki'

        # Check TCP options for FNET
        elif fnet_tcp_opts_match:
            match_confidence_opts = MATCH_MEDIUM
            stack_name_opts = 'FNET'
            # FNET may need a bit more time to send the [FIN, ACK] packet
            timeout2 = 20

        # Check TCP options for PicoTCP
        elif picotcp_tcp_opts_1_match or picotcp_tcp_opts_2_match:
            match_confidence_opts = MATCH_MEDIUM
            stack_name_opts = 'PicoTCP'

        # Check TCP options for Nut/Net
        elif nutnet_tcp_opts_match:
            match_confidence_opts = MATCH_LOW
            stack_name_opts = 'Nut/Net'

        # Check TCP options for CycloneTCP
        elif cyclone_tcp_opts_match:
            match_confidence_opts = MATCH_LOW
            stack_name_opts = 'CycloneTCP'

        seqn = syn_ack[TCP].ack
        ackn = syn_ack[TCP].seq+1

        # Send a TCP segment with the Urgent flag set
        urg_pkt = ip/TCP(dport=dst_port, sport=syn_ack[TCP].dport, flags='UA', seq=seqn, ack=ackn, urgptr=0x00)/Raw(load=b'\x41\x41\x41')
        urg_resp = sr1(urg_pkt, timeout=timeout2, iface=interface)

        # Terminate the connection
        rst = ip/TCP(dport=dst_port, sport=syn_ack[TCP].dport, flags='R', seq=seqn, ack=ackn)
        send(rst, iface=interface)

        # Check the response to the packet with the Urgent flag
        if urg_resp:
            if urg_resp[TCP].flags == 'A':
                # Check the Urgent flag response for uIP/Contiki
                if urg_resp[TCP].window in [1240, 1460]:
                    stack_name_urg = 'uIP/Contiki'
                    match_confidence_urg = MATCH_LOW

                # Check the Urgent flag response for Nut/Net
                elif urg_resp[TCP].window == 3213:
                    stack_name_urg = 'Nut/Net'
                    match_confidence_urg = MATCH_LOW

                # Check the Urgent flag response for Nucleus Net
                elif urg_resp[TCP].window == 16000:
                    stack_name_urg = 'Nucleus Net'
                    match_confidence_urg = MATCH_LOW

                # Check the Urgent flag response for CycloneTCP
                elif urg_resp[TCP].window == 2858:
                    stack_name_urg = 'CycloneTCP'
                    match_confidence_urg = MATCH_LOW

                # Check the Urgent flag response for NDKTCPIP
                elif urg_resp[TCP].window == 1024:
                    stack_name_urg = 'NDKTCPIP'
                    match_confidence_urg = MATCH_LOW

                # Check the Urgent flag response for NicheStack
                elif urg_resp[TCP].window in [2048, 3000, 3072, 5840, 8192, 1160, 16384]:
                    stack_name_urg = 'NicheStack'
                    match_confidence_urg = MATCH_LOW

            # Check the Urgent flag response for FNET
            elif urg_resp[TCP].flags == 'FA' and urg_resp[TCP].window == 2048:
                stack_name_urg = 'FNET'
                match_confidence_urg = MATCH_LOW

            elif urg_resp[TCP].flags == 'R':
                # Check the Urgent flag response for PicoTCP
                if urg_resp[TCP].window == 0:
                    stack_name_urg = 'PicoTCP'
                    match_confidence_urg = MATCH_LOW

            elif urg_resp[TCP].flags == 'PA':
                # Make an additional check for NDKTCPIP, in case we are dealing with an TCP echo server
                if urg_resp[TCP].window == 1024:
                    stack_name_urg = 'NDKTCPIP'
                    match_confidence_urg = MATCH_LOW

        # If we have a discrepancy between TCP options and TCP Urgent flag fingerprint...
        if stack_name_opts != stack_name_urg:
            if match_confidence_opts >= match_confidence_urg:
                stack_name = stack_name_opts
                match_confidence = match_confidence_opts
            else:
                stack_name = stack_name_urg
                match_confidence = match_confidence_urg

        # If both fingerprints match the same stack...
        else:
            stack_name = stack_name_opts
            match_confidence = match_confidence_opts + match_confidence_urg

    except Exception as ex:
        if 'Errno 19' in '%s' % ex:
            print('\nERROR: the interface \'{}\' is invalid\n'.format(interface))
        else:
            print('\nERROR: {}\n'.format(ex))

    finally:
        # Cleanup the iptables rule
        if skip_iptables == False:
            subprocess.check_call(['iptables', '-D', 'OUTPUT', '-p', 'tcp',
                                   '--tcp-flags', 'RST', 'RST', '-s', '%s' % ip.src, '-j', 'DROP'])

    return (stack_name, match_confidence)


def is_target_alive(ip_addr, timeout):
    ip = IP(dst=ip_addr, ttl=64, proto=0x01)

    std_icmp_payload = b'\xcd\x69\x08\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17' \
                       b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27' \
                       b'\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37'

    reply = sr1(ip/ICMP(id=0xff, seq=1, type=0x8)/Raw(load=std_icmp_payload), filter='icmp[icmptype] = {}'.format(0x0), timeout=timeout, verbose=0)
    return False if not reply else True


'''
The is the main code block
'''
if __name__ == '__main__':
    conf.verb = 0
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--tcp-port', dest='tcp_dport', default=DEFAULT_TCP_DPORT, type=int, nargs='?', help='known open TCP port (default: {})'.format(DEFAULT_TCP_DPORT))
    parser.add_argument('--http-port', dest='http_dport', default=DEFAULT_HTTP_DPORT, type=int, nargs='?', help='known open HTTP port (default: {})'.format(DEFAULT_HTTP_DPORT))
    parser.add_argument('--ssh-port', dest='ssh_dport', default=DEFAULT_SSH_DPORT, type=int, nargs='?', help='known open SSH port (default: {})'.format(DEFAULT_SSH_DPORT))
    parser.add_argument('--ftp-port', dest='ftp_dport', default=DEFAULT_FTP_DPORT, type=int, nargs='?', help='known open FTP port (default: {})'.format(DEFAULT_FTP_DPORT))
    parser.add_argument('-t', '--timeout', dest='timeout', default=DEFAULT_TIMEOUT, type=int, nargs='?', help='timeout (default: {})'.format(DEFAULT_TIMEOUT))
    parser.add_argument('-i', '--iface', dest='interface', default=None, nargs='?', help='interface name as shown in scapy\'s show_interfaces() function')
    parser.add_argument('-og', '--override-gateway', dest='gw', default=None, const='use_ip_dst', type=str, nargs='?', help='override gateway for ip_dst in scapy routing table')
    parser.add_argument('-st', '--skip-iptables', dest='skip_iptables', default=False, action='store_true', help='do not use iptables to block RST packets')
    parser.add_argument('-f', '--in-file', dest='in_file', default=None, nargs='?', type=str, help='input file path (range of IP addresses to scan)')
    parser.add_argument('-o', '--out-csv', dest='out_csv', default=None, nargs='?', type=str, help='output .csv file path')
    parser.add_argument('ip_dst', default=None, nargs='?', help='destination IP address')
    args = parser.parse_args()

    gw = None
    if args.gw:
        if args.gw == 'use_ip_dst':
            gw = args.ip_dst
        else:
            gw = args.gw

    if gw:
        conf.route.add(host=(args.ip_dst), gw=gw)

    interface = args.interface
    dst_hosts = args.ip_dst
    tcp_dport = args.tcp_dport
    http_dport = args.http_dport
    ssh_dport = args.ssh_dport
    ftp_dport = args.ftp_dport
    timeout = args.timeout
    out_csv = args.out_csv
    in_file = args.in_file
    skip_iptables = args.skip_iptables

    ip_addresses = set()
    if in_file != None:
        in_file = os.path.abspath(in_file)
        with open(in_file) as _f:
            for line in _f:
                try: 
                    addr = ipaddress.IPv4Address(line.replace('\n','').replace('\r',''))
                    ip_addresses.add(addr)
                except ipaddress.AddressValueError as ex:
                    pass

    elif dst_hosts != None:
        try:
            ip_addresses = ipaddress.IPv4Network(dst_hosts)
        except ValueError as ex:
            print(f'\nERROR: Invalid IP address range: {ex}')
    else:
        print('\nERROR: You must specify a valid IP address to scan (either the \'--in-file\', of \'ip_dst\' option.\n')
        parser.print_help()
        sys.exit(1)

    for dst_host in ip_addresses:
        _icmp = 'N/A'
        _tcp  = 'N/A'
        _http = 'N/A'
        _ssh  = 'N/A'
        _ftp  = 'N/A'
        
        dst_host = str(dst_host)
        # exclude broadcast addresses
        if dst_host.endswith('.0') or dst_host.endswith('.255'):
            continue

        # Check if the host is alive before doing anything
        if not is_target_alive(dst_host, 0.3):
            print(f'\n{dst_host} appears to be down')
        else:
            print(f'\n{dst_host} is alive')
            (stack_name, match_confidence) = icmpv4_probe(dst_host, timeout)
            if stack_name:
                print(f'\tICMP => {stack_name} ({match_level_str(match_confidence)})')
                _icmp = f'{stack_name} <- {match_level_str(match_confidence)}'
            else:
                print(f'\tICMP => Unknown ({match_level_str(match_confidence)})')
                _icmp = f'Unknown <- {match_level_str(match_confidence)}'

            if tcp_dport != None:
                (stack_name, match_confidence) = tcpv4_probe(dst_host, tcp_dport, interface, [], skip_iptables, timeout)
                if stack_name:
                    print(f'\tTCP => {stack_name} ({match_level_str(match_confidence)})')
                    _tcp = f'{stack_name} <- {match_level_str(match_confidence)}'
                else:
                    print(f'\tTCP => Unknown ({match_level_str(match_confidence)})')
                    _tcp = f'Unknown <- {match_level_str(match_confidence)}'

            if http_dport != None:
                (stack_name, match_confidence) = httpv4_probe(dst_host, http_dport, interface, skip_iptables, timeout)
                if stack_name:
                    print(f'\tHTTP => {stack_name} ({match_level_str(match_confidence)})')
                    _http = f'{stack_name} <- {match_level_str(match_confidence)}'
                else:
                    print(f'\tHTTP => Unknown ({match_level_str(match_confidence)})')
                    _http = f'Unknown <- {match_level_str(match_confidence)}'

            if ssh_dport != None:
                (stack_name, match_confidence) = sshv4_probe(dst_host, ssh_dport, interface, skip_iptables, timeout)
                if stack_name:
                    print(f'\tSSH => {stack_name} ({match_level_str(match_confidence)})')
                    _ssh = f'{stack_name} <- {match_level_str(match_confidence)}'
                else:
                    print(f'\tSSH => Unknown ({match_level_str(match_confidence)})')
                    _ssh = f'Unknown <- {match_level_str(match_confidence)}'

            if ftp_dport != None:
                (stack_name, match_confidence) = ftpv4_probe(dst_host, ftp_dport, interface, skip_iptables, timeout)
                if stack_name:
                    print(f'\tFTP => {stack_name} ({match_level_str(match_confidence)})')
                    _ftp = f'{stack_name} <- {match_level_str(match_confidence)}'
                else:
                    print(f'\tFTP => Unknown ({match_level_str(match_confidence)})')
                    _ftp = f'Unknown <- {match_level_str(match_confidence)}'

            if out_csv:
                with open(os.path.abspath(out_csv), 'a') as _f:
                    data = [dst_host, _icmp, _tcp, _http, _ssh, _ftp]
                    writer = csv.writer(_f)
                    writer.writerow(data)
