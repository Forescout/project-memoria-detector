#!/usr/bin/python
# project-memoria-detector -- detection tool for vulnerable embedded TCP/IP stacks 
# see https://www.forescout.com/research-labs/amnesia33/

# Copyright (C) 2020 Forescout Technologies, Inc.

# Program License

# "The Program" refers to any copyrightable work licensed under this License. Each licensee is addressed as "you."

# All rights granted under this License are granted for the term of copyright on the Program, and are irrevocable provided the stated conditions are met. This License explicitly affirms your unlimited permission to run the unmodified Program for personal, governmental, business or non-profit use. You are prohibited from using the Program in derivative works for commercial purposes. You are prohibited from modifying the Program to be used in a commercial product or service, either alone or in conjunction with other code, either downloadable or accessed as a service. "Derivative works" shall mean any work, whether in source or object form, that is based on (or derived from) the Program and for which the editorial revisions, annotations, elaborations, or other modifications represent, as a whole, an original work of authorship.

# You may convey verbatim copies of the Program's source code as you receive it, in any medium, provided that you conspicuously and appropriately publish on each copy an appropriate copyright notice; keep intact all notices stating that this License applies to the code; keep intact all notices of the absence of any warranty; give all recipients a copy of this License along with the Program; and do not financially benefit from the sale or other conveyance of the Program either alone or in conjunction with other code, downloaded or accessed as a service.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# This License does not grant permission to use the trade names, trademarks, service marks, or product names of the Licensor, except as required for reasonable and customary use in describing the origin of the Program and reproducing the content of the copyright notice.


import sys
import subprocess
import argparse
from binascii import hexlify
from scapy.all import conf, send, sr1, IP, ICMP, TCP, Raw, RandShort
import time

DEFAULT_TCP_DPORT=80
DEFAULT_TIMEOUT=4

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

uip_tcp_opts_1 = [
        ('MSS', 1460),
]

uip_tcp_opts_2 = [
        ('MSS', 1240),
]

nutnet_tcp_opts = [
        ('MSS', 536),
]

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

# MATCHES
MATCH_VUL=3
MATCH_POT=2
MATCH_POT_WEAK=1
MATCH_OTHER=0
MATCH_NO_REPLY=-1

def match_level_str(match_level):
    if match_level >= MATCH_VUL:
        return 'High'
    elif match_level == MATCH_POT:
        return 'Medium'
    elif match_level == MATCH_POT_WEAK:
        return 'Low'
    elif match_level == MATCH_OTHER:
        return 'No match'
    return 'No reply'

'''
This function attempts to actively fingerprint the usage of embedded TCP/IP stacks via ICMPv4 echo requests.
The function performs malformed ICMPv4 echo requests and checks for specific ICMPv4 echo replies.

Based on the response seen, it returns the 'stack_name' string that suggests which embedded TCP/IP stack is used in the DUT.
(currently, only PicoTCP and uIP/Contiki signatures are available)

If none of the expected responses was seen, 'None' is returned.
A match status is also returned (see MATCHES)

'''
def icmpv4_probe(dst_host, timeout):
    icmptype_i=0x8
    icmptype_name_i='ICMP ECHO'
    icmptype_o=0x0
    icmptype_name_o='ICMP ECHO_REPLY'

    response = None
    response2 = None 
    stack_name = ''
    match = ''

    # Send a normal ICMP packet with a 'seq' number other than zero, just to ensure the seq counter at picoTCP is
    # changed and the next packet will be accepted.
    r = sr1(IP(dst=dst_host, ttl=20)/ICMP(id=0xff, seq=1, type=icmptype_i),filter='icmp[icmptype] = {}'.format(icmptype_o), timeout=timeout)
    if not r:
        return (stack_name, match_level_str(MATCH_NO_REPLY))

    # Prepare a malformed ICMP packet
    icmp_raw = b'\x08\x01\x02'
    ipv4_probe = IP(dst=dst_host, ttl=20, proto=0x01)/Raw(load=icmp_raw)

    # Send the malformed ICMP packet
    # If we get the expected response it is either PicoTCP or uIP/Contiki:
    #   - we first check that the TTL value of the echo packet is changed into 64 for the reply packet
    #   - we then check the payload sequence of the echo reply packet
    response = sr1(ipv4_probe, filter='icmp[icmptype] = {}'.format(icmptype_o), timeout=timeout)
    if response:
        if (response.ttl == 64):
            if (hexlify(response.load) == b'0001ff'):
                match = MATCH_VUL 
                stack_name = 'PicoTCP'
            elif (hexlify(response.load) == b'00010a'):
                match = MATCH_VUL
                stack_name = 'uIP/Contiki'
        if not match:
            match = MATCH_OTHER

    else: # we did not get a reply for the first malformed packet
        _id = 0xab
        _seq = 0xba
        # Nut/Net should reply to ICMP packets with incorrect IP and ICMP checksums
        ipv4_probe = IP(dst=dst_host, ttl=20, chksum=0xdead)/ICMP(id=_id, seq=_seq, type=icmptype_i, chksum=0xbeaf)
        response = sr1(ipv4_probe, filter='icmp[icmptype] = {}'.format(icmptype_o), timeout=timeout)
        if response:
            if (response.ttl == 64):
                if (response[ICMP].id == _id and response[ICMP].seq == _seq and response[ICMP].type == 0x00):
                    match = MATCH_POT_WEAK
                    stack_name = 'Nut/Net'
        if not match:
            match = MATCH_OTHER # no reply for the second malformed packet

    return (stack_name, match_level_str(match))


'''
This function attempts to actively fingerprint the usage of embedded TCP/IP stacks via specific TCP signatures.
'''
def tcpv4_probe(dst_host, dst_port, interface, use_fw, timeout):
    # Use the default interface if none is provided
    if interface == None:
        interface = conf.iface

    src_ip_addr = None
    stack_name_tcp = None
    match_tcp = MATCH_NO_REPLY
    stack_name_tcp_opts = None
    stack_name_tcp_urg  = None
    match_tcp_opts = MATCH_OTHER
    match_tcp_urg  = MATCH_OTHER

    try:
        seqn = 0
        ip_lyr = IP(version=0x4, id=0x00fb, dst=dst_host)
        src_port = int(RandShort()._fix()/2+2**15)
        syn = ip_lyr/TCP(dport=dst_port, sport=src_port, flags='S', seq=seqn)

        # We need to set up this rule in order to disable RST packets sent by the Linux kernel
        src_ip_addr = syn.src
        if use_fw:
            subprocess.check_call(['iptables', '-A', 'OUTPUT', '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-s', '%s' % src_ip_addr, '-j', 'DROP'])

        syn_ack = sr1(syn, timeout=timeout, iface=interface)
        if not syn_ack or 'R' in syn_ack[TCP].flags:
            return (None, match_level_str(MATCH_NO_REPLY))

        # check the TCP options sequence
        uip_tcp_opts_1_match = check_tcp_options(syn_ack[TCP].options, uip_tcp_opts_1)
        uip_tcp_opts_2_match = check_tcp_options(syn_ack[TCP].options, uip_tcp_opts_2)
        fnet_tcp_opts_match = check_tcp_options(syn_ack[TCP].options, fnet_tcp_opts)
        picotcp_tcp_opts_1_match = check_tcp_options(syn_ack[TCP].options, picotcp_tcp_opts_1)
        picotcp_tcp_opts_2_match = check_tcp_options(syn_ack[TCP].options, picotcp_tcp_opts_2)
        nutnet_tcp_opts_match = check_tcp_options(syn_ack[TCP].options, nutnet_tcp_opts)
        timeout2=timeout

        if uip_tcp_opts_1_match or uip_tcp_opts_2_match: 
            match_tcp_opts = MATCH_POT_WEAK 
            stack_name_tcp_opts = 'uIP/Contiki'
        elif fnet_tcp_opts_match:
            match_tcp_opts = MATCH_POT
            stack_name_tcp_opts = 'FNET'
            timeout2=20 # FNET may need a bit more time to send the [FIN, ACK] packet
        elif picotcp_tcp_opts_1_match or picotcp_tcp_opts_2_match:
            match_tcp_opts = MATCH_POT
            stack_name_tcp_opts = 'PicoTCP'
        elif nutnet_tcp_opts_match:
            match_tcp_opts = MATCH_POT_WEAK
            stack_name_tcp_opts = 'Nut/Net' 

        seqn += 1
        ackn = syn_ack[TCP].seq + 1

        ack = ip_lyr/TCP(dport=dst_port, sport=src_port, flags='A', seq=seqn, ack=ackn)
        send(ack, iface=interface)

        tcp_data = b'\x41\x41'
        urgent_offset = 0x00

        urg_pkt  = ip_lyr/TCP(dport=dst_port, sport=src_port, flags='UA', seq=seqn, ack=ackn, urgptr=urgent_offset)/Raw(load=tcp_data)
        urg_resp = sr1(urg_pkt, timeout=timeout2, iface=interface)

        # Check the response to the packet with the Urgent flag set
        if urg_resp:
            stack_name_tcp_urg = None
            match_tcp_urg = MATCH_OTHER

            if urg_resp[TCP].flags == 'A':
                if urg_resp[TCP].window == 1240 or urg_resp[TCP].window == 1460:
                    stack_name_tcp_urg = 'uIP/Contiki'
                    match_tcp_urg = MATCH_POT_WEAK
                elif urg_resp[TCP].window == 3214:
                    stack_name_tcp_urg = 'Nut/Net'
                    match_tcp_urg = MATCH_POT_WEAK

            elif urg_resp[TCP].flags == 'FA' and urg_resp[TCP].window == 2048:
                stack_name_tcp_urg = 'FNET'
                match_tcp_urg = MATCH_POT_WEAK
            elif urg_resp[TCP].flags == 'R' and urg_resp[TCP].window == 0:
                stack_name_tcp_urg = 'PicoTCP'
                match_tcp_urg = MATCH_POT_WEAK


        # If we have a discrepancy between TCP options and TCP Urgent flag fingerprint...
        if stack_name_tcp_opts != stack_name_tcp_urg:
            if match_tcp_opts >= match_tcp_urg:
                stack_name_tcp = stack_name_tcp_opts
                match_tcp = match_tcp_opts
            else:
                stack_name_tcp = stack_name_tcp_urg
                match_tcp = match_tcp_urg

        # If both fingerprints match the same stack...
        else:
            stack_name_tcp = stack_name_tcp_opts
            match_tcp = match_tcp_opts + match_tcp_urg

        # Terminate the connection
        rst = ip_lyr/TCP(dport=dst_port, sport=src_port, flags='R', seq=seqn, ack=ackn)
        send(rst, iface=interface)

    except Exception as ex:
        if 'Errno 19' in '%s' % ex:
            print('\nERROR: the interface \'{}\' is invalid\n'.format(interface))
        else:
            print('\nERROR: {}\n'.format(ex))

    finally:
        # Cleanup the iptables rule
        if use_fw:
            if src_ip_addr != None:
                subprocess.check_call(['iptables', '-D', 'OUTPUT', '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-s', '%s' % src_ip_addr, '-j', 'DROP'])

    return (stack_name_tcp, match_level_str(match_tcp))

'''
The is the main code block
'''
if __name__ == '__main__':
    conf.verb = 0 # make Scapy silent

    parser = argparse.ArgumentParser()
    parser.add_argument('ip_dst', help='destination IP address')
    parser.add_argument('-p', '--port', dest='tcp_dport', default=DEFAULT_TCP_DPORT, type=int, nargs='?', help='known open TCP port (default: {})'.format(DEFAULT_TCP_DPORT))
    parser.add_argument('-t', '--timeout', dest='timeout', default=DEFAULT_TIMEOUT, type=int, nargs='?', help='timeout (default: {})'.format(DEFAULT_TIMEOUT))
    parser.add_argument('-i', '--iface', dest='interface', default=None, nargs='?', help='interface name as shown in scapy\'s show_interfaces() function')
    parser.add_argument('-og', '--override-gateway', dest='gw', default=None, const='use_ip_dst', type=str, nargs='?', help='override gateway for ip_dst in scapy routing table')
    parser.add_argument('-fw', '--override-firewall', dest='fw', default=True, const=True, type=bool, nargs='?', help='override firewall')
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
    dst_host = args.ip_dst
    dst_port = args.tcp_dport
    timeout = args.timeout
    fw = args.fw

    if dst_host != None:
        print('{}'.format(dst_host))
        (stack_name_icmp, match_icmp) = icmpv4_probe(dst_host, timeout)
        if stack_name_icmp:
            print('\tICMP fingerprint => the host {} may be running the {} TCP/IP stack ({} level of confidence)'.format(dst_host, stack_name_icmp, match_icmp))
        else:
            print('\tICMP fingerprint => failed to determine the TCP/IP stack (reason: {})'.format(match_icmp))

        if dst_port != None:
            (stack_name_tcp, match_tcp) = tcpv4_probe(dst_host, dst_port, interface, fw, timeout)
            if stack_name_tcp:
                print('\tTCP fingerprint => the host {} may be running the {} TCP/IP stack ({} level of confidence)\n'.format(dst_host, stack_name_tcp, match_tcp))
            else:
                print('\tTCP fingerprint => failed to determine the TCP/IP stack (reason: {})\n'.format(match_tcp))
