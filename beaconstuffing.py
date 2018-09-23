#!/usr/bin/env python3

import argparse
import sys
from Crypto.Cipher import AES
import hashlib
import time
import random
import os
try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, rdpcap, Dot11ProbeReq, Dot11ProbeResp, srp, sniff, wrpcap
    from sense_hat import SenseHat
except ModuleNotFoundError or ImportError:
    print("Scapy, nanpy, and sense hat modules not installed on OS")
    pass
from nanpy import (ArduinoApi, SerialManager)


class Util:
    ap_lst = []
    ledPin = 7
    net_SSID = ''
    interface = 'wlan1'


class Dot11Frame:
    '''
    Build IEEE 802.11 frame (beacon or probe request)
    '''
    def __init__(self, interface=Util.interface, net_ssid='', bssid='33:33:33:33:33:33',
                 source='22:22:22:22:22:22', dst='ff:ff:ff:ff:ff:ff'):
        self.source = source
        self.dst = dst
        self.net_ssid = net_ssid
        self.interface = interface + 'mon'
        self.bssid = bssid
        self.rates = "\x03\x12\x96\x18\x24\x30\x48\x60"
        self.dsset = '\x01'

    def base_frame(self, subtype, message=''):
        frame_type = ''
        fc = 0
        if subtype == 4:
            frame_type = Dot11ProbeReq()
        elif subtype == 5:
            frame_type = Dot11ProbeResp()
        elif subtype == 8:
            frame_type = Dot11Beacon(cap='ESS')
        dot11 = Dot11(type='Management', subtype=subtype, FCfield=fc,   # subtype=(4: Probe Request, 8: Beacon)
                      addr1=self.dst,       # Receiver address
                      addr2=self.source,    # Transmitter address
                      addr3=self.bssid)     # BSSID
        essid = Dot11Elt(ID='SSID', info=self.net_ssid, len=len(self.net_ssid))
        base_frame = RadioTap() / dot11 / frame_type / essid
        if not message:
            return []
        data = str.encode(message)
        payload = Dot11Elt(ID='vendor', info=data, len=len(data))
        frame = base_frame / payload
        return frame

    def beacon(self, message=''):
        subtype = 8
        frame = self.base_frame(subtype, message=message)
        print("[*] 802.11 Beacon: SSID = %s" % self.net_ssid)
        sendp(frame, iface=self.interface, inter=0.100, loop=0, verbose=False)
        print("Beacon sent")

    def probe_req(self, message=''):
        subtype = 4
        frame = self.base_frame(subtype, message=message)
        rates = Dot11Elt(ID='Rates', info=self.rates)
        dsset = Dot11Elt(ID='DSset', info=self.dsset)
        frame = frame / rates / dsset
        print("[*] 802.11 Probe Request: SSID = %s" % self.net_ssid)
        srp(frame)

    def probe_resp(self, message):
        subtype = 5
        frame = self.base_frame(subtype, message=message)
        rates = Dot11Elt(ID='Rates', info=self.rates)
        dsset = Dot11Elt(ID='DSset', info=self.dsset)
        frame = frame / rates / dsset
        print("[*] 802.11 Probe Response: SSID = %s" % self.net_ssid)
        sendp(frame, iface=self.interface, inter=0.100, loop=0, verbose=False)


def main():
    '''
    Parses through CLI arguments for either send, receive
    send (--send):
        - prompts user for message to embed in beacon frame
        - file (-f): get message from text file
        - unencrypted (--unencrypted): send unencrypted message to embed in beacon, otherwise send encrypted message
    receive (--receive):
        - sniff packets for beacon frames
        - file (-f): filter beacon with message from .pcap file
        - save (-s): save output of scapy sniffing tool to a .pcap file
    '''
    parse = argparse.ArgumentParser()
    parse.add_argument('--send', action='store_true')
    parse.add_argument('--receive', action='store_true')
    parse.add_argument('--unencrypted', action='store_true')
    parse.add_argument('-f')
    parse.add_argument('-s')
    # parse.add_argument('-h', action='store_true')
    t = sys.argv[1:]
    args = parse.parse_args(t)
    print("Enter SSID to broadcast beacon:")
    net_ssid = input(">>")
    Util.net_ssid = net_ssid
    frame_dir = os.getcwd()
    if args.send and args.f is not None:
        frame = Dot11Frame(net_ssid=net_ssid)
        msg_dir = frame_dir + args.f
        with open(msg_dir, 'r') as f:
            message = ''.join(f.readlines())
        if args.unencrypted is None:
            message = encrypt(message)
        frame.beacon(message)
    elif args.send:
        mac_addr = get_mac_addr()
        frame = Dot11Frame(net_ssid=net_ssid, source=mac_addr)
        while True:
            print("Enter message to broadcast:")
            message = input(">>")
            if message == 'q' or message == 'quit':
                print("Done sending beacons")
                os._exit(0)
            else:
                if args.unencrypted is None:
                    message = encrypt(message)
                frame.beacon(message)
            sniff(iface=frame.interface, prn=send_probe)
    elif args.receive and args.f is None:
        print("[*]Listening on wlan1mon,", 'link-type IEEE802_11_RADIO (802.11 plus radiotap header)')
        packets = sniff(iface='wlan1mon', prn=search_frame)
        if args.s is not None:
            wrpcap(args.s, packets)
    elif args.receive and args.f is not None:
        print("Reading from file:", args.f)
        pcap_dir = frame_dir + args.f
        frames = rdpcap(pcap_dir)
        data = _read_frames(frames, net_ssid)
        print(data)
        # response = "Message received"
        # print(response)
        # frame.probe_req(response)
    # elif args.h is not None:
    #     help_message()


def help_message():
    print("Parses through CLI arguments for either send, receive")
    print("send (--send):")
    print("    - prompts user for message to embed in beacon frame")
    print("    - file (-f): get message from text file")
    print("    - unencrypted (--unencrypted): send unencrypted message to"
          " embed in beacon, otherwise send encrypted message")
    print("receive (--receive):")
    print("    - sniff packets for beacon frames")
    print("    - file (-f): filter beacon with message from .pcap file")
    print("    - save (-s): save output of scapy sniffing tool to a .pcap file")


def setup_arduino():
    '''
    Setup arduino connection
    :return: Arduino API object used to control Arduino UNO
    '''
    a = None
    try:
        connection = SerialManager()
        a = ArduinoApi(connection=connection)
        a.pinMode(Util.ledPin, a.OUTPUT)
    except:
        # arduino_present = False
        # print("Arduino device not found")
        pass
    return a


def setup_sense_hat():
    '''
    Setup sense hat
    :return: sense hat object
    '''
    sense = SenseHat()
    sense.clear()
    return sense


def remove_duplicate(lst):
    final_lst = []
    for num in lst:
        if num not in final_lst:
            final_lst.append(num)
    return final_lst


def encrypt(msg):
    '''
    Encrypts message with AES encryption
    :param msg: base text to be encrypted
    :return: ciphertext
    '''
    key = hashlib.sha256("password".encode()).digest()
    IV = 'abcdefghijklmnop'
    obj = AES.new(key, AES.MODE_CFB, IV.encode())
    return obj.encrypt(msg.encode())


def decrypt(cipher_text):
    '''
    Decrypts cipher text
    :param cipher_text: encrypted data
    :return: decrypted message
    '''
    key = hashlib.sha256("password".encode()).digest()
    IV = 'abcdefghijklmnop'
    obj = AES.new(key, AES.MODE_CFB, IV.encode())
    return obj.decrypt(cipher_text)


def get_mac_addr():
    '''
    Generates randomized arbitrary mac addresses for each beacon built
    :return: mac address
    '''
    mac_lst = []
    for x in range(0, 6):
        mac_lst.append(str(random.randint(10, 99)))
    mac_addr = ":".join(mac_lst)
    # print(mac_addr)
    return mac_addr


def search_frame(packet):
    '''
    Parses through sniffed packets to extract message from stuffed beacon frame
    :param packet: sniffed packet
    '''
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:  # type 4 == ProbRequest
            if packet.addr2 not in Util.ap_lst:
                Util.ap_lst.append(packet.addr2)
                data = bytes.decode(packet.getlayer(Dot11Elt, ID=221).info).strip('\n')
                # print("Source:", packet.addr2)
                print("Embedded beacon message:", data)
                print("Enter response to send to AP")
                response = input(">>")
                mac_addr = get_mac_addr()
                frame = Dot11Frame(net_ssid=Util.net_SSID, source=mac_addr)
                frame.probe_req(response)
                try:
                    a = setup_arduino()
                    if a is not None:
                        a.digitalWrite(Util.ledPin, a.HIGH)
                        time.sleep(2)
                        a.digitalWrite(Util.ledPin, a.LOW)
                except:
                    pass
                try:
                    sense = setup_sense_hat()
                    sense.show_message(data)
                except:
                    # print("Sense Hat not connected")
                    pass


def send_probe(packet):
    # print("Waiting for probe response")
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 4:  # type 4 == ProbRequest
            ssid = bytes.decode(packet.getlayer(Dot11Elt, ID=0).info).strip('\n')
            if packet.addr2 not in Util.ap_lst and ssid == Util.net_SSID:
                Util.ap_lst.append(packet.addr2)
                data = bytes.decode(packet.getlayer(Dot11Elt, ID=221).info).strip('\n')
                print("Client response:", data)
                print("Send response to client")
                message = input(">>")
                mac_addr = get_mac_addr()
                try:
                    frame = Dot11Frame(net_ssid=Util.net_SSID, source=mac_addr)
                    frame.probe_resp(message)
                except BaseException as e:
                    raise ValueError("Dot 11 probe response not constructed properly")


def _read_frames(frame, net_ssid):
    '''
    Parses through pcap file to retrieve message from stuffed beacon frame
    :param frame: pcap file
    :param net_ssid: ssid of access point broadcasting beacon
    :return: msg: message from stuffed beacon frame
    '''
    data = ''
    ssid = str.encode(net_ssid)
    beacons = frame.filter(lambda x: 'Dot11Beacon' in x)                # filter out just the beacon frames
    packets = beacons.filter(lambda x: x.getlayer(Dot11Elt, ID=0, info=ssid))   # filter out beacons with our SSID
    packet_lst = []
    for packet in packets:
        data = packet.getlayer(Dot11Elt, ID=221)
        if data not in packet_lst:
            packet_lst.append(data)
    msg = bytes.decode(data.info).strip('\n')
    return msg


if __name__ == '__main__':
    main()
