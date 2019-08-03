from Crypto.Cipher import AES
import hashlib
import subprocess
import shlex
import time
import random
from threading import *


lock = Lock()


def encrypt(msg):
    key = hashlib.sha256("password".encode()).digest()
    IV = 'abcdefghijklmnop'
    obj = AES.new(key, AES.MODE_CFB, IV.encode())
    return obj.encrypt(msg.encode())


def decrypt(cipher_text):
    key = hashlib.sha256("password".encode()).digest()
    IV = 'abcdefghijklmnop'
    obj = AES.new(key, AES.MODE_CFB, IV.encode())
    return obj.decrypt(cipher_text)


def change_freq_channel(channel_c):
    print('Channel:',str(channel_c))
    command = 'iwconfig wlan1mon channel '+str(channel_c)
    command = shlex.split(command)
    subprocess.Popen(command, shell=False) # To prevent shell injection attacks !


def channel_thread():
    while True:
        for channel_c in range(1,15):
            t = Thread(target=change_freq_channel,args=(channel_c,))
            t.daemon = True
            lock.acquire()
            t.start()
            time.sleep(0.1)
            lock.release()


def get_mac_addr():
    mac_lst = []
    for x in range(0, 6):
        mac_lst.append(str(random.randint(10, 99)))
    mac_addr = ":".join(mac_lst)
    print(mac_addr)
    return mac_addr
