import os
import math
import struct
import random
import logging

MAX_MIX = 2048
MIN_MIX = 16
MIX_FACTOR = 3
MIX_SEED = MAX_MIX - MIN_MIX


class TcpFIN(Exception):
    pass


class Mix(object):
    def __init__(self):
        self.randint = random.SystemRandom().randint
        self.mix_up_factor = 0

    def add_mix_up(self, data):
        mix_len = self.get_random() - 4
        send_data = struct.pack("HH", len(data), mix_len)
        send_data += data
        send_data += '\x00' * mix_len
        return send_data

    def split_mix_up(self, sock):
        data = read_all(sock, 4)
        data_len, mix_len = struct.unpack("HH", data)
        data = read_all(sock, data_len)
        read_all(sock, mix_len)
        return data

    def get_random(self):
        if self.mix_up_factor > MIX_FACTOR * 10:
            seed = MIN_MIX
        else:
            seed = int(MIX_SEED * math.pow(2, -self.mix_up_factor/MIX_FACTOR)) + MIN_MIX
            self.mix_up_factor += 1
        return self.randint(seed >> 2, seed + MIN_MIX)


def filepath(f):
    return os.path.join(os.path.split(os.path.realpath(__file__))[0], f)


def send_all(sock, data):
    bytes_sent = 0
    con = 0
    while 1:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent
        con = con + 1
        if con > 20:
            raise Exception('send too many times!')


def read_all(sock, data_len):
    data = ''
    while data_len > 0:
        d = sock.recv(data_len)
        if len(d) <= 0:
            if len(data) > 0:
                raise Exception('read_all read error!')
            else:
                raise TcpFIN('read_all sock FIN!')
        data += d
        data_len -= len(d)
    return data


#copy from SS
def set_user(username):
    if username is None:
        return

    import pwd
    import grp

    try:
        pwrec = pwd.getpwnam(username)
    except KeyError:
        logging.error('user not found: %s' % username)
        raise
    user = pwrec[0]
    uid = pwrec[2]
    gid = pwrec[3]

    cur_uid = os.getuid()
    if uid == cur_uid:
        return
    if cur_uid != 0:
        logging.error('can not set user as nonroot user')
        # will raise later

    # inspired by supervisor
    if hasattr(os, 'setgroups'):
        groups = [grprec[2] for grprec in grp.getgrall() if user in grprec[3]]
        groups.insert(0, gid)
        os.setgroups(groups)
    os.setgid(gid)
    os.setuid(uid)
