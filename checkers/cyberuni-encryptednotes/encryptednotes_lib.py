#!/usr/bin/env python3

import base64
import json
import random
import string
import zlib

from hashlib import sha256
from Crypto.Cipher import AES
from pwn import *

from checklib import *
from service_client import Client as AuthClient

AUTH_PORT = 1234
PORT = 1236

def random_string(min, max):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(random.randint(min, max)))

def get_random_creds():
    username = random_string(8, 24)
    password = random_string(8, 24)
    return username, password

def register_random_user(team_addr):
    try:
        username, password = get_random_creds()
        c = AuthClient(team_addr, AUTH_PORT, username, password, "2")
        c.register()
        return username, password
    except Exception as e:
        raise Exception("Cannot register user on auth service", str(e))

def get_token(team_addr, username, password):
    try:
        c = AuthClient(team_addr, AUTH_PORT, username, password, "2")
        c.login()
        token = c.get_token()
        return token
    except Exception as e:
        raise Exception("Cannot get a token from auth service", str(e))


# OT stuff
class Receiver:
    def __init__(self, b):
        self.b = b

    def round2(self, pk, x):
        N, e = pk
        n = len(x)
        assert n == len(self.b)

        v = []
        k = []
        for i in range(n):
            kk = random.randrange(1 << 2048)
            k.append(kk)
            cur = x[i][self.b[i]] + pow(kk, e, N)
            v.append(cur % N)
        self.k = k
        self.N = N
        return v

    def decode(self, c):
        n = len(c)
        assert n == len(self.b)

        m = []
        for i in range(n):
            mm = (c[i][self.b[i]]-self.k[i]) % self.N
            m.append(mm)
        return m


# GC evaluation
VAL_LENGTH = 5
PAD_LENGTH = 3


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def H(k):
    return sha256(k).digest()


def dec(k, x):
    k = H(k)
    val = xor(k, x)
    if val[:PAD_LENGTH] == b"\0"*PAD_LENGTH:
        return val[PAD_LENGTH:]


def decode_gate(opv, g, ins, to_hex):
    if to_hex:
        ins = [bytes.fromhex(x) for x in ins]
        g = [bytes.fromhex(r) for r in g]
    if opv == "INV":
        res = ins[0]
    elif opv == "XOR":
        res = xor(ins[0], ins[1])
    else:
        for x in g:
            k = b"".join(ins)
            val = dec(k, x)
            if val is not None:
                res = val
                break
    if to_hex:
        return res.hex()
    return res


def evaluate(garbled_circuit, inputs, wires_out, to_hex=True):
    enc_A, enc_B = inputs
    vals = enc_A+enc_B+[None]*len(garbled_circuit)
    for g in garbled_circuit:
        idx, opv, ins, gate = g
        k = [vals[i] for i in ins]
        cur = decode_gate(opv, gate, k, to_hex)
        assert cur is not None
        vals[idx] = cur

    n_outs = len(wires_out)
    vals_out = vals[-n_outs:]
    out = [w.index(v) for v, w in zip(vals_out, wires_out)]
    return out


# Client
def bytes2bits(b):
    bits = ''.join(f'{x:08b}' for x in b)
    return list(map(int, bits))


def bits2bytes(arr):
    n = len(arr)
    assert n % 8 == 0
    nbytes = n // 8
    s = "".join(map(str, arr))
    return int.to_bytes(int(s, 2), nbytes, "big")


class Client:
    def __init__(self, host, token):
        self.r = remote(host, PORT)
        self.r.recvlines(1)
        self.r.sendlineafter(b"token: ", token.encode())

    def set_keyword(self, keyword):
        self.r.recvlines(6)
        self.r.sendlineafter(b"> ", b"1")
        self.r.sendlineafter(b"secret: ", keyword.encode())

    def set_public(self, data):
        self.r.recvlines(6)
        self.r.sendlineafter(b"> ", b"2")
        self.r.sendlineafter(b"text: ", data.encode())

    def get_public(self, user):
        self.r.recvlines(6)
        self.r.sendlineafter(b"> ", b"4")
        self.r.sendlineafter(b"user: ", user.encode())
        return self.r.recvline(False).decode()

    def run_function(self, choice, user, my_in):
        self.r.recvlines(6)
        self.r.sendlineafter(b"> ", b"3")
        self.r.sendlineafter(b"user: ", user.encode())
        self.r.recvlines(3)
        self.r.sendlineafter(b"> ", str(choice).encode())

        data = self.r.recvline(False)
        tmp = zlib.decompress(base64.b64decode(data))
        obj = json.loads(tmp.decode())
        circ = obj["circuit"]

        N, e, x = obj["ot"]["N"], obj["ot"]["e"], obj["ot"]["x"]
        in_B = bytes2bits(my_in)
        assert len(in_B) == 128

        if choice == 2:
            in_B = in_B[::-1]
        receiver = Receiver(in_B)
        v = receiver.round2((N, e), x)
        vdict = json.dumps({"v": v})
        self.r.sendline(vdict.encode())
        data = self.r.recvline(False)
        obj = json.loads(data.decode())
        c = obj["c"]
        m = receiver.decode(c)

        enc_B = [f'{x:010x}' for x in m]

        res = evaluate(circ["gates"], (circ["enc_A"],
                       enc_B), circ["wires_out"])
        if choice == 2:
            res = res[::-1]
        return bits2bytes(res)


# SLA functions
def sla_user_setkeyword(team_addr):
    try:
        username, password = register_random_user(team_addr)
        token = get_token(team_addr, username, password)
        c = Client(team_addr, token)
    except Exception as e:
        raise Exception("Cannot login", str(e))
    try:
        key = random_string(16, 16)
        rdata = random_string(32, 32)
        c.set_keyword(key)
        c.set_public(rdata)
        return username, key
    except Exception as e:
        raise Exception("Cannot put data", str(e))


def sla_user_echo(team_addr, target_user, key):
    try:
        username, password = register_random_user(team_addr)
        token = get_token(team_addr, username, password)
        c = Client(team_addr, token)
    except Exception as e:
        raise Exception("Cannot login", str(e))
    try:
        rdata = os.urandom(16)
        res = c.run_function(1, target_user, rdata)
        if res != rdata:
            raise Exception("Echo function not working", f"sla_user_echo input={rdata.hex()} output={res.hex()}")
    except Exception as e:
        raise Exception("Cannot run echo function", str(e))


def sla_user_encrypt(team_addr, target_user, key):
    try:
        username, password = register_random_user(team_addr)
        token = get_token(team_addr, username, password)
        c = Client(team_addr, token)
    except Exception as e:
        raise Exception("Cannot login", str(e))
    try:
        rdata = os.urandom(16)
        #print("running GC")
        res = c.run_function(2, target_user, rdata)
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        pt = cipher.decrypt(res)
        if pt != rdata:
            raise Exception("Encrypt function not working", f"sla_user_encrypt input={rdata.hex()} key={key} output={res.hex()}")
    except Exception as e:
        raise Exception("Cannot run encrypt function", str(e))


def sla_user_readpublic(team_addr, target_user, key):
    try:
        username, password = register_random_user(team_addr)
        token = get_token(team_addr, username, password)
        c = Client(team_addr, token)
    except Exception as e:
        raise Exception("Cannot login", str(e))
    try:
        res = c.get_public(target_user)
    except Exception as e:
        raise Exception("Cannot read public data", str(e))


# Get flag functions
def get_flag_pubdata(c, target_user, key, flag):
    try:
        pubdata = c.get_public(target_user)
        ct = bytes.fromhex(pubdata)
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        pt = cipher.decrypt(ct)
        if pt.decode() != flag:
            raise Exception("Incorrect public data for flag", f"get_flag_pubdata pubdata={pubdata.hex()} key={key} pt={pt.hex()}")
    except Exception as e:
        raise Exception("Cannot read public data", str(e))


def get_flag_AES(c, target_user, key, flag):
    try:
        ct = c.run_function(2, target_user, flag.encode()[:16])
        #print("run GC")
        pubdata = c.get_public(target_user)
        if ct.hex() != pubdata[:32]:
            raise Exception("Incorrect encryption function for flag", f"get_flag_AES pubdata={pubdata.hex()} ct={ct.hex()}")
    except Exception as e:
        raise Exception("Cannot run encryption function", str(e))


class CheckMachine:
    def __init__(self, checker):
        self.checker = checker
    
    def check_sla(self):
        user, key = sla_user_setkeyword(self.checker.host)
        slas = [sla_user_echo, sla_user_encrypt, sla_user_readpublic]

        f = random.choice(slas)
        f(self.checker.host, user, key)

        return

    def put_flag(self, flag_id, flag, vuln):
        try:
            random.seed("123"+flag+"789")
            key = random_string(16, 16)
            username, password = register_random_user(self.checker.host)
            token = get_token(self.checker.host, username, password)
            c = Client(self.checker.host, token)
        except Exception as e:
            raise Exception("Cannot login", str(e))

        try:
            c.set_keyword(key)
            c.set_public(flag)
        except Exception as e:
            raise Exception("Cannot put data", str(e))
        
        return username, f"{flag_id},{key},{username},{password}"

    def get_flag(self, new_flag_id, flag, vuln):
        try:
            username, password = register_random_user(self.checker.host)
            token = get_token(self.checker.host, username, password)
            c = Client(self.checker.host, token)
        except Exception as e:
            raise Exception("Cannot login", str(e))

        checks = [get_flag_pubdata, get_flag_AES]
        check = random.choice(checks)

        random.seed("123"+flag+"789")
        key = random_string(16, 16)
        username, password = get_random_creds()
        check(c, username, key, flag)
        
        return flag

