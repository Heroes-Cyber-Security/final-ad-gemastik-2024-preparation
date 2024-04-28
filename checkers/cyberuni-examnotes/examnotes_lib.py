#!/usr/bin/env python3

import random
import string

from pwn import *

from checklib import *
from service_client import Client

AUTH_PORT = 1234
PORT = 1235

def get_random_string(n):
    alph = string.ascii_letters + string.digits
    return "".join(random.choice(alph) for _ in range(n))

class CheckMachine:
    def __init__(self, checker):
        self.checker = checker
    
    def check_sla(self):
        number_of_notes = random.randint(1, 5)
        username = get_random_string(random.randint(10, 16))
        password = get_random_string(random.randint(10, 16))
        note_titles = [get_random_string(random.randint(10, 16)) for _ in range(number_of_notes)]
        note_contents = [get_random_string(random.randint(20, 100)) for _ in range(number_of_notes)]

        c = Client(self.checker.host, AUTH_PORT, username, password, "1")
        
        try:
            c.register()
        except Exception as e:
            raise Exception("Cannot register", str(e))

        try:
            c.login()
            login_token = c.get_token()
        except Exception as e:
            raise Exception("Cannot get login token from auth", str(e))

        try:
            r = remote(self.checker.host, PORT)
        except Exception as e:
            raise Exception("Cannot connect to ExamNotes", str(e))

        try:
            r.recvuntil(b": ")
            r.sendline(login_token.encode())
            r.recvline()
            assert r.recvline().startswith(b"Successfully authenticated")
        except Exception as e:
            raise Exception("Cannot login via token on ExamNotes", str(e))

        try:
            for i in range(number_of_notes):
                r.recvuntil(b'0. Exit\n')
                r.sendline(b"1")
                r.recvuntil(b": ")
                r.sendline(note_titles[i].encode())
                r.recvuntil(b": ")
                r.sendline(note_contents[i].encode())
                assert b"added" in r.recvline()
            r.close()
        except Exception as e:
            raise Exception("Cannot create a new note on ExamNotes", str(e))

        try:
            r = remote(self.checker.host, PORT)
        except Exception as e:
            raise Exception("Cannot connect to ExamNotes", str(e))

        try:
            r.recvuntil(b": ")
            r.sendline(login_token.encode())
            r.recvline()
            assert r.recvline().startswith(b"Successfully authenticated")
        except Exception as e:
            raise Exception("Cannot login via token on ExamNotes", str(e))

        try:
            for _ in range(random.randint(1, 3)):
                if random.randint(0, 1) == 0:
                    r.recvuntil(b'0. Exit\n')
                    r.sendline(b"2")
                    recovered_notes = r.recvlines(number_of_notes)
                    assert all([note_titles[i].encode() in b"".join(recovered_notes) for i in range(number_of_notes)])
                else:
                    r.recvuntil(b'0. Exit\n')
                    r.sendline(b"3")
                    r.recvuntil(b": ")
                    note_id = random.randint(0, number_of_notes-1)
                    r.sendline(str(note_id).encode())
                    assert note_titles[note_id].encode() in r.recvline()
                    assert note_contents[note_id].encode() in r.recvline()
        except Exception as e:
            raise Exception("Cannot list or read notes on ExamNotes", str(e))
        
        return
    
    def put_flag(self, flag_id, flag, vuln):
        random.seed(int.from_bytes(flag.encode(), "big"))
        username = get_random_string(random.randint(10, 16))
        password = get_random_string(random.randint(10, 16))
        
        c = Client(self.checker.host, AUTH_PORT, username, password, "1")
        
        try:
            c.register()
        except Exception as e:
            raise Exception("Cannot register", str(e))

        try:
            c.login()
            login_token = c.get_token()
        except Exception as e:
            raise Exeption("Cannot get login token from auth", str(e))

        try:
            r = remote(self.checker.host, PORT)
        except Exception as e:
            raise Exception("Cannot connect to ExamNotes", str(e))

        try:
            r.recvuntil(b": ")
            r.sendline(login_token.encode())
            r.recvline()
            assert r.recvline().startswith(b"Successfully authenticated")
        except Exception as e:
            raise Exception("Cannot login via token on ExamNotes", str(e))

        try:
            r.recvuntil(b'0. Exit\n')
            r.sendline(b"1")
            r.recvuntil(b": ")
            r.sendline(b"flag")
            r.recvuntil(b": ")
            r.sendline(flag.encode())
            assert b"added" in r.recvline()
            r.close()
        except Exception as e:
            raise Exception("Cannot create a new note on ExamNotes", str(e))
        
        return username, f'{flag_id},{username},{password}'
    
    def get_flag(self, new_flag_id, flag, vuln):
        random.seed(int.from_bytes(flag.encode(), "big"))
        username = get_random_string(random.randint(10, 16))
        password = get_random_string(random.randint(10, 16))

        c = Client(self.checker.host, AUTH_PORT, username, password, "1")
        
        try:
            c.login()
            login_token = c.get_token()
        except Exception as e:
            raise Exception("Cannot get login token from auth", str(e))

        try:
            r = remote(self.checker.host, PORT)
        except Exception as e:
            raise Exception("Cannot connect to ExamNotes", str(e))
        
        try:
            r.recvuntil(b": ")
            r.sendline(login_token.encode())
            r.recvline()
            assert r.recvline().startswith(b"Successfully authenticated")
        except Exception as e:
            raise Exception("Cannot login via token on ExamNotes", str(e))

        try:
            r.recvuntil(b'0. Exit\n')
            r.sendline(b"3")
            r.recvuntil(b": ")
            note_id = 0
            r.sendline(str(note_id).encode())
            assert b"flag" in r.recvline()
            assert flag.encode() in r.recvline()
        except Exception as e:
            raise Exception("Cannot retrieve flag", str(e))
            
        return flag

