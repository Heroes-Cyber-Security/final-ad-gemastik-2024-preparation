#!/usr/bin/env python3

import requests

from checklib import *

challenge = 'xl'

auth_header = {
    'Authorization':  'Basic YWRtaW46YWRtaW4='
}

class CheckMachine:
    def __init__(self, checker):
        self.checker = checker

    def check_sla(self):
        r = requests.get(f'http://{self.checker.host}/check/{challenge}', timeout=2, headers=auth_header)
        self.checker.check_response(r, 'Check failed')

    def put_flag(self, flag_id, flag, vuln):
        body = {
            'flag': flag,
            'challenge': challenge
        }
        r = requests.post(f'http://{self.checker.host}/flag', timeout=2, json=body, headers=auth_header)
        self.checker.check_response(r, 'Could not put flag')
        return flag_id, flag_id

    def get_flag(self, new_flag_id, flag, vuln):
        flag_id, password = new_flag_id.split(',')
        r = requests.get(f'http://{self.checker.host}:{PORT}/get_flag/{flag_id}/{password}', timeout=2)
        self.checker.assert_in('Flag:', r.text, 'Could not get flag', status=Status.CORRUPT)
        return r.text.split()[1]

