#!/usr/bin/env python3

import copy
import sys

from checklib.checker import CheckFinished
from pathlib import Path

BASE_DIR = Path(__file__).absolute().resolve().parent
sys.path.insert(0, str(BASE_DIR))

trojan_argv = copy.deepcopy(sys.argv)

from flags_shop_lib import *

class Checker(BaseChecker):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mch = CheckMachine(self)

    def action(self, action, *args, **kwargs):
        try:
            super().action(action, *args, **kwargs)
        except CheckFinished:
            raise
        except Exception as e:
            self.cquit(
                Status.DOWN,
                'Connection error',
                str(e)
            )

    def check(self):
        self.mch.check_sla()
        self.cquit(Status.OK)

    def put(self, flag_id, flag, vuln):
        flag_id, new_flag_id = self.mch.put_flag(flag_id, flag, vuln)
        self.cquit(Status.OK, flag_id, new_flag_id)

    def get(self, flag_id, flag, vuln):
        got_flag = self.mch.get_flag(flag_id, flag, vuln)
        self.assert_eq(got_flag, flag, 'Could not get flag', status=Status.CORRUPT)
        self.cquit(Status.OK)

if __name__ == '__main__':
    c = Checker(trojan_argv[2])
    try:
        c.action(trojan_argv[1], *trojan_argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)

