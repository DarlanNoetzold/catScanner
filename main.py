import sys
import argparse
import subprocess
import os
import time
import threading
import re
import random
from urllib.parse import urlsplit

CURSOR_UP = '\x1b[1A'
ERASE_ONE_LINE = '\x1b[2K'

time_intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
)

class output_bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT = '\033[41m'  # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT = '\033[43m'
    BG_LOW_TXT = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END = '\x1b[0m'

proc_high = output_bcolors.BADFAIL + "●" + output_bcolors.ENDC
proc_med = output_bcolors.WARNING + "●" + output_bcolors.ENDC
proc_low = output_bcolors.OKGREEN + "●" + output_bcolors.ENDC

def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)

class control_program:
    busy = False
    delay = 0.015

    @staticmethod
    def control_program_cursor():
        while 1:
            for cursor in ' ': yield cursor

    def __init__(self, delay=None):
        self.control_program_generator = self.control_program_cursor()
        if delay and float(delay): self.delay = delay
        self.disabled = False

    def control_program_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    x = output_bcolors.BG_SCAN_TXT_START + next(self.control_program_generator) + output_bcolors.BG_SCAN_TXT_END
                    inc = inc + 1
                    print(x, end='')
                    if inc > random.uniform(0, terminal_size()):  # 30 init
                        print(end="\r")
                        output_bcolors.BG_SCAN_TXT_START = '\x1b[6;30;' + str(round(random.uniform(40, 47))) + 'm'
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            print(
                "\n\t" + output_bcolors.BG_ERR_TXT + "CatScanner are Quitting..." + output_bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.control_program_task).start()
        except Exception as e:
            print("\n")

    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            print(
                "\n\t" + output_bcolors.BG_ERR_TXT + "CatScanner are Quitting..." + output_bcolors.ENDC)
            sys.exit(1)

control_program = control_program()

