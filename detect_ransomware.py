import pickle
import subprocess
import os

from config import Config


class DetectRansomware:

    def __init__(self):
        self.rf_model = None
        with open('detect_ransomware.pkl', 'rb') as f:
            self.rf_model = pickle.load(f)

    def resource_activity_detection(self, results):
        try:
            for key, val in results.items():
                process_name = key.split(':')[1]
                if process_name in Config.WHITELIST:
                    continue
                cpu = sum(val['cpu_percent'])/len(val['cpu_percent'])
                ram = sum(val['ram'])/len(val['ram'])
                read_bytes = sum(val['read_bytes'])/len(val['read_bytes'])
                write_bytes = sum(val['write_bytes'])/len(val['write_bytes'])
                read_count = sum(val['read_count'])/len(val['read_count'])
                write_count = sum(val['write_count'])/len(val['write_count'])
                detection = self.rf_model.predict([[cpu, ram, read_bytes, write_bytes, read_count, write_count]])[0]
                if detection == 1:
                    return True
            return False
        except (IndexError, Exception):
            return False

    def network_based_activity_detection(self, results):
        try:
            for key, val in results.items():
                process_name = key.split(':')[1]
                if process_name in Config.WHITELIST:
                    for network_activity in val:
                        raddr = network_activity['raddr'].split(',')[0].replace("'", "").replace('"', '')[8:]
                        if raddr in Config.SUSPECTED_RADDR:
                            return True
                        rdns = self.do_reverse_dns_lookup(raddr)
                        if (rdns is not None) and (rdns in Config.SUSPECTED_RDNS):
                            return True
            return False
        except (IndexError, OSError, Exception):
            return False

    @staticmethod
    def do_reverse_dns_lookup(ip_address):
        try:
            output = subprocess.check_output(['nslookup', ip_address], universal_newlines=True)
            hostname = output.split('Name: ')[1].split()[0]
            return hostname
        except (subprocess.CalledProcessError, OSError, Exception):
            return None

    @staticmethod
    def take_action_on_ransomware_detection():
        print('[!] Ransomware Detected !!!!!!!!!!!!!!!!!!!')
        print('[+] Shutting down the system')
        os.system("shutdown /s /t 1")
