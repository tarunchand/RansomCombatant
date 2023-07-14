import psutil
import time
import threading
import json

from config import Config
from detect_ransomware import DetectRansomware


def get_current_running_process():
    running_process = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            # Get process info as named tuple (pid, name)
            proc_info = proc.as_dict(attrs=['pid', 'name'])
            running_process.append((proc_info['pid'], proc_info['name']))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return running_process


lock = threading.Lock()


class ProcessesToMonitor:
    global lock

    def __init__(self):
        self.processes = dict()

    def add_item(self, pid, process_name):
        with lock:
            self.processes[pid] = process_name

    def remove_item(self, pid):
        with lock:
            self.processes[pid] = None

    def get_processes_to_monitor(self):
        with lock:
            return self.processes


processes_to_monitor = ProcessesToMonitor()


def monitor_process():
    print('[+] Monitoring Process')
    global processes_to_monitor
    previous_processes = get_current_running_process()

    while True:
        try:
            current_processes = get_current_running_process()

            # Find the new and exited processes
            new_processes = [p for p in current_processes if p not in previous_processes]
            exited_processes = [p for p in previous_processes if p not in current_processes]

            # Print the new and exited processes
            for pid, name in new_processes:
                print("New process started: PID={} Name={}".format(pid, name))
                processes_to_monitor.add_item(pid, name)

            for pid, name in exited_processes:
                print("Process exited: PID={} Name={}".format(pid, name))
                processes_to_monitor.remove_item(pid)

            # Update the previous list of processes and wait for 1 second before updating again
            previous_processes = current_processes
            time.sleep(1)
        except KeyboardInterrupt:
            exit(0)
        except (OSError, Exception) as _:
            print('[!] Exception in Monitoring Process')


def monitor_resource_activity():
    global processes_to_monitor
    ransomware_detection = DetectRansomware()
    results = dict()
    cur_count = 21
    while True:
        if cur_count > 999999:  # To prevent integer overflow
            cur_count = 1
        if (cur_count % Config.DUMP_INTERVAL) == 0:
            if ransomware_detection.resource_activity_detection(results):
                ransomware_detection.take_action_on_ransomware_detection()
            with open('resource_activity', 'w') as f:
                json.dump(results, f)
        cur_count += 1
        try:
            processes = processes_to_monitor.get_processes_to_monitor()
            for pid, name in processes.items():
                if name is None:
                    continue
                try:
                    process_obj = psutil.Process(pid)
                except (psutil.NoSuchProcess, Exception):
                    continue
                process_key = str(pid) + ':' + name
                if not results.get(process_key, False):
                    results[process_key] = dict({
                        'cpu_percent': [process_obj.cpu_percent()],
                        'ram': [process_obj.memory_info().rss],
                        'read_count': [process_obj.io_counters().read_count],
                        'write_count': [process_obj.io_counters().write_count],
                        'read_bytes': [process_obj.io_counters().read_bytes],
                        'write_bytes': [process_obj.io_counters().write_bytes]
                        })
                else:
                    results[process_key]['cpu_percent'].append(process_obj.cpu_percent())
                    results[process_key]['ram'].append(process_obj.memory_info().rss)
                    results[process_key]['read_count'].append(process_obj.io_counters().read_count)
                    results[process_key]['write_count'].append(process_obj.io_counters().write_count)
                    results[process_key]['read_bytes'].append(process_obj.io_counters().read_bytes)
                    results[process_key]['write_bytes'].append(process_obj.io_counters().write_bytes)
            time.sleep(1)
        except KeyboardInterrupt:
            exit(0)
        except Exception as ex:
            print('[!] Exception in monitoring resource activity')
            print(ex)


def monitor_network_activity():
    ransomware_detection = DetectRansomware()
    global processes_to_monitor
    results = dict()
    cur_count = 1
    while True:
        if cur_count > 999999:  # To prevent integer overflow
            cur_count = 1
        if (cur_count % Config.DUMP_INTERVAL) == 0:
            if ransomware_detection.network_based_activity_detection(results):
                ransomware_detection.take_action_on_ransomware_detection()
            with open('network_activity', 'w') as f:
                json.dump(results, f)
        cur_count += 1
        try:
            processes = processes_to_monitor.get_processes_to_monitor()
            for pid, name in processes.items():
                if name is None:
                    continue
                try:
                    process_obj = psutil.Process(pid)
                except (psutil.NoSuchProcess, Exception):
                    continue
                connections = process_obj.connections()
                for conn in connections:
                    process_key = str(pid) + ':' + name
                    network_activity = dict({
                            'family': str(conn.family), 
                            'type': str(conn.type),
                            'laddr': str(conn.laddr),
                            'raddr': str(conn.raddr),
                            'status': conn.status
                            })
                    if not results.get(process_key, False):
                        results[process_key] = [network_activity]
                    else:
                        results[process_key].append(network_activity)
            time.sleep(10)
        except KeyboardInterrupt:
            exit(0)
        except Exception as ex:
            print('[!] Exception in monitoring network activity')
            print(ex)


if __name__ == '__main__':
    t1 = threading.Thread(target=monitor_process)
    t2 = threading.Thread(target=monitor_resource_activity)
    t3 = threading.Thread(target=monitor_network_activity)

    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()
