import subprocess
import schedule
import time


def backup_safeguard_folder():
    subprocess.Popen(['python', 'safe_guard_backup.py'])


if __name__ == '__main__':
    print('[+] Ransom Combatant')
    process_monitor = ['python', 'process_monitor.py']
    safe_guard_monitor = ['python', 'safe_guard_monitor.py']
    print('[+] Starting Process Monitor.....')
    subprocess.Popen(process_monitor)
    print('[+] Starting Safe Guard Monitor......')
    subprocess.Popen(safe_guard_monitor)
    print('[+] Scheduling Safe-Guard backup everyday')
    schedule.every().day.at('11:10').do(backup_safeguard_folder)
    while True:
        schedule.run_pending()
        time.sleep(50)