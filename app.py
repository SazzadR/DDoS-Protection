import os
import re
import math
import time
import json
import config
import subprocess

def func_collect_http_info():
    shell_command = "netstat -ntu | awk \'{print $5}\' | cut -d: -f1 | sort | uniq -c | sort -nr"
    result = subprocess.check_output(shell_command, shell=True)
    result = str(result)
    result = result.replace('\\n', '\n')

    f = open('request_status.txt', 'w')
    f.write(result)
    f.close()

def func_block_suspicious_connections():
    new_suspicious_connections = []

    f = open('request_status.txt', 'r')

    for line in f.readlines():
        hit_counts   = re.findall(r'^\D*(\d+)', line)
        ip_addresses = re.findall(r'(?:\d{1,3}\.)+(?:\d{1,3})', line)

        if (len(hit_counts) and len(ip_addresses)):
            ip_address = ip_addresses[0]
            hit_count  = hit_counts[0]

            if (int(hit_count) > config.REQUEST_LIMIT):

                existing_blocked_connections = func_existing_blocked_connections()
                existing_blocked_ips = func_ips_from_records(existing_blocked_connections)

                if ip_address not in existing_blocked_ips:
                    block_command = 'iptables -A INPUT -s ' + ip_address + ' -j DROP'
                    subprocess.check_output(block_command, shell=True)

                    save_command = 'iptables-save'
                    subprocess.check_output(save_command, shell=True)

                    record = {
                        'ip': ip_address,
                        'time_of_block': int(round(time.time() * 1000))
                    }
                    new_suspicious_connections.append(record)

    func_record_new_suspicious_connections(new_suspicious_connections)

def func_existing_blocked_connections():
    with open('blocked_list.txt') as blocked_list:
        try:
            existing_blocked_connections = json.load(blocked_list)
        except ValueError:
            existing_blocked_connections = []

    return existing_blocked_connections

def func_ips_from_records(connections):
    result = []
    for record in connections:
        result.append(record['ip'])

    return result

def func_record_new_suspicious_connections(new_suspicious_connections):
    # Get existing blocked ip(s)
    existing_blocked_connections = func_existing_blocked_connections()
    existing_blocked_ips = func_ips_from_records(existing_blocked_connections)

    result = existing_blocked_connections

    for new_record in new_suspicious_connections:
        if new_record['ip'] not in existing_blocked_ips:
            result.append(new_record)

    result = json.dumps(result)

    f = open('blocked_list.txt', 'w')
    f.write(result)
    f.close()

def func_unblock():
    current_timestamp = int(round(time.time() * 1000))

    existing_blocked_connections = func_existing_blocked_connections()
    for blocked_connection in existing_blocked_connections:
        time_diff_in_second = math.floor((current_timestamp - blocked_connection['time_of_block']) / 1000)
        if (time_diff_in_second > config.BlOCKAGE_TIME):
            unblock_command = 'iptables -D INPUT -s ' + blocked_connection['ip'] + ' -j DROP'
            subprocess.check_output(unblock_command, shell=True)

            save_command = 'iptables-save'
            subprocess.check_output(save_command, shell=True)

            existing_blocked_connections.remove(blocked_connection)

    result = json.dumps(existing_blocked_connections)

    f = open('blocked_list.txt', 'w')
    f.write(result)
    f.close()



file_for_blocked_exists = os.path.isfile('./blocked_list.txt')

if (not file_for_blocked_exists):
    file_create_command = "touch blocked_list.txt"
    result = subprocess.check_output(file_create_command, shell=True)

func_collect_http_info()
func_block_suspicious_connections()
func_unblock()
