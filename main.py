# necessary python modules 
import re 
from collections import defaultdict

# reading the imported file  
def readFirewallLogs(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

# taking log enrty to split it into fileds from categorizing 
def takeLogEntry(log_entry):
    fields = log_entry.split()
    return {
        'date': fields[0],
        'time': fields[1],
        'action': fields[2],
        'protocol': fields[3],
        'srcIp': fields[4],
        'dstIP': fields[5],
        'srcPort': fields[6],
        'dstPort': fields[7],
        'size': fields[8],
        'tcpFlags': fields[9],
        'info': ' '.join(fields[10:])
    }

# implementation 
# find repeated ip addresses 
def analyzeLogs(logs):
    source_ip_counter = defaultdict(int)

    for log_entry in logs:
        parsed_log = takeLogEntry(log_entry)
        source_ip = parsed_log['srcIp']
        source_ip_counter[source_ip] += 1

# Print source IPs that were repeated more than 3 (assuming thinking more     than 3 is an usual case)
    for ip, count in source_ip_counter.items():
        if count > 1:
            print(f"IP Address {ip} has been repeated {count} times in the log file")
          
if __name__ == "__main__":
    logFilePath = "firewalllog_2023_11_7.log.txt"
    firewallLogs = readFirewallLogs(logFilePath)
    analyzeLogs(firewallLogs)
