#!/usr/bin/env python
import requests
import os
import pyfiglet  # type: ignore
import subprocess
import re
import ipaddress
from colorama import Fore
from urllib.parse import urlparse
from sys import exit 

# URL = 'google.com'
# print(sys.platform)

# Extracting host and port from url
def extract_url(url):
    parsed_url = urlparse(url)
    host = parsed_url.hostname
    port = parsed_url.port or 443
    return host, port

def find_dns(text):
    dns = re.findall(r"Name:\s+(.*?)\s+Address:\s+(.*?)\s+", text)
    return dns

# Function to validate found ip addresses
def vaildate_ip(ip):
    try:
        ip = ipaddress.ip_address(ip)
        if isinstance(ip, ipaddress.IPv4Address):
            return "IPv4"
        elif isinstance(ip, ipaddress.IPv6Address):
            return "IPv6"
        else:
            return "Unknown"
    except Exception as e:
        print(Fore.RED+"\033[1m"+"An error has occured: "+"\033[0m"+f"{e}")
        exit()

def nslookup(url):
    host, port = extract_url(url)
    command = ["nslookup",host]
    print("\033[1m"+Fore.CYAN+"\nRunning nslookup\n"+"\033[0m")
    try:
        # Running nslookup command
        dnslookup = subprocess.run(command, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, text = True)
        
        print(Fore.GREEN+"Command run successfully...\n"+"\033[0m")
        result = dnslookup.stdout
        
        # Creating a set for ip addresses
        ip_list = {"IPv4":[],"IPv6":[]}
        
        # Finding dns and address from output
        dns_list = find_dns(result)
        
        for dns in dns_list:
            print("\033[1m"+"Name: "+"\033[0m"+f"{dns[0]}")
            addr_type = vaildate_ip(dns[1])
            if "Unknown" not in addr_type: 
                print(Fore.RED+"\033[1m"+f"Address: "+"\033[0m"+f"{dns[1]}")
                ip_list[addr_type].append(dns[1])
            else:
                print(Fore.GREEN+"\033[1m"+f"IP not found"+"\033[0m")
        return ip_list

    except Exception as e:
        print(Fore.RED+"\033[1m"+"An error has occured: "+"\033[0m"+f"{e}")
        exit()

def show_headers(url):
    
    try: 
        print(Fore.CYAN+"\033[1m"+"\nRequesting Headers\n"+"\033[0m")
    
        # Sending request using HEAD method
        response = requests.head(url)
        for headers in response.headers:
            print("\033[1m"+f"{headers}: "+"\033[0m"f"{response.headers[headers]}")

    except Exception as e:
        print(Fore.RED+"\033[1m"+"An error has occured: "+"\033[0m"+f"{e}")
        exit()

def nmap_results(ip_list):
    
    # different command for ipv4 and ipv6 address scans
    command_ipv4 = ["nmap", "-Pn", "-sV"]
    command_ipv6 = ["nmap", "-Pn", "-sV", "-6"]
    for ip in ip_list["IPv4"]:
        command_ipv4.append(ip)
    for ip in ip_list["IPv6"]:
        command_ipv6.append(ip)
    try:
        print(Fore.CYAN+"\033[1m"+f"\nRunning Nmap Scan for IPv4 Addresses\n"+"\033[0m")
        
        # Running Scan for ipv6 addresses
        result_ipv4 = subprocess.run(command_ipv4, stdout = subprocess.PIPE, stderr = subprocess.PIPE, text = True)
        print(result_ipv4.stdout,end="")
        
        # Running Scan for ipv6 addresses
        if ip_list["IPv6"]:

            print(Fore.CYAN+"\033[1m"+f"\nRunning Nmap Scan for IPv6 Addresses\n"+"\033[0m")
            result_ipv6 = subprocess.run(command_ipv6, stdout = subprocess.PIPE, stderr = subprocess.PIPE, text = True)
            print(result_ipv6.stdout,end="")
    
    except Exception as e:
        print(Fore.RED+"\033[1m"+"An error has occured: "+"\033[0m"+f"{e}")
        exit()

if __name__ == "__main__":
    os.system("clear")
    banner = pyfiglet.figlet_format("Hacker Recon")
    print(banner)
    URL = input("[*] Enter URL: ")
    ip_list = nslookup(URL)
    nmap_results(ip_list)
    # show_headers(URL)
