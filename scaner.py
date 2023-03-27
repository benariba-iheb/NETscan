import nmap

scanner = nmap.PortScanner()

print("Welcome to the NETscan tool")
print("<----------------------------------------------------->")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1)TCP(SYN ACK) Scan
                2)UDP Scan
                3)total Scan \n""")

print("You have selected option: ", resp)

#////////////////////////////////////////////////////////////////////////////////////////

if resp == '1':
    print("TCP(SYN ACK) scan: ")
    scanner.scan(ip_addr ,  "1-1024" , "-v -sS" , True) 
    os_matches = scanner[ip_addr]['osmatch']
    hostname = scanner[ip_addr].hostname()
    
    print(f"The hostname of the target host is: {hostname}")
    
    for os_match in os_matches:
        print(f"Name: {os_match['name']}")        
        has_wifi = False
        for os_class in os_match['osclass']:
              if os_class['type'] == 'WAP':
                  has_wifi = True
                  break
                  
    print(scanner.scaninfo())
    print("ip Status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("open ports: ", scanner[ip_addr]['tcp'].keys())

#////////////////////////////////////////////////////////////////////////////////////////
    
elif resp == '2':
    print("UDP scan: ")
    scanner.scan(ip_addr , "1-1024" , "-v -sU" , True) 
    os_matches = scanner[ip_addr]['osmatch']
    hostname = scanner[ip_addr].hostname()
        
    print(f"The hostname of the target host is: {hostname}")
    
    for os_match in os_matches:
        print(f"Name: {os_match['name']}")        
        has_wifi = False
        for os_class in os_match['osclass']:
              if os_class['type'] == 'WAP':
                  has_wifi = True
                  break
        
    print(scanner.scaninfo())
    print("ip Status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("open ports: ", scanner[ip_addr]['udp'].keys())

#////////////////////////////////////////////////////////////////////////////////////////

elif resp == '3':
    print("total scan: ")
    scanner.scan(ip_addr , "1-1024" , "-v -sS -sV -sC -A -O" , True) 
    os_matches = scanner[ip_addr]['osmatch']
    hostname = scanner[ip_addr].hostname()
        
    print(f"The hostname of the target host is: {hostname}")
    
    for os_match in os_matches:
        print(f"Name: {os_match['name']}")        
        has_wifi = False
        for os_class in os_match['osclass']:
              if os_class['type'] == 'WAP':
                    has_wifi = True
                    break
    
    print(scanner.scaninfo())
    print("ip Status: ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("open ports: ", scanner[ip_addr]['tcp'].keys())

#////////////////////////////////////////////////////////////////////////////////////////

else:
    print("please enter one of the specefied scanning types.")
