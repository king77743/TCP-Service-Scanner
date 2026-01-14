import scapy.all as scapy
def scan(ip,port):
    packet=scapy.IP(dst=ip)/scapy.TCP(dport=port,flags="S")
    ans=scapy.sr1(packet,timeout=1,verbose=0)
    if ans:
        if ans.haslayer(scapy.TCP):
            if ans[scapy.TCP].flags=="SA":
                print(f"port:{port} open")
                scapy.send(scapy.IP(dst=ip)/scapy.TCP(dport=port,flags="R"),verbose=0)
            elif ans[scapy.TCP].flags=="RA":
                    print(f"port:{port} close")
    else:
        print(f"port:{port} filtering")
try:
    target=input("IP:")
    port=int(input("Port:"))
    if target and port:
        scan(target,port)
except KeyboardInterrupt:
    pass