import scapy.all as scapy
g='\033[92m'
y="\033[93m"
r='\033[0m'
c='\033[36m'
red='\033[91m'

scan_res=[]
port_name = {

    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    
    1433: 'MS-SQL', 3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
    
    
    3389: 'RDP', 5900: 'VNC', 2375: 'Docker-API', 10050: 'Zabbix',
    
    
    3000: 'Grafana', 5000: 'Flask/Docker', 8000: 'Django', 8080: 'HTTP-Alt', 
    9000: 'Portainer', 9200: 'Elasticsearch',
    
    
    1194: 'OpenVPN', 51820: 'WireGuard', 8883: 'MQTT-IoT', 554: 'RTSP-Cam',49152:"upnp"
}

ports = sorted(list(port_name.keys()))




def scan(ip):
    for port in ports:
    
        packet=scapy.IP(dst=ip)/scapy.TCP(dport=port,flags="S")
        ans=scapy.sr1(packet,timeout=1,verbose=0)
        if ans:
            if ans.haslayer(scapy.TCP):
                if ans[scapy.TCP].flags=="SA":
                    otkrit=f"{g}[+]{r} Порт {port:<5}  {port_name.get(port, 'Unknown'):<10}  {g}ОТКРЫТ{r}"
                    scan_res.append(otkrit)
                    scapy.send(scapy.IP(dst=ip)/scapy.TCP(dport=port,flags="R"),verbose=0)
                elif ans[scapy.TCP].flags=="RA":
                    pass
        else:
            filter=f"{y}[!]{r} Порт {port:<5}  {port_name.get(port, "Unknown"):<10}  {y}фильтруется{r}"
            scan_res.append(filter)
    if scan_res:
        for o in scan_res:
            print(o)
    else:
        print(f"{red}[-]{r} Все порты закрыты")
try:
    target=input(f"{c}[*]{r}Введите IP:")
    if target:
        scan(target)
except KeyboardInterrupt:
    print(f"\n{y}[!]{r} Остановлено")
