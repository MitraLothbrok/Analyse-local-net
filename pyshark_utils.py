import pyshark
from collections import Counter
import ipaddress
import scapy_utils  # Наш модуль для работы с ARP

# Загрузка MAC-адресов Apple
mac_addresses = scapy_utils.load_mac_addresses("output.txt")

# Проверка и вывод информации о MAC-адресе (Apple или другой)
def print_mac_info(ip, mac, dst_ip):
    if scapy_utils.is_apple_device(mac, mac_addresses):
        print(f"{ip} -> {mac} -> {dst_ip} apple")
    else:
        print(f"{ip} -> {mac} -> {dst_ip} another")

# Проверка, является ли IP-адрес локальным
def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

# Подсчет количества уникальных устройств в сети
def count_devices_in_network(file):
    cap = pyshark.FileCapture(file)
    unique_devices = set()

    for packet in cap:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # Исключаем широковещательные IP
            if not src_ip.endswith(".255") and src_ip != "255.255.255.255" and is_local_ip(src_ip):
                unique_devices.add(src_ip)
            if not dst_ip.endswith(".255") and dst_ip != "255.255.255.255" and is_local_ip(dst_ip):
                unique_devices.add(dst_ip)

    cap.close()
    
    print(f"Количество уникальных устройств в сети: {len(unique_devices)}")
    return len(unique_devices)

# Расширенная фильтрация пакетов с поддержкой ARP и DNS
def analyze_pcapng(file):
    print("Начало анализа...")
    cap = pyshark.FileCapture(file)

    router_ip = "192.168.0.1"  # Указываем IP маршрутизатора
    dns_requests = []  # Список для DNS запросов
    arp_packets = 0  # Счетчик ARP пакетов

    # Проходим по каждому пакету
    for packet in cap:
        # Работа с IP-пакетами
        if 'IP' in packet:
            src_ip = packet.ip.src  # IP отправителя
            dst_ip = packet.ip.dst  # IP назначения

            # Исключаем пакеты от маршрутизатора и добавляем проверку на локальные IP
            if src_ip != router_ip and is_local_ip(src_ip):
                # Получаем MAC-адрес для IP отправителя
                mac_src = scapy_utils.get_mac_address(src_ip, mac_addresses)
                if mac_src:
                    # Если отправитель - локальное устройство, выводим IP, MAC и IP назначения
                    print_mac_info(src_ip, mac_src, dst_ip)

        # Работа с DNS-пакетами
        if 'DNS' in packet:
            dns_requests.append(packet.dns.qry_name)
            print(f"DNS запрос: {packet.dns.qry_name} от IP {packet.ip.src}")

        # Работа с ARP-пакетами
        if 'ARP' in packet:
            arp_packets += 1
            print(f"ARP пакет: {packet.arp.src_proto_ipv4} -> {packet.arp.dst_proto_ipv4}, MAC: {packet.arp.src_hw_mac}")

    cap.close()

    # Подсчет необычных DNS запросов
    dns_request_counts = Counter(dns_requests)
    unusual_dns_requests = [dns for dns, count in dns_request_counts.items() if count == 1]

    print(f"\nАнализ завершен.")
    print(f"Необычные DNS запросы: {unusual_dns_requests}")
    print(f"Всего DNS запросов: {len(dns_requests)}")
    print(f"Всего уникальных DNS запросов: {len(set(dns_requests))}")
    print(f"Всего ARP пакетов: {arp_packets}")

    # Вызов функции подсчета уникальных устройств
    count_devices_in_network(file)

# Пример вызова анализа
