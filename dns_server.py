import socket
import struct

print("DNS сервер запускается...")
# Определяем адрес и порт для DNS-сервера
DNS_SERVER_IP = '127.0.0.1'
DNS_SERVER_PORT = 53

# Словарь для хранения доменных имен и их IP-адресов
DNS_RECORDS = {
    'example.com.': '192.168.1.100',
}

def create_dns_response(query):
    # Извлекаем информацию из запроса
    transaction_id = query[:2]  # первые 2 байта - ID транзакции
    flags = b'\x81\x80'  # ответ (QR=1), авторитетный ответ (AA=1)
    questions = query[4:];  # сохраняем часть запроса, относящуюся к вопросам
    answer_count = struct.pack('>H', 1)  # кол-во ответов = 1

    # Формируем ответ, если домен найден
    domain = query[12:query.find(b'\x00', 12) + 1]  # Извлекаем доменное имя из запроса
    ip_address = DNS_RECORDS.get(domain.decode(), None)

    if ip_address:
        ip_bytes = socket.inet_aton(ip_address)  # Конвертируем IP в байты
        answer = (
            domain + b'\x00' +    # доменное имя
            struct.pack('>H', 1) +  # тип (A)
            struct.pack('>H', 1) +  # класс (IN)
            struct.pack('>I', 60) +  # TTL (60 секунд)
            struct.pack('>H', 4) +  # длина ответа (4 байта для IPv4)
            ip_bytes               # ответ (IP-адрес)
        )
    else:
        answer = b''  # Ответа нет

    return transaction_id + flags + answer_count + questions + answer

def start_dns_server():
    # Создаем сокет и привязываем его к адресу и порту
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((DNS_SERVER_IP, DNS_SERVER_PORT))

    print(f'DNS server running at {DNS_SERVER_IP}:{DNS_SERVER_PORT}')

    while True:
        # Получаем запрос
        query, addr = server.recvfrom(512)  # Размер пакета 512 байт
        print(f'Received request from {addr}')
        response = create_dns_response(query)
        server.sendto(response, addr)  # Отправляем ответ


if __name__ == "__main__":
    start_dns_server()
