import tkinter as tk
from tkinter import filedialog, messagebox
from pyshark_utils import analyze_pcapng, count_devices_in_network
from scapy_utils import get_mac_address, send_deauth

class NetworkAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Analyzer")

        # Заголовок
        self.label_title = tk.Label(root, text="Network Analyzer Tool", font=("Arial", 16))
        self.label_title.pack(pady=10)

        # Кнопка выбора файла pcapng
        self.button_open_file = tk.Button(root, text="Open pcapng file", command=self.open_file)
        self.button_open_file.pack(pady=5)

        # Поле для выбора сетевого интерфейса
        self.label_interface = tk.Label(root, text="Network Interface")
        self.label_interface.pack(pady=5)
        self.entry_interface = tk.Entry(root)
        self.entry_interface.pack(pady=5)

        # Кнопка для анализа файла
        self.button_analyze = tk.Button(root, text="Analyze pcapng", command=self.analyze_file)
        self.button_analyze.pack(pady=5)

        # Вывод результатов анализа
        self.result_text = tk.Text(root, height=10, width=60)
        self.result_text.pack(pady=10)

        # Кнопка для отправки deauth пакетов
        self.button_deauth = tk.Button(root, text="Send Deauth", command=self.send_deauth)
        self.button_deauth.pack(pady=5)

        # Переменные для хранения данных
        self.pcapng_file = None
        self.common_ip = None

    def open_file(self):
        # Открытие диалогового окна для выбора файла
        self.pcapng_file = filedialog.askopenfilename(filetypes=[("PCAPNG files", "*.pcapng")])
        if self.pcapng_file:
            self.result_text.insert(tk.END, f"Selected file: {self.pcapng_file}\n")
        else:
            messagebox.showwarning("Warning", "No file selected!")

    def analyze_file(self):
        if not self.pcapng_file:
            messagebox.showwarning("Warning", "No pcapng file selected!")
            return

        # Анализ pcapng файла
        self.common_ip = analyze_pcapng(self.pcapng_file)

        # Подсчет устройств в сети
        total_devices = count_devices_in_network(self.pcapng_file)
        self.result_text.insert(tk.END, f"Total devices in the network: {total_devices}\n")

        if self.common_ip:
            self.result_text.insert(tk.END, f"Most common IP: {self.common_ip}\n")
        else:
            self.result_text.insert(tk.END, "No common IP found.\n")

    def send_deauth(self):
        if not self.common_ip:
            messagebox.showwarning("Warning", "No common IP found to deauth!")
            return

        network_interface = self.entry_interface.get()
        if not network_interface:
            messagebox.showwarning("Warning", "Network interface is required!")
            return

        # Получение MAC адреса
        mac_address = get_mac_address(self.common_ip)
        if mac_address:
            self.result_text.insert(tk.END, f"MAC address of {self.common_ip}: {mac_address}\n")
            send_deauth(mac_address, network_interface)
            self.result_text.insert(tk.END, f"Deauth packets sent to {mac_address}\n")
        else:
            self.result_text.insert(tk.END, f"Could not find MAC address for {self.common_ip}\n")


# Основная часть
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkAnalyzerApp(root)
    root.mainloop()
