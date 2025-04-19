import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import ARP, Ether, srp
import socket
import requests
import csv
import time

COMMON_VPN_PORTS = [1194, 443, 51820, 1701, 500, 4500]
DEFAULT_SUBNET = "192.168.1.1/24"
VPN_SUBNETS = ["10.0.0.0/24", "10.8.0.0/24", "172.16.0.0/24", "100.64.0.0/24"]

def lookup_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Không rõ"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Không rõ"

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=1):
                open_ports.append(port)
        except:
            pass
    return open_ports

def update_status(text, percent=0):
    status_label.config(text=text)
    progress_bar["value"] = percent
    root.update_idletasks()

def scan_network(subnet):
    update_status("Đang quét mạng...", 5)
    try:
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]
    except Exception as e:
        messagebox.showerror("Lỗi", f"Không thể quét subnet này: {e}")
        return []

    devices = []
    total = len(result)
    for idx, (sent, received) in enumerate(result):
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_hostname(ip)
        vendor = lookup_vendor(mac)
        vpn_ports = scan_ports(ip, COMMON_VPN_PORTS)
        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "vpn_ports": ", ".join(map(str, vpn_ports)) if vpn_ports else ""
        })
        update_status(f"Đang xử lý {idx+1}/{total} thiết bị...", 10 + int((idx+1) / total * 85))

    return devices

def show_devices(subnet):
    tree.delete(*tree.get_children())
    update_status("Bắt đầu quét...", 0)
    devices = scan_network(subnet)
    if not devices:
        update_status("Không tìm thấy thiết bị nào.", 0)
        return
    for idx, dev in enumerate(devices):
        tree.insert("", "end", text=str(idx + 1),
                    values=(dev["ip"], dev["mac"], dev["hostname"], dev["vendor"], dev["vpn_ports"]))
    update_status("✅ Hoàn tất!", 100)

def scan_lan():
    subnet = entry_subnet.get().strip()
    if not subnet:
        messagebox.showwarning("Cảnh báo", "Vui lòng nhập subnet.")
        return
    threading.Thread(target=show_devices, args=(subnet,), daemon=True).start()

def load_vpn_subnets_from_file():
    file_path = filedialog.askopenfilename(title="Chọn file chứa danh sách subnet VPN", filetypes=[("Text files", "*.txt")])
    if not file_path:
        return []

    with open(file_path, 'r') as file:
        subnets = file.readlines()

    # Xóa các ký tự newline và bỏ qua các dòng trống
    subnets = [subnet.strip() for subnet in subnets if subnet.strip()]
    return subnets

def scan_vpn_from_file():
    subnets = load_vpn_subnets_from_file()
    if not subnets:
        messagebox.showwarning("Cảnh báo", "Không tìm thấy subnet trong file.")
        return

    tree.delete(*tree.get_children())
    all_devices = []
    update_status("Đang quét các subnet VPN từ file...", 0)
    
    def scan_vpn(subnet, idx, total):
        update_status(f"Đang quét VPN subnet {subnet} ({idx+1}/{total})", int(idx / total * 100))
        devices = scan_network(subnet)
        for dev in devices:
            tree.insert("", "end", text=str(len(tree.get_children()) + 1),
                        values=(dev["ip"], dev["mac"], dev["hostname"], dev["vendor"], dev["vpn_ports"]))

    # Chạy quét các subnet song song bằng các thread
    total = len(subnets)
    threads = []
    for i, subnet in enumerate(subnets):
        thread = threading.Thread(target=scan_vpn, args=(subnet, i, total))
        threads.append(thread)
        thread.start()

    # Đợi tất cả các thread hoàn thành
    for thread in threads:
        thread.join()

    update_status("✅ Hoàn tất VPN từ file!", 100)
    
def scan_vpn_common():
    subnets = ["10.0.0.0/24", "10.8.0.0/24", "172.16.0.0/24", "100.64.0.0/24"]
    for subnet in subnets:
        scan_network(subnet)

def save_to_csv():
    if not tree.get_children():
        messagebox.showinfo("Thông báo", "Không có dữ liệu để lưu.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return

    with open(file_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["IP", "MAC", "Tên thiết bị", "Hãng", "Cổng VPN mở"])
        for item in tree.get_children():
            writer.writerow(tree.item(item)["values"])

    messagebox.showinfo("Thành công", f"Đã lưu vào:\n{file_path}")

# === GUI ===
root = tk.Tk()
root.title("Quét thiết bị WiFi + VPN")
root.geometry("900x560")

frame_top = tk.Frame(root)
frame_top.pack(pady=10)

tk.Label(frame_top, text="Subnet:").pack(side=tk.LEFT, padx=5)
entry_subnet = tk.Entry(frame_top, width=22)
entry_subnet.insert(0, DEFAULT_SUBNET)
entry_subnet.pack(side=tk.LEFT, padx=5)

tk.Button(frame_top, text="🔍 Quét LAN", command=scan_lan).pack(side=tk.LEFT, padx=5)
tk.Button(frame_top, text="🛡️ Quét VPN phổ biến", command=lambda: threading.Thread(target=scan_vpn_common, daemon=True).start()).pack(side=tk.LEFT, padx=5)
tk.Button(frame_top, text="📝 Chọn file quét VPN", command=scan_vpn_from_file).pack(side=tk.LEFT, padx=5)
tk.Button(frame_top, text="💾 Lưu kết quả CSV", command=save_to_csv).pack(side=tk.LEFT, padx=5)

columns = ("IP", "MAC", "Tên thiết bị", "Hãng", "Cổng VPN mở")
tree = ttk.Treeview(root, columns=columns, show='headings')
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=160)
tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# === Progress Bar + Status ===
bottom_frame = tk.Frame(root)
bottom_frame.pack(fill=tk.X, padx=10, pady=5)

progress_bar = ttk.Progressbar(bottom_frame, length=300, mode="determinate")
progress_bar.pack(side=tk.LEFT, padx=5)

status_label = tk.Label(bottom_frame, text="Sẵn sàng")
status_label.pack(side=tk.LEFT, padx=10)

root.mainloop()
