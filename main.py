import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QTableWidget, QTableWidgetItem
import socket
from scapy.all import ARP, Ether, srp


# Function to get the IP address of the local machine.
def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except socket.error as e:
        print("Error getting IP:", e)
        return None


# Function to scan ports of a given IP address.
def scan_ports(ip):
    open_ports = []
    common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1723, 3306, 3389, 5900, 8080]
    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports


# Function to scan the network for other devices.
def scan_network(ip):
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        return devices
    except Exception as e:
        print("Error during network scanning:", e)
        return []


# Define the main NetworkScanner class that will be the main window.
class NetworkScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Get local IP address.
        self.my_ip = get_ip()
        if self.my_ip is None:
            sys.exit()

        # Derive subnet from local IP address.
        ip_parts = self.my_ip.split('.')
        self.my_subnet = '.'.join(ip_parts[0:3]) + '.0/24'

        # Set window parameters.
        self.setGeometry(300, 300, 800, 600)
        self.setWindowTitle('Network Scanner')

        # Create table to display device information.
        self.table = QTableWidget(self)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(['IP Address', 'MAC Address', 'Port Scan', 'Open Ports'])
        self.table.setRowCount(0)

        # Create Scan Network button.
        self.scan_button = QPushButton('Scan Network', self)
        self.scan_button.clicked.connect(self.scan_network_and_update)

        # Create vertical layout and add table and button to it.
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.table)
        self.layout.addWidget(self.scan_button)

        # Apply the layout to the window.
        self.setLayout(self.layout)

    # Function to update the display with new network scan data.
    def scan_network_and_update(self):
        self.table.setRowCount(0)  # Clear table before new scan.
        devices = scan_network(self.my_subnet)
        for i, device in enumerate(devices):
            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(device['ip']))
            self.table.setItem(i, 1, QTableWidgetItem(device['mac']))

            # Add Port Scan button to table for each device.
            port_scan_button = QPushButton('Port Scan')
            port_scan_button.clicked.connect(lambda checked, ip=device['ip'], row=i: self.perform_port_scan(ip, row))
            self.table.setCellWidget(i, 2, port_scan_button)

    # Function to scan ports of a specific IP and update the display.
    def perform_port_scan(self, ip, row):
        open_ports = scan_ports(ip)
        self.table.setItem(row, 3, QTableWidgetItem(", ".join(map(str, open_ports))))


if __name__ == '__main__':
    app = QApplication(sys.argv)

    scanner = NetworkScanner()
    scanner.show()

    sys.exit(app.exec_())
