import xml.etree.ElementTree as ET
import sys

def parse_nmap_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    for host in root.findall('host'):
        ip = host.find('address').get('addr')
        for port in host.findall('ports/port'):
            port_id = port.get('portid')
            port_state = port.find('state').get('state')
            if port_id == '9443' and port_state == 'open':
                print("IP:", ip)
                break

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3", sys.argv[0], "<nmap_file>")
        sys.exit(1)
    file_path = sys.argv[1]
    parse_nmap_file(file_path)

