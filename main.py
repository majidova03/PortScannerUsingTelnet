import telnetlib
import socket
import ipaddress


def check_port(ip, port):
    try:
        tn = telnetlib.Telnet(ip, port, timeout=2)
        print(f"{ip}:{port} - Open")
        tn.close()
    except Exception as e:
        print(f"{ip}:{port} - Filtered")
    except (ConnectionRefusedError, socket.timeout):
        print(f"{ip}:{port} - Closed")



def scan_port(ip, port):
    print(f"Scanning {ip}:{port}...")
    check_port(ip, port)


def main():
    target = input("Enter IP address, IP range (CIDR notation), or domain: ")

    try:
        ip_list = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
    except ValueError:
        try:
            ip_list = [socket.gethostbyname(target)]
        except socket.gaierror:
            print("Invalid domain or IP address")
            return

    port = int(input("Enter port to check: "))
    if port < 1 or port > 65535:
        print("Invalid port number")
        return

    for ip in ip_list:
        scan_port(ip, port)


if __name__ == "__main__":
    main()
