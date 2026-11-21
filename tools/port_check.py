import socket
import sys

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-Alt",
}

def check_port(host: str, port: int, timeout: float = 1.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 port_check.py <host> [port1 port2 ...]")
        sys.exit(1)

    target = sys.argv[1]
    if len(sys.argv) > 2:
        ports = [int(p) for p in sys.argv[2:]]
    else:
        ports = list(COMMON_PORTS.keys())

    print(f"Scanning {target}...")
    for port in ports:
        service = COMMON_PORTS.get(port, "Unknown")
        status = "OPEN" if check_port(target, port) else "CLOSED/FILTERED"
        print(f"  [{port}] ({service}): {status}")

if __name__ == "__main__":
    main()
