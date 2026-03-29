import socket
import time
import urllib.request
import threading

def sim_ddos():
    print("[*] Starting simulated DDoS/SYN flood traffic...")
    # Send garbage to random ports to trigger port scan / DDoS rules
    # We will send 300 packets very fast to localhost
    for i in range(1, 350):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"X" * 1024, ('127.0.0.1', 8000 + (i % 50)))
        except:
            pass
    print("[*] Finished simulated traffic.")

if __name__ == '__main__':
    # Start a few threads to generate burst traffic
    threads = []
    for _ in range(5):
        t = threading.Thread(target=sim_ddos)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
        
    print("[*] Attack simulation complete! Check your NetGuard dashboard.")
