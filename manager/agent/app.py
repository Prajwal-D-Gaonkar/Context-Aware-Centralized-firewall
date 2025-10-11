# agent/app.py
import time
import random
import requests


MANAGER_API_URL = "http://localhost:5000/api/logs"

def generate_dummy_traffic():
    """
    Simulate network traffic logs
    """
    traffic = {
        "source_ip": f"192.168.1.{random.randint(1, 255)}",
        "dest_ip": f"10.0.0.{random.randint(1, 255)}",
        "protocol": random.choice(["HTTP", "HTTPS", "FTP", "SSH"]),
        "bytes": random.randint(100, 5000),
        "timestamp": time.time()
    }
    return traffic

def send_to_manager(log):
    """
    Send the traffic log to the manager API
    """
    try:
        response = requests.post(MANAGER_API_URL, json=log)
        if response.status_code == 200:
            print(f"Log sent successfully: {log}")
        else:
            print(f"Failed to send log: {response.status_code}")
    except Exception as e:
        print(f"Error sending log: {e}")

def run_agent(interval=5):
    """
    Main loop to generate and send traffic logs
    """
    print("Agent started... sending traffic logs to manager")
    while True:
        log = generate_dummy_traffic()
        send_to_manager(log)
        time.sleep(interval)

if __name__ == "__main__":
    run_agent()
