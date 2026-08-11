import time
import schedule
from inference import run_inference
import urllib3

def job():
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Triggering SBA Inference Job...")
    try:
        run_inference(index="wazuh-alerts-*") # Defaulting back to alerts for production
    except Exception as e:
        print(f"Error during inference run: {e}")

if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("SBA Microservice Scheduler Started. Running inference every 5 minutes.")
    
    # Schedule the job every 5 minutes
    schedule.every(5).minutes.do(job)
    
    # Run once at startup
    job()
    
    # Keep running
    while True:
        schedule.run_pending()
        time.sleep(1)
