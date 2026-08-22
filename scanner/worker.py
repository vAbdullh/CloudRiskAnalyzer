import os
import sys
import time
import signal
import logging
import redis

from api_client import InternalBackendClient
from runner import ScanRunner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Global shutdown flag
shutdown_requested = False

def handle_shutdown(signum, frame):
    global shutdown_requested
    logging.info(f"Shutdown signal received ({signum}). Exiting gracefully...")
    shutdown_requested = True

# Register system signals for container termination
signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

def main():
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    logging.info(f"Connecting to Redis queue at {redis_url}...")
    
    try:
        r = redis.Redis.from_url(redis_url)
        # Test connection
        r.ping()
        logging.info("Successfully connected to Redis.")
    except Exception as e:
        logging.critical(f"Failed to connect to Redis: {e}")
        sys.exit(1)

    try:
        client = InternalBackendClient()
    except Exception as e:
        logging.critical(f"Failed to initialize API client: {e}")
        sys.exit(1)

    # Sync the rules catalog with database on startup (with retries for backend boot time)
    max_retries = 10
    retry_delay = 2
    for attempt in range(1, max_retries + 1):
        try:
            logging.info(f"Initiating rules catalog sync (Attempt {attempt}/{max_retries})...")
            rules_metadata = ScanRunner.get_all_rules_metadata()
            client.sync_rules(rules_metadata)
            logging.info("Rules catalog successfully synced!")
            break
        except Exception as e:
            if attempt == max_retries:
                logging.error(f"Rules sync failed after {max_retries} attempts: {e}. Worker will proceed anyway.")
            else:
                logging.warning(f"Backend not ready yet ({e}). Retrying in {retry_delay}s...")
                time.sleep(retry_delay)

    logging.info("Scanner worker is up and listening for jobs...")

    while not shutdown_requested:
        try:
            # Block (sleep) until a job ID is pushed to "scan_queue"
            queue_item = None
            try:
                queue_item = r.blpop("scan_queue", timeout=5)
            except (redis.exceptions.TimeoutError, TimeoutError, redis.exceptions.ConnectionError) as e:
                logging.debug(f"Redis polling error/timeout: {e}")

            job_id = None
            job = None

            if queue_item:
                _, job_id_bytes = queue_item
                job_id = job_id_bytes.decode("utf-8")
                logging.info(f"Picked up Job ID: {job_id} from Redis queue")
                # 1. Fetch job configurations and decrypted credentials
                job = client.get_job(job_id)
            else:
                # Fallback to database polling
                job = client.poll_job()
                if job:
                    job_id = job.get("job_id")
                    logging.info(f"Picked up Job ID: {job_id} from Database fallback")

            if not job or not job_id:
                # Nothing found in Redis or DB
                continue

            # 2. Update status to RUNNING
            client.update_status(job_id, "RUNNING")

            try:
                # 3. Execute cloud scan
                results = ScanRunner.execute_scan(job["provider"], job["credentials"])

                # 4. Submit results (this will also mark status as COMPLETED)
                client.submit_results(job_id, results)
                logging.info(f"Job {job_id} completed successfully")

            except Exception as scan_error:
                logging.error(f"Scan execution failed for Job {job_id}: {scan_error}")
                # 5. On failure, mark status as FAILED
                client.update_status(job_id, "FAILED")

        except (redis.exceptions.TimeoutError, TimeoutError):
            # This is a normal socket timeout while waiting, just continue
            continue
        except redis.exceptions.ConnectionError:
            logging.error("Redis connection lost. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as loop_error:
            logging.error(f"Unexpected error in worker loop: {loop_error}")
            time.sleep(2)

    logging.info("Scanner worker has shut down.")

if __name__ == "__main__":
    main()
