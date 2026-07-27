from dotenv import load_dotenv
import time

load_dotenv()

from app import create_app
from app.services.virustotal_service import scan_url, get_scan_result

app = create_app()

with app.app_context():

    url = "https://google.com"

    print("Submitting URL...")
    submit_result = scan_url(url)
    print(submit_result)

    print("\nWaiting 5 seconds...")
    time.sleep(5)

    print("\nFetching result...")
    result = get_scan_result(url)
    print(result)