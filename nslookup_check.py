import shodan
import socket
import csv

# Shodan API Key (Replace with your actual API key)
SHODAN_API_KEY = "YOUR_SHODAN_KEY"

# Shodan search query (Customize as needed)
QUERY = "ssl:#######"  # Example query to find assets related to company

# Perform NSlookup
def nslookup(hostname):
    try:
        result = socket.gethostbyname_ex(hostname)
        # Return the canonical hostname instead of converting to string
        return result[0]
    except socket.gaierror:
        return "Resolution Failed"

# Fetch Shodan results
def fetch_shodan_results():
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(QUERY)

        print(f"Found {results['total']} results for query: {QUERY}")
        records = []

        for result in results['matches']:
            ip = result['ip_str']
            hostnames = result.get('hostnames', [])

            for hostname in hostnames:
                nslookup_result = nslookup(hostname)
                # Don't join the result if it's already a string
                if isinstance(nslookup_result, list):
                    nslookup_result = " ".join(nslookup_result)
                records.append([hostname, ip, nslookup_result])

        return records

    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
        return []

# Save results in a CSV file
def save_results_to_csv(records, filename="shodan_nslookup_results.csv"):
    headers = ["Hostname", "Shodan IP", "NSlookup IP(s)"]

    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(records)

    print(f"Results saved to {filename}")

# Main execution
def main():
    results = fetch_shodan_results()
    if results:
        save_results_to_csv(results)

if __name__ == "__main__":
    main()
