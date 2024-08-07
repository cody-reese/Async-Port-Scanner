import asyncio
import socket
import logging
import argparse
import json
import csv
import unittest

# Set up logging to capture details about the scanning process and any errors
logging.basicConfig(filename='port_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the maximum number of concurrent port scans allowed
MAX_CONCURRENT_SCANS = 100
# Create a semaphore to limit the number of concurrent connections
semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

async def scan_port(target_host, target_port):
    async with semaphore:  # Ensure that only a limited number of scans run concurrently
        try:
            # Attempt to establish a connection to the specified port
            connection = asyncio.open_connection(target_host, target_port)
            reader, writer = await asyncio.wait_for(connection, timeout=1)  # Set a timeout for the connection
            # Fetch the service banner if the connection is successful
            service_info = await fetch_service_banner(reader)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.1)  # Short delay to avoid network flooding
            return target_port, service_info
        except asyncio.TimeoutError:
            logging.warning(f"Timeout occurred for port {target_port} on {target_host}")
            return target_port, None
        except ConnectionRefusedError:
            logging.warning(f"Connection refused for port {target_port} on {target_host}")
            return target_port, None
        except Exception as e:
            logging.error(f"Unexpected error for port {target_port} on {target_host}: {e}")
            return target_port, None

async def scan_ports(target_host, ports_to_scan):
    # Create a list of tasks for scanning each port
    scan_tasks = [scan_port(target_host, port) for port in ports_to_scan]
    # Run all scan tasks concurrently and gather results
    results = await asyncio.gather(*scan_tasks)
    # Filter out ports with no service info and return only open ports
    open_ports = {port: info for port, info in results if info is not None}
    return open_ports

async def fetch_service_banner(reader):
    try:
        # Read up to 1024 bytes from the connection to get the service banner
        banner = await reader.read(1024)
        return banner.decode().strip()  # Decode and strip any extra whitespace
    except asyncio.CancelledError:
        return None

def parse_arguments():
    # Set up argument parser to handle command-line inputs
    parser = argparse.ArgumentParser(description="Network Port Scanner")
    parser.add_argument('host', type=str, help='IP address of the target host')
    parser.add_argument('ports', type=int, nargs='+', help='List of ports to be scanned')
    parser.add_argument('--output', choices=['json', 'csv'], default='json', help='Output file format (json or csv)')
    return parser.parse_args()

def save_scan_results(target_host, open_ports, output_format):
    logging.info(f"Results for {target_host}: {open_ports}")

    # Save results to JSON file
    if output_format == 'json':
        with open('scan_results.json', 'w') as json_file:
            json.dump({'host': target_host, 'open_ports': open_ports}, json_file, indent=4)
    # Save results to CSV file
    elif output_format == 'csv':
        with open('scan_results.csv', 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['Port', 'Service Banner'])
            for port, banner in open_ports.items():
                writer.writerow([port, banner])

class PortScannerTests(unittest.TestCase):
    def test_argument_parsing(self):
        # Test that arguments are parsed correctly
        parser = parse_arguments()
        self.assertIsInstance(parser.host, str)
        self.assertIsInstance(parser.ports, list)
        self.assertTrue(parser.ports)
    
    def test_port_range_parsing(self):
        # Test port range parsing functionality
        self.assertEqual(parse_ports(['22', '80', '100-102']), [22, 80, 100, 101, 102])
        self.assertRaises(ValueError, parse_ports, ['100-80'])

def main():
    args = parse_arguments()
    target_host = args.host
    ports_to_scan = args.ports
    output_format = args.output

    print(f"Starting scan on {target_host}...")
    open_ports = asyncio.run(scan_ports(target_host, ports_to_scan))

    if open_ports:
        print(f"Discovered open ports on {target_host}:")
        for port, banner in open_ports.items():
            print(f"Port {port}: {banner}")
    else:
        print(f"No open ports were found on {target_host}.")

    save_scan_results(target_host, open_ports, output_format)

if __name__ == "__main__":
    main()
