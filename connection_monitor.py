import psutil
import socket
import time
import sys
import os
from datetime import datetime
from collections import defaultdict
from threading import Thread
from queue import Queue
import msvcrt  # For Windows keyboard input

class ConnectionMonitor:
    def __init__(self):
        self.previous_connections = set()
        self.previous_connection_data = {}  # Store full connection data
        self.closed_connections = {}  # Store closed connections with their data for one cycle
        self.dns_cache = {}
        self.dns_queue = Queue()
        self.dns_thread = None
        self.running = False
        self.available_states = ['ALL', 'ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'LISTEN']
        self.current_filter_index = 1  # Start with ESTABLISHED (index 1)
        self.scroll_offset = 0  # Current scroll position
        self.sort_columns = ['pid', 'process', 'status', 'local', 'remote']
        self.current_sort_index = 1  # Start with process (index 1)
        self.sort_reverse = False  # Ascending by default

    def resolve_hostname(self, ip_address):
        """Resolve IP address to hostname with caching - non-blocking"""
        if ip_address in self.dns_cache:
            return self.dns_cache[ip_address]

        # Return IP immediately if not in cache, will be resolved in background
        return ip_address

    def dns_resolver_worker(self):
        """Background worker thread for DNS resolution"""
        while self.running:
            try:
                ip_address = self.dns_queue.get(timeout=0.5)
                if ip_address and ip_address not in self.dns_cache:
                    try:
                        hostname = socket.gethostbyaddr(ip_address)[0]
                        self.dns_cache[ip_address] = hostname
                    except (socket.herror, socket.gaierror, OSError):
                        self.dns_cache[ip_address] = ip_address
                self.dns_queue.task_done()
            except:
                continue

    def queue_dns_resolution(self, ip_address):
        """Queue an IP address for background DNS resolution"""
        if ip_address and ip_address not in self.dns_cache:
            try:
                self.dns_queue.put_nowait(ip_address)
            except:
                pass

    def get_port_name(self, port):
        """Get service name for a port number"""
        if port >= 32767:
            return ""
        try:
            service_name = socket.getservbyport(port)
            return f" ({service_name})"
        except (OSError, socket.error):
            return ""

    def get_process_name(self, pid):
        """Get process name from PID"""
        try:
            process = psutil.Process(pid)
            return process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Unknown"

    def get_tcp_connections(self):
        """Get all TCP connections with process information"""
        connections = []

        try:
            for conn in psutil.net_connections(kind='tcp'):
                # Extract connection details
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"

                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    remote_addr = f"{remote_ip}:{remote_port}"

                    # Queue IP for background DNS resolution
                    self.queue_dns_resolution(remote_ip)

                    # Get hostname (will be IP if not resolved yet)
                    hostname = self.resolve_hostname(remote_ip)
                    port_name = self.get_port_name(remote_port)
                    remote_display = f"{hostname}:{remote_port}{port_name}"
                else:
                    remote_addr = "N/A"
                    remote_display = "N/A"

                # Get process information
                pid = conn.pid if conn.pid else 0
                process_name = self.get_process_name(pid) if pid else "System"

                connections.append({
                    'local': local_addr,
                    'remote': remote_addr,
                    'remote_display': remote_display,
                    'status': conn.status,
                    'pid': pid,
                    'process': process_name
                })

        except psutil.AccessDenied as e:
            print("\n" + "=" * 80)
            print("ERROR: Access Denied")
            print("=" * 80)
            print("This program requires administrator privileges to view process information.")
            print("\nOn Windows, please:")
            print("  1. Open Command Prompt as Administrator")
            print("  2. Navigate to this directory")
            print("  3. Run: python connection_monitor.py")
            print("=" * 80)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error getting connections: {e}")
            return []

        return connections

    def get_terminal_height(self):
        """Get terminal height"""
        try:
            import shutil
            return shutil.get_terminal_size().lines
        except:
            return 40  # Default fallback

    def cycle_filter(self):
        """Cycle through available state filters"""
        self.current_filter_index = (self.current_filter_index + 1) % len(self.available_states)
        self.scroll_offset = 0  # Reset scroll when changing filter

    def get_current_filter(self):
        """Get current filter state"""
        return self.available_states[self.current_filter_index]

    def scroll_up(self, amount=1):
        """Scroll up in the connection list"""
        self.scroll_offset = max(0, self.scroll_offset - amount)

    def scroll_down(self, max_offset, amount=1):
        """Scroll down in the connection list"""
        self.scroll_offset = min(max_offset, self.scroll_offset + amount)

    def cycle_sort(self):
        """Cycle through sort columns"""
        self.current_sort_index = (self.current_sort_index + 1) % len(self.sort_columns)
        self.scroll_offset = 0  # Reset scroll when changing sort

    def get_current_sort(self):
        """Get current sort column"""
        return self.sort_columns[self.current_sort_index]

    def get_sort_key(self, conn):
        """Get sort key for a connection based on current sort column"""
        sort_col = self.get_current_sort()
        if sort_col == 'pid':
            return conn.get('pid', 0)
        elif sort_col == 'process':
            return conn.get('process', '').lower()
        elif sort_col == 'status':
            return conn.get('status', '')
        elif sort_col == 'local':
            return conn.get('local', '')
        elif sort_col == 'remote':
            return conn.get('remote_display', '')
        return ''

    def display_connections(self, connections):
        """Display connections in a formatted table"""
        # Clear screen - use os.system for better Windows compatibility
        os.system('cls' if os.name == 'nt' else 'clear')

        # ANSI color codes
        DARK_GREEN_BG = '\033[42m'
        RED_BG = '\033[41m'
        RESET = '\033[0m'
        BOLD = '\033[1m'

        # Track current connections
        current_set = {(c['local'], c['remote'], c['pid']) for c in connections}
        new_connections = current_set - self.previous_connections
        disappeared_connections = self.previous_connections - current_set

        # Store newly disappeared connections with their data from previous cycle
        new_closed = {}
        for conn_tuple in disappeared_connections:
            # Get the connection data from previous cycle
            if conn_tuple in self.previous_connection_data:
                new_closed[conn_tuple] = self.previous_connection_data[conn_tuple]

        # Combine active connections and closed connections for display
        all_connections = list(connections)

        # Add closed connections to display
        for conn_tuple, conn_data in self.closed_connections.items():
            all_connections.append(conn_data)

        # Apply state filter
        current_filter = self.get_current_filter()
        if current_filter != 'ALL':
            all_connections = [c for c in all_connections if c['status'] == current_filter]

        # Count connections by state
        state_counts = defaultdict(int)
        for conn in connections:
            state_counts[conn['status']] += 1

        # Calculate dynamic column widths
        pid_width = 8
        min_process_width = 25
        min_status_width = 12
        min_local_width = 25
        min_remote_width = 50

        if all_connections:
            max_process_len = max(len(conn['process']) for conn in all_connections)
            max_status_len = max(len(conn['status']) for conn in all_connections)
            max_local_len = max(len(conn['local']) for conn in all_connections)
            max_remote_len = max(len(conn['remote_display']) for conn in all_connections)

            process_width = max(min_process_width, max_process_len + 1)
            status_width = max(min_status_width, max_status_len + 1)
            local_width = max(min_local_width, max_local_len + 1)
            remote_width = max(min_remote_width, max_remote_len + 1)
        else:
            process_width = min_process_width
            status_width = min_status_width
            local_width = min_local_width
            remote_width = min_remote_width

        total_width = pid_width + process_width + status_width + local_width + remote_width + 4

        # Calculate how many rows we can display
        terminal_height = self.get_terminal_height()
        header_lines = 10  # Number of header lines
        footer_lines = 1  # Footer line
        max_rows = terminal_height - header_lines - footer_lines

        # Calculate total available rows and max scroll offset
        total_rows = len(all_connections)
        max_scroll = max(0, total_rows - max_rows)

        # Get current sort column for display
        sort_col = self.get_current_sort()
        sort_display = sort_col.upper()

        # Display static header
        print(f"{BOLD}TCP Connection Monitor{RESET} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total connections: {len(connections)} | Displaying: {len(all_connections)} | Filter: {BOLD}{current_filter}{RESET} | Sort by: {BOLD}{sort_display}{RESET}")

        # Display state counts
        state_summary = " | ".join([f"{state}: {count}" for state, count in sorted(state_counts.items())])
        print(f"States: {state_summary}")

        if self.closed_connections:
            print(f"Recently closed: {len(self.closed_connections)}")

        # Show scroll position
        if total_rows > max_rows:
            print(f"Viewing rows {self.scroll_offset + 1}-{min(self.scroll_offset + max_rows, total_rows)} of {total_rows}")

        print(f"\n{BOLD}Controls:{RESET} [f] Filter | [s] Sort | [↑/↓] Scroll | [PgUp/PgDn] Page | [q] Quit")
        print("=" * total_width)
        print(f"{'PID':<{pid_width}} {'Process':<{process_width}} {'Status':<{status_width}} {'Local Address':<{local_width}} {'Remote Endpoint':<{remote_width}}")
        print("-" * total_width)

        if not all_connections:
            print("No connections matching filter.")
        else:
            # Sort connections by current sort column
            sorted_connections = sorted(all_connections, key=self.get_sort_key)

            # Create flat list of rows to display (no grouping, just sorted)
            display_rows = []
            for conn in sorted_connections:
                display_rows.append({
                    'conn': conn,
                    'process': conn['process'],
                    'pid': conn['pid']
                })

            # Apply scrolling offset
            visible_rows = display_rows[self.scroll_offset:self.scroll_offset + max_rows]

            # Display visible rows
            for row in visible_rows:
                conn = row['conn']
                conn_tuple = (conn['local'], conn['remote'], conn['pid'])
                is_new = conn_tuple in new_connections
                is_closed = conn_tuple in self.closed_connections

                # Apply background colors
                if is_closed:
                    prefix = RED_BG
                    suffix = RESET
                elif is_new:
                    prefix = DARK_GREEN_BG
                    suffix = RESET
                else:
                    prefix = ''
                    suffix = ''

                pid_str = str(row['pid']) if row['pid'] else ''
                print(f"{prefix}{pid_str:<{pid_width}} {row['process']:<{process_width}} {conn['status']:<{status_width}} {conn['local']:<{local_width}} {conn['remote_display']:<{remote_width}}{suffix}")

        print("-" * total_width)

        # Update previous connections and closed connections
        self.previous_connections = current_set
        # Store current connection data for next cycle
        self.previous_connection_data = {(c['local'], c['remote'], c['pid']): c for c in connections}
        self.closed_connections = new_closed  # Replace with newly closed connections

        # Return max_scroll and page size for scrolling
        return max_scroll, max_rows

    def monitor_new_connections(self, connections):
        """Highlight new connections since last check"""
        current_set = {(c['local'], c['remote'], c['pid']) for c in connections}
        new_connections = current_set - self.previous_connections

        if new_connections:
            print("\n[NEW CONNECTIONS]")
            for conn in connections:
                conn_tuple = (conn['local'], conn['remote'], conn['pid'])
                if conn_tuple in new_connections:
                    print(f"  {conn['process']} ({conn['pid']}) -> {conn['remote_display']}")

        self.previous_connections = current_set

    def check_keyboard_input(self, max_scroll, page_size):
        """Check for keyboard input (non-blocking) on Windows. Returns (continue, needs_refresh)"""
        if msvcrt.kbhit():
            key_bytes = msvcrt.getch()

            # Check for special keys (start with 0xe0 or 0x00)
            if key_bytes in (b'\xe0', b'\x00'):
                special_key = msvcrt.getch()
                if special_key == b'H':  # Up arrow
                    self.scroll_up()
                    return True, True  # Continue, refresh needed
                elif special_key == b'P':  # Down arrow
                    self.scroll_down(max_scroll)
                    return True, True  # Continue, refresh needed
                elif special_key == b'I':  # Page Up
                    self.scroll_up(page_size)
                    return True, True  # Continue, refresh needed
                elif special_key == b'Q':  # Page Down
                    self.scroll_down(max_scroll, page_size)
                    return True, True  # Continue, refresh needed
            else:
                key = key_bytes.decode('utf-8', errors='ignore').lower()
                if key == 'f':
                    self.cycle_filter()
                    return True, True  # Continue, refresh needed
                elif key == 's':
                    self.cycle_sort()
                    return True, True  # Continue, refresh needed
                elif key == 'q':
                    return False, False  # Stop, no refresh needed
        return True, False  # Continue, no refresh needed

    def run(self, refresh_interval=2):
        """Run the connection monitor"""
        print("Starting TCP Connection Monitor...")
        print("Note: May require administrator/root privileges for full process information.")
        print("DNS names will resolve in the background...\n")
        time.sleep(1)

        # Start DNS resolver thread
        self.running = True
        self.dns_thread = Thread(target=self.dns_resolver_worker, daemon=True)
        self.dns_thread.start()

        try:
            connections = []
            max_scroll = 0
            page_size = 20
            while True:
                connections = self.get_tcp_connections()
                max_scroll, page_size = self.display_connections(connections)

                # Sleep in small increments to check for keyboard input
                for _ in range(int(refresh_interval * 10)):
                    running, needs_refresh = self.check_keyboard_input(max_scroll, page_size)
                    if not running:
                        raise KeyboardInterrupt
                    if needs_refresh:
                        # Immediately redisplay with current connections
                        max_scroll, page_size = self.display_connections(connections)
                    time.sleep(0.1)

        except KeyboardInterrupt:
            print("\n\nMonitoring stopped.")
            self.running = False
            sys.exit(0)
        except Exception as e:
            print(f"\nError: {e}")
            self.running = False
            sys.exit(1)

def main():
    print("TCP Connection Monitor")
    print("=" * 50)
    print("\nThis tool monitors all TCP connections in real-time.")
    print("It shows:")
    print("  - Process name and PID")
    print("  - Local address and port")
    print("  - Remote endpoint with hostname resolution")
    print("\nNote: Run with administrator/root privileges for complete information.\n")

    # Parse command line arguments for refresh interval
    refresh_interval = 2
    if len(sys.argv) > 1:
        try:
            refresh_interval = int(sys.argv[1])
        except ValueError:
            print("Invalid refresh interval. Using default (2 seconds).")

    monitor = ConnectionMonitor()
    monitor.run(refresh_interval)

if __name__ == "__main__":
    main()
