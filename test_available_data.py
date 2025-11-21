import psutil
import pprint

print("=" * 80)
print("AVAILABLE CONNECTION DATA")
print("=" * 80)

# Get a sample connection
connections = psutil.net_connections(kind='tcp')
if connections:
    sample_conn = connections[0]
    print("\nConnection object attributes:")
    print(f"  dir(conn): {dir(sample_conn)}")
    print(f"\nSample connection data:")
    print(f"  fd: {sample_conn.fd}")
    print(f"  family: {sample_conn.family}")
    print(f"  type: {sample_conn.type}")
    print(f"  laddr: {sample_conn.laddr}")
    print(f"  raddr: {sample_conn.raddr}")
    print(f"  status: {sample_conn.status}")
    print(f"  pid: {sample_conn.pid}")

print("\n" + "=" * 80)
print("AVAILABLE PROCESS DATA")
print("=" * 80)

# Get a sample process
for conn in connections:
    if conn.pid:
        try:
            proc = psutil.Process(conn.pid)
            print(f"\nProcess object attributes:")
            print(f"  Available methods/properties:")
            attrs = [attr for attr in dir(proc) if not attr.startswith('_')]
            for attr in attrs:
                print(f"    - {attr}")

            print(f"\n\nSample process data (PID {conn.pid}):")
            print(f"  name(): {proc.name()}")
            print(f"  exe(): {proc.exe()}")
            print(f"  cmdline(): {proc.cmdline()}")
            print(f"  cwd(): {proc.cwd()}")
            print(f"  username(): {proc.username()}")
            print(f"  create_time(): {proc.create_time()}")
            print(f"  status(): {proc.status()}")
            print(f"  cpu_percent(): {proc.cpu_percent()}")
            print(f"  memory_info(): {proc.memory_info()}")
            print(f"  num_threads(): {proc.num_threads()}")

            # Network-related
            print(f"  connections(): {len(proc.connections())} connections")

            break
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"  Error accessing process {conn.pid}: {e}")
            continue

print("\n" + "=" * 80)
print("ADDITIONAL NETWORK STATS")
print("=" * 80)

# Network interface stats
print("\nNetwork IO counters:")
net_io = psutil.net_io_counters(pernic=False)
print(f"  bytes_sent: {net_io.bytes_sent}")
print(f"  bytes_recv: {net_io.bytes_recv}")
print(f"  packets_sent: {net_io.packets_sent}")
print(f"  packets_recv: {net_io.packets_recv}")

print("\n" + "=" * 80)
