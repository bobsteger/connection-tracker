# TCP Connection Monitor

A real-time TCP connection monitoring tool for Windows that displays all active network connections with process information, DNS resolution, and interactive controls.

## Features

- **Real-time monitoring** - Continuously updates connection list every 2 seconds
- **Process identification** - Shows which program is making each connection (name and PID)
- **DNS resolution** - Resolves IP addresses to hostnames in the background
- **Port service names** - Displays common port names (e.g., https, http, smtp)
- **Connection state filtering** - Filter by ALL, ESTABLISHED, TIME_WAIT, CLOSE_WAIT, or LISTEN
- **Sortable columns** - Sort by PID, Process, Status, Local Address, or Remote Endpoint
- **Visual indicators**:
  - Green background for new connections
  - Red background for recently closed connections
- **Interactive scrolling** - Navigate large lists with arrow keys and page up/down

## Requirements

- Python 3.6+
- Windows (uses `msvcrt` for keyboard input)
- Administrator privileges (required for full process information)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/connection-monitor.git
   cd connection-monitor
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run as Administrator for full functionality:

```bash
python connection_monitor.py
```

Optionally specify a custom refresh interval (in seconds):

```bash
python connection_monitor.py 5
```

## Controls

| Key | Action |
|-----|--------|
| `f` | Cycle through connection state filters |
| `s` | Cycle through sort columns |
| `↑` / `↓` | Scroll one line |
| `PgUp` / `PgDn` | Scroll one page |
| `q` | Quit |

## Display Columns

| Column | Description |
|--------|-------------|
| PID | Process ID |
| Process | Name of the program |
| Status | Connection state (ESTABLISHED, TIME_WAIT, etc.) |
| Local Address | Local IP and port |
| Remote Endpoint | Remote hostname/IP, port, and service name |

## License

MIT License
