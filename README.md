# cpture

Network packet capture tool that monitors HTTP Host headers.

## Installation

One-click installation script that sets up cpture as a systemd service:

```bash
sudo ./install.sh
```

This will:
- Install the capture service
- Enable automatic start on system reboot
- Start capturing immediately
- Install the `capture` command to view captured hosts

## Usage

### View Captured Hosts

```bash
capture
```

This displays all captured hosts from the `captured_hosts.txt` file.

### Service Management

```bash
# Check service status
sudo systemctl status capture

# View live logs
sudo journalctl -u capture -f

# Stop the service
sudo systemctl stop capture

# Start the service
sudo systemctl start capture

# Restart the service
sudo systemctl restart capture

# Disable auto-start on boot
sudo systemctl disable capture
```

## How It Works

The capture service runs as a systemd daemon and:
- Monitors network traffic on ports 80 and 700
- Captures HTTP Host headers
- Saves unique hosts to `/var/lib/cpture/captured_hosts.txt`
- Automatically starts on system reboot

## Requirements

- Root/sudo privileges (required for raw packet capture)
- Python 3
- Linux system with systemd