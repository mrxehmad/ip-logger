# IP Change Logger with Geolocation Tracking

A lightweight C program that monitors your public IP address, detects changes, and logs them with geolocation data.

## Features

- **Interval-based polling**: Checks for IP changes at regular intervals specified by the user
- **Redundant API support**: Uses multiple geolocation APIs to ensure reliability
- **Structured logging**: Stores data in a human-readable and machine-parseable JSON format
- **Systemd service ready**: Can be deployed as a background Linux service

## Requirements

- C compiler (GCC recommended)
- libcurl development package
- libjansson development package

On Debian/Ubuntu systems:
```
sudo apt install build-essential libcurl4-openssl-dev libjansson-dev
```

On CentOS/RHEL/Fedora:
```
sudo dnf install gcc make libcurl-devel jansson-devel
```

## Building

```
make
```
or 

```
gcc -o iplogger iplogger.c -lcurl -ljansson
```
## Usage

```
./ip_change_logger [OPTIONS]
```

### Options

- `-t <minutes>`: Polling interval in minutes (default: 15)
- `-o <file>`: Output log file path (default: ip_log.json)
- `-h`: Show help

### Examples

Check IP every 5 minutes:
```
./ip_change_logger -t 5
```

Use a custom log file:
```
./ip_change_logger -o /path/to/log/file.json
```

## Output Format

The program creates a JSON file with entries for each IP change:

```json
[
  {
    "timestamp": "2025-04-30 14:00:00",
    "ip": "38.2.1.3",
    "country": "UK",
    "asn": "AS112590 My ISP"
  },
  {
    "timestamp": "2025-04-30 14:05:00",
    "ip": "192.0.2.1",
    "country": "US",
    "asn": "AS1234 My ISP"
  }
]
```

## Installing as a Service

The program can be installed as a systemd service to run in the background:


```ip_change_logger.service
[Unit]
Description=IP Change Logger Service
After=network.target

[Service]
ExecStart=/usr/local/bin/iplogger -t 30 -o /var/www/ip_logger.json
#WorkingDirectory=/var/log/iplogger
User=root
Group=root
Restart=always
Nice=19
IOSchedulingClass=idle
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
```

```
sudo cp ip_change_logger.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ip_change_logger.service
sudo systemctl start ip_change_logger.service
```

## API Fallback Mechanism

The program tries the following APIs in order:
1. ip-api.com
2. ipinfo.io
3. ifconfig.me

If one API fails, it automatically tries the next one.

## License

This project is open-source software.
