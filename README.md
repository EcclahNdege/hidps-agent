# HIDPS Agent

## Description

The HIDPS Agent is a lightweight, host-based intrusion detection and prevention system agent. It is designed to be installed on a Linux system to monitor its activity, collect logs, and report back to a central monitoring server. The agent can also receive and execute commands from the server, allowing for remote administration and response.

## Features

*   **Simple Installation:** A single script to install and configure the agent to run persistently across reboots.
*   **Log Monitoring:**
    *   Reads logins, authentication attempts, and UFW logs using `journalctl`.
    *   Monitors `syslog` files via `auditd`.
*   **System Monitoring:**
    *   Tracks running processes using `psutil`.
    *   Reports system resource usage, including CPU, RAM, and storage.
*   **Firewall Management:**
    *   Reads the current status and rules of the firewall.
*   **Remote Controllability:**
    *   Receives commands from the monitoring server for real-time interaction.
    *   Executes shell commands as instructed by the server.
*   **Data Emission:**
    *   Forwards collected logs and system metrics to the central server.
*   **File Monitoring:**
    *   Dynamically add or remove files and directories from the monitoring list using `auditd`.
    *   Comes with a set of default files to monitor.

## Installation

To install the agent, run the following command. This will download and execute the installation script, which will set up the agent and configure it to start on boot.

```bash
curl -sSL https://your-server.com/install.sh | sudo bash
```

## Uninstallation

To remove the agent from your system, you can run the uninstallation script:

```bash
/usr/local/hidps-agent/uninstall.sh
```

## Usage

The HIDPS Agent runs as a background service. Its behavior is primarily controlled by the central monitoring server.

### Commands

The agent can receive and execute the following commands from the monitor:

*   `monitor_file <path>`: Adds a new file or directory to the monitoring list.
*   `unmonitor_file <path>`: Removes a file or directory from the monitoring list.
*   `get_system_usage`: Retrieves the current CPU, RAM, and storage usage.
*   `get_firewall_status`: Fetches the current firewall status and rules.
*   `execute_command <command>`: Executes a shell command on the host.

### Monitoring

By default, the agent monitors the following:

*   **Logins and Authentication:** All login attempts (successful and failed).
*   **UFW Logs:** All firewall activity logged by UFW.
*   **Syslog:** Standard system log files.
*   **Default Files:**
    *   `/etc/passwd`
    *   `/etc/shadow`
    *   `/etc/sudoers`

## Contributing

Contributions are welcome! Please open an issue or submit a pull request with your changes.

## License

This project is licensed under the MIT License.