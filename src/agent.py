import asyncio
import json
import psutil
import subprocess
import datetime
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration
AGENT_ID = "agent_001"  # This should be dynamic or configured

def print_normalized_log(log_type, service, message):
    """Formats a log entry into a standardized JSON format and prints it."""
    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "service": service,
        "message": message,
        "type": log_type,
    }
    print(json.dumps(log_entry))


async def run_command(command):
    """Runs a shell command and returns its output."""
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    if stderr:
        return f"Error: {stderr.decode().strip()}"
    return stdout.decode().strip()

async def get_system_usage():
    """Gets CPU, RAM, and storage usage."""
    cpu_usage = psutil.cpu_percent(interval=1)
    ram_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    return {
        "cpu_usage": cpu_usage,
        "ram_usage": ram_usage,
        "disk_usage": disk_usage
    }


# --- File Monitoring with Watchdog ---

# Global state for paths to monitor
watched_paths = set()
paths_lock = asyncio.Lock()
reload_watcher = asyncio.Event()

async def monitor_file(path):
    """Command to add a file or directory to the monitoring list and reload the watcher."""
    async with paths_lock:
        watched_paths.add(os.path.abspath(path))
    reload_watcher.set()
    print_normalized_log('agent_info', 'watchdog', f"Request to monitor {path} received. Watcher will reload.")
    return f"Added {path} to watch list."

async def unmonitor_file(path):
    """Command to remove a file or directory from the monitoring list and reloads the watcher."""
    async with paths_lock:
        # Use discard for safe removal
        watched_paths.discard(os.path.abspath(path))
    reload_watcher.set()
    print_normalized_log('agent_info', 'watchdog', f"Request to unmonitor {path} received. Watcher will reload.")
    return f"Removed {path} from watch list."

class WatchdogEventHandler(FileSystemEventHandler):
    """Handles file system events from watchdog and logs them."""

    def on_created(self, event):
        message = f"File/Dir created: {event.src_path}"
        print_normalized_log('file_monitoring', 'watchdog', message)

    def on_deleted(self, event):
        message = f"File/Dir deleted: {event.src_path}"
        print_normalized_log('file_monitoring', 'watchdog', message)

    def on_modified(self, event):
        if event.is_directory:
            return  # Directory modifications are often noisy (e.g., timestamp updates)
        message = f"File modified: {event.src_path}"
        print_normalized_log('file_monitoring', 'watchdog', message)

    def on_moved(self, event):
        message = f"File/Dir moved or renamed: from {event.src_path} to {event.dest_path}"
        print_normalized_log('file_monitoring', 'watchdog', message)

async def monitor_files_with_watchdog():
    """Monitors files and directories using watchdog, with dynamic reloading."""
    # Set up default paths to watch from $PATH and the README
    path_env = os.environ.get('PATH', '')
    default_dirs = {p for p in path_env.split(os.pathsep) if os.path.isdir(p)}
    default_files = {'/etc/passwd', '/etc/shadow', '/etc/sudoers'}

    async with paths_lock:
        watched_paths.update(default_dirs)
        watched_paths.update(default_files)

    event_handler = WatchdogEventHandler()

    while True:
        observer = Observer()
        watches = {}  # Using a dict {path: is_recursive} to manage watches

        async with paths_lock:
            current_watched_paths = set(watched_paths)

        for path in current_watched_paths:
            if not os.path.exists(path):
                continue
            if os.path.isdir(path):
                # If we're already watching this path non-recursively, upgrade to recursive
                if path not in watches or not watches[path]:
                    watches[path] = True
            elif os.path.isfile(path):
                parent_dir = os.path.dirname(path)
                # If not already watching this dir, add as non-recursive
                if parent_dir not in watches:
                    watches[parent_dir] = False

        for path, is_recursive in watches.items():
            observer.schedule(event_handler, path, recursive=is_recursive)

        observer.start()
        print_normalized_log('agent_info', 'watchdog', f"Started watching {len(watches)} paths.")

        try:
            await reload_watcher.wait()
            reload_watcher.clear()
            print_normalized_log('agent_info', 'watchdog', "Reloading file watcher...")
        finally:
            observer.stop()
            observer.join()

async def stream_journal_logs():
    """Continuously streams logs from journalctl for login and firewall events."""
    log_command = "sudo journalctl -f -n 0 --no-pager -o json"
    process = await asyncio.create_subprocess_shell(
        log_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    while True:
        try:
            line = await process.stdout.readline()
            if not line:
                await asyncio.sleep(1)  # Avoid busy-looping if process exits
                continue

            log_data = json.loads(line)
            message = log_data.get('MESSAGE', '')
            service = log_data.get('SYSLOG_IDENTIFIER', 'unknown')

            log_type = None
            # UFW logs often come from the kernel and contain 'UFW'
            if 'UFW' in message and log_data.get('_TRANSPORT') == 'kernel':
                log_type = 'firewall'
                service = 'ufw'
            elif service in ['sshd', 'login', 'sudo', 'su']:
                log_type = 'login'

            if log_type:
                print_normalized_log(log_type, service, message)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # In case of malformed JSON or other errors, we can skip the line.
            pass
        except Exception as e:
            print_normalized_log('agent_error', 'stream_journal_logs', f"An unexpected error occurred: {e}")
            await asyncio.sleep(5)

async def monitor_processes():
    """Monitors for new and terminated processes."""
    known_pids = set(psutil.pids())
    while True:
        await asyncio.sleep(5)
        current_pids = set(psutil.pids())
        new_pids = current_pids - known_pids
        terminated_pids = known_pids - current_pids

        for pid in new_pids:
            try:
                p = psutil.Process(pid)
                message = f"New process started: PID={pid}, Name={p.name()}, Cmdline={' '.join(p.cmdline())}"
                print_normalized_log('process', 'psutil', message)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        for pid in terminated_pids:
            message = f"Process terminated: PID={pid}"
            print_normalized_log('process', 'psutil', message)
        
        known_pids = current_pids

async def local_system_usage_reporter():
    """Periodically reports system usage in normalized log format."""
    while True:
        try:
            usage = await get_system_usage()
            print_normalized_log('system_usage', 'psutil', usage)
            await asyncio.sleep(60)
        except Exception as e:
            print_normalized_log('agent_error', 'local_system_usage_reporter', f"An unexpected error occurred: {e}")
            await asyncio.sleep(60)

async def main():
    """Main function for local testing."""
    print("Starting HIDPS Agent in local test mode...")

    # Start monitoring tasks
    tasks = [
        asyncio.create_task(stream_journal_logs()),
        asyncio.create_task(monitor_files_with_watchdog()),
        asyncio.create_task(monitor_processes()),
        asyncio.create_task(local_system_usage_reporter())
    ]

    print("Agent is running. Press Ctrl+C to stop.")
    await monitor_file('/home/ecclahub/test/test.txt')
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Agent stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")
