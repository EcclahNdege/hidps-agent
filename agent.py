import asyncio
import json
import psutil
import subprocess
import datetime
import os
import sys
import websockets
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration (Loaded from Environment Variables)
AGENT_ID = os.environ.get("AGENT_ID", "agent_unknown")
BACKEND_URL = os.environ.get("BACKEND_URL", "wss://hidps-backend-gi76.onrender.com")
RECONNECT_DELAY = 5

# Global Event Queue for Logs
log_queue = asyncio.Queue()

# --- Logging Helper ---

def queue_normalized_log(log_type, service, message):
    """Formats a log entry and puts it in the async queue to be sent."""
    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "agent_id": AGENT_ID,
        "service": service,
        "message": message,
        "type": log_type,
    }
    # Put in queue non-blocking (the sender task will handle it)
    try:
        log_queue.put_nowait(log_entry)
    except asyncio.QueueFull:
        pass # Drop log if queue is full to prevent memory leaks in extreme cases

# --- System Commands (UFW) ---

async def run_shell_command(command_list):
    """Runs a shell command and returns success boolean and output."""
    try:
        process = await asyncio.create_subprocess_exec(
            *command_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode == 0:
            return True, stdout.decode().strip()
        else:
            return False, stderr.decode().strip()
    except Exception as e:
        return False, str(e)

async def set_firewall_state(enable: bool):
    """Enables or disables UFW."""
    action = "enable" if enable else "disable"
    # --force is needed for 'enable' to avoid yes/no prompt
    cmd = ['ufw', '--force', 'enable'] if enable else ['ufw', 'disable']
    
    success, output = await run_shell_command(cmd)
    
    if success:
        queue_normalized_log('firewall', 'firewall_manager', f"Firewall {action}d successfully.")
        return {"status": "success", "message": f"Firewall {action}d"}
    else:
        queue_normalized_log('firewall', 'firewall_manager', f"Failed to {action} firewall: {output}")
        return {"status": "error", "message": output}

async def get_firewall_status():
    """Gets raw UFW status."""
    success, output = await run_shell_command(['ufw', 'status'])
    return output if success else "Unknown"

async def get_firewall_rules():
    """Parses 'ufw status numbered' into a JSON-friendly list of rules."""
    success, output = await run_shell_command(['ufw', 'status', 'numbered'])
    if not success:
        return []
    
    rules = []
    # Simple parser for UFW status table
    lines = output.split('\n')
    for line in lines:
        if '[' in line and ']' in line:
            # Format: [ 1] 22/tcp ALLOW IN Anywhere
            try:
                parts = line.split(']')
                index = parts[0].replace('[', '').strip()
                details = parts[1].strip().split()
                # details example: ['22/tcp', 'ALLOW', 'IN', 'Anywhere']
                rules.append({
                    "id": index,
                    "to": details[0],
                    "action": details[1],
                    "from": details[-1]
                })
            except: continue
    return rules

async def manage_rule(action, rule_data):
    """Adds or deletes rules using the 'ufw' command."""
    # action: 'allow' or 'delete'
    # rule_data: e.g., '80/tcp' or '1' (for delete)
    cmd = ['ufw', action, rule_data]
    success, output = await run_shell_command(cmd)
    
    # Refresh rules after change
    new_rules = await get_firewall_rules()
    return {"status": "success" if success else "error", "rules": new_rules}

# --- Monitoring Functions ---

async def get_system_usage():
    """Gets CPU, RAM, and storage usage."""
    return {
        "cpu_usage": psutil.cpu_percent(interval=None),
        "ram_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent
    }

# --- Watchdog Logic (FIXED) ---

watched_paths = set()
paths_lock = asyncio.Lock()
reload_watcher = asyncio.Event()

class WatchdogEventHandler(FileSystemEventHandler):
    """Handles file system events and logs them."""
    
    def __init__(self, watched_files):
        super().__init__()
        self.watched_files = watched_files  # Set of specific file paths we care about
    
    def _should_log_event(self, path):
        """Check if this path is one we're explicitly monitoring."""
        abs_path = os.path.abspath(path)
        # Check if the path exactly matches one of our watched files
        # OR if it's inside a watched directory
        for watched in self.watched_files:
            if abs_path == watched or abs_path.startswith(watched + os.sep):
                return True
        return False
    
    def on_created(self, event):
        if self._should_log_event(event.src_path):
            queue_normalized_log('file_monitoring', 'watchdog', f"File/Dir created: {event.src_path}")
    
    def on_deleted(self, event):
        if self._should_log_event(event.src_path):
            queue_normalized_log('file_monitoring', 'watchdog', f"File/Dir deleted: {event.src_path}")
    
    def on_modified(self, event):
        if not event.is_directory and self._should_log_event(event.src_path):
            queue_normalized_log('file_monitoring', 'watchdog', f"File modified: {event.src_path}")
    
    def on_moved(self, event):
        if self._should_log_event(event.src_path):
            queue_normalized_log('file_monitoring', 'watchdog', f"Moved: {event.src_path} to {event.dest_path}")

async def monitor_file_command(path):
    """Add a path to the watch list."""
    async with paths_lock:
        abs_path = os.path.abspath(path)
        watched_paths.add(abs_path)
        queue_normalized_log('agent_info', 'watchdog', f"Now monitoring: {abs_path}")
    reload_watcher.set()

async def unmonitor_file_command(path):
    """Remove a path from the watch list."""
    async with paths_lock:
        abs_path = os.path.abspath(path)
        watched_paths.discard(abs_path)
        queue_normalized_log('agent_info', 'watchdog', f"Stopped monitoring: {abs_path}")
    reload_watcher.set()

async def watchdog_task():
    """Manages the file observer loop with proper directory and file watching."""
    
    # Add default paths
    async with paths_lock:
        watched_paths.add('/etc/passwd')
        watched_paths.add('/etc/shadow')

    observer = None
    
    while True:
        try:
            # Stop existing observer if running
            if observer and observer.is_alive():
                observer.stop()
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, observer.join)
            
            # Get current watched paths
            async with paths_lock:
                current_paths = set(watched_paths)
            
            if not current_paths:
                # No paths to watch, just wait for reload signal
                await reload_watcher.wait()
                reload_watcher.clear()
                continue
            
            # Create new observer with current paths
            observer = Observer()
            event_handler = WatchdogEventHandler(current_paths)
            
            # Group paths by their parent directories
            dirs_to_watch = {}
            for path in current_paths:
                if not os.path.exists(path):
                    queue_normalized_log('agent_error', 'watchdog', f"Path does not exist: {path}")
                    continue
                
                if os.path.isdir(path):
                    # Watch the directory recursively
                    dirs_to_watch[path] = True  # recursive
                else:
                    # For files, watch their parent directory non-recursively
                    parent_dir = os.path.dirname(path)
                    if parent_dir not in dirs_to_watch:
                        dirs_to_watch[parent_dir] = False  # non-recursive
            
            # Schedule watches
            active_watches = 0
            for dir_path, recursive in dirs_to_watch.items():
                try:
                    observer.schedule(event_handler, dir_path, recursive=recursive)
                    active_watches += 1
                    queue_normalized_log('agent_info', 'watchdog', 
                        f"Watching directory: {dir_path} (recursive={recursive})")
                except Exception as e:
                    queue_normalized_log('agent_error', 'watchdog', 
                        f"Failed to watch {dir_path}: {e}")
            
            if active_watches > 0:
                observer.start()
                queue_normalized_log('agent_info', 'watchdog', 
                    f"File monitoring active: watching {active_watches} directories for {len(current_paths)} paths")
            else:
                queue_normalized_log('agent_error', 'watchdog', 
                    "No valid paths to watch")
            
            # Wait for reload signal or indefinitely if watching
            await reload_watcher.wait()
            reload_watcher.clear()
            
        except Exception as e:
            queue_normalized_log('agent_error', 'watchdog', f"Watchdog error: {e}")
            await asyncio.sleep(5)

# --- Journal Logs Streaming ---

async def stream_journal_logs():
    """Streams logs from journalctl."""
    cmd = "journalctl -f -n 50 --no-pager -o json"
    process = await asyncio.create_subprocess_shell(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    
    while True:
        line = await process.stdout.readline()
        if not line:
            await asyncio.sleep(1)
            continue
        try:
            log_data = json.loads(line)
            message = log_data.get('MESSAGE', '')
            service = log_data.get('SYSLOG_IDENTIFIER', 'unknown')
            
            # Filtering logic
            log_type = None
            if 'UFW' in message and log_data.get('_TRANSPORT') == 'kernel':
                log_type = 'firewall'
                service = 'ufw'
            elif service in ['sshd', 'login', 'sudo', 'su']:
                log_type = 'login'

            if log_type:
                queue_normalized_log(log_type, service, message)
        except:
            pass

# --- Process Monitoring ---

async def monitor_processes():
    known_pids = set(psutil.pids())
    while True:
        await asyncio.sleep(5)
        current_pids = set(psutil.pids())
        new_pids = current_pids - known_pids
        
        for pid in new_pids:
            try:
                p = psutil.Process(pid)
                msg = f"New Process: {p.name()} (PID {pid}) {p.cmdline()}"
                queue_normalized_log('process', 'psutil', msg)
            except: pass
        known_pids = current_pids

# --- WebSocket & Main Logic ---

async def websocket_handler():
    """Handles the WebSocket connection, sending logs and receiving commands."""
    uri = f"{BACKEND_URL}?agent_id={AGENT_ID}"
    
    while True:
        try:
            print(f"Connecting to {BACKEND_URL}...")
            async with websockets.connect(uri) as websocket:
                print("Connected to Backend.")
                queue_normalized_log('agent_info', 'core', "Agent connected to backend.")

                # Create tasks for this connection session
                sender = asyncio.create_task(log_sender(websocket))
                receiver = asyncio.create_task(command_receiver(websocket))
                stats_reporter = asyncio.create_task(periodic_stats(websocket))

                # Wait for either task to end (connection closed or error)
                done, pending = await asyncio.wait(
                    [sender, receiver, stats_reporter],
                    return_when=asyncio.FIRST_COMPLETED
                )

                for task in pending:
                    task.cancel()
                
        except (websockets.exceptions.ConnectionClosed, OSError) as e:
            print(f"Connection lost: {e}. Retrying in {RECONNECT_DELAY}s...")
            await asyncio.sleep(RECONNECT_DELAY)
        except Exception as e:
            print(f"Unexpected error: {e}")
            await asyncio.sleep(RECONNECT_DELAY)

async def log_sender(websocket):
    """Reads from the queue and sends to WebSocket."""
    while True:
        log_entry = await log_queue.get()
        try:
            await websocket.send(json.dumps(log_entry))
        except websockets.exceptions.ConnectionClosed:
            # Connection closed, put the log back and let the handler reconnect.
            await log_queue.put(log_entry)
            raise 

async def periodic_stats(websocket):
    """Sends system stats AND firewall status every 30 seconds."""
    while True:
        stats = await get_system_usage()
        # Check if UFW is active
        success, output = await run_shell_command(['ufw', 'status'])
        is_enabled = "Status: active" in output
        
        payload = {
            "type": "agent_report", 
            "agent_id": AGENT_ID,
            "data": {
                **stats,
                "firewall_enabled": is_enabled,
                "firewall_rules": await get_firewall_rules()
            }
        }
        await websocket.send(json.dumps(payload))
        await asyncio.sleep(30)

async def command_receiver(websocket):
    """Listens for commands from backend."""
    async for message in websocket:
        try:
            data = json.loads(message)
            cmd_type = data.get("command")
            payload = data.get("payload", {})
            
            queue_normalized_log('agent_info', 'core', f"Received command: {cmd_type}")

            if cmd_type == "add_firewall_rule":
                result = await manage_rule('allow', payload.get("rule"))
                await websocket.send(json.dumps({"type": "firewall_update", "rules": result['rules']}))
            
            elif cmd_type == "delete_firewall_rule":
                # UFW delete uses the rule index number
                result = await manage_rule('delete', str(payload.get("index")))
                await websocket.send(json.dumps({"type": "firewall_update", "rules": result['rules']}))

            elif cmd_type == "toggle_firewall":
                await set_firewall_state(payload.get("enabled", False))
            
            elif cmd_type == "monitor_file":
                await monitor_file_command(payload.get("path"))
            
            elif cmd_type == "unmonitor_file":
                await unmonitor_file_command(payload.get("path"))

            elif cmd_type == "get_firewall_status":
                status = await get_firewall_status()
                # Respond directly (optional, usually updates state via stats or logs)
                resp = {"type": "command_response", "id": data.get("id"), "result": status}
                await websocket.send(json.dumps(resp))

        except json.JSONDecodeError:
            print("Received invalid JSON command")

async def main():
    # Start background data collectors
    asyncio.create_task(stream_journal_logs())
    asyncio.create_task(monitor_processes())
    asyncio.create_task(watchdog_task())
    
    # Start main connection loop
    await websocket_handler()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("WARNING: This agent is designed to run as root (for UFW/Journal access).")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Agent stopped.")