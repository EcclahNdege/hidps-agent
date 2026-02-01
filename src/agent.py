import asyncio
import json
import psutil
import subprocess

# Configuration
AGENT_ID = "agent_001"  # This should be dynamic or configured

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

async def stream_logs(log_command):
    """Continuously streams logs from a given command."""
    process = await asyncio.create_subprocess_shell(
        log_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        print(f"LOG: {line.decode().strip()}")

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
                print(f"PROCESS_NEW: PID={pid}, Name={p.name()}, Cmdline={' '.join(p.cmdline())}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        for pid in terminated_pids:
            print(f"PROCESS_TERMINATED: PID={pid}")
        
        known_pids = current_pids

async def local_system_usage_reporter():
    """Periodically prints system usage locally."""
    while True:
        usage = await get_system_usage()
        print(f"SYSTEM_USAGE: {json.dumps(usage)}")
        await asyncio.sleep(60)

async def main():
    """Main function for local testing."""
    print("Starting HIDPS Agent in local test mode...")

    # Start monitoring tasks
    tasks = [
        asyncio.create_task(stream_logs("sudo journalctl -f -n 0 --no-pager")),
        asyncio.create_task(stream_logs("sudo tail -f /var/log/audit/audit.log")),
        asyncio.create_task(monitor_processes()),
        # asyncio.create_task(local_system_usage_reporter())
    ]

    print("Agent is running. Press Ctrl+C to stop.")
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Agent stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")
