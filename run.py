import uvicorn
import os
import sys
import argparse

# Add the project directory to sys.path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

BANNER = """
\033[94m
   ______      __               ______                      __  ___    ____
  / ____/_  __/ /_  ___  _____ / ____/_  ______ __________/ / /   |  /  _/
 / /   / / / / __ \/ _ \/ ___// / __/ / / / __ `/ ___/ __  / / /| |  / /  
/ /___/ /_/ / /_/ /  __/ /   / /_/ / /_/ / /_/ / /  / /_/ / / ___ | / /   
\____/\__, /_.___/\___/_/    \____/\__,_/\__,_/_/   \__,_/ /_/  |_/___/   
     /____/                                                               
\033[0m
\033[96m>> Next-Gen Multi-Agent Cyber Threat Intelligence System\033[0m
\033[90m--------------------------------------------------------------------------\033[0m
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberGuard AI Runner")
    parser.add_argument("--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port number (default: 8000)")
    args = parser.parse_args()

    print(BANNER)
    print(f"[*] Initializing Neural Defense Agents...")
    print(f"[*] Dashboard Access: http://{args.host}:{args.port}/dashboard")
    print(f"[*] Press Ctrl+C to stop the system\n")

    try:
        uvicorn.run("api.main:app", host=args.host, port=args.port, reload=True)
    except KeyboardInterrupt:
        print("\n\033[93m[!] System shutdown requested. Safely terminating agents...\033[0m")
    except Exception as e:
        print(f"\n\033[91m[X] Critical Error during startup: {e}\033[0m")
