#!/usr/bin/env python3
"""
Record events from Redis stream dpi:logs into JSONL format.
"""
import argparse
import json
import os
import signal
import sys
import time
import redis


def main():
    parser = argparse.ArgumentParser(description="Record dpi:logs stream to JSONL.")
    parser.add_argument("--host", default="127.0.0.1", help="Redis host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=6379, help="Redis port (default: 6379)")
    parser.add_argument("--password-file", help="Path to Redis password file")
    parser.add_argument("--password", default=None, help="Redis password string")
    parser.add_argument("--stream", default="dpi:logs", help="Stream name (default: dpi:logs)")
    parser.add_argument("--out", required=True, help="Output JSONL file path")
    args = parser.parse_args()

    password = args.password
    if args.password_file and os.path.isfile(args.password_file):
        with open(args.password_file, "r", encoding="utf-8") as f:
            password = f.read().strip()

    r = redis.Redis(
        host=args.host,
        port=args.port,
        password=password,
        decode_responses=True,
    )

    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    out_file = open(args.out, "w", encoding="utf-8")

    running = True

    def handle_signal(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    last_id = "$"
    count_written = 0

    try:
        while running:
            try:
                entries = r.xread(streams={args.stream: last_id}, count=5000, block=1000)
                if not entries:
                    continue

                for stream_name, stream_entries in entries:
                    for entry_id, fields in stream_entries:
                        try:
                            ms_part = int(entry_id.split("-")[0])
                            ts = ms_part / 1000.0
                        except (ValueError, IndexError):
                            ts = 0.0

                        record = dict(fields)
                        record["id"] = entry_id
                        record["ts"] = ts

                        out_file.write(json.dumps(record) + "\n")
                        count_written += 1
                        last_id = entry_id

            except (redis.ConnectionError, redis.TimeoutError):
                if not running:
                    break
                time.sleep(0.1)
            except Exception as e:
                if not running:
                    break
                print(f"Warning: error reading from Redis: {e}", file=sys.stderr)
                time.sleep(0.1)
    finally:
        out_file.flush()
        out_file.close()
        print(f"Recorded {count_written} events.")

    sys.exit(0)


if __name__ == "__main__":
    main()

