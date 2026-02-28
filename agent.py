import json
import os
import time
import traceback

from monitor import system_monitor
from monitor import process_monitor
from monitor import network_monitor
from monitor import eventlog_monitor
from detection import rule_engine
from response import self_heal
from utils.logger import log_event

_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def _load_config():
    try:
        with open(_config_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def start_agent(stop_event=None):
    try:
        log_event("Agent entry reached")
        time.sleep(2)
        log_event("Agent initialized, entering main loop")

        while True:
            if stop_event is not None and stop_event.is_set():
                log_event("Agent stopping gracefully")
                break

            try:
                # 1. Collect data
                system_data = system_monitor.get_system_metrics()
                process_data = process_monitor.get_suspicious_processes()
                network_data = network_monitor.get_suspicious_connections()

                data = {
                    "system": system_data,
                    "processes": process_data,
                    "network": network_data,
                    "failed_logins": eventlog_monitor.get_failed_logins(),
                }

                # 2. HEARTBEAT (ALWAYS)
                log_event("Heartbeat: Monitoring active")

                # 3. Optional lightweight visibility
                log_event(
                    f"Snapshot | net={len(network_data)} "
                    f"proc={len(process_data)}"
                )

                # 4. Analyze threats (FAIL-SAFE)
                threats = rule_engine.analyze(data) or []

                # 5. Respond
                if threats:
                    for threat in threats:
                        log_event(f"Threat detected: {threat}")
                        self_heal.heal(threat)
                else:
                    log_event("No threats detected")

            except Exception as e:
                log_event(f"Runtime error: {e}")
                log_event(traceback.format_exc())

            config = _load_config()
            interval = config.get("monitoring_interval_seconds", 5)
            time.sleep(interval)

    except Exception as e:
        log_event("FATAL AGENT ERROR")
        log_event(str(e))
        log_event(traceback.format_exc())
