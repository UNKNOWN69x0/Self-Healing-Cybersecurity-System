import json
import os
import time
import traceback

from monitor import system_monitor
from monitor import process_monitor
from monitor import network_monitor
from monitor import eventlog_monitor
from monitor.traffic_monitor import TrafficMonitor
from monitor.threat_intel import check_connection_threat
from detection import rule_engine
from detection.ml_anomaly import AnomalyDetector
from response import self_heal
from utils.logger import log_event
from utils.notifier import notify_user

_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
_model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "anomaly_model.pkl")


def _load_config():
    try:
        with open(_config_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def start_agent(stop_event=None):
    try:
        log_event("Agent entry reached")
        print("Agent entry reached")
        time.sleep(2)
        log_event("Agent initialized, entering main loop")
        print("Agent initialized, entering main loop")

        traffic_monitor = TrafficMonitor()
        config = _load_config()
        ml_cfg = config.get("ml", {})
        anomaly_detector = AnomalyDetector(
            model_path=_model_path,
            min_samples=ml_cfg.get("min_training_samples", 20),
            retrain_interval=ml_cfg.get("retrain_interval", 50),
            contamination=ml_cfg.get("contamination", 0.1),
        )

        while True:
            if stop_event is not None and stop_event.is_set():
                log_event("Agent stopping gracefully")
                print("Agent stopping gracefully")
                break

            try:
                # 1. Collect system metrics
                system_data = system_monitor.get_system_metrics()
                process_data = process_monitor.get_suspicious_processes()
                network_data = network_monitor.get_suspicious_connections()
                failed_logins = eventlog_monitor.get_failed_logins()

                # 2. Collect traffic data
                traffic_data = traffic_monitor.get_traffic_delta()

                data = {
                    "system": system_data,
                    "processes": process_data,
                    "network": network_data,
                    "failed_logins": failed_logins,
                    "traffic": traffic_data,
                }

                # 3. HEARTBEAT (ALWAYS)
                log_event("Heartbeat: Monitoring active")
                print("Heartbeat: Monitoring active")

                # 4. Optional lightweight visibility
                log_event(
                    f"Snapshot | net={len(network_data)} "
                    f"proc={len(process_data)}"
                )

                # 5. Check threat intelligence for each network connection
                for conn in network_data:
                    ip = conn.get("ip")
                    port = conn.get("port")
                    if ip and port:
                        level = check_connection_threat(ip, port)
                        if level:
                            log_event(f"Threat intel: {ip}:{port} -> {level}")

                # 6. Analyze threats using rule engine (FAIL-SAFE)
                threats = rule_engine.analyze(data) or []

                # 7. ML anomaly detection
                config = _load_config()
                ml_cfg = config.get("ml", {})
                if ml_cfg.get("enabled", True):
                    features = [
                        system_data.get("cpu", 0),
                        system_data.get("memory", 0),
                        traffic_data.get("total_connections", 0),
                        len(process_data),
                        traffic_data.get("bytes_sent_per_sec", 0),
                        traffic_data.get("bytes_recv_per_sec", 0),
                        len({c.get("ip") for c in network_data if c.get("ip")}),
                        failed_logins,
                    ]
                    anomaly_detector.collect(features)
                    status = anomaly_detector.get_status()
                    log_event(f"ML status: {status}")
                    if anomaly_detector.predict(features):
                        ml_threat = {
                            "type": "ML_ANOMALY",
                            "severity": "HIGH",
                            "detail": (
                                f"cpu={features[0]:.1f}% mem={features[1]:.1f}% "
                                f"conns={int(features[2])} "
                                f"sent={features[4]:.0f}B/s recv={features[5]:.0f}B/s"
                            ),
                        }
                        threats.append(ml_threat)

                # 8. Respond to all threats
                notif_cfg = config.get("notifications", {})
                notif_enabled = notif_cfg.get("enabled", True)
                min_severity = notif_cfg.get("min_severity", "MEDIUM")
                severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

                if threats:
                    for threat in threats:
                        log_event(f"Threat detected: {threat}")
                        print(f"Threat detected: {threat}")
                        self_heal.heal(threat)
                        # Send notification for high-severity threats
                        sev = threat.get("severity", "INFO")
                        if notif_enabled and severity_order.index(sev) >= severity_order.index(min_severity):
                            notify_user(
                                title=f"SHCS: {threat.get('type', 'THREAT')}",
                                message=threat.get("detail", str(threat)),
                                severity=sev,
                            )
                else:
                    log_event("No threats detected")
                    print("No threats detected")

            except Exception as e:
                log_event(f"Runtime error: {e}")
                log_event(traceback.format_exc())

            interval = config.get("monitoring_interval_seconds", 5)
            time.sleep(interval)

    except Exception as e:
        log_event("FATAL AGENT ERROR")
        log_event(str(e))
        log_event(traceback.format_exc())
