import os
import tempfile
import shutil
from typing import Dict, List
from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from scapy.all import PcapReader, IP, ARP, TCP, UDP, ICMP

# Import detector classes from existing nids.py
from nids import NIDSDetector, AlertEvent, AlertLogger

app = FastAPI(
    title="Sentinel NIDS Web Console",
    description="Web API and Dashboard interface for Sentinel Network Intrusion Detection System",
    version="1.0.0"
)

# Enable CORS for local testing and cross-origin hosting
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class WebAlertLogger:
    """In-memory alert logger for collecting NIDS alerts dynamically."""
    def __init__(self) -> None:
        self.alerts: List[Dict] = []

    def log(self, event: AlertEvent) -> None:
        self.alerts.append({
            "timestamp": event.timestamp,
            "alert_type": event.alert_type,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "details": event.details
        })

    def close(self) -> None:
        pass

# Profile configuration mapping
PROFILE_PRESETS = {
    "balanced": {
        "port_scan_threshold": 10,
        "syn_threshold": 100,
        "syn_window_seconds": 1.0,
        "syn_ack_ratio_max": 0.2,
        "alert_cooldown_seconds": 2.0,
    },
    "sensitive": {
        "port_scan_threshold": 8,
        "syn_threshold": 70,
        "syn_window_seconds": 1.0,
        "syn_ack_ratio_max": 0.3,
        "alert_cooldown_seconds": 1.5,
    },
    "strict": {
        "port_scan_threshold": 15,
        "syn_threshold": 180,
        "syn_window_seconds": 1.0,
        "syn_ack_ratio_max": 0.15,
        "alert_cooldown_seconds": 3.0,
    },
}

def analyze_pcap_file(filepath: str, profile_name: str) -> Dict:
    """Runs the NIDS Detector on a local PCAP file and gathers statistics."""
    preset = PROFILE_PRESETS.get(profile_name, PROFILE_PRESETS["balanced"])
    logger = WebAlertLogger()
    
    # Initialize the rule engine detector
    detector = NIDSDetector(
        logger=logger,
        port_scan_threshold=preset["port_scan_threshold"],
        syn_threshold=preset["syn_threshold"],
        syn_window_seconds=preset["syn_window_seconds"],
        syn_ack_ratio_max=preset["syn_ack_ratio_max"],
        alert_cooldown_seconds=preset["alert_cooldown_seconds"]
    )
    
    proto_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
    packets_processed = 0

    try:
        with PcapReader(filepath) as reader:
            for pkt in reader:
                packets_processed += 1
                
                # Protocol tallying
                if pkt.haslayer(TCP):
                    proto_stats["TCP"] += 1
                elif pkt.haslayer(UDP):
                    proto_stats["UDP"] += 1
                elif pkt.haslayer(ICMP):
                    proto_stats["ICMP"] += 1
                elif pkt.haslayer(ARP):
                    proto_stats["ARP"] += 1
                else:
                    proto_stats["OTHER"] += 1
                
                # Feed packet to rule engine
                detector.handle_packet(pkt)
    except Exception as e:
        raise RuntimeError(f"Error reading PCAP file: {str(e)}")

    # Extract source IP frequency from alerts for dashboard breakdown
    src_ip_freq = {}
    for alert in logger.alerts:
        src = alert["src_ip"]
        src_ip_freq[src] = src_ip_freq.get(src, 0) + 1

    return {
        "packets_processed": packets_processed,
        "alerts_count": len(logger.alerts),
        "protocol_stats": proto_stats,
        "alerts": logger.alerts,
        "top_offenders": sorted(src_ip_freq.items(), key=lambda x: x[1], reverse=True)[:5],
        "profile_applied": profile_name
    }

@app.post("/api/analyze")
async def api_analyze_pcap(
    file: UploadFile = File(...), 
    profile: str = Query("balanced", regex="^(balanced|sensitive|strict)$")
):
    """Endpoint to upload and analyze any network packet capture (PCAP) file."""
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Only PCAP or PCAPNG files are supported.")
    
    # Write the uploaded file to a temporary file
    temp_dir = tempfile.gettempdir()
    temp_file_path = os.path.join(temp_dir, f"upload_{file.filename}")
    
    try:
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        analysis_result = analyze_pcap_file(temp_file_path, profile)
        return JSONResponse(content=analysis_result)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    finally:
        # Cleanup temporary files
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@app.get("/api/replay-test")
async def api_replay_test(
    profile: str = Query("balanced", regex="^(balanced|sensitive|strict)$")
):
    """Endpoint to run NIDS on the pre-built 'all_alerts_test.pcap' simulation file."""
    test_pcap_path = os.path.join(os.path.dirname(__file__), "all_alerts_test.pcap")
    
    if not os.path.exists(test_pcap_path):
        raise HTTPException(status_code=404, detail="Test PCAP file 'all_alerts_test.pcap' was not found.")
    
    try:
        analysis_result = analyze_pcap_file(test_pcap_path, profile)
        return JSONResponse(content=analysis_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation replay failed: {str(e)}")

# Healthcheck route
@app.get("/api/health")
async def health():
    return {"status": "healthy", "service": "Sentinel NIDS Web App"}

# Serve Frontend static files from 'public' folder
public_path = os.path.join(os.path.dirname(__file__), "public")
if os.path.isdir(public_path):
    app.mount("/", StaticFiles(directory="public", html=True), name="public")
