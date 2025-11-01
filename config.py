# configuration file

# Points to the PCAP file I want to analyze
PCAP_PATH = r"C:\Users\MyHP\OneDrive\Desktop\yara rules\sample.pcap"

# Folder to save the extracted files
ARTIFACT_DIR = r"C:\Users\MyHP\OneDrive\Desktop\yara rules\temp_artifacts"

# Log file path
LOG_PATH = r"C:\Users\MyHP\OneDrive\Desktop\yara rules\extractor.log"

# TShark preferences to reassemble packets
TSHARK_PREFS = {
    "tcp.desegment_tcp_streams": "TRUE",
    "http.desegment_headers": "TRUE",
    "http.desegment_body": "TRUE"
}
