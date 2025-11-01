# provides tools to interact with the OS: join paths, checking files & folders exist...
import os

# gives access to system-specific info: exiting the program if there's an error, etc.
import sys

# lets you read & write data in JSON format (it's gonna create one and save the info in it)
import json

# provides hash functions
import hashlib

# writes everything important about how the code runs to a log file
import logging

# a clean way to work with paths: managing directories, building paths...
from pathlib import Path

# reading & analyzing packets in PCAP, allows me to access packets details...
import pyshark

import config


# Base directory where we save extracted artifacts
ARTIFACT_DIR = Path(config.ARTIFACT_DIR)
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)  # make sure it exists


# write everything important the program does both to your screen and to your log file,
# with timestamps and message types.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(config.LOG_PATH),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("extractor")


# creates unique hash name for every extracted file
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# save the file's data in artifact folder + metadata
def save_artifact(data: bytes, info: dict):
    sha = sha256_bytes(data)

    file_path = ARTIFACT_DIR / sha
    metadata_path = ARTIFACT_DIR / f"{sha}.meta.json"

    # to avoid duplicates, check if the file already exists
    if not file_path.exists():
        with open(file_path, "wb") as f:
            f.write(data)
        log.info(f"Saved artifact {sha} ({len(data)} bytes)")
    else:
        log.info(f"Artifact {sha} already exists, skipping")

    # write a json metadata file
    info.update({
        "sha256": sha,
        "size": len(data)
    })

    with open(metadata_path, "w") as meta:
        json.dump(info, meta, indent=2)


def process_pcap(pcap_path: str):
    # writing message in log
    log.info(f"Opening PCAP: {pcap_path}")

    # open the capture with pyshark using override_prefs
    cap = pyshark.FileCapture(
        pcap_path,
        keep_packets=False,  # drop packets from memory after processing each one
        override_prefs=config.TSHARK_PREFS
    )

    streams = {}        # {stream_id: bytearray(data...)}
    packet_count = 0

    for pkt in cap:
        packet_count += 1
        if packet_count % 100 == 0:
            log.info(f"Processed {packet_count} packets so far...")

        try:
            # only care about TCP packets
            if "TCP" in pkt:
                # use TCP stream index to group packets that belong to the same conversation
                stream_id = int(pkt.tcp.stream)

                # check if the packet actually has TCP payload bytes
                if hasattr(pkt.tcp, "payload"):
                    # payload looks like: "24:24:57:73:89", need to remove ":" then convert hex->bytes
                    raw_hex = pkt.tcp.payload.replace(":", "")
                    data = bytes.fromhex(raw_hex)

                    # append to the correct stream buffer
                    streams.setdefault(stream_id, bytearray()).extend(data)

        except Exception as e:
            log.warning(f"Packet error: {e}")

    cap.close()
    log.info(f"Packets read: {packet_count}, streams: {len(streams)}")

    # now walk over each TCP stream and try to carve HTTP bodies
    for sid, stream_data in streams.items():
        data = bytes(stream_data)

        # quick & dirty HTTP detection
        if (
            b"HTTP/1." in data or
            b"GET" in data or
            b"POST" in data
        ):
            # find end of HTTP headers (\r\n\r\n)
            start = data.find(b"\r\n\r\n")
            if start != -1:
                body = data[start + 4:]

                # save the extracted body as an artifact
                save_artifact(
                    body,
                    {
                        "protocol": "HTTP",
                        "stream_id": sid,
                        "pcap": pcap_path,
                    }
                )

    log.info("Extraction complete!")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        log.error("Usage: python file_extractor.py <pcap file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    if not os.path.exists(pcap_file):
        log.error(f"PCAP not found: {pcap_file}")
        sys.exit(1)

    process_pcap(pcap_file)
