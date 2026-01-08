import joblib
import numpy as np
import os
import pandas as pd
import subprocess
import sys
import time
import warnings

from train import train
from contextlib import contextmanager


def choose_interface():
    interfaces = []
    try:
        result = subprocess.run(
            ["tshark", "-D"], capture_output=True, text=True, check=True
        )
        for line in result.stdout.strip().split("\n"):
            if line:
                index, name = line.split(".", 1)
                interfaces.append((index.strip(), name.strip()))
    except subprocess.CalledProcessError:
        print("Error retrieving network interfaces.")
        sys.exit(1)

    print("Available network interfaces:")
    for index, name in interfaces:
        print(f"{index}: {name}")

    selected_index = input("Select the interface number to monitor: ").strip()
    for index, name in interfaces:
        if index == selected_index:
            return name

    print("Invalid selection.")
    sys.exit(1)


CAPTURE_INTERFACE = choose_interface()
CAPTURE_DURATION_SECONDS = 5
PCAP_FILE = "/tmp/capture.pcap"
FLOWS_CSV = "/tmp/flows.csv"
MODEL_FILENAME = "rf_dos_model.joblib"

# Features used by the model
MODEL_FEATURES = [
    "Bwd Packet Length Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Packet Length Variance",
    "Init Fwd Win Bytes",
]

# Column mapping 
COLUMN_MAP = {
    "protocol": "Protocol",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Fwd Packets Length Total",
    "totlen_bwd_pkts": "Bwd Packets Length Total",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Packet Length Min",
    "pkt_len_max": "Packet Length Max",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwe_flag_cnt": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Avg Packet Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init Fwd Win Bytes",
    "init_bwd_win_byts": "Init Bwd Win Bytes",
    "fwd_act_data_pkts": "Fwd Act Data Packets",
    "fwd_seg_size_min": "Fwd Seg Size Min",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')


def check_dependencies():
    print("Checking dependencies...")

    try:
        subprocess.run(["tshark", "-v"], check=True, capture_output=True)
        print("tshark found.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: tshark not found. Please install it (sudo apt install tshark).")
        sys.exit(1)


# Context manager to clean up temporary files
@contextmanager
def cleanup():
    yield
    files = [PCAP_FILE, FLOWS_CSV]
    for f in files:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass


def main():
    warnings.filterwarnings("ignore")
    check_dependencies()

    print(f"Loading model: {MODEL_FILENAME}...")
    try:
        model = joblib.load(MODEL_FILENAME)
        print("Model loaded successfully.")
    except Exception as e:
        train(MODEL_FILENAME)
        model = joblib.load(MODEL_FILENAME)
        print("Model loaded successfully.")

    print(
        f"\nStarting real-time DoS/DDoS detection on interface '{CAPTURE_INTERFACE}'..."
    )
    print(
        f"Capturing in {CAPTURE_DURATION_SECONDS}-second intervals. Press Ctrl+C to stop."
    )

    try:
        clear_screen()
        while True:
            print(f"\n--- Cycle started at {time.strftime('%H:%M:%S')} ---")

            print(f"Capturing network traffic for {CAPTURE_DURATION_SECONDS}s...")
            with cleanup():
                try:
                    subprocess.run(["tshark", "-i", CAPTURE_INTERFACE, "-a", f"duration:{CAPTURE_DURATION_SECONDS}", "-w", PCAP_FILE, "-F", "pcap"], check=True, capture_output=True)
                except Exception:
                    time.sleep(5)
                    continue


                try:
                    print("Extracting features...")
                    subprocess.run(
                        ["cicflowmeter", "-f", PCAP_FILE, "-c", FLOWS_CSV], check=True, capture_output=True
                    )
                except Exception:
                    print("Failed to extract features.")
                    continue

                if not os.path.exists(FLOWS_CSV) or os.path.getsize(FLOWS_CSV) == 0:
                    print("Flows file not found.")
                    continue

                try:
                    df_flows = pd.read_csv(FLOWS_CSV)
                except Exception:
                    print("Error reading CSV.")
                    continue

                if df_flows.empty:
                    print("CSV empty.")
                    continue

                # Update column names, to match those used in training
                original_columns = set(df_flows.columns)
                renamed_columns = {}
                for original, new in COLUMN_MAP.items():
                    if original in original_columns:
                        renamed_columns[original] = new
                df_flows = df_flows.rename(columns=renamed_columns)

                # Ensure all model features are present, by adding all 
                # features used in cicflowmeter
                for feature in MODEL_FEATURES:
                    if feature not in df_flows.columns:
                        df_flows[feature] = 0

                # Isolate only the features used by the model
                features_data = df_flows[MODEL_FEATURES].copy()
                features_data.replace([np.inf, -np.inf], np.nan, inplace=True)
                features_data.dropna(inplace=True)

                # Perform predictions
                if len(features_data) > 0:
                    predictions = model.predict(features_data)
                    results = pd.Series(predictions).value_counts() 

                    print(f"Flows analyzed: {len(predictions)}")
                    benign = results.get("Benign", 0)
                    malicious = len(predictions) - (benign or 0)

                    print(f"Normal: {benign} | Suspicious: {malicious}")

                    if malicious > 0:
                        print("\n!!! WARNING: POTENTIAL ATTACK DETECTED!!!")
                        print(results)
                else:
                    print("No valid flows for inference.")

                # delay to see results
                time.sleep(5)
                clear_screen()


    except KeyboardInterrupt:
        print("\nStopping...")


if __name__ == "__main__":
    main()
