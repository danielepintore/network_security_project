from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import joblib
import os
import kagglehub
import shutil


def train(MODEL_FILENAME="rf_dos_model.joblib"):
    try:
        path = kagglehub.dataset_download("dhoogla/cicids2017")
        print(f"Dataset downloaded to {path}")

        # Load training dataset
        dfs = []
        for f in os.listdir(path):
            if f.endswith(".parquet"):
                df_tmp = pd.read_parquet(os.path.join(path, f))
                dfs.append(df_tmp)

        # Merge all dataframes
        df = pd.concat(dfs, ignore_index=True)

        dos_labels = [
            "Benign",
            "DDoS",
            "DoS Hulk",
            "DoS GoldenEye",
            "DoS slowloris",
            "DoS Slowhttptest",
        ]

        included_features = [
            "Bwd Packet Length Mean",
            "Fwd IAT Std",
            "Fwd IAT Max",
            "Packet Length Variance",
            "Init Fwd Win Bytes",
            "Label",
        ]

        # Cleaning dataset removing unused labels and features
        df_dos = df[df["Label"].isin(dos_labels)]
        df_dos = df_dos[included_features]

        # Remove DoS attack type label
        X = df_dos.drop(columns=["Label"])
        # Expected output is the Label column
        y = df_dos["Label"]

        # Split dataset into training and testing sets
        print("Splitting dataset...")
        X_train, _, y_train, _ = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        rf = RandomForestClassifier(
            n_estimators=100, random_state=42, n_jobs=-1, verbose=0
        )
        print("Training started...")
        rf.fit(X_train, y_train)
        joblib.dump(rf, MODEL_FILENAME)
        print(f"Model saved to {MODEL_FILENAME}")

        # Clean up downloaded dataset using python utils
        #shutil.rmtree(path)
        
    except Exception as e:
        raise RuntimeError(f"Training failed: {e}")
