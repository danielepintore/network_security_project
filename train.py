from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import joblib
import os
import kagglehub

def train(MODEL_FILENAME="rf_dos_model.joblib"):
    path = kagglehub.dataset_download("dhoogla/cicids2017")

    dfs = []

    for f in os.listdir(path):
        if f.endswith(".parquet"):
            df_tmp = pd.read_parquet(os.path.join(path, f))
            dfs.append(df_tmp)

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
        "Label"
    ]

    df_dos = df[df["Label"].isin(dos_labels)]
    df_dos = df_dos[included_features]

    X = df_dos.drop(columns=["Label"]) # ovviamente dall'input rimuovo le labels
    y = df_dos["Label"] # l'output correto sono le labels

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    if os.path.exists(MODEL_FILENAME):
        print("Caricamento in corso...")
        rf = joblib.load(MODEL_FILENAME)
    else:
        rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, verbose=0)
        rf.fit(X_train, y_train)
        print("Training completato!")
        
        joblib.dump(rf, MODEL_FILENAME)







