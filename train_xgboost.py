"""
XGBoost Training Pipeline for Network Intrusion Detection
Trains on CICIDS-2017 dataset for multi-class attack classification.

Usage:
    python3 train_xgboost.py

The script will:
    1. Load all CSV files from the dataset/ folder
    2. Clean and preprocess the data
    3. Train an XGBoost classifier (BENIGN vs attack types)
    4. Evaluate the model with detailed metrics
    5. Save the trained model, scaler, and label encoder to models/
"""

import os
import sys
import time
import warnings
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
)
import xgboost as xgb

warnings.filterwarnings('ignore')

# ============================================================
# Configuration
# ============================================================

DATASET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dataset')
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

# Output model files
MODEL_PATH = os.path.join(MODEL_DIR, 'xgboost_model.json')
SCALER_PATH = os.path.join(MODEL_DIR, 'xgb_scaler.pkl')
ENCODER_PATH = os.path.join(MODEL_DIR, 'xgb_label_encoder.pkl')
FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, 'xgb_feature_names.pkl')
METADATA_PATH = os.path.join(MODEL_DIR, 'xgb_metadata.pkl')

# Training hyperparameters
XGB_PARAMS = {
    'n_estimators': 200,
    'max_depth': 8,
    'learning_rate': 0.1,
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'min_child_weight': 5,
    'gamma': 0.1,
    'reg_alpha': 0.1,
    'reg_lambda': 1.0,
    'random_state': 42,
    'n_jobs': -1,
    'eval_metric': 'mlogloss',
    'use_label_encoder': False,
}

# Maximum samples per class to handle imbalance (downsample majority class)
MAX_SAMPLES_PER_CLASS = 100000

# Binary classification mode: True = BENIGN vs ATTACK, False = multi-class
BINARY_MODE = False

# ============================================================
# Explicit Feature Columns (from CICIDS-2017 dataset)
# These are the exact columns used for training — excludes
# identifiers (Src/Dst IP, Port, Protocol, Timestamp) and
# target columns (Label, Attempted Category).
# ============================================================

FEATURE_COLUMNS = [
    'Flow Duration',
    'Total Fwd Packet',
    'Total Bwd packets',
    'Total Length of Fwd Packet',
    'Total Length of Bwd Packet',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Total',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max',
    'Fwd IAT Min',
    'Bwd IAT Total',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    'Fwd PSH Flags',
    'Bwd PSH Flags',
    'Fwd URG Flags',
    'Bwd URG Flags',
    'Fwd RST Flags',
    'Bwd RST Flags',
    'Fwd Header Length',
    'Bwd Header Length',
    'Fwd Packets/s',
    'Bwd Packets/s',
    'Packet Length Min',
    'Packet Length Max',
    'Packet Length Mean',
    'Packet Length Std',
    'Packet Length Variance',
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'URG Flag Count',
    'CWR Flag Count',
    'ECE Flag Count',
    'Down/Up Ratio',
    'Average Packet Size',
    'Fwd Segment Size Avg',
    'Bwd Segment Size Avg',
    'Fwd Bytes/Bulk Avg',
    'Fwd Packet/Bulk Avg',
    'Fwd Bulk Rate Avg',
    'Bwd Bytes/Bulk Avg',
    'Bwd Packet/Bulk Avg',
    'Bwd Bulk Rate Avg',
    'Subflow Fwd Packets',
    'Subflow Fwd Bytes',
    'Subflow Bwd Packets',
    'Subflow Bwd Bytes',
    'FWD Init Win Bytes',
    'Bwd Init Win Bytes',
    'Fwd Act Data Pkts',
    'Fwd Seg Size Min',
    'Active Mean',
    'Active Std',
    'Active Max',
    'Active Min',
    'Idle Mean',
    'Idle Std',
    'Idle Max',
    'Idle Min',
    'ICMP Code',
    'ICMP Type',
    'Total TCP Flow Time',
]


# ============================================================
# Helper Functions
# ============================================================

def print_banner():
    """Print training banner."""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     ██╗  ██╗ ██████╗ ██████╗  ██████╗  ██████╗ ███████╗  ║
    ║     ╚██╗██╔╝██╔════╝ ██╔══██╗██╔═══██╗██╔═══██╗██╔════╝  ║
    ║      ╚███╔╝ ██║  ███╗██████╔╝██║   ██║██║   ██║███████╗  ║
    ║      ██╔██╗ ██║   ██║██╔══██╗██║   ██║██║   ██║╚════██║  ║
    ║     ██╔╝ ██╗╚██████╔╝██████╔╝╚██████╔╝╚██████╔╝███████║  ║
    ║     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝  ║
    ║                                                           ║
    ║        XGBoost IDS Training Pipeline v1.0                 ║
    ║        Dataset: CICIDS-2017                               ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


def is_lfs_pointer(filepath):
    """Check if a file is a Git LFS pointer."""
    try:
        with open(filepath, 'r') as f:
            first_line = f.readline()
            return first_line.startswith('version https://git-lfs.github.com')
    except Exception:
        return False


def load_dataset():
    """Load all CSV files from the dataset directory."""
    print("[*] Loading CICIDS-2017 dataset...")
    print(f"    Dataset directory: {DATASET_DIR}")

    csv_files = sorted([f for f in os.listdir(DATASET_DIR) if f.endswith('.csv')])

    if not csv_files:
        print("[!] ERROR: No CSV files found in dataset/ directory!")
        print("    Please place the CICIDS-2017 CSV files in the dataset/ folder.")
        sys.exit(1)

    # Check if files are Git LFS pointers
    first_file = os.path.join(DATASET_DIR, csv_files[0])
    if is_lfs_pointer(first_file):
        print("[!] ERROR: CSV files are Git LFS pointers, not actual data!")
        print("    The files need to be downloaded. Run:")
        print("    python3 download_dataset.py")
        print("")
        print("    Or download manually from Hugging Face:")
        print("    huggingface.co/datasets/eugenesiow/CICIDS2017")
        print(f"\n    Place the actual CSV files in: {DATASET_DIR}")
        sys.exit(1)

    dataframes = []
    total_rows = 0

    for csv_file in csv_files:
        filepath = os.path.join(DATASET_DIR, csv_file)
        print(f"    Loading {csv_file}...", end=' ')

        try:
            df = pd.read_csv(filepath, encoding='utf-8', low_memory=False)
        except UnicodeDecodeError:
            df = pd.read_csv(filepath, encoding='latin-1', low_memory=False)

        rows = len(df)
        total_rows += rows
        print(f"{rows:,} rows, {len(df.columns)} columns")
        dataframes.append(df)

    # Combine all dataframes
    print(f"\n[*] Combining all files...")
    df = pd.concat(dataframes, ignore_index=True)
    print(f"    Total dataset: {len(df):,} rows x {len(df.columns)} columns")

    return df


def preprocess_data(df):
    """Clean and preprocess the CICIDS-2017 dataset."""
    print("\n[*] Preprocessing data...")

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Identify the label column
    label_col = None
    for candidate in ['Label', 'label', ' Label', 'Attack Type', 'attack_type']:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        print("[!] ERROR: No label column found in dataset!")
        print(f"    Available columns: {list(df.columns)}")
        sys.exit(1)

    print(f"    Label column: '{label_col}'")

    # Clean labels
    df[label_col] = df[label_col].astype(str).str.strip()

    # Show class distribution
    class_dist = df[label_col].value_counts()
    print(f"\n    Class distribution (before balancing):")
    for cls, count in class_dist.items():
        print(f"      {cls:35s}: {count:>8,} ({count/len(df)*100:5.1f}%)")

    # ─── Select only the explicit feature columns ─────────
    # Use the predefined FEATURE_COLUMNS list to ensure we
    # train on exactly the factors specified.
    available_features = [col for col in FEATURE_COLUMNS if col in df.columns]
    missing_features = [col for col in FEATURE_COLUMNS if col not in df.columns]

    if missing_features:
        print(f"\n    ⚠️  Missing {len(missing_features)} feature columns (will be filled with 0):")
        for col in missing_features:
            print(f"        - {col}")

    print(f"\n    Selected {len(available_features)}/{len(FEATURE_COLUMNS)} explicit feature columns")
    print(f"    Excluded identifier columns: Src IP dec, Dst IP dec, Src Port, Dst Port, Protocol, Timestamp")
    print(f"    Excluded target columns: Label, Attempted Category")

    # Separate features and labels
    y = df[label_col].copy()
    X = df[available_features].copy()

    # Add missing feature columns as zeros
    for col in missing_features:
        X[col] = 0

    # Reorder to match FEATURE_COLUMNS exactly
    X = X[FEATURE_COLUMNS]

    # Convert all columns to numeric, coerce errors to NaN
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce')

    # Replace inf values with NaN, then fill NaN with 0
    print(f"    Handling inf/NaN values...")
    inf_count = np.isinf(X.values).sum()
    nan_count = X.isna().sum().sum()
    print(f"      Infinite values: {inf_count:,}")
    print(f"      NaN values: {nan_count:,}")

    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # Remove duplicate rows
    initial_len = len(X)
    mask = ~X.duplicated()
    X = X[mask]
    y = y[mask]
    dropped = initial_len - len(X)
    if dropped > 0:
        print(f"    Removed {dropped:,} duplicate rows")

    # Remove zero-variance columns (but keep track for consistency)
    zero_var_cols = X.columns[X.std() == 0].tolist()
    if zero_var_cols:
        print(f"    Note: {len(zero_var_cols)} zero-variance columns found: {zero_var_cols[:5]}...")
        print(f"    Keeping them for feature alignment consistency.")

    # Binary or multi-class
    if BINARY_MODE:
        print(f"\n    Converting to binary: BENIGN (0) vs ATTACK (1)")
        y = y.apply(lambda x: 'BENIGN' if x == 'BENIGN' else 'ATTACK')

    # Handle class imbalance by downsampling
    print(f"\n    Balancing classes (max {MAX_SAMPLES_PER_CLASS:,} per class)...")
    balanced_indices = []
    for cls in y.unique():
        cls_indices = y[y == cls].index.tolist()
        if len(cls_indices) > MAX_SAMPLES_PER_CLASS:
            cls_indices = np.random.RandomState(42).choice(
                cls_indices, MAX_SAMPLES_PER_CLASS, replace=False
            ).tolist()
        balanced_indices.extend(cls_indices)

    np.random.RandomState(42).shuffle(balanced_indices)
    X = X.loc[balanced_indices].reset_index(drop=True)
    y = y.loc[balanced_indices].reset_index(drop=True)

    # Show balanced distribution
    class_dist = y.value_counts()
    print(f"\n    Class distribution (after balancing):")
    for cls, count in class_dist.items():
        print(f"      {cls:35s}: {count:>8,} ({count/len(y)*100:5.1f}%)")

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    print(f"\n    Label encoding: {dict(zip(le.classes_, le.transform(le.classes_)))}")

    feature_names = X.columns.tolist()
    print(f"\n    Final dataset: {X.shape[0]:,} samples x {X.shape[1]} features")
    print(f"    Feature columns: {feature_names[:5]} ... ({len(feature_names)} total)")

    return X, y_encoded, le, feature_names


def train_model(X, y, le, feature_names):
    """Train XGBoost classifier."""
    print("\n" + "=" * 60)
    print("  TRAINING XGBOOST MODEL")
    print("=" * 60)

    n_classes = len(le.classes_)
    print(f"\n    Classes: {n_classes}")
    print(f"    Features: {len(feature_names)}")

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"    Train set: {len(X_train):,} samples")
    print(f"    Test set:  {len(X_test):,} samples")

    # Scale features
    print(f"\n[*] Scaling features with StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Configure XGBoost
    params = XGB_PARAMS.copy()
    if n_classes == 2:
        params['objective'] = 'binary:logistic'
        params['eval_metric'] = 'logloss'
    else:
        params['objective'] = 'multi:softprob'
        params['num_class'] = n_classes
        params['eval_metric'] = 'mlogloss'

    print(f"\n[*] XGBoost parameters:")
    for k, v in params.items():
        print(f"      {k}: {v}")

    # Train
    print(f"\n[*] Training XGBoost model...")
    train_start = time.time()

    model = xgb.XGBClassifier(**params)
    model.fit(
        X_train_scaled, y_train,
        eval_set=[(X_train_scaled, y_train), (X_test_scaled, y_test)],
        verbose=True,
    )

    train_duration = time.time() - train_start
    print(f"\n[✓] Training completed in {train_duration:.1f}s")

    # Evaluate
    print(f"\n" + "=" * 60)
    print("  MODEL EVALUATION")
    print("=" * 60)

    y_pred = model.predict(X_test_scaled)

    accuracy = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average='macro')
    f1_weighted = f1_score(y_test, y_pred, average='weighted')

    print(f"\n    Accuracy:       {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"    F1 (macro):     {f1_macro:.4f}")
    print(f"    F1 (weighted):  {f1_weighted:.4f}")

    print(f"\n    Classification Report:")
    print("    " + "-" * 72)
    report = classification_report(
        y_test, y_pred,
        target_names=le.classes_,
        digits=4,
    )
    for line in report.split('\n'):
        print(f"    {line}")

    # Feature importance
    print(f"\n    Top 15 Most Important Features:")
    print("    " + "-" * 50)
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    for rank, idx in enumerate(indices[:15], 1):
        print(f"      {rank:2d}. {feature_names[idx]:35s}  {importances[idx]:.4f}")

    return model, scaler, train_duration, accuracy, f1_weighted


def save_artifacts(model, scaler, le, feature_names, train_duration, accuracy, f1_weighted):
    """Save model, scaler, encoder, and metadata."""
    print(f"\n[*] Saving model artifacts to {MODEL_DIR}/")

    # Save XGBoost model in JSON format
    model.save_model(MODEL_PATH)
    print(f"    Model:         {MODEL_PATH}")

    # Save scaler
    joblib.dump(scaler, SCALER_PATH)
    print(f"    Scaler:        {SCALER_PATH}")

    # Save label encoder
    joblib.dump(le, ENCODER_PATH)
    print(f"    Encoder:       {ENCODER_PATH}")

    # Save feature names
    joblib.dump(feature_names, FEATURE_NAMES_PATH)
    print(f"    Features:      {FEATURE_NAMES_PATH}")

    # Save metadata
    metadata = {
        'model_type': 'XGBoost',
        'dataset': 'CICIDS-2017',
        'n_features': len(feature_names),
        'n_classes': len(le.classes_),
        'classes': list(le.classes_),
        'accuracy': accuracy,
        'f1_weighted': f1_weighted,
        'training_duration': train_duration,
        'trained_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'xgb_params': XGB_PARAMS,
        'binary_mode': BINARY_MODE,
    }
    joblib.dump(metadata, METADATA_PATH)
    print(f"    Metadata:      {METADATA_PATH}")

    # Print file sizes
    print(f"\n    File sizes:")
    for path in [MODEL_PATH, SCALER_PATH, ENCODER_PATH, FEATURE_NAMES_PATH, METADATA_PATH]:
        if os.path.exists(path):
            size = os.path.getsize(path)
            if size > 1024 * 1024:
                print(f"      {os.path.basename(path):30s}  {size / (1024*1024):.1f} MB")
            else:
                print(f"      {os.path.basename(path):30s}  {size / 1024:.1f} KB")


# ============================================================
# Main
# ============================================================

def main():
    print_banner()

    total_start = time.time()

    # Step 1: Load data
    df = load_dataset()

    # Step 2: Preprocess
    X, y, le, feature_names = preprocess_data(df)

    # Step 3: Train
    model, scaler, train_duration, accuracy, f1_weighted = train_model(X, y, le, feature_names)

    # Step 4: Save
    save_artifacts(model, scaler, le, feature_names, train_duration, accuracy, f1_weighted)

    total_duration = time.time() - total_start

    print(f"\n" + "=" * 60)
    print(f"  TRAINING COMPLETE")
    print(f"=" * 60)
    print(f"    Total time:     {total_duration:.1f}s")
    print(f"    Accuracy:       {accuracy*100:.2f}%")
    print(f"    F1 (weighted):  {f1_weighted:.4f}")
    print(f"    Model saved:    {MODEL_PATH}")
    print(f"\n    The model is ready for use in the detection engine!")
    print(f"    Run 'python3 app.py' to start NetGuard with XGBoost detection.\n")


if __name__ == '__main__':
    main()
