"""
Download CICIDS-2017 dataset from Hugging Face for XGBoost training.

This script downloads the CICIDS-2017 dataset CSV files from Hugging Face
and places them in the dataset/ folder.

Usage:
    python3 download_dataset.py
"""

import os
import sys
import glob

DATASET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dataset')

# Hugging Face dataset repos to try (in order of preference)
HF_REPOS = [
    'eugenesiow/CICIDS2017',
    'bvk/CICIDS-2017',
    'c01dsnap/CIC-IDS2017',
    'makekali/CIC-IDS-2017',
    'bvsam/cic-ids-2017',
]

# Expected CSV files
EXPECTED_FILES = [
    'friday.csv',
    'monday.csv',
    'thursday.csv',
    'tuesday.csv',
    'wednesday.csv',
]

# Mapping from original CICIDS filenames to simplified names
ORIGINAL_NAMES = {
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv': 'friday.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': 'friday.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv': 'friday.csv',
    'Monday-WorkingHours.pcap_ISCX.csv': 'monday.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv': 'thursday.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv': 'thursday.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv': 'tuesday.csv',
    'Wednesday-workingHours.pcap_ISCX.csv': 'wednesday.csv',
}


def is_lfs_pointer(filepath):
    """Check if a file is a Git LFS pointer."""
    try:
        with open(filepath, 'r') as f:
            first_line = f.readline()
            return first_line.startswith('version https://git-lfs.github.com')
    except Exception:
        return False


def check_existing():
    """Check if valid CSV data already exists."""
    all_valid = True
    for fname in EXPECTED_FILES:
        fpath = os.path.join(DATASET_DIR, fname)
        if not os.path.exists(fpath):
            print(f"  ✗ Missing: {fname}")
            all_valid = False
        elif is_lfs_pointer(fpath):
            print(f"  ✗ LFS pointer (not real data): {fname}")
            all_valid = False
        else:
            size_mb = os.path.getsize(fpath) / (1024 * 1024)
            if size_mb < 1:
                print(f"  ✗ Too small ({size_mb:.1f}MB): {fname}")
                all_valid = False
            else:
                print(f"  ✓ Valid ({size_mb:.1f}MB): {fname}")
    return all_valid


def find_csv_files(directory):
    """Find all CSV files in a directory (recursive)."""
    csv_files = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            if f.endswith('.csv'):
                csv_files.append(os.path.join(root, f))
    return csv_files


def download_from_huggingface():
    """Download dataset from Hugging Face."""
    try:
        from huggingface_hub import snapshot_download, list_repo_files
        print("[*] Hugging Face Hub available.")
    except ImportError:
        print("[!] huggingface_hub not installed. Installing...")
        os.system(f"{sys.executable} -m pip install huggingface_hub")
        from huggingface_hub import snapshot_download, list_repo_files

    for repo_id in HF_REPOS:
        print(f"\n[*] Trying Hugging Face repo: {repo_id}")
        try:
            # List files in the repo to check if it has CSV files
            files = list_repo_files(repo_id, repo_type="dataset")
            csv_files = [f for f in files if f.endswith('.csv')]
            parquet_files = [f for f in files if f.endswith('.parquet')]

            if csv_files:
                print(f"    Found {len(csv_files)} CSV files: {csv_files[:5]}")
            elif parquet_files:
                print(f"    Found {len(parquet_files)} Parquet files (will convert)")
            else:
                print(f"    No CSV/Parquet files found, skipping...")
                continue

            # Download the dataset
            print(f"    Downloading from {repo_id}...")
            download_dir = snapshot_download(
                repo_id=repo_id,
                repo_type="dataset",
                local_dir=os.path.join(DATASET_DIR, '_hf_download'),
            )

            print(f"    Downloaded to: {download_dir}")

            # Find and move CSV files
            downloaded_csvs = find_csv_files(download_dir)
            if downloaded_csvs:
                print(f"    Found {len(downloaded_csvs)} CSV files in download.")
                for csv_path in downloaded_csvs:
                    fname = os.path.basename(csv_path)
                    dest_name = ORIGINAL_NAMES.get(fname, fname.lower())
                    dest_path = os.path.join(DATASET_DIR, dest_name)

                    # Remove LFS pointer if it exists
                    if os.path.exists(dest_path) and is_lfs_pointer(dest_path):
                        os.remove(dest_path)

                    if not os.path.exists(dest_path):
                        size_mb = os.path.getsize(csv_path) / (1024 * 1024)
                        print(f"    Copying {fname} → {dest_name} ({size_mb:.1f}MB)")
                        import shutil
                        shutil.copy2(csv_path, dest_path)
                    elif os.path.exists(dest_path) and dest_name in [v for v in ORIGINAL_NAMES.values()]:
                        # Multiple files map to same day - concatenate
                        size_mb = os.path.getsize(csv_path) / (1024 * 1024)
                        print(f"    Appending {fname} → {dest_name} ({size_mb:.1f}MB)")
                        import pandas as pd
                        df_existing = pd.read_csv(dest_path, low_memory=False)
                        df_new = pd.read_csv(csv_path, low_memory=False)
                        df_combined = pd.concat([df_existing, df_new], ignore_index=True)
                        df_combined.to_csv(dest_path, index=False)

                return True

            # Handle Parquet files
            downloaded_parquets = [f for f in glob.glob(os.path.join(download_dir, '**/*.parquet'), recursive=True)]
            if downloaded_parquets:
                print(f"    Found {len(downloaded_parquets)} Parquet files. Converting to CSV...")
                try:
                    import pandas as pd
                    for pq_path in downloaded_parquets:
                        fname = os.path.basename(pq_path).replace('.parquet', '.csv')
                        dest_path = os.path.join(DATASET_DIR, fname.lower())
                        print(f"    Converting {os.path.basename(pq_path)} → {fname.lower()}")
                        df = pd.read_parquet(pq_path)
                        df.to_csv(dest_path, index=False)
                    return True
                except Exception as e:
                    print(f"    Parquet conversion error: {e}")
                    continue

        except Exception as e:
            print(f"    Failed: {e}")
            continue

    return False


def download_with_datasets_lib():
    """Try downloading with the HuggingFace datasets library."""
    try:
        from datasets import load_dataset
        print("\n[*] Trying HuggingFace 'datasets' library...")

        for repo_id in HF_REPOS:
            print(f"    Trying: {repo_id}")
            try:
                dataset = load_dataset(repo_id)
                print(f"    Loaded! Splits: {list(dataset.keys())}")

                import pandas as pd
                for split_name, split_data in dataset.items():
                    df = split_data.to_pandas()
                    dest_name = f"{split_name}.csv"
                    dest_path = os.path.join(DATASET_DIR, dest_name)
                    print(f"    Saving {split_name} → {dest_name} ({len(df):,} rows)")
                    df.to_csv(dest_path, index=False)
                return True
            except Exception as e:
                print(f"    Failed: {e}")
                continue
    except ImportError:
        print("[!] 'datasets' library not available.")
    return False


def print_instructions():
    """Print manual download instructions."""
    print(f"""
╔════════════════════════════════════════════════════════════════╗
║              MANUAL DOWNLOAD INSTRUCTIONS                     ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  Download CICIDS-2017 from Hugging Face:                       ║
║                                                                ║
║  1. Go to one of these Hugging Face repos:                     ║
║     • huggingface.co/datasets/eugenesiow/CICIDS2017           ║
║     • huggingface.co/datasets/bvk/CICIDS-2017                 ║
║     • huggingface.co/datasets/c01dsnap/CIC-IDS2017            ║
║                                                                ║
║  2. Click "Files and versions" tab                             ║
║                                                                ║
║  3. Download the CSV files                                     ║
║                                                                ║
║  4. Place them in:                                             ║
║     {DATASET_DIR:<55s} ║
║                                                                ║
║  Expected files: monday.csv, tuesday.csv, wednesday.csv,       ║
║                  thursday.csv, friday.csv                       ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    """)


def main():
    print("\n[*] CICIDS-2017 Dataset Manager (Hugging Face)")
    print(f"    Target directory: {DATASET_DIR}\n")

    os.makedirs(DATASET_DIR, exist_ok=True)

    # Check current state
    print("[*] Checking existing files:")
    if check_existing():
        print("\n[✓] All dataset files are valid! You can run training:")
        print("    python3 train_xgboost.py")
        return

    # Try Hugging Face Hub download
    print("\n[*] Attempting download from Hugging Face...")
    if download_from_huggingface():
        print("\n[*] Re-checking files after download:")
        if check_existing():
            print("\n[✓] Download complete! You can now run:")
            print("    python3 train_xgboost.py")
            return
        else:
            print("\n[!] Some files may still be missing.")

    # Try datasets library as fallback
    if download_with_datasets_lib():
        print("\n[*] Re-checking files after download:")
        if check_existing():
            print("\n[✓] Download complete! You can now run:")
            print("    python3 train_xgboost.py")
            return

    # Manual instructions
    print_instructions()


if __name__ == '__main__':
    main()
