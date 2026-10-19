"""Data preprocessing pipeline for smart contract feature cleaning, scaling, and train-test splitting."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Optional, Union, List
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from src.feature_extractor import FEATURE_NAMES

# Default directories
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
DEFAULT_DATASET_PATH = DATA_DIR / "sample_contract_features.csv"
DEFAULT_SCALER_PATH = MODELS_DIR / "scaler.joblib"


@dataclass
class PreprocessedData:
    """Container holding split, cleaned, and scaled datasets ready for training/evaluation."""
    X_train: pd.DataFrame
    X_test: pd.DataFrame
    y_train: pd.Series
    y_test: pd.Series
    X_train_scaled: np.ndarray
    X_test_scaled: np.ndarray
    scaler: StandardScaler
    feature_names: List[str]

    @property
    def train_size(self) -> int:
        return len(self.X_train)

    @property
    def test_size(self) -> int:
        return len(self.X_test)


def load_and_validate_dataset(csv_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """
    Load dataset from CSV, validate schema, check for missing values, and verify column types.
    """
    path = Path(csv_path or DEFAULT_DATASET_PATH)
    if not path.exists():
        raise FileNotFoundError(f"Contract feature dataset not found at: {path}")

    df = pd.read_csv(path)

    # Validate target column exists
    if "is_honeypot" not in df.columns:
        raise ValueError("Missing required target column 'is_honeypot' in dataset")

    # Validate feature columns exist
    missing_features = [col for col in FEATURE_NAMES if col not in df.columns]
    if missing_features:
        raise ValueError(f"Dataset is missing required feature columns: {missing_features}")

    # Check for nulls and fill or alert
    null_counts = df[FEATURE_NAMES].isnull().sum()
    if null_counts.any():
        df[FEATURE_NAMES] = df[FEATURE_NAMES].fillna(0)

    # Coerce feature columns to numeric
    for col in FEATURE_NAMES:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    df["is_honeypot"] = pd.to_numeric(df["is_honeypot"], errors="coerce").fillna(0).astype(int)

    return df


def split_features_and_target(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.Series, pd.DataFrame]:
    """
    Extract feature matrix X, target series y, and metadata columns.
    """
    metadata_cols = [c for c in ["contract_id", "contract_name", "source_origin"] if c in df.columns]
    metadata = df[metadata_cols].copy() if metadata_cols else pd.DataFrame(index=df.index)

    X = df[FEATURE_NAMES].copy()
    y = df["is_honeypot"].copy().astype(int)

    return X, y, metadata


def prepare_train_test_split(
    X: pd.DataFrame,
    y: pd.Series,
    test_size: float = 0.2,
    random_state: int = 42,
    stratify: bool = True,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Perform stratified train-test splitting to maintain class balance across splits.
    """
    strat = y if stratify else None
    return train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=strat,
    )


def fit_and_save_scaler(
    X_train: pd.DataFrame,
    scaler_path: Optional[Union[str, Path]] = None,
) -> StandardScaler:
    """
    Fit a StandardScaler on training features and save artifact via joblib.
    """
    path = Path(scaler_path or DEFAULT_SCALER_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)

    scaler = StandardScaler()
    scaler.fit(X_train)
    joblib.dump(scaler, path)
    return scaler


def load_scaler(scaler_path: Optional[Union[str, Path]] = None) -> Optional[StandardScaler]:
    """
    Load saved scaler artifact from disk if available, otherwise return None.
    """
    path = Path(scaler_path or DEFAULT_SCALER_PATH)
    if not path.exists():
        return None
    try:
        return joblib.load(path)
    except Exception:
        return None


def scale_features(
    scaler: StandardScaler,
    X: Union[pd.DataFrame, np.ndarray, List[float]],
) -> np.ndarray:
    """Scale input features using a previously fitted StandardScaler."""
    if isinstance(X, list):
        X = np.array(X).reshape(1, -1)
    return scaler.transform(X)


def get_preprocessed_data(
    csv_path: Optional[Union[str, Path]] = None,
    scaler_path: Optional[Union[str, Path]] = None,
    test_size: float = 0.2,
    random_state: int = 42,
    save_scaler: bool = True,
) -> PreprocessedData:
    """
    High-level end-to-end preprocessing pipeline returning PreprocessedData container.
    """
    df = load_and_validate_dataset(csv_path)
    X, y, _ = split_features_and_target(df)
    X_train, X_test, y_train, y_test = prepare_train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=True
    )

    if save_scaler:
        scaler = fit_and_save_scaler(X_train, scaler_path)
    else:
        scaler = StandardScaler()
        scaler.fit(X_train)

    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    return PreprocessedData(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        X_train_scaled=X_train_scaled,
        X_test_scaled=X_test_scaled,
        scaler=scaler,
        feature_names=list(FEATURE_NAMES),
    )


if __name__ == "__main__":
    print("=" * 60)
    print(" Smart Contract ML Preprocessing Pipeline ")
    print("=" * 60)
    data = get_preprocessed_data()
    print(f"Dataset path: {DEFAULT_DATASET_PATH}")
    print(f"Features: {len(data.feature_names)}")
    print(f"Total training samples: {data.train_size} (Benign: {(data.y_train == 0).sum()}, Honeypot: {(data.y_train == 1).sum()})")
    print(f"Total testing samples:  {data.test_size} (Benign: {(data.y_test == 0).sum()}, Honeypot: {(data.y_test == 1).sum()})")
    print(f"Scaler saved to: {DEFAULT_SCALER_PATH}")
    print("Preprocessing completed successfully.")
