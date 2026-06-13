from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

DATA_PATH = Path("dataset/phishing.csv")
MODEL_PATH = Path("model/model.pkl")
META_PATH = Path("model/model_meta.pkl")


def load_and_prepare_data():
    df = pd.read_csv(DATA_PATH)
    df = df.drop(["index"], axis=1)
    df = df.rename(
        columns={
            "having_IPhaving_IP_Address": "having_IP_Address",
            "URLURL_Length": "URL_Length",
        }
    )
    X = df.drop("Result", axis=1)
    y = df["Result"]
    return X, y


def train():
    X, y = load_and_prepare_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=18,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, digits=4))

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump({"feature_names": list(X.columns)}, META_PATH)
    print(f"\nSaved model to: {MODEL_PATH}")
    print(f"Saved metadata to: {META_PATH}")


if __name__ == "__main__":
    train()