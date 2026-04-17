from __future__ import annotations

import csv
import pickle
from pathlib import Path
from typing import Any

from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATASET_PATH = BASE_DIR / "data" / "phishing_dataset.csv"
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.pkl"


def _combine_features(email: str, url: str) -> str:
    return f"email: {email.strip()} url: {url.strip()}"


def _load_dataset(dataset_path: Path) -> tuple[list[str], list[str]]:
    texts: list[str] = []
    labels: list[str] = []

    with dataset_path.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            email = str(row.get("email", ""))
            url = str(row.get("url", ""))
            label = str(row.get("label", "")).strip().lower()

            if label not in {"phishing", "safe"}:
                continue

            texts.append(_combine_features(email=email, url=url))
            labels.append(label)

    if not texts:
        raise ValueError("Dataset is empty or invalid. Expected columns: email,url,label")

    return texts, labels


def train_and_save_model(
    dataset_path: str | Path = DEFAULT_DATASET_PATH,
    model_path: str | Path = DEFAULT_MODEL_PATH,
    vectorizer_type: str = "tfidf",
    model_type: str = "logistic",
) -> dict[str, Any]:
    dataset_path = Path(dataset_path)
    model_path = Path(model_path)

    texts, labels = _load_dataset(dataset_path)

    if vectorizer_type == "count":
        vectorizer = CountVectorizer(ngram_range=(1, 2), min_df=1)
    else:
        vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)

    if model_type == "nb":
        classifier = MultinomialNB()
    else:
        classifier = LogisticRegression(max_iter=1000)

    pipeline = Pipeline([
        ("vectorizer", vectorizer),
        ("classifier", classifier),
    ])

    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    pipeline.fit(x_train, y_train)
    accuracy = float(pipeline.score(x_test, y_test))

    model_path.parent.mkdir(parents=True, exist_ok=True)
    with model_path.open("wb") as model_file:
        pickle.dump(pipeline, model_file)

    return {
        "dataset_size": len(texts),
        "accuracy": round(accuracy, 4),
        "vectorizer": vectorizer_type,
        "model": model_type,
        "model_path": str(model_path),
    }


def _load_model(model_path: Path = DEFAULT_MODEL_PATH) -> Pipeline:
    with model_path.open("rb") as model_file:
        return pickle.load(model_file)


def predict_phishing(email: str, url: str) -> dict[str, str | float]:
    if not DEFAULT_MODEL_PATH.exists():
        train_and_save_model()

    pipeline = _load_model(DEFAULT_MODEL_PATH)

    features = [_combine_features(email=email, url=url)]
    prediction = str(pipeline.predict(features)[0])
    probabilities = pipeline.predict_proba(features)[0]

    class_names = list(pipeline.classes_)
    predicted_index = class_names.index(prediction)
    confidence = float(probabilities[predicted_index]) * 100

    return {
        "prediction": "Phishing" if prediction == "phishing" else "Safe",
        "confidence": round(confidence, 2),
    }
