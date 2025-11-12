from fastapi import FastAPI, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict
import pandas as pd
import joblib
import numpy as np
import os
import tempfile
import traceback
import time
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer

# ✅ ---------------------------------------------------------
# 🧠 Import HybridModel class from separate module
# ✅ ---------------------------------------------------------
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'models'))
from hybrid_model import HybridModel


# ✅ Initialize FastAPI
app = FastAPI()

# ✅ Allow requests from React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Model paths
MODEL_DIR = r"C:\Users\rashy\Desktop\intrusion detection\intrusion detection\backend\models"

# ✅ Separate models for prediction and evaluation
PREDICT_MODELS = {
    "tii": os.path.join(MODEL_DIR, "TII.joblib"),
    "cicids": os.path.join(MODEL_DIR, "CIDS2019.joblib")
}

EVALUATE_MODELS = {
    "tii": os.path.join(MODEL_DIR, "Hybrid_RF_SVM_TII.joblib"),
    "cicids": os.path.join(MODEL_DIR, "Hybrid_RF_SVM_CICIDS2019.joblib")
}

# ✅ Pydantic model for manual flow prediction
class FlowInput(BaseModel):
    model: str
    features: Dict[str, float]

# -------------------------------------------------------------------------
# 🧠 1️⃣ Real-time Manual Flow Prediction Endpoint
# -------------------------------------------------------------------------
@app.post("/predict")
async def predict_flow(flow: FlowInput):
    model_name = flow.model.lower()
    feature_dict = flow.features

    # ✅ Validate model name
    if model_name not in PREDICT_MODELS:
        return JSONResponse(
            content={"error": "Invalid model type. Choose 'tii' or 'cicids'"},
            status_code=400
        )

    # ✅ Validate features
    if not feature_dict:
        return JSONResponse(
            content={"error": "No features provided. Please provide network flow features in JSON format."},
            status_code=400
        )

    # ✅ Check numeric values
    non_numeric = [f"{k}: {v}" for k, v in feature_dict.items() if not isinstance(v, (int, float))]
    if non_numeric:
        return JSONResponse(
            content={"error": f"Non-numeric features detected: {', '.join(non_numeric)}"},
            status_code=400
        )

    # ✅ Load model
    model_path = PREDICT_MODELS[model_name]
    print(f"🧠 Loading PREDICT model from: {model_path}")

    if not os.path.exists(model_path):
        return JSONResponse(content={"error": f"❌ Model file not found: {model_path}"}, status_code=500)

    try:
        clf = joblib.load(model_path)
        print("✅ Prediction model loaded successfully.")
    except Exception as e:
        print("❌ Error loading model:")
        traceback.print_exc()
        return JSONResponse(content={"error": f"Model load error: {str(e)}"}, status_code=500)

    try:
        # ✅ Convert input dict to DataFrame
        X = pd.DataFrame([feature_dict])
        numeric_columns = X.select_dtypes(include=[np.number]).columns
        X = X[numeric_columns]

        # ✅ Handle missing values
        imputer = SimpleImputer(strategy='median')
        X = pd.DataFrame(imputer.fit_transform(X), columns=numeric_columns)

        # ✅ Align with model's expected features
        if hasattr(clf, "feature_names_in_"):
            expected_cols = list(clf.feature_names_in_)
            X = X.reindex(columns=expected_cols, fill_value=np.nan)
            col_medians = X.median()
            X = X.fillna(col_medians).fillna(0)
            print(f"✅ Aligned features to model. Expected: {len(expected_cols)}, Got: {X.shape[1]}")
        else:
            # Fallback if model doesn't have feature_names_in_
            if model_name == "tii":
                expected_features = 77
            elif model_name == "cicids":
                expected_features = 16
            else:
                expected_features = X.shape[1]

            if X.shape[1] < expected_features:
                for i in range(X.shape[1], expected_features):
                    X[f"feature_{i}"] = 0
            elif X.shape[1] > expected_features:
                X = X.iloc[:, :expected_features]

            print(f"⚠️ Model doesn't have feature_names_in_. Adjusted to {expected_features} features.")

        # ✅ Predict
        pred = clf.predict(X)[0]
        label = "Benign" if pred == 0 else "Malicious"

        return {
            "model": model_name.upper(),
            "prediction": int(pred),
            "label": label,
            "features_used": len(X.columns),
            "input_features": len(feature_dict)
        }

    except Exception as e:
        print("❌ Prediction Error:")
        traceback.print_exc()
        return JSONResponse(
            content={"error": f"Prediction error: {str(e)}"},
            status_code=500
        )

# -------------------------------------------------------------------------
# 📝 2️⃣ CSV Evaluation Endpoint
# -------------------------------------------------------------------------
@app.post("/evaluate")
async def evaluate(
    file: UploadFile,
    model: str = Form(...),
    sample_size: int = Form(10000)
):
    model_name = model.lower()

    if model_name not in EVALUATE_MODELS:
        return JSONResponse(content={"error": "Invalid model type"}, status_code=400)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        print("📂 Loading dataset...")
        df = pd.read_csv(tmp_path)

        # 🧹 Clean column names
        df.columns = (
            df.columns
            .str.strip()
            .str.lower()
            .str.replace(' ', '_')
        )
        print("✅ Cleaned Columns (first 10):", list(df.columns)[:10], "...")

        # 📊 Sample if dataset is large
        original_size = len(df)
        if len(df) > sample_size:
            print(f"📊 Dataset has {original_size:,} rows. Sampling {sample_size:,} for faster evaluation...")
            if 'label_traffic_id' in df.columns:
                df, _ = train_test_split(df, train_size=sample_size, stratify=df['label_traffic_id'], random_state=42)
            elif 'label' in df.columns:
                df, _ = train_test_split(df, train_size=sample_size, stratify=df['label'], random_state=42)
            else:
                df = df.sample(n=min(sample_size, len(df)), random_state=42)
            print(f"✅ Sampled dataset to {len(df):,} rows")

        # Identify labels
        if 'label_traffic_id' in df.columns:
            y_true = df['label_traffic_id']
            X = df.drop('label_traffic_id', axis=1)
        elif 'label' in df.columns:
            y_true = df['label']
            X = df.drop('label', axis=1)
        else:
            return JSONResponse(content={"error": "❌ Label column not found in CSV"}, status_code=400)

        # Numeric only
        numeric_columns = X.select_dtypes(include=[np.number]).columns
        X = X[numeric_columns]

        imputer = SimpleImputer(strategy='median')
        X = pd.DataFrame(imputer.fit_transform(X), columns=numeric_columns)

        model_path = EVALUATE_MODELS[model_name]
        print(f"🧠 Loading EVALUATION model from: {model_path}")

        if not os.path.exists(model_path):
            return JSONResponse(content={"error": f"❌ Model file not found: {model_path}"}, status_code=500)

        clf = joblib.load(model_path)
        print("✅ Evaluation model loaded successfully.")

        if hasattr(clf, "feature_names_in_"):
            X = X.reindex(columns=clf.feature_names_in_, fill_value=0)

        # Predict and calculate metrics
        start_time = time.time()
        y_pred = clf.predict(X)
        prediction_time = time.time() - start_time

        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
        rec = recall_score(y_true, y_pred, average="weighted", zero_division=0)
        f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
        cm = confusion_matrix(y_true, y_pred).tolist()

        return {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "confusion_matrix": cm,
            "sample_size": len(X),
            "original_size": original_size,
            "prediction_time": round(prediction_time, 2)
        }

    except Exception as e:
        print("❌ Backend Evaluation Error:")
        traceback.print_exc()
        return JSONResponse(content={"error": str(e)}, status_code=500)

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
