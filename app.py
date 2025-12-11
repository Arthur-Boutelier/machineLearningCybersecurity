import mlflow
import pandas as pd
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict
from contextlib import asynccontextmanager
from sklearn.preprocessing import LabelEncoder, StandardScaler
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse


MLFLOW_BASE_URI = "mlartifacts/273187884848526666/models/"
MODEL_IDS = {"XGB_smote": "m-f4e49f3cf49c40d69845852c773644d5", "knn_smote": "m-f9d00d4f520e4549adc943d2b0ee1d8d", "rand_forest_smote": "m-e2aaab546efa4c4f864f4d004284f41e", "hard_voting": "m-273e898ee4bd49f28dce06a11e25faa3"}

MODELS: Dict[str, object] = {}

df = pd.read_csv("df.csv")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global MODELS
    print("Starting model loading...")
    for model_name, model_id in MODEL_IDS.items():
        try:
            model_uri = f"{MLFLOW_BASE_URI}{model_id}/artifacts"

            if model_name == "XGB_smote":
                MODELS[model_name] = mlflow.xgboost.load_model(model_uri)
            else:
                MODELS[model_name] = mlflow.sklearn.load_model(model_uri)
            print(f"Model {model_name} (ID: {model_id}) loaded successfully")
        except Exception as e:
            print(f"Error loading model {model_name} (ID: {model_id}): {e}")

    if not MODELS:
        raise RuntimeError("No models were loaded. API cannot serve predictions.")

    print("Application shutdown. Models unloaded.")
    yield


origins = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "*",
]

app = FastAPI(title="Machine Learning Project", lifespan=lifespan)

app.mount("/static", StaticFiles(directory="frontend"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CyberFeatures(BaseModel):
    DestinationPort: int
    FlowDuration: int
    TotalFwdPackets: int
    TotalBackwardPackets: int
    TotalLengthOfFwdPackets: int
    TotalLengthOfBwdPackets: int
    FwdPacketLengthMax: int
    FwdPacketLengthMin: int
    FwdPacketLengthMean: float
    FwdPacketLengthStd: float
    BwdPacketLengthMax: int
    BwdPacketLengthMin: int
    BwdPacketLengthMean: float
    BwdPacketLengthStd: float
    FlowBytesPerS: float
    FlowPacketsPerS: float
    FlowIatMean: float
    FlowIatStd: float
    FlowIatMax: int
    FlowIatMin: int
    FwdIatTotal: int
    FwdIatMean: float
    FwdIatStd: float
    FwdIatMax: int
    FwdIatMin: int
    BwdIatTotal: int
    BwdIatMean: float
    BwdIatStd: float
    BwdIatMax: int
    BwdIatMin: int
    FwdPshFlags: int
    BwdPshFlags: int
    FwdUrgFlags: int
    BwdUrgFlags: int
    FwdHeaderLength: int
    BwdHeaderLength: int
    FwdPacketsPerS: float
    BwdPacketsPerS: float
    MinPacketLength: int
    MaxPacketLength: int
    PacketLengthMean: float
    PacketLengthStd: float
    PacketLengthVariance: float
    FinFlagCount: int
    SynFlagCount: int
    RstFlagCount: int
    PshFlagCount: int
    AckFlagCount: int
    UrgFlagCount: int
    CweFlagCount: int
    EceFlagCount: int
    DownPerupRatio: int
    AveragePacketSize: float
    AvgFwdSegmentSize: float
    AvgBwdSegmentSize: float
    FwdHeaderLength1: int
    FwdAvgBytesPerBulk: int
    FwdAvgPacketsPerBulk: int
    FwdAvgBulkRate: int
    BwdAvgBytesPerBulk: int
    BwdAvgPacketsPerBulk: int
    BwdAvgBulkRate: int
    SubflowFwdPackets: int
    SubflowFwdBytes: int
    SubflowBwdPackets: int
    SubflowBwdBytes: int
    Init_win_bytes_forward: int
    Init_win_bytes_backward: int
    Act_data_pkt_fwd: int
    Min_seg_size_forward: int
    ActiveMean: float
    ActiveStd: float
    ActiveMax: int
    ActiveMin: int
    IdleMean: float
    IdleStd: float
    IdleMax: int
    IdleMin: int
    SourceFile:int


class PredictionRequest(BaseModel):
    data: List[CyberFeatures]

MODEL_FEATURE_NAMES = [' Destination Port', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets', 'Total Length of Fwd Packets', ' Total Length of Bwd Packets', ' Fwd Packet Length Max', ' Fwd Packet Length Min', ' Fwd Packet Length Mean', ' Fwd Packet Length Std', 'Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean', ' Bwd Packet Length Std', 'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags', ' Fwd Header Length', ' Bwd Header Length', 'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length', ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance', 'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count', ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size', ' Avg Bwd Segment Size', ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes', 'Init_Win_bytes_forward', ' Init_Win_bytes_backward', ' act_data_pkt_fwd', ' min_seg_size_forward', 'Active Mean', ' Active Std', ' Active Max', ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min', 'source_file']
FEEATURE_KEEPER = [' Destination Port', ' Flow Duration', ' Total Fwd Packets',
       ' Total Backward Packets', 'Total Length of Fwd Packets',
       ' Fwd Packet Length Max', ' Fwd Packet Length Min',
       ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
       'Bwd Packet Length Max', ' Bwd Packet Length Min',
       ' Bwd Packet Length Mean', ' Bwd Packet Length Std', 'Flow Bytes/s',
       ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max',
       'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max',
       ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Std', ' Bwd IAT Max',
       ' Bwd IAT Min', 'Fwd PSH Flags', ' Fwd Header Length',
       ' Bwd Header Length', 'Fwd Packets/s', ' Bwd Packets/s',
       ' Min Packet Length', ' Max Packet Length', ' Packet Length Mean',
       ' Packet Length Std', ' Packet Length Variance', 'FIN Flag Count',
       ' SYN Flag Count', ' PSH Flag Count', ' URG Flag Count',
       ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size',
       ' Avg Bwd Segment Size', ' Fwd Header Length.1', 'Subflow Fwd Packets',
       ' Subflow Fwd Bytes', ' Subflow Bwd Packets', 'Init_Win_bytes_forward',
       ' Init_Win_bytes_backward', ' act_data_pkt_fwd',
       ' min_seg_size_forward', ' Active Std', ' Active Max', 'Idle Mean',
       ' Idle Std', ' Idle Max', ' Idle Min', 'source_file']

PYDANTIC_NAMES = list(CyberFeatures.__annotations__.keys())

RENAME_MAPPING = dict(zip(PYDANTIC_NAMES, MODEL_FEATURE_NAMES))
print(RENAME_MAPPING)

@app.get("/frontend")
def serve_frontend():
    return FileResponse("frontend/index.html")


@app.get("/")
def health_check():
    if not MODELS:
        raise HTTPException(status_code=503, detail="No models loaded")
    return {
        "status": "ok",
        "loaded_models": list(MODELS.keys()),
        "base_uri": MLFLOW_BASE_URI
    }

@app.post("/predict/{model_name}")
def predict(model_name: str, request: PredictionRequest):
    current_model = MODELS.get(model_name)
    if current_model is None:
        raise HTTPException(
            status_code=404,
            detail=f"Model '{model_name}' not found. Available models: {list(MODELS.keys())}"
        )

    data_dicts = [item.model_dump() for item in request.data]
    df = pd.DataFrame(data_dicts)

    try:
        df = df.rename(columns=RENAME_MAPPING)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors du renommage des colonnes : {e}")

    try:
        df = df[FEEATURE_KEEPER]
        numeric_cols = df.select_dtypes(include=np.number).columns

        categorical_cols = df.select_dtypes(include=['object']).columns

        binary_cols = [col for col in numeric_cols if df[col].nunique() == 2]
        categorical_cols = binary_cols + ['source_file'] + categorical_cols.tolist()
        numeric_cols = [col for col in numeric_cols if col not in binary_cols]

        le = LabelEncoder()
        for col in categorical_cols:
            df[col] = le.fit_transform(df[col].astype(str))

    except KeyError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur de clé lors du réordonnancement. Le modèle '{model_name}' n'a pas pu traiter la caractéristique: {e}. Vérifiez la liste MODEL_FEATURE_NAMES."
        )

    try:
        predictions = current_model.predict(df)
        return {"predictions": predictions.tolist()}
    except Exception as e:
        print(f"Erreur de prédiction pour {model_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur de prédiction pour le modèle {model_name}: {e}")

