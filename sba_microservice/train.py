import os
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime, timedelta, timezone
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.file_persistence import FilePersistence
from pyod.models.iforest import IForest
from scipy.stats import ecdf
from opensearch_client import connect_opensearch, fetch_historical_logs

def train_baseline():
    print("Starting SBA baseline training pipeline...")
    
    # 1. Fetch 14 days of historical logs
    client = connect_opensearch()
    #end_time = datetime.now(timezone.utc)
    end_time = datetime.now(timezone.utc) - timedelta(hours=4)
    start_time = end_time - timedelta(days=14)
    
    start_str = start_time.isoformat()
    end_str = end_time.isoformat()
    
    print(f"Fetching logs from {start_str} to {end_str}", flush=True)
    logs_by_host = fetch_historical_logs(client, start_str, end_str, index="wazuh-archives-*", max_docs=100000)
    
    if not logs_by_host:
        print("No logs found in the given 14-day window. Aborting training.")
        return
    
    # Ensure models directory exists
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    drain3_state_path = os.path.join(models_dir, 'drain3_state.bin')
    
    # Configure Drain3
    config = TemplateMinerConfig()
    config.load(os.path.join(os.path.dirname(__file__), 'drain3.ini')) if os.path.exists(os.path.join(os.path.dirname(__file__), 'drain3.ini')) else None
    
    # Use FilePersistence to save the state
    persistence = FilePersistence(drain3_state_path)
    template_miner = TemplateMiner(persistence_handler=persistence, config=config)
    
    print(f"Parsing logs and building Drain3 vocabulary... (Total hosts: {len(logs_by_host)})", flush=True)
    # We will build a list of records for our dataframe
    records = []
    
    try:
        from tqdm import tqdm
    except ImportError:
        tqdm = lambda x, **kwargs: x

    debug_samples = 0
    for host, logs in logs_by_host.items():
        print(f"[TRAIN DEBUG] Processing {len(logs)} logs for host: {host}", flush=True)
        for log in tqdm(logs, desc=f"Parsing {host}"):
            log_message = log.get('full_log')
            extracted_background_event = None
            
            if log_message and (log_message.strip().startswith('{') or log_message.strip().startswith('[')):
                try:
                    import json
                    parsed_json = json.loads(log_message)
                    if 'win' in parsed_json and 'system' in parsed_json['win']:
                        sys_data = parsed_json['win']['system']
                        provider = sys_data.get('providerName', 'UnknownProvider')
                        evt_id = sys_data.get('eventID', 'UnknownID')
                        extracted_background_event = f"Windows Event {evt_id} ({provider})"
                except:
                    pass
                log_message = log.get('rule', {}).get('description', '')
                
            if not log_message:
                log_message = log.get('rule', {}).get('description', extracted_background_event or 'Unknown Telemetry Event')
                
            if debug_samples < 5:
                print(f"\n[TRAIN DEBUG] Sample Log Message (Full): {log_message}", flush=True)
                debug_samples += 1
            timestamp = log.get('timestamp')
            
            # Drain3 extraction
            result = template_miner.add_log_message(log_message)
            cluster_id = result["cluster_id"]
            
            records.append({
                'host': host,
                'timestamp': pd.to_datetime(timestamp),
                'cluster_id': f"cluster_{cluster_id}"
            })
            
    print(f"Total Drain3 clusters created: {len(template_miner.drain.clusters)}")
    
    if not records:
        print("No valid logs were parsed. Aborting.")
        return
        
    df = pd.DataFrame(records)
    
    # 3. Vectorization: 5-minute time windows per host
    print("Vectorizing into 5-minute windows...")
    
    # Group by host and 5-min intervals
    df = df.set_index('timestamp')
    
    # We need a pivot table where rows are (host, time_window) and cols are cluster_ids
    # Counting occurrences of each cluster_id in the 5-min window
    freq_df = df.groupby(['host', pd.Grouper(freq='5min')])['cluster_id'].value_counts().unstack(fill_value=0)
    
    # Ensure 'cluster_0' (unmatched/unseen logs) is always a feature so it can be scored
    if 'cluster_0' not in freq_df.columns:
        freq_df['cluster_0'] = 0
        
    # Inject a synthetic outlier so PyOD learns that a spike in unseen logs is highly anomalous
    synthetic_row = {col: 0 for col in freq_df.columns}
    synthetic_row['cluster_0'] = 100
    synthetic_df = pd.DataFrame([synthetic_row], index=pd.MultiIndex.from_tuples([('synthetic_host', pd.Timestamp.now(tz=timezone.utc))]))
    freq_df = pd.concat([freq_df, synthetic_df])
        
    print(f"[TRAIN DEBUG] Vectorized DataFrame shape: {freq_df.shape}", flush=True)
    print(f"[TRAIN DEBUG] Vectorized Data Head:\n{freq_df.head(3)}", flush=True)
    
    if freq_df.empty:
        print("Not enough data to form frequency windows. Aborting.")
        return
        
    print(f"Dataset shape for training: {freq_df.shape} (Windows, Features)")
    
    # 4. Model Fitting: Train PyOD IForest
    print("Training PyOD Isolation Forest...")
    clf = IForest(n_estimators=100, contamination=0.01, random_state=42)
    clf.fit(freq_df.values)
    
    # 5. Score Scaling: Calculate percentiles for 0-100 scale
    # We use empirical CDF from the training decision scores
    train_scores = clf.decision_scores_
    
    print("Calculating scaling parameters (Empirical CDF)...")
    def score_scaler(score, train_scores=train_scores):
        # We can use scipy's ecdf or manually calculate percentile
        # A simple percentile function: how many train scores are below the given score
        return np.mean(train_scores < score) * 100.0
        
    # Serialize the scaler as a simple closure or just save the train_scores to compute percentiles later
    scaler_data = {'train_scores': train_scores}
    
    # 6. Serialization
    print("Serializing artifacts...")
    joblib.dump(clf, os.path.join(models_dir, 'iforest_model.joblib'))
    joblib.dump(scaler_data, os.path.join(models_dir, 'scaler_data.joblib'))
    
    # Save the feature columns so inference knows the exact features
    feature_cols = freq_df.columns.tolist()
    joblib.dump(feature_cols, os.path.join(models_dir, 'feature_cols.joblib'))
    
    print("Training pipeline completed successfully.")

if __name__ == "__main__":
    train_baseline()
