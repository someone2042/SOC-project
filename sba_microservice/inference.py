import os
import joblib
import pandas as pd
import numpy as np
import shap
from datetime import datetime, timedelta, timezone
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.file_persistence import FilePersistence
from opensearch_client import connect_opensearch, fetch_historical_logs, push_sba_scores

def run_inference(client=None, index="wazuh-archives-*"):
    print("Starting SBA live inference pipeline...", flush=True)
    
    # 1. Load artifacts
    print("Loading model artifacts...", flush=True)
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    clf_path = os.path.join(models_dir, 'iforest_model.joblib')
    scaler_path = os.path.join(models_dir, 'scaler_data.joblib')
    feature_cols_path = os.path.join(models_dir, 'feature_cols.joblib')
    drain3_state_path = os.path.join(models_dir, 'drain3_state.bin')
    
    if not all(os.path.exists(p) for p in [clf_path, scaler_path, feature_cols_path, drain3_state_path]):
        print("Missing serialized models. Please run train.py first.", flush=True)
        return
        
    clf = joblib.load(clf_path)
    scaler_data = joblib.load(scaler_path)
    train_scores = scaler_data['train_scores']
    feature_cols = joblib.load(feature_cols_path)
    
    def score_scaler(score):
        return np.mean(train_scores < score) * 100.0
        
    print("Initializing read-only Drain3 parser...", flush=True)
    config = TemplateMinerConfig()
    if os.path.exists(os.path.join(os.path.dirname(__file__), 'drain3.ini')):
        config.load(os.path.join(os.path.dirname(__file__), 'drain3.ini'))
    
    persistence = FilePersistence(drain3_state_path)
    template_miner = TemplateMiner(persistence_handler=persistence, config=config)
    
    # 2. Fetch last 5 minutes of logs
    if client is None:
        client = connect_opensearch()
        
    # For production, we fetch logs in 5-minute windows
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=5)
    
    start_str = start_time.isoformat()
    end_str = end_time.isoformat()
    
    print(f"Fetching logs from {start_str} to {end_str} on index {index}", flush=True)
    logs_by_host = fetch_historical_logs(client, start_str, end_str, index=index, max_docs=50000)
    
    if not logs_by_host:
        print("No logs found in the last 5 minutes. Exiting.", flush=True)
        return
        
    # 3 & 4. Parse and Vectorize
    print(f"Parsing logs and vectorizing for {len(logs_by_host)} hosts...", flush=True)
    records = []
    
    for host, logs in logs_by_host.items():
        print(f"[INFERENCE DEBUG] Processing {len(logs)} logs for host: {host}", flush=True)
        debug_samples = 0
        for log in logs:
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
            
            cluster = template_miner.match(log_message)
            cluster_id = f"cluster_{cluster.cluster_id}" if cluster else "cluster_0"
            
            if debug_samples < 3:
                print(f"[INFERENCE DEBUG] Host '{host}' | Log: {log_message} -> Mapped to: {cluster_id}", flush=True)
                debug_samples += 1
                
            records.append({
                'host': host,
                'cluster_id': cluster_id
            })
            
    df = pd.DataFrame(records)
    
    print("Constructing frequency vectors...", flush=True)
    freq_df = df.groupby('host')['cluster_id'].value_counts().unstack(fill_value=0)
    print(f"[INFERENCE DEBUG] Raw Host Vectors (Before aligning with training features):\n{freq_df}", flush=True)
    
    # Align columns with training data using reindex to avoid fragmentation
    freq_df = freq_df.reindex(columns=feature_cols, fill_value=0)
    print(f"[INFERENCE DEBUG] Final Host Vectors (Aligned with PyOD):\n{freq_df}", flush=True)
    
    if freq_df.empty:
        print("No feature vectors could be constructed.", flush=True)
        return
        
    # 5. Score and Scale
    print("Scoring hosts using PyOD Isolation Forest...", flush=True)
    X_pred = freq_df.values
    raw_scores = clf.decision_function(X_pred)
    scaled_scores = [score_scaler(s) for s in raw_scores]
    
    print("Initializing SHAP explainer for anomalous hosts...", flush=True)
    explainer = shap.TreeExplainer(clf)
    
    results = []
    
    # 6. Feature Attribution and Output
    for i, host in enumerate(freq_df.index):
        score = scaled_scores[i]
        
        factors = []
        negative_impact_idx = []
        if score > 75:  # Lowered slightly so lab tests with moderate spikes trigger SHAP
            print(f"Host '{host}' flagged anomalous with score {score:.2f}. Extracting factors...", flush=True)
            shap_values = explainer.shap_values(X_pred[i:i+1])
            feature_contributions = shap_values[0]
            # In sklearn's Isolation Forest, negative SHAP values indicate contribution towards an anomaly
            # Extract up to 10 factors that most strongly push the score towards anomaly (most negative first)
            negative_impact_idx = [idx for idx in np.argsort(feature_contributions) if feature_contributions[idx] < 0][:10]
            
            for idx in negative_impact_idx:
                cluster_col = feature_cols[idx]
                try:
                    cluster_id_num = int(cluster_col.split('_')[1])
                    weight = round(abs(float(feature_contributions[idx])), 3)
                    if cluster_id_num == 0:
                        factors.append(f"Unseen/Unmatched Log Templates (Zero-Day Behavior) [Weight: {weight}]")
                    else:
                        cluster_def = template_miner.drain.id_to_cluster.get(cluster_id_num)
                        template_str = cluster_def.get_template() if cluster_def else "Unknown Template"
                        factors.append(f"{template_str} [Weight: {weight}]")
                except Exception as e:
                    print(f"Failed to extract template for cluster {cluster_col}: {e}", flush=True)
        else:
            print(f"Host '{host}' score: {score:.2f} (Normal)", flush=True)
        
        # Generate AI-friendly interpretation
        severity = "CRITICAL" if score > 90 else "HIGH" if score > 80 else "ELEVATED"
        # Sum the absolute weights of the top 3 factors to account for correlated multi-alerts
        top_3_weight_sum = sum(abs(float(feature_contributions[idx])) for idx in negative_impact_idx[:3]) if negative_impact_idx else 0
        nature = "Concentrated Spike" if top_3_weight_sum > 1.0 else "Diffuse Background Noise"
        
        results.append({
            "timestamp": end_str,
            "host": host,
            "ml_sba_score": round(score, 2),
            "anomaly_severity": severity,
            "anomaly_nature": nature,
            "sba_contributing_factors": factors
        })
        
    # 7. Push to OpenSearch
    print(f"Pushing {len(results)} inference results to OpenSearch...", flush=True)
    if results:
        push_sba_scores(client, results)
        
    print("Inference pipeline finished successfully.", flush=True)
    return results

if __name__ == "__main__":
    run_inference(index="wazuh-archives-*")
