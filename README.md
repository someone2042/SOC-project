# Lucid SOC

Lucid SOC is an autonomous, AI-driven Security Operations Center (SOC) platform designed to ingest, triage, and investigate security alerts with high fidelity. It shifts the paradigm from traditional reactive dashboards to an active, agentic investigation engine with "Glass-Box" transparency.

##  Key Features

*   **Autonomous LLM Triage (ReAct):** Powered by LangGraph and Google Gemini, the core agent autonomously investigates incoming alerts by utilizing a suite of integrated tools (Threat Intel, SIEM querying, etc.) before reaching a final verdict.
*   **System Behavior Analytics (SBA):** A dedicated Machine Learning microservice that uses Unsupervised Learning (Isolation Forests) and Explainable AI (SHAP) to detect contextual anomalies in unstructured log volumes over time.
*   **Glass-Box Transparency:** The platform physically intercepts the LLM's reasoning loop (Thoughts, Actions, Observations) and renders them in an interactive timeline, ensuring every AI decision is fully auditable by human analysts.
*   **Human-in-the-loop ML:** A feedback mechanism allows analysts to mark specific behavioral spikes as "Normal," mathematically forcing the ML model to adapt its baseline during the next retraining cycle.
*   **Modular Tool Architecture:** Adding new integrations (CrowdStrike, Active Directory, Shodan) requires zero changes to core logic. Developers simply write a Python function, decorate it with `@tool`, and plug it into the agent.

---

##  Architecture Stack

*   **Backend:** Python 3.10+, FastAPI (Asynchronous orchestration)
*   **Agentic Framework:** LangGraph (`create_react_agent`) & LangChain
*   **Machine Learning:** PyOD (Isolation Forest), Drain3 (Log Parsing), SHAP (Explainability)
*   **Data Persistence:** SQLite (Fast, localized relational mapping and API caching)
*   **Frontend:** Vanilla JavaScript, HTML5, TailwindCSS (Served statically)
*   **Integrations:** Wazuh API, OpenSearch, VirusTotal, AbuseIPDB

---

##  Prerequisites

To run this platform, you must have access to:
1. Python 3.10 or higher.
2. An active **Wazuh Manager** and **Wazuh Indexer (OpenSearch)** instance.
3. API Keys for **Google Gemini**, **VirusTotal**, and **AbuseIPDB**.

---

##  Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/someone2042/SOC-project
   cd lucid-soc
   ```

2. **Create a virtual environment and install dependencies:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables:**
   Create a `.env` file in the root of the project and populate it with your credentials:
   ```env
   # Wazuh API Configuration
   WAZUH_API_URL=https://<YOUR_WAZUH_IP>:55000
   WAZUH_API_USER=wazuh
   WAZUH_API_PASSWORD=your_password

   # LLM Configuration
   GEMINI_API_KEY=your_gemini_api_key

   # Threat Intel APIs
   VIRUSTOTAL_API_KEY=your_vt_api_key
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key

   # SIEM Configuration
   OPENSEARCH_URL=https://<YOUR_OPENSEARCH_IP>:9200
   OPENSEARCH_USER=admin
   OPENSEARCH_PASSWORD=your_password
   ```

---

##  Running the Platform

The project consists of two main components: the primary FastAPI SOC platform and the background SBA Machine Learning microservice.

### 1. Start the Main SOC Application
Run the FastAPI server using `uvicorn`:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
*   The **Live Feed Dashboard** will be available at `http://localhost:8000/`
*   The **System Health Dashboard** will be available at `http://localhost:8000/static/health.html`

### 2. Configure Wazuh Integration
Configure your Wazuh Manager's `ossec.conf` to forward alerts to the platform's webhook ingestion endpoint:
```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://<YOUR_SOC_IP>:8000/webhook/wazuh</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

### 3. Run the ML Training Pipeline (Optional/Periodic)
To train the initial baseline for the System Behavior Analytics (SBA) model based on historical OpenSearch data:
```bash
python sba_microservice/train.py
```

*(Note: In production, the SBA inference loop runs automatically as a background daemon initiated by `main.py` via `run_scheduler.py` or as a separate container).*

---

##  Extending the Platform (Modularity)

Lucid SOC was designed for highly modular tool integration. To give the AI agent a new capability (e.g., querying an internal LDAP server):

1. Create a new file in the `tools/` directory (e.g., `tools/ldap.py`).
2. Write a standard Python function with strict type hints and a detailed docstring explaining *when* the AI should use it.
3. Decorate the function with the LangChain `@tool` decorator.
```python
from langchain_core.tools import tool

@tool
def check_user_department(username: str) -> dict:
    """Use this tool to look up a user's department in Active Directory."""
    # Your logic here...
    return {"department": "Finance"}
```
4. Import your new tool into `agent/core_agent.py` and append it to the `tools` list array. The LLM will immediately understand how and when to use it autonomously.

---

