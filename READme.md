# EDR AI Log Intelligence

An interactive, Python-based security log analysis application that helps users examine Endpoint Detection and Response (EDR) logs, identify suspicious events, understand risk indicators, and generate AI-assisted security reports.

## Features

- **EDR Log Parsing:** Parses JSON-formatted and plain-text log entries.
- **Security Analysis:** Identifies potentially suspicious events using rule-based analysis.
- **Risk Scoring:** Assigns heuristic risk scores to help prioritize security events.
- **SHAP-Style Explainability:** Displays feature contributions to explain how the heuristic risk score is calculated.
- **AI Security Assistant:** Generates explanations and summaries of findings, with a local fallback when the AI API is unavailable.
- **Interactive Dashboard:** Displays metrics, charts, security findings, and event details.
- **Filtering and Search:** Helps users investigate events by severity and other available fields.
- **Report Export:** Supports downloading analysis reports and exporting event data as CSV or JSON.

## Technology Stack

- **Python** — Core application and analysis logic.
- **Streamlit** — Interactive web interface.
- **Pandas** — Data processing and tabular analysis.
- **NumPy** — Numerical operations.
- **SHAP** — Explainability-related functionality.
- **Matplotlib** — Visualizations.
- **OpenAI API** — AI-assisted explanations when configured.
- **Python-dotenv** — Loading environment variables from a `.env` file.

## Project Structure

```text
edr-ai/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── parser.py
│   ├── analyzer.py
│   ├── shap_explainer.py
│   └── llm.py
├── secrets/
│   └── openai_api_key.txt
├── .env
├── .gitignore
├── requirements.txt
└── README.md
```

## Prerequisites

- Python 3.10 or later; Python 3.11 is recommended.
- pip
- A supported web browser.
- An OpenAI API key if you want to use API-based explanations.

## Installation and Setup

### 1. Clone the repository

```powershell
git clone <YOUR_REPOSITORY_URL>
cd edr-ai
```

If the project is already on your computer, open PowerShell in the project directory instead.

### 2. Create a virtual environment

```powershell
python -m venv .venv
```

### 3. Activate the virtual environment

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, run the following in the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

Then activate the environment again.

### 4. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 5. Configure the API key (optional)

Create or update the `.env` file in the project root:

```env
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4o-mini
```

Replace the placeholder with your own API key. Keep `.env` out of version control. Never commit API keys or other credentials to GitHub.

If no API key is configured, the application may use its local explanation fallback, provided that fallback is available and configured correctly.

## Running the Application

From the project root, with the virtual environment activated, run:

```powershell
python -m streamlit run app\main.py
```

Streamlit will display a local URL, usually:

```text
http://localhost:8501
```

Open the URL in your browser to use the dashboard.

## How to Use

1. Start the Streamlit application.
2. Upload an EDR log file using the interface.
3. Review the parsed events and dashboard metrics.
4. Examine security findings and suspicious indicators.
5. Inspect risk scores and their feature contributions.
6. Use the AI Assistant to request explanations of findings, when available.
7. Search or filter events and export supported reports.

The exact supported file formats and available controls depend on the current implementation of the application.

## Security and Limitations

- **Read-only analysis:** The application is intended to analyze uploaded logs; it should not modify the original EDR logs or automatically terminate processes.
- **Heuristic risk scores:** Risk scores are rule-based estimates, not calibrated probabilities of malware or compromise.
- **Not a replacement for an EDR solution:** Findings require investigation and validation by a security analyst.
- **AI limitations:** AI-generated explanations may be incomplete or inaccurate and should be verified.
- **Sensitive data:** Review logs before uploading them to any external AI service. Logs may contain usernames, IP addresses, hostnames, and other sensitive information.
- **API costs:** OpenAI API usage may incur separate charges depending on your account and usage.

## Troubleshooting

### `ModuleNotFoundError: No module named 'app'`

Ensure `app\__init__.py` exists and run the command from the project root:

```powershell
python -m streamlit run app\main.py
```

### Missing Python dependencies

Activate the virtual environment and reinstall dependencies:

```powershell
python -m pip install -r requirements.txt
```

### Streamlit command not found

Run Streamlit through Python:

```powershell
python -m streamlit run app\main.py
```

### AI API errors

Verify that your API key is configured correctly and that your OpenAI API account has available quota and billing configured where required. The ChatGPT subscription and API billing are separate.

## Future Enhancements

- Support for additional EDR log formats.
- Improved event correlation and threat-hunting workflows.
- Customizable detection rules.
- Enhanced visualizations and investigation timelines.
- More detailed AI-generated incident summaries.
- Evaluation against labeled security datasets.

