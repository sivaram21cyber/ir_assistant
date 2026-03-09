# 🛡️ AI SOC Investigation Assistant

A comprehensive Streamlit-based application that helps Security Operations Center (SOC) analysts investigate security alerts using AI-powered analysis, playbook matching, IOC extraction, and threat intelligence enrichment.

## 🚀 Features

- **IOC Extraction**: Automatically extracts IP addresses, domains, URLs, file hashes, usernames, hostnames, and process names from alerts
- **MITRE ATT&CK Mapping**: Maps alerts to relevant MITRE ATT&CK techniques and tactics
- **Playbook Matching**: Matches alerts to SOC playbooks using keyword or semantic (vector) search
- **Detection Rule Context**: Provides detection logic and investigation focus areas
- **Threat Intelligence**: Mock threat intel enrichment for IOC reputation analysis
- **Investigation Sources**: Suggests relevant data sources (EDR, SIEM, Firewall, etc.) for investigation
- **AI Investigation Guidance**: Generates comprehensive investigation guidance using local LLM (Ollama)
- **Investigation Memory**: Stores past investigations for reference

## 📋 Requirements

- Python 3.9+
- Ollama (for local LLM inference)
- 8GB+ RAM recommended

## 🛠️ Installation

### 1. Clone or Navigate to the Project

```bash
cd /home/ubuntu/ir_assistant
```

### 2. Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Ollama and Download Model

```bash
# Install Ollama (if not already installed)
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama service
ollama serve &

# Pull the required model
ollama pull llama3.2:3b
```

## 🏃 Running the Application

```bash
# Ensure Ollama is running
ollama serve &

# Run the Streamlit app
streamlit run app.py
```

The application will be available at `http://localhost:8501`

## 📁 Project Structure

```
ir_assistant/
├── app.py                          # Main Streamlit application
├── llm_interface.py                # Ollama LLM integration
├── requirements.txt                # Python dependencies
├── README.md                       # This file
│
├── engines/                        # Analysis engines
│   ├── __init__.py
│   ├── ioc_extractor.py           # IOC extraction (IP, domain, hash, etc.)
│   ├── mitre_mapper.py            # MITRE ATT&CK technique mapping
│   ├── playbook_engine.py         # Keyword-based playbook matching
│   ├── playbook_vector_engine.py  # Semantic playbook search (ChromaDB)
│   ├── threat_intel_engine.py     # Mock threat intelligence
│   ├── detection_dictionary_engine.py  # Detection rule matching
│   └── investigation_source_engine.py  # Investigation source suggestions
│
├── utils/                          # Utility modules
│   ├── __init__.py
│   ├── log_parser.py              # Alert text parsing
│   └── prompt_builder.py          # LLM prompt construction
│
├── data/                           # Data files
│   ├── playbooks/                 # SOC playbook definitions
│   │   ├── phishing.json
│   │   ├── malware.json
│   │   ├── lateral_movement.json
│   │   ├── data_exfiltration.json
│   │   ├── brute_force.json
│   │   ├── command_control.json
│   │   ├── privilege_escalation.json
│   │   └── insider_threat.json
│   ├── detection_dictionary/      # Detection rules
│   │   └── rules.json
│   ├── threat_intel/              # Mock threat intelligence
│   │   ├── ip_addresses.json
│   │   ├── domains.json
│   │   ├── hashes.json
│   │   └── urls.json
│   ├── investigation_sources.json # Investigation data sources
│   ├── authorized_scanners.json   # Authorized scanner whitelist
│   └── investigation_memory.json  # Past investigations storage
│
└── vector_store/                   # ChromaDB vector storage
    └── chroma_db/
```

## 🔄 Analysis Pipeline

When you submit an alert, the application runs through this pipeline:

1. **Parse Alert**: Extract structured information from alert text
2. **Extract IOCs**: Identify indicators of compromise (IPs, domains, hashes, etc.)
3. **Map MITRE**: Match alert to MITRE ATT&CK techniques
4. **Match Playbook**: Find relevant SOC playbook (keyword or semantic search)
5. **Get Detection Rule**: Retrieve detection rule context
6. **Enrich IOCs**: Look up threat intelligence for each IOC
7. **Suggest Sources**: Recommend investigation data sources
8. **Generate AI Guidance**: Use LLM to generate investigation recommendations

## 💡 Usage Guide

### Basic Usage

1. Start the application with `streamlit run app.py`
2. Paste a security alert into the text area
3. Click "Analyze Alert"
4. Review results in the tabbed interface

### Example Alert

```
[ALERT] Suspicious PowerShell Execution Detected
Host: WORKSTATION-001
User: john.doe
Process: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3...
Parent Process: explorer.exe
Destination IP: 45.33.32.156
Time: 2025-03-09 10:30:45 UTC
Severity: High
```

### Using Semantic Search

Enable "Use Semantic Search" in the sidebar to use vector embeddings for more accurate playbook matching. This requires ChromaDB and sentence-transformers.

## 🔧 Configuration

### LLM Settings

The application uses Ollama with the `llama3.2:3b` model by default. To change:

1. Edit `llm_interface.py`
2. Modify the `model` parameter in the `OllamaLLM` class
3. Ensure the model is pulled: `ollama pull <model-name>`

### Adding Playbooks

Add new playbook JSON files to `data/playbooks/`:

```json
{
  "name": "Custom Playbook Name",
  "description": "Description of the playbook",
  "keywords": ["keyword1", "keyword2"],
  "mitre_techniques": ["T1XXX", "T1YYY"],
  "investigation_steps": [
    "Step 1",
    "Step 2"
  ],
  "containment_steps": [
    "Action 1",
    "Action 2"
  ]
}
```

### Adding Detection Rules

Add rules to `data/detection_dictionary/rules.json`:

```json
{
  "rule_name": "Rule Name",
  "logic": "Detection logic expression",
  "description": "What this rule detects",
  "investigation_focus": "What to investigate",
  "severity": "high",
  "mitre_techniques": ["T1XXX"],
  "keywords": ["keyword1", "keyword2"]
}
```

### Adding Threat Intelligence

Add IOC data to files in `data/threat_intel/`:

- `ip_addresses.json` - IP reputation data
- `domains.json` - Domain reputation data
- `hashes.json` - File hash reputation data
- `urls.json` - URL reputation data

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Streamlit UI (app.py)                    │
├─────────────────────────────────────────────────────────────┤
│                    Analysis Pipeline                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ Log      │ │ IOC      │ │ MITRE    │ │ Playbook │      │
│  │ Parser   │ │ Extractor│ │ Mapper   │ │ Engine   │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │Detection │ │ Threat   │ │ Invest.  │ │ Prompt   │      │
│  │ Engine   │ │ Intel    │ │ Sources  │ │ Builder  │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
├─────────────────────────────────────────────────────────────┤
│                    LLM Interface                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Ollama (llama3.2:3b)                    │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    Data Layer                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │Playbooks │ │Detection │ │ Threat   │ │ ChromaDB │      │
│  │ (JSON)   │ │ Rules    │ │ Intel    │ │ Vectors  │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## 🔒 Offline Mode

This application is designed to work completely offline:

- **Local LLM**: Uses Ollama running locally
- **Mock Threat Intel**: Pre-loaded threat intelligence data
- **Local Vector Store**: ChromaDB persists embeddings locally

No external API calls are made during analysis.

## 🐛 Troubleshooting

### Ollama Not Connected

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama if not running
ollama serve
```

### Model Not Found

```bash
# Pull the required model
ollama pull llama3.2:3b

# Or use a different available model
ollama list
```

### Vector Engine Errors

If ChromaDB or sentence-transformers fail to load:

```bash
pip install --upgrade chromadb sentence-transformers
```

### Memory Issues

For large models, ensure sufficient RAM. Consider using smaller models:

```bash
ollama pull llama3.2:1b  # Smaller model
```

## 📝 License

MIT License - Feel free to use and modify for your SOC operations.

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- Additional playbooks for different alert types
- More MITRE ATT&CK techniques
- Integration with real threat intelligence APIs
- Enhanced IOC extraction patterns
- Custom LLM fine-tuning for SOC analysis
