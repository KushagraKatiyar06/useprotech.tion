# MalwareScope agent package
from .ingestion_agent import run_ingestion
from .static_analysis_agent import run_static_analysis
from .mitre_agent import run_mitre_mapping
from .remediation_agent import run_remediation
from .report_agent import run_report
