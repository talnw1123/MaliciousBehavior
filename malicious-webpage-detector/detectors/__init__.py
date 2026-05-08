"""
Detection modules for Malicious Webpage Behavior Detection System
"""

from detectors.iframe_detector import IframeDetector
from detectors.js_detector import JSDetector
from detectors.script_detector import ScriptDetector
from detectors.link_detector import LinkDetector
from detectors.safe_browsing import SafeBrowsingDetector
from detectors.risk_scorer import RiskScorer

__all__ = [
    "IframeDetector",
    "JSDetector",
    "ScriptDetector",
    "LinkDetector",
    "SafeBrowsingDetector",
    "RiskScorer",
]
