"""
Risk Scorer Module
Calculates overall risk level based on detection findings
"""

from config import RISK_THRESHOLDS


class RiskScorer:
    """Calculates and determines overall risk level."""

    def __init__(self):
        self.findings = []
        self.total_score = 0
        self.risk_level = "LOW"

    def add_findings(self, findings):
        """
        Add findings from detection modules.

        Args:
            findings: List of finding dictionaries
        """
        self.findings.extend(findings)

    def calculate_score(self):
        """Calculate total risk score from all findings with category caps."""
        # Cap points per category to prevent score inflation from repeated findings
        category_caps = {
            "external_script": 30,  # Max 30 points for all external scripts combined
            "dangerous_link": 30,   # Max 30 points for all dangerous links combined
            "iframe": 50,           # Max 50 points for all iframe findings
            "javascript": 50,       # Max 50 points for all JS findings
            "cryptojacking": 50,    # Max 50 points for cryptojacking findings
            "safe_browsing": 100,   # Max 100 points for safe browsing (can trigger critical alone)
        }

        category_scores = {}
        for finding in self.findings:
            category = finding.get("category", "other")
            points = finding.get("points", 0)
            category_scores[category] = category_scores.get(category, 0) + points

        # Apply caps
        capped_total = 0
        for category, score in category_scores.items():
            cap = category_caps.get(category, 100)
            capped_total += min(score, cap)

        self.total_score = min(capped_total, 100)
        return self.total_score

    def determine_risk_level(self):
        """Determine risk level based on score thresholds."""
        score = self.calculate_score()

        for level, (min_score, max_score) in RISK_THRESHOLDS.items():
            if min_score <= score <= max_score:
                self.risk_level = level
                break

        return self.risk_level

    def get_results(self):
        """
        Get complete risk assessment results.

        Returns:
            dict: Risk assessment results
        """
        self.determine_risk_level()

        # Generate recommendations based on findings
        recommendations = self._generate_recommendations()

        return {
            "risk_level": self.risk_level,
            "risk_score": self.total_score,
            "findings": self.findings,
            "recommendations": recommendations,
        }

    def _generate_recommendations(self):
        """Generate human-readable recommendations based on findings."""
        recommendations = []

        # Check for specific finding types
        categories = set(f["category"] for f in self.findings)

        if "iframe" in categories:
            hidden_iframes = [f for f in self.findings if "Hidden" in f.get("description", "")]
            if hidden_iframes:
                recommendations.append(
                    "Hidden iframes detected - this page may redirect you to phishing or malware sites without your knowledge"
                )

            malicious_iframes = [f for f in self.findings if "malicious" in f.get("description", "").lower()]
            if malicious_iframes:
                recommendations.append(
                    "Iframes loading from known malicious domains - avoid this site immediately"
                )

        if "javascript" in categories:
            obfuscated = [f for f in self.findings if "obfuscat" in f.get("description", "").lower() or "eval" in f.get("description", "").lower()]
            if obfuscated:
                recommendations.append(
                    "Obfuscated JavaScript detected - the page may be hiding malicious code or keyloggers"
                )

            base64 = [f for f in self.findings if "base64" in f.get("description", "").lower()]
            if base64:
                recommendations.append(
                    "Base64 encoding detected - malicious payloads may be hidden in encoded strings"
                )

        if "cryptojacking" in categories:
            recommendations.append(
                "CRYPTOJACKING DETECTED - This site is using your device to mine cryptocurrency! Leave immediately!"
            )

        if "external_script" in categories:
            malicious_scripts = [f for f in self.findings if "malicious" in f.get("description", "").lower()]
            if malicious_scripts:
                recommendations.append(
                    "Scripts from known malicious domains detected - these may contain malware or spyware"
                )
            else:
                recommendations.append(
                    "External scripts detected - these may track your behavior or inject unwanted content"
                )

        if "dangerous_link" in categories:
            recommendations.append(
                "Links to sensitive files detected - configuration files or credentials may be exposed"
            )
            
        if "safe_browsing" in categories:
            recommendations.append(
                "GOOGLE SAFE BROWSING ALERT: This site or its resources have been flagged as malicious by Google!"
            )

        # General recommendation based on risk level
        if self.risk_level in ["HIGH", "CRITICAL"]:
            recommendations.append(
                "HIGH RISK: Do not enter personal information or credentials on this website"
            )
        elif self.risk_level == "MEDIUM":
            recommendations.append(
                "MEDIUM RISK: Exercise caution when using this website. Avoid entering sensitive information."
            )

        if not recommendations:
            recommendations.append("No significant threats detected. Always practice safe browsing habits.")

        return recommendations
