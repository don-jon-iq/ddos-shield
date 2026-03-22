"""
Network audit report generator for DDoS Shield.

Generates comprehensive security audit reports including:
- Executive summary with network grade
- Device inventory with risk scores
- Vulnerability details sorted by severity
- Bandwidth analysis highlights
- Prioritized remediation recommendations
- Exportable as JSON via API
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from vulnerability import DeviceAssessment, calculate_network_grade
from remediation import get_device_remediations, get_firewall_suggestions
from health import get_health_score, get_last_health
from bandwidth import bandwidth_tracker
from alert_engine import get_recent_alerts, get_alert_counts

logger = logging.getLogger("ddos_shield.report")


def generate_audit_report(
    assessments: list[DeviceAssessment],
    devices: list[dict] | None = None,
) -> dict:
    """
    Generate a comprehensive network security audit report.

    Args:
        assessments: List of DeviceAssessment objects from vulnerability scanning
        devices: Optional list of discovered device dicts for inventory

    Returns:
        Complete audit report as a dict (JSON-serializable)
    """
    grade_data = calculate_network_grade(assessments)
    health = get_health_score()
    health_checks = get_last_health()
    alert_counts = get_alert_counts()
    top_talkers = bandwidth_tracker.get_top_talkers(10)

    # Build per-device details with remediations
    device_reports = []
    all_vulns = []
    for assessment in sorted(assessments, key=lambda a: a.security_score):
        vuln_dicts = [v.to_dict() for v in assessment.vulnerabilities]
        remediations = get_device_remediations(
            assessment.ip_address,
            assessment.mac_address,
            vuln_dicts,
        )
        device_reports.append({
            "ip_address": assessment.ip_address,
            "mac_address": assessment.mac_address,
            "security_score": assessment.security_score,
            "open_ports": assessment.open_ports,
            "risk_summary": assessment.risk_summary,
            "vulnerabilities": vuln_dicts,
            "remediations": remediations,
        })
        for v in vuln_dicts:
            all_vulns.append({**v, "device_ip": assessment.ip_address})

    # Sort all vulnerabilities by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_vulns.sort(key=lambda v: severity_order.get(v.get("risk_level", "LOW"), 9))

    # Firewall suggestions
    firewall_rules = get_firewall_suggestions(
        [a.to_dict() for a in assessments]
    )

    # Executive summary
    critical_count = grade_data.get("critical_count", 0)
    high_count = grade_data.get("high_count", 0)
    total_vulns = grade_data.get("total_vulnerabilities", 0)
    device_count = grade_data.get("total_devices", 0)

    exec_summary = _build_executive_summary(
        grade_data, critical_count, high_count, total_vulns, device_count, health
    )

    # Top recommendations (prioritized)
    top_recommendations = _build_top_recommendations(all_vulns, firewall_rules)

    report = {
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": exec_summary,
        "network_grade": grade_data,
        "health": {
            "score": health,
            "checks": health_checks,
        },
        "device_count": device_count,
        "devices": device_reports,
        "all_vulnerabilities": all_vulns,
        "vulnerability_summary": {
            "total": total_vulns,
            "critical": critical_count,
            "high": high_count,
            "medium": grade_data.get("medium_count", 0),
            "low": grade_data.get("low_count", 0),
        },
        "bandwidth_top_talkers": top_talkers,
        "firewall_suggestions": firewall_rules,
        "top_recommendations": top_recommendations,
        "alert_summary": alert_counts,
        "recent_alerts": get_recent_alerts(limit=20),
    }

    logger.info(
        "Generated audit report: grade=%s, devices=%d, vulns=%d",
        grade_data.get("grade", "?"), device_count, total_vulns,
    )

    return report


def _build_executive_summary(
    grade_data: dict,
    critical_count: int,
    high_count: int,
    total_vulns: int,
    device_count: int,
    health: dict,
) -> dict:
    """Build the executive summary section of the report."""
    grade = grade_data.get("grade", "?")
    score = grade_data.get("score", 0)

    if grade == "A":
        overall_status = "excellent"
        summary_text = (
            f"The network scored {score}/100 (Grade {grade}). "
            f"All {device_count} devices are well-configured with minimal security risks. "
            "Continue regular monitoring and patching."
        )
    elif grade == "B":
        overall_status = "good"
        summary_text = (
            f"The network scored {score}/100 (Grade {grade}). "
            f"Found {total_vulns} issue(s) across {device_count} devices. "
            "Address the identified vulnerabilities to improve the score."
        )
    elif grade == "C":
        overall_status = "fair"
        summary_text = (
            f"The network scored {score}/100 (Grade {grade}). "
            f"Found {total_vulns} vulnerability(ies) including {high_count} high-severity issues. "
            "Immediate action recommended on high-risk findings."
        )
    elif grade == "D":
        overall_status = "poor"
        summary_text = (
            f"The network scored {score}/100 (Grade {grade}). "
            f"Found {total_vulns} vulnerability(ies) including {critical_count} critical "
            f"and {high_count} high-severity issues. Urgent remediation required."
        )
    else:
        overall_status = "critical"
        summary_text = (
            f"The network scored {score}/100 (Grade {grade}). "
            f"CRITICAL: {critical_count} critical and {high_count} high-severity vulnerabilities "
            f"found across {device_count} devices. Immediate action required to prevent compromise."
        )

    return {
        "grade": grade,
        "score": score,
        "status": overall_status,
        "summary": summary_text,
        "device_count": device_count,
        "total_vulnerabilities": total_vulns,
        "critical_issues": critical_count,
        "high_issues": high_count,
        "health_status": health.get("status", "unknown"),
        "health_score": health.get("score", 0),
    }


def _build_top_recommendations(
    all_vulns: list[dict],
    firewall_rules: list[dict],
) -> list[dict]:
    """Build prioritized top recommendations."""
    recommendations: list[dict] = []
    seen_services: set[str] = set()

    # Priority 1: Critical vulnerabilities
    for vuln in all_vulns:
        service = vuln.get("service", "")
        if vuln.get("risk_level") == "CRITICAL" and service not in seen_services:
            seen_services.add(service)
            recommendations.append({
                "priority": 1,
                "urgency": "IMMEDIATE",
                "title": f"Fix critical: {service} on port {vuln.get('port')}",
                "description": vuln.get("description", ""),
                "affected_device": vuln.get("device_ip", ""),
                "recommendation": vuln.get("recommendation", ""),
            })

    # Priority 2: High vulnerabilities
    for vuln in all_vulns:
        service = vuln.get("service", "")
        if vuln.get("risk_level") == "HIGH" and service not in seen_services:
            seen_services.add(service)
            recommendations.append({
                "priority": 2,
                "urgency": "HIGH",
                "title": f"Address high-risk: {service} on port {vuln.get('port')}",
                "description": vuln.get("description", ""),
                "affected_device": vuln.get("device_ip", ""),
                "recommendation": vuln.get("recommendation", ""),
            })

    # Priority 3: Firewall rules to apply
    if firewall_rules:
        recommendations.append({
            "priority": 3,
            "urgency": "RECOMMENDED",
            "title": f"Apply {len(firewall_rules)} firewall rules",
            "description": "Block dangerous ports identified during the scan",
            "affected_device": "network-wide",
            "recommendation": "Apply the suggested iptables/ufw rules to restrict access to vulnerable services",
        })

    return recommendations[:10]  # Top 10 recommendations
