import logging
from typing import Any, Dict

logging.basicConfig(level="DEBUG")


def normalize_scan_results(results: Dict[str, Any]) -> Dict[str, Any]:

    logging.info("Rozpoczynanie normalizacji wyników skanowania")

    _normalize_dependency_vulnerabilities(results.get("trivy_images", {}))

    _normalize_infrastructure_config(results.get("trivy_misconfig", {}))

    _normalize_sast_issues(results.get("bandit", {}))

    _normalize_docker_compose_security(results.get("docker_compose_security", {}))

    logging.info("Normalizacja zakończona")

    return results


def _normalize_dependency_vulnerabilities(trivy_images: Dict[str, Any]):
    """
    Dodaje after_normalizing do każdej podatności w zależnościach
    CVSS z NVD * 10 * 0.4
    """
    for image_name, image_data in trivy_images.items():
        image_results = image_data.get("results", [])

        for target in image_results:
            vulnerabilities = target.get("Vulnerabilities", [])

            for vuln in vulnerabilities:
                cvss_score = _extract_cvss_score(vuln)

                vuln_score = cvss_score * 10

                vuln["after_normalizing"] = {
                    "weight": 0.4,
                    "final_scoring": vuln_score,
                    "cvss_score": cvss_score,
                }

    logging.debug("Dependency vulnerabilities normalized")


def _normalize_infrastructure_config(trivy_misconfig: Dict[str, Any]):
    """
    Dodaje after_normalizing do każdej podatności w konfiguracji infrastruktury na podstawie severity
    """
    misconfig_results = trivy_misconfig.get("results", [])

    for target in misconfig_results:
        misconfigurations = target.get("Misconfigurations", [])

        for misconfig in misconfigurations:
            severity_score = _convert_severity_to_numeric(
                misconfig.get("Severity", "UNKNOWN")
            )

            config_score = severity_score

            misconfig["after_normalizing"] = {
                "weight": 0.35,
                "final_scoring": config_score,
                "severity_score": severity_score,
            }

    logging.debug("Infrastructure config normalized")


def _normalize_sast_issues(bandit_results: Dict[str, Any]):
    """Dodaje after_normalizing do każdej podatności SAST w kodzie zrodlowym na podstawie severity"""

    sast_results = bandit_results.get("results", [])

    for target in sast_results:
        vulnerabilities = target.get("Vulnerabilities", [])

        for vuln in vulnerabilities:
            severity_score = _convert_severity_to_numeric(
                vuln.get("Severity", "UNKNOWN")
            )

            sast_score = severity_score

            vuln["after_normalizing"] = {
                "weight": 0.25,
                "final_scoring": sast_score,
                "severity_score": severity_score,
            }

    logging.debug("SAST issues normalized")


def _normalize_docker_compose_security(docker_compose_results: Dict[str, Any]):

    compose_results = docker_compose_results.get("results", [])

    for target in compose_results:
        security_issues = target.get("SecurityIssues", [])

        for issue in security_issues:
            severity_score = _convert_severity_to_numeric(
                issue.get("severity", "UNKNOWN")
            )

            compose_score = severity_score * 0.35

            issue["after_normalizing"] = {
                "weight": 0.35,
                "final_scoring": compose_score,
                "severity_score": severity_score,
            }

    logging.debug("Docker Compose security normalized")


def _extract_cvss_score(vulnerability: Dict[str, Any]) -> float:

    cvss_data = vulnerability.get("CVSS", {})

    possible_paths = [
        cvss_data.get("nvd", {}).get("V3Score")
        if isinstance(cvss_data.get("nvd"), dict)
        else None,
        cvss_data.get("nvd", {}).get("V2Score")
        if isinstance(cvss_data.get("nvd"), dict)
        else None,
        cvss_data.get("redhat", {}).get("V3Score")
        if isinstance(cvss_data.get("redhat"), dict)
        else None,
        cvss_data.get("V3Score"),
        cvss_data.get("V2Score"),
        cvss_data.get("BaseScore"),
    ]

    for score in possible_paths:
        if score and isinstance(score, (int, float)):
            return float(score)

    severity = vulnerability.get("Severity", "UNKNOWN").upper()
    severity_to_cvss = {
        "CRITICAL": 9.0,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
        "UNKNOWN": 0.0,
    }

    return severity_to_cvss.get(severity, 0.0)


def _convert_severity_to_numeric(severity: str) -> float:

    severity_mapping = {
        "CRITICAL": 100,
        "HIGH": 80,
        "MEDIUM": 50,
        "LOW": 20,
        "INFO": 10,
        "UNKNOWN": 00,
    }

    return severity_mapping.get(severity.upper(), 0.0)
