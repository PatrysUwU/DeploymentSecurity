import logging
import re
from typing import Any, Dict, Optional

logging.basicConfig(level="DEBUG")


def contextualize_scan_results(results: Dict[str, Any]) -> Dict[str, Any]:

    logging.info("Rozpoczynanie kontekstualizacji wyników skanowania")

    _contextualize_image_scans(results.get("trivy_images", {}))

    logging.info("Kontekstualizacja zakończona")
    return results


def _contextualize_image_scans(trivy_images: Dict[str, Any]):

    for image_name, image_data in trivy_images.items():
        container_config = image_data.get("container_config", {})
        has_open_ports = _check_for_open_ports(container_config)

        logging.debug(f"Obraz {image_name}: otwarte porty = {has_open_ports}")

        image_results = image_data.get("results", [])
        for target in image_results:
            vulnerabilities = target.get("Vulnerabilities", [])

            for vuln in vulnerabilities:
                _add_vulnerability_context(vuln, has_open_ports, image_name)


def _check_for_open_ports(container_config: Dict[str, Any]) -> bool:

    ports = container_config.get("ports", [])

    if not ports:
        return False

    for port in ports:
        if isinstance(port, str) and port.strip():
            return True

    return False


def _add_vulnerability_context(
    vuln: Dict[str, Any], has_open_ports: bool, image_name: str
):

    context_wage = 1.0

    attack_vector = _extract_attack_vector(vuln)

    if attack_vector == "NETWORK" and not has_open_ports:
        context_wage = 0.1
        logging.debug(
            f"Vulnerability {vuln.get('VulnerabilityID', 'N/A')} w obrazie {image_name}: "
            f"wektor NETWORK ale zamknięte porty - context_wage = {context_wage}"
        )

    vuln["context_wage"] = context_wage


def _extract_attack_vector(vuln: Dict[str, Any]) -> Optional[str]:

    cvss_data = vuln.get("CVSS", {})

    possible_vectors = []

    if isinstance(cvss_data.get("nvd"), dict):
        nvd_data = cvss_data["nvd"]
        if "V3Vector" in nvd_data:
            possible_vectors.append(nvd_data["V3Vector"])

    if isinstance(cvss_data.get("redhat"), dict):
        redhat_data = cvss_data["redhat"]
        if "V3Vector" in redhat_data:
            possible_vectors.append(redhat_data["V3Vector"])

    if "V3Vector" in cvss_data:
        possible_vectors.append(cvss_data["V3Vector"])
    if "Vector" in cvss_data:
        possible_vectors.append(cvss_data["Vector"])

    for vector_string in possible_vectors:
        if isinstance(vector_string, str):
            attack_vector = _parse_attack_vector_from_cvss(vector_string)
            if attack_vector:
                return attack_vector

    return None


def _parse_attack_vector_from_cvss(cvss_vector: str) -> Optional[str]:

    if not cvss_vector:
        return None

    av_match = re.search(r"AV:([NALP])", cvss_vector)

    if av_match:
        av_code = av_match.group(1)
        av_mapping = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
        return av_mapping.get(av_code)

    return None
