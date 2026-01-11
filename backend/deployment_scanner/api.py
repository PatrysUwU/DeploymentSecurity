import json
import logging
import os
from pathlib import Path

from deployment_scanner import aggregate, contextualize, normalize, remediate

logging.basicConfig(level="DEBUG")


def scan(proj_path: str, output=True) -> dict:
    results = aggregate.aggregate_scan(proj_path)
    normalized_results = normalize.normalize_scan_results(results)
    contextualized_results = contextualize.contextualize_scan_results(
        normalized_results
    )

    security_score = _calculate_security_score(contextualized_results)
    contextualized_results["final_security_score"] = security_score


    if output:
        with open(proj_path + "/scan_results.json", "w") as f:
            json.dump(contextualized_results, f, indent=4, ensure_ascii=False)

    return contextualized_results


def remediate_repo(proj_path: str):
    scan_results = scan(proj_path, output=False)
    remediated_dir = f"{proj_path}/remediation"
    os.makedirs(remediated_dir, exist_ok=True)
    print(proj_path)
    print(remediated_dir)
    remediate.remediate_repo(scan_results, proj_path, remediated_dir)


def _calculate_security_score(results: dict) -> float:

    WEIGHTS = {"trivy_images": 0.4, "misconfig": 0.35, "bandit": 0.25}

    category_scores = {}

    trivy_images_total = 0.0
    trivy_images_count = 0
    trivy_images = results.get("trivy_images", {})
    for image_name, image_data in trivy_images.items():
        for target in image_data.get("results", []):
            for vuln in target.get("Vulnerabilities", []):
                if "after_normalizing" in vuln:
                    after_norm = vuln["after_normalizing"]
                    final_scoring = after_norm.get("final_scoring", 0.0)
                    context_wage = vuln.get("context_wage", 1.0)
                    weighted_score = final_scoring * context_wage
                    trivy_images_total += weighted_score
                    trivy_images_count += 1

    category_scores["trivy_images"] = (
        trivy_images_total / trivy_images_count if trivy_images_count > 0 else 0.0
    )

    trivy_misconfig_total = 0.0
    trivy_misconfig_count = 0
    trivy_misconfig = results.get("trivy_misconfig", {})
    for target in trivy_misconfig.get("results", []):
        for misconfig in target.get("Misconfigurations", []):
            if "after_normalizing" in misconfig:
                after_norm = misconfig["after_normalizing"]
                final_scoring = after_norm.get("final_scoring", 0.0)
                context_wage = misconfig.get("context_wage", 1.0)

                weighted_score = final_scoring * context_wage
                trivy_misconfig_total += weighted_score
                trivy_misconfig_count += 1

    category_scores["misconfig"] = (
        trivy_misconfig_total / trivy_misconfig_count
        if trivy_misconfig_count > 0
        else 0.0
    )

    bandit_total = 0.0
    bandit_count = 0
    bandit_results = results.get("bandit", {})
    for target in bandit_results.get("results", []):
        for vuln in target.get("Vulnerabilities", []):
            if "after_normalizing" in vuln:
                after_norm = vuln["after_normalizing"]
                final_scoring = after_norm.get("final_scoring", 0.0)
                context_wage = vuln.get("context_wage", 1.0)


                weighted_score = final_scoring * context_wage
                bandit_total += weighted_score
                bandit_count += 1

    category_scores["bandit"] = bandit_total / bandit_count if bandit_count > 0 else 0.0

    docker_compose_total = 0.0
    docker_compose_count = 0
    docker_compose_results = results.get("docker_compose_security", {})
    for target in docker_compose_results.get("results", []):
        for issue in target.get("SecurityIssues", []):
            if "after_normalizing" in issue:
                after_norm = issue["after_normalizing"]
                final_scoring = after_norm.get("final_scoring", 0.0)
                context_wage = issue.get("context_wage", 1.0)

                weighted_score = final_scoring * context_wage
                docker_compose_total += weighted_score
                docker_compose_count += 1

    trivy_misconfig_total += docker_compose_total
    trivy_misconfig_count += docker_compose_count

    category_scores["misconfig"] = (
        trivy_misconfig_total / trivy_misconfig_count
        if trivy_misconfig_count > 0
        else 0.0
    )

    final_risk_score = 0.0
    for category, weight in WEIGHTS.items():
        final_risk_score += category_scores[category] * weight

    security_score = max(0.0, 100.0 - final_risk_score)

    if "summary" not in results:
        results["summary"] = {}

    results["summary"]["risk_scores"] = {
        "bandit": category_scores["bandit"],
        "trivy_images": category_scores["trivy_images"],
        "misconfig": category_scores["misconfig"],
        "weighted_final": final_risk_score,
    }

    logging.info(
        f"Security score: {security_score:.2f} (bandit: {category_scores['bandit']:.2f}, "
        f"trivy_images: {category_scores['trivy_images']:.2f}, "
        f"misconfig: {category_scores['misconfig']:.2f}, "
        f"final_risk: {final_risk_score:.2f})"
    )
    return security_score
