import os

from deployment_scanner.handlers import bandit_remediate, docker_compose_remediate

HANDLED_VULNERABILITIES_BANDIT = ["B105"]
HANDLED_VULNERABILITIES_DOCKER_COMPOSE_SECURITY = ["COMPOSE_PRIVILEGED",
                                                   "COMPOSE_DANGEROUS_ENV"]


def remediate_repo(scan_results, proj_path: str, remediated_dir):
    if scan_results["bandit"] != {}:
        _remediate_bandit(scan_results, proj_path, remediated_dir)
    if scan_results["docker_compose_security"] != {}:
        _remediate_docker_compose(scan_results, proj_path, remediated_dir)


def _remediate_bandit(scan_results, proj_path, remediated_dir):
    for result in scan_results["bandit"]["results"]:
        processed_file = None
        file_contents = []

        for vuln in result["Vulnerabilities"]:
            current_file = vuln["File"]
            print("handling file:", current_file)

            if processed_file is None or current_file != processed_file:
                if processed_file is not None:
                    output_path = os.path.join(
                        remediated_dir, os.path.basename(processed_file)
                    )
                    with open(output_path, "w") as f:
                        f.writelines(file_contents)

                processed_file = current_file
                with open(processed_file, "r") as f:
                    file_contents = f.readlines()

            if vuln["VulnerabilityID"] in HANDLED_VULNERABILITIES_BANDIT:
                file_contents = _bandit_vulnerability_controller(vuln, file_contents)

        if processed_file is not None:
            output_path = os.path.join(remediated_dir, os.path.basename(processed_file))
            with open(output_path, "w") as f:
                f.writelines(file_contents)


def _bandit_vulnerability_controller(vuln_info, file_contents):
    if vuln_info["VulnerabilityID"] == "B105":
        return bandit_remediate.handle_b105(vuln_info, file_contents)

def _remediate_docker_compose(scan_results, proj_path, remediated_dir):
    for result in scan_results["docker_compose_security"]["results"]:
        processed_file = None
        file_contents = []

        for vuln in result["Vulnerabilities"]:
            current_file = vuln["compose_file"]
            print("handling file:", current_file)

            if processed_file is None or current_file != processed_file:
                if processed_file is not None:
                    output_path = os.path.join(
                        remediated_dir, os.path.basename(processed_file)
                    )
                    with open(output_path, "w") as f:
                        f.writelines(file_contents)

                processed_file = current_file
                with open(processed_file, "r") as f:
                    file_contents = f.readlines()

            if vuln["id"] in HANDLED_VULNERABILITIES_DOCKER_COMPOSE_SECURITY:
                file_contents = _docker_compose_security_controller(vuln, file_contents)

        if processed_file is not None:
            output_path = os.path.join(remediated_dir, os.path.basename(processed_file))
            with open(output_path, "w") as f:
                f.writelines(file_contents)


def _docker_compose_security_controller(vuln_info, file_contents):
    if vuln_info["id"] == "COMPOSE_PRIVILEGED":
        return docker_compose_remediate.handle_compose_privileged(file_contents)
    if vuln_info["id"] == "COMPOSE_DANGEROUS_ENV":
        return docker_compose_remediate.handle_compose_dangerous_env(file_contents)
