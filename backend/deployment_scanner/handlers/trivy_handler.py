from typing import Any, Dict, List, Optional
from pathlib import Path

from .base_handler import BaseHandler


class TrivyHandler(BaseHandler):
    def scan_image(self, image: str):
        cmd = [
            "trivy",
            "image",
            "--format",
            "json",
            image,
        ]

        code, out, err = self.run_cmd(cmd)
        data = self.parse_json(out)

        return {
            "tool": "trivy",
            "type": "IMAGE_SCAN",
            "results": self._extract_vulnerabilities(data, image),
            "errors": err,
        }

    def _extract_vulnerabilities(
        self, data: Optional[Dict[str, Any]], image: str
    ) -> list[dict]:
        if not data:
            return []

        target = {"Target": image, "Type": "image", "Vulnerabilities": []}

        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                target["Vulnerabilities"].append(
                    {
                        "VulnerabilityID": vuln.get("VulnerabilityID"),
                        "Severity": vuln.get("Severity"),
                        "Title": vuln.get("Title"),
                        "Description": vuln.get("Description"),
                        "Package": vuln.get("PkgName"),
                        "InstalledVersion": vuln.get("InstalledVersion"),
                        "FixedVersion": vuln.get("FixedVersion"),
                        "CVSS": vuln.get("CVSS", {}),
                        "DataSource": "Trivy",
                        "PublishedDate": vuln.get("PublishedDate"),
                        "LastModifiedDate": vuln.get("LastModifiedDate"),
                    }
                )

        return [target]

    def scan_misconfig(self, path: str):
        cmd = [
            "trivy",
            "fs",
            "--format",
            "json",
            "--scanners",
            "misconfig",
            path,
        ]

        code, out, err = self.run_cmd(cmd)
        data = self.parse_json(out)

        return {
            "tool": "trivy",
            "type": "MISCONFIG_SCAN",
            "results": self._extract_misconfigurations(data, path),
            "errors": err,
        }

    def _extract_misconfigurations(
        self, data: Optional[Dict[str, Any]], path: str
    ) -> list[dict]:
        if not data:
            return []

        target = {"Target": path, "Type": "misconfig", "Misconfigurations": []}

        for result in data.get("Results", []):
            result_target = result.get("Target", "")

            for misconfig in result.get("Misconfigurations", []):
                cause_metadata = misconfig.get("CauseMetadata", {})

                misconfig_entry = {
                    "ID": misconfig.get("ID"),
                    "Severity": misconfig.get("Severity"),
                    "Title": misconfig.get("Title"),
                    "Description": misconfig.get("Description"),
                    "Message": misconfig.get("Message"),
                    "Type": misconfig.get("Type"),
                    "Status": misconfig.get("Status"),
                    "DataSource": "Trivy",
                    "File": result_target,
                }

                if "StartLine" in cause_metadata:
                    misconfig_entry["StartLine"] = cause_metadata["StartLine"]
                if "EndLine" in cause_metadata:
                    misconfig_entry["EndLine"] = cause_metadata["EndLine"]

                target["Misconfigurations"].append(misconfig_entry)

        return [target]

    def scan_dependencies(self, path: str) -> Dict[str, Any]:

        results = {
            "tool": "trivy",
            "type": "DEPENDENCY_SCAN",
            "results": [],
            "errors": ""
        }

        path_obj = Path(path)
        dependency_files = []

        dependency_patterns = [
            "package-lock.json",
            "requirements.txt",
            "yarn.lock",
            "composer.lock",
            "Gemfile.lock",
            "go.mod",
            "pom.xml",
            "Cargo.lock"
        ]

        for pattern in dependency_patterns:
            found_files = list(path_obj.rglob(pattern))
            dependency_files.extend(found_files)

        if not dependency_files:
            results["errors"] = "No dependency files found"
            return results

        for dep_file in dependency_files:
            try:
                file_result = self._scan_dependency_file(str(dep_file))
                if file_result:
                    results["results"].extend(file_result)
            except Exception as e:
                results["errors"] += f"Error scanning {dep_file}: {str(e)}; "

        return results

    def _scan_dependency_file(self, file_path: str) -> List[Dict[str, Any]]:

        cmd = [
            "trivy",
            "fs",
            "--format",
            "json",
            "--scanners",
            "vuln",
            file_path,
        ]

        code, out, err = self.run_cmd(cmd)
        data = self.parse_json(out)

        return self._extract_dependency_vulnerabilities(data, file_path)

    def _extract_dependency_vulnerabilities(
        self, data: Optional[Dict[str, Any]], file_path: str
    ) -> List[Dict[str, Any]]:

        if not data:
            return []

        results = []

        for result in data.get("Results", []):
            target = {
                "Target": file_path,
                "Type": "dependency",
                "DependencyType": self._get_dependency_type(file_path),
                "Vulnerabilities": []
            }

            for vuln in result.get("Vulnerabilities", []):
                vulnerability = {
                    "VulnerabilityID": vuln.get("VulnerabilityID"),
                    "Severity": vuln.get("Severity"),
                    "Title": vuln.get("Title"),
                    "Description": vuln.get("Description"),
                    "Package": vuln.get("PkgName"),
                    "InstalledVersion": vuln.get("InstalledVersion"),
                    "FixedVersion": vuln.get("FixedVersion"),
                    "CVSS": vuln.get("CVSS", {}),
                    "DataSource": "Trivy",
                    "PublishedDate": vuln.get("PublishedDate"),
                    "LastModifiedDate": vuln.get("LastModifiedDate"),
                    "PkgPath": vuln.get("PkgPath", ""),
                    "Layer": vuln.get("Layer", {}),
                }
                target["Vulnerabilities"].append(vulnerability)

            if target["Vulnerabilities"]:  # Dodaj tylko jeśli są podatności
                results.append(target)

        return results

    def _get_dependency_type(self, file_path: str) -> str:

        file_name = Path(file_path).name.lower()

        type_mapping = {
            "package-lock.json": "npm",
            "yarn.lock": "yarn",
            "requirements.txt": "pip",
            "composer.lock": "composer",
            "gemfile.lock": "bundler",
            "go.mod": "go",
            "go.sum": "go",
            "pom.xml": "maven",
            "cargo.lock": "cargo",
            "pipfile.lock": "pipenv"
        }

        return type_mapping.get(file_name, "unknown")
