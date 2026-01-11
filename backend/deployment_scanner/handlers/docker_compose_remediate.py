import re
def handle_compose_privileged(file_contents: list[str]) -> list[str]:
    for i, line in enumerate(file_contents):
        stripped = line.strip()

        if stripped.startswith("privileged: true"):
            indentation = line[: len(line) - len(line.lstrip())]

            remediated_line = (
                f"{indentation}privileged: false  # SECURITY: disable privileged mode\n"
            )

            file_contents[i] = remediated_line

    return file_contents

def handle_compose_dangerous_env(file_contents: list[str]) -> list[str]:
    dangerous_env_vars = [
        "DEBUG",
        "DEVELOPMENT",
        "DEV_MODE",
        "DISABLE_AUTH",
        "SKIP_SSL",
        "API_KEY",
    ]

    pattern = re.compile(r"^(\s*)-\s*([A-Z_]+)(\s*=\s*.*)?$")

    for i, line in enumerate(file_contents):
        match = pattern.match(line)
        if not match:
            continue

        var_name = match.group(2)
        if var_name in dangerous_env_vars:
            indentation = match.group(1)

            remediated_line = (
                f"{indentation}- {var_name}=false  # SECURITY: disable dangerous environment variable\n"
            )
            file_contents[i] = remediated_line

    return file_contents
