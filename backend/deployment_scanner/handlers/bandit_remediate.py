import re

def handle_b105(vuln_info: dict, file_contents: list[str]) -> list[str]:
    line_number = vuln_info.get("Line")
    if not line_number:
        return file_contents

    index = line_number - 1

    if index < 0 or index >= len(file_contents):
        return file_contents

    original_line = file_contents[index]
    indentation = original_line[: len(original_line) - len(original_line.lstrip())]

    match = re.match(r"\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=", original_line)
    if not match:
        return file_contents

    variable_name = match.group(1)

    remediated_line = (
        f'{indentation}{variable_name} = os.getenv("PASSWORD")  # SET PASSWORD IN ENV VAR\n'
    )

    file_contents[index] = remediated_line
    return file_contents
