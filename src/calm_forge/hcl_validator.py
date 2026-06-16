"""Lightweight HCL syntax validator for generated Terraform Stack files.

Checks structural correctness without requiring terraform to be installed.
Catches: unbalanced braces, unterminated strings, stray block openers.
"""


def validate_hcl_syntax(content: str) -> list[str]:
    """Return a list of error strings. Empty list means valid."""
    errors: list[str] = []
    depth = 0
    in_string = False
    in_block_comment = False
    i = 0
    line = 1
    n = len(content)

    while i < n:
        ch = content[i]

        # Track line numbers
        if ch == "\n":
            if in_string:
                errors.append(f"Line {line}: unterminated string (newline inside string literal)")
                in_string = False
            line += 1
            i += 1
            continue

        # Inside a block comment /* ... */
        if in_block_comment:
            if ch == "*" and i + 1 < n and content[i + 1] == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        # Inside a string — only track escape sequences and closing quote
        if in_string:
            if ch == "\\" and i + 1 < n:
                # Skip escaped character
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue

        # Line comment: # or //
        if ch == "#":
            # Skip to end of line
            while i < n and content[i] != "\n":
                i += 1
            continue

        if ch == "/" and i + 1 < n and content[i + 1] == "/":
            # Skip to end of line
            while i < n and content[i] != "\n":
                i += 1
            continue

        # Block comment open
        if ch == "/" and i + 1 < n and content[i + 1] == "*":
            in_block_comment = True
            i += 2
            continue

        # String open
        if ch == '"':
            in_string = True
            i += 1
            continue

        # Brace tracking
        if ch == "{":
            depth += 1
            i += 1
            continue

        if ch == "}":
            depth -= 1
            if depth < 0:
                errors.append(
                    f"Line {line}: unexpected '}}' — more closing braces than opening braces"
                )
                depth = 0
            i += 1
            continue

        i += 1

    # Post-scan checks
    if in_string:
        errors.append(f"Line {line}: unterminated string at end of file")

    if in_block_comment:
        errors.append("Unterminated block comment (/* not closed)")

    if depth > 0:
        errors.append(
            f"Unbalanced braces: {depth} block(s) opened but never closed"
        )

    return errors
