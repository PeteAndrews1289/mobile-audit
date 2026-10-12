"""Small lexical helpers for source-pattern checks.

This is not a language parser. It removes common line and block comments while
leaving quoted text intact, including URLs with ``//`` inside them.
"""

from __future__ import annotations


def without_code_comments(line: str, in_block: bool) -> tuple[str, bool]:
    result: list[str] = []
    quote = ""
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        pair = line[index:index + 2]
        if in_block:
            if pair == "*/":
                in_block = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if pair == "//":
            break
        if pair == "/*":
            in_block = True
            index += 2
            continue
        if char in "\"'":
            quote = char
        result.append(char)
        index += 1
    return "".join(result), in_block
