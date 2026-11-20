import re


_TOKENS = re.compile(
    r'"""[\s\S]*?"""|"(?:\\.|[^"\\\r\n])*"|\'(?:\\.|[^\'\\\r\n])*\'|//[^\r\n]*|/\*'
)
_BLOCK_BOUNDARY = re.compile(r"/\*|\*/")
_NON_NEWLINE = re.compile(r"[^\r\n]")


def without_comments(text: str) -> str:
    """Blank out Kotlin comments while preserving offsets and string literals."""
    pieces = []
    start = 0
    while token := _TOKENS.search(text, start):
        pieces.append(text[start:token.start()])
        end = token.end()
        if token[0] == "/*":
            depth = 1
            for boundary in _BLOCK_BOUNDARY.finditer(text, end):
                depth += 1 if boundary[0] == "/*" else -1
                if depth == 0:
                    end = boundary.end()
                    break
            else:
                end = len(text)
        value = text[token.start():end]
        pieces.append(_NON_NEWLINE.sub(" ", value) if value.startswith(("//", "/*")) else value)
        start = end
    pieces.append(text[start:])
    return "".join(pieces)
