"""The wiki's page names: the one mapping from a docs page to its GitHub wiki page. scripts/wiki.py generates the wiki
from docs/ with it, and every message that sends a person to the docs names the page with wiki_url."""

WIKI = "https://github.com/Cygnux-Labs/Tracekit/wiki"
# page names where the file name reads badly; the rest come from the path and WORDS
NAMES = {
    "quickstart-v2.md": "Quickstart", "policy-v2.md": "Policy", "gateway.md": "LLM-Gateway",
    "otel.md": "OpenTelemetry", "why.md": "Tracekit-Why", "why-architecture.md": "Tracekit-Why-Architecture",
    "concepts/README.md": "How-Tracekit-Works", "sample/README.md": "Sample-Bundle", "pcm.md": "Proof-Carrying-Messages",
}
WORDS = {w.lower(): w for w in [
    "A2A", "ADK", "AI", "and", "agentgateway", "agentsh", "C2C", "CrewAI", "E2B", "EU", "FAQ", "ISO", "LangChain", "LiteLLM",
    "LlamaIndex", "MCP", "microsandbox", "NIST", "OpenAI", "OpenShell", "OSS", "OWASP", "RMF", "SDK", "v2"]}


def page_name(path):
    """The wiki page name of a page under docs/: its directory and file name in title case, e.g. Integrations-OpenShell
    for integrations/openshell.md, a directory's README.md named by the directory."""
    if path in NAMES:
        return NAMES[path]
    parts = path[:-len(".md")].split("/")
    if parts[-1] == "README":
        parts.pop()
    return "-".join(WORDS.get(w, w.capitalize()) for p in parts for w in p.split("-"))


def wiki_url(path, anchor=None):
    """The wiki URL of the docs page `path` (docs/witnesses.md), at `anchor` when given."""
    return f"{WIKI}/{page_name(path[len('docs/'):])}" + (f"#{anchor}" if anchor else "")
