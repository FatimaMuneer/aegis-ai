
"""Groq-powered conversational assistant for AEGIS."""

import os
from importlib import import_module
from pathlib import Path

def load_dotenv(path: Path) -> None:
    """Load simple KEY=VALUE entries without requiring python-dotenv."""
    if not path.is_file():
        return

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value[:1] == value[-1:] and value.startswith(("'", '"')):
            value = value[1:-1]
        if key:
            os.environ.setdefault(key, value)

# Load the project's root .env file.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

MODEL = "openai/gpt-oss-20b"

SYSTEM_PROMPT = """
You are AEGIS, an intelligent AI accountability assistant.

Your responsibilities:
- Answer questions naturally and clearly.
- Understand conversational context.
- Explain AI safety, cybersecurity, and AEGIS features.
- Help users understand security decisions.
- Be honest when you do not know something.

IMPORTANT SECURITY RULES:
- You are a conversational assistant, not the security engine.
- Never claim that an action has been approved or executed.
- Never bypass, modify, or override AEGIS security policies.
- Never execute commands, SQL, or external actions yourself.
- Security decisions must always be made by the separate AEGIS engine.

Keep answers helpful, professional, and reasonably concise.
"""


def ask_ai(
    message: str,
    history: list | None = None,
    system_context: str = "",
) -> str:
    """Generate a conversational response using Groq."""

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        return "My AI connection is not configured. Please check the GROQ_API_KEY setting."

    try:
        groq = import_module("groq")
        client = groq.Groq(api_key=api_key)

        messages = [{
            "role": "system",
            "content": (
                SYSTEM_PROMPT
                + "\\n\\nVERIFIED AEGIS BACKEND CONTEXT:\\n"
                + (system_context or "No live backend context was supplied.")
                + "\\n\\nTreat this context as the source of truth. "
                "Distinguish observed audit activity from currently running "
                "agents. Never invent agents, connections, scripts, or capabilities. "
                "If information is absent, say so."
            ),
        }]

        # Include recent conversation context.
        if history:
            messages.extend(history[-10:])

        messages.append({"role": "user", "content": message})

        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            temperature=0.6,
            max_completion_tokens=1024,
        )

        answer = response.choices[0].message.content

        return answer.strip() if answer else "I couldn't generate a response."

    except Exception:
        return "I'm having trouble connecting to my AI service. Please try again shortly."
