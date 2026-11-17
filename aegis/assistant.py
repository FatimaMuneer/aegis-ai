
"""Groq-powered conversational assistant for AEGIS."""

import os
from pathlib import Path

from dotenv import load_dotenv
from groq import Groq

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


def ask_ai(message: str, history: list | None = None) -> str:
    """Generate a conversational response using Groq."""

    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        return "My AI connection is not configured. Please check the GROQ_API_KEY setting."

    try:
        client = Groq(api_key=api_key)

        messages = [{"role": "system", "content": SYSTEM_PROMPT}]

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
