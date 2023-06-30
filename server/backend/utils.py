"""
    File: utils.py
    Description: Utility functions for the backend server.
"""
import openai
from .models import Event
import json
from .consts import consts

# Set up your OpenAI API credentials
openai.api_key = consts["OPENAI_API_KEY"]

def ask_chatgpt(event: Event) -> dict:
    prompt = (
        f"I'm on a linux based machine, and I use a eBPF to monitor some syscalls. \
          Now I found the following event: {event.serialize()}."
        + 'Is it malicious? If so, why? and what should I do about it? Please also explain in the reason what is this process? \
            "Please assume that I am a code developer, thus i might use the terminal and other dev tools for work reasons." \
            "Note! that it is probably less possible that this event is suspicious, PLEASE think well before declaring it is a suspicious activity!!!" \
            Please answer in a valid json way using this format: \
        { \
         "event": "<event name>", \
         "suspicious": "<is it suspicious? Yes or No.>", \
         "reason": "<reason for event>", \
         "process": "<process explained>", \
         "action": "<suggested action>" \
        }'
    )

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": prompt},
            ],
        )

        answer = response.choices[0].message["content"]

        return json.loads(answer)
    except Exception:
        return {"error": "error parsing response"}



