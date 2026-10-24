# Casos que deben detectar (C13): llamadas a modelos sin límite de tokens
from openai import OpenAI

client = OpenAI()

def responder(prompt):
    return client.chat.completions.create(  # ruleid: py-openai-no-max-tokens-ctl13
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )

def responder_gemini(model, prompt):
    return model.generate_content(prompt)  # ruleid: py-gemini-no-token-limit-ctl13

# Casos seguros: límite de tokens por request
def responder_safe(prompt):
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=512,
    )

def responder_gemini_safe(model, prompt):
    return model.generate_content(
        prompt,
        generation_config={"max_output_tokens": 512},
    )
