// Caso que debe detectar (C13): sin límite de tokens por request
async function responder(openai, prompt) {
  return openai.chat.completions.create({ // ruleid: js-openai-no-max-tokens-ctl13
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
  });
}

// Caso seguro: max_tokens por request
async function responderSafe(openai, prompt) {
  return openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: prompt }],
    max_tokens: 512,
  });
}
