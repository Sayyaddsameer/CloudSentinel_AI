// chatbot.js -- AI assistant chat interface
// Bogavalli Akash

const CHAT_ENDPOINT = `${window.ENV_API_URL || ""}/chat`;

let currentModule = "cloud-infra";

function getSelectedModule() {
  const sel = document.getElementById("module-select");
  return sel ? sel.value : "cloud-infra";
}

function appendBubble(text, role) {
  const messages = document.getElementById("chat-messages");
  const wrap = document.createElement("div");

  const label = document.createElement("div");
  label.className = "bubble-label";
  label.textContent = role === "user" ? "You" : "CloudSentinel AI";

  const bubble = document.createElement("div");
  bubble.className = `chat-bubble ${role === "user" ? "bubble-user" : "bubble-ai"}`;
  bubble.textContent = text;

  wrap.appendChild(label);
  wrap.appendChild(bubble);
  messages.appendChild(wrap);
  messages.scrollTop = messages.scrollHeight;
  return bubble;
}

function appendTypingIndicator() {
  const messages = document.getElementById("chat-messages");
  const wrap = document.createElement("div");
  wrap.id = "typing-indicator";

  const label = document.createElement("div");
  label.className = "bubble-label";
  label.textContent = "CloudSentinel AI";

  const bubble = document.createElement("div");
  bubble.className = "chat-bubble bubble-ai";
  bubble.innerHTML = `<span class="spinner" style="width:14px;height:14px;border-width:2px;"></span>`;

  wrap.appendChild(label);
  wrap.appendChild(bubble);
  messages.appendChild(wrap);
  messages.scrollTop = messages.scrollHeight;
}

function removeTypingIndicator() {
  const el = document.getElementById("typing-indicator");
  if (el) el.remove();
}

async function sendMessage() {
  const input  = document.getElementById("chat-input");
  const question = input.value.trim();
  if (!question) return;

  const module = getSelectedModule();
  input.value = "";
  input.style.height = "44px";

  appendBubble(question, "user");
  appendTypingIndicator();

  const sendBtn = document.getElementById("send-btn");
  sendBtn.disabled = true;

  try {
    const resp = await fetch(CHAT_ENDPOINT, {
      method:  "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization:  getToken(),
      },
      body: JSON.stringify({ question, module }),
    });

    removeTypingIndicator();

    if (!resp.ok) {
      appendBubble("Something went wrong. Please try again.", "ai");
      return;
    }

    const data = await resp.json();
    appendBubble(data.answer || "No response received.", "ai");
  } catch (e) {
    removeTypingIndicator();
    appendBubble(`Error: ${e.message}`, "ai");
  } finally {
    sendBtn.disabled = false;
    input.focus();
  }
}

// Auto-grow textarea
document.addEventListener("DOMContentLoaded", () => {
  requireAuth();

  const input = document.getElementById("chat-input");
  if (input) {
    input.addEventListener("input", () => {
      input.style.height = "44px";
      input.style.height = Math.min(input.scrollHeight, 120) + "px";
    });

    // Send on Enter, newline on Shift+Enter
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });
  }

  // Greet the user
  appendBubble(
    "Hi! I am the CloudSentinel AI assistant. Ask me about your detected risks, " +
    "how to fix them, or what to prioritize. Select a module from the dropdown to focus my context.",
    "ai"
  );
});
