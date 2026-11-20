/* Example config for local work. Copy to config.js (config.js is generated at
   deploy time and is not committed).
   apiBase: API Gateway HTTP API, used for every endpoint except chat.
   chatUrl: Lambda Function URL for POST (chat only; no 30 s limit). Optional:
            if missing, chat goes to apiBase + "/chat".
   web/dev/mock_server.py serves its own config.js with both set to the mock. */
window.TH_CONFIG = {
  apiBase: "http://localhost:8000",
  chatUrl: "http://localhost:8000/chat"
};
