FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Chainlit runs from a runtime directory so .chainlit/ stays out of /app
WORKDIR /chainlit-runtime

CMD ["/bin/bash"]
