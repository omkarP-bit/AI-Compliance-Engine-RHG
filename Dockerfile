FROM python:3.12-slim

ARG OPA_VERSION=0.63.0
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -L -o /usr/local/bin/opa \
      "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static" && \
    chmod +x /usr/local/bin/opa && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /var/task

COPY services/ace/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt awslambdaric

COPY services/ace/ ace/
COPY policies/ policies/
COPY services/ace/lambda_handler.py /var/task/lambda_handler.py

ENV PYTHONPATH=/var/task
ENV OPA_URL=http://localhost:8181

EXPOSE 8000 8181

CMD ["python", "-m", "awslambdaric", "lambda_handler.handler"]
