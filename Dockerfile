FROM python:3.12-slim

WORKDIR /app

COPY services/ace/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/ace/ ace/
COPY policies/ policies/

ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "ace.main:app", "--host", "0.0.0.0", "--port", "8000"]
