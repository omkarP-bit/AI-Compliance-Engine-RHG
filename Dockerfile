FROM python:3.12-slim

WORKDIR /var/task

COPY services/ace/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt awslambdaric

COPY services/ace/ ace/
COPY services/common/ common/
COPY policies/ policies/
COPY services/ace/lambda_handler.py /var/task/lambda_handler.py

ENV PYTHONPATH=/var/task

EXPOSE 8000

CMD ["python", "-m", "awslambdaric", "lambda_handler.handler"]
