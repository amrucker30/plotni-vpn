FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY plotni_server.py .

EXPOSE 9999

CMD ["python", "plotni_server.py"]
