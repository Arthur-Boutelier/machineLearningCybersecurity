FROM python:3.11-slim

WORKDIR /app

COPY requirementsDocker.txt .
RUN pip install --no-cache-dir -r requirementsDocker.txt

COPY app.py .
COPY df.csv .
COPY mlartifacts ./mlartifacts
COPY frontend ./frontend

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
