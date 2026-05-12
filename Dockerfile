FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY run.py .

# SCORE_TOKEN must be set at runtime — score routes are disabled if unset
ENV SCORE_TOKEN=""
EXPOSE 5000
CMD ["python", "run.py"]
