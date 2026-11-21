FROM mcr.microsoft.com/playwright/python:v1.63.0-noble
WORKDIR /sandbox
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY worker.py ./worker.py
USER pwuser
CMD ["uvicorn","worker:app","--host","0.0.0.0","--port","8001"]
