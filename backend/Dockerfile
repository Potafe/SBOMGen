# ---------- Base layer with scanners ----------
FROM yazat/scanners:latest AS base

WORKDIR /app

# ---------- Python dependencies ----------
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ---------- Application layer ----------
COPY app/ ./app/
COPY static/ ./static/

RUN mkdir -p temp results logs

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]