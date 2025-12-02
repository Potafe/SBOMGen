FROM python:3.11

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    lsb-release \
    gnupg \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

COPY docker/install_scanners.sh .
RUN chmod +x install_scanners.sh && sed -i 's/\r$//' install_scanners.sh && ./install_scanners.sh

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

RUN mkdir -p temp results logs

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]