# Oficjalny obraz Kali Linux (automatycznie pobierze wersję ARM64 dla M1)
FROM kalilinux/kali-rolling

# Zmienna zapobiegająca interaktywnym promptom podczas instalacji
ENV DEBIAN_FRONTEND=noninteractive

# Aktualizacja repozytoriów i instalacja narzędzi do reconu oraz środowiska webowego
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    sqlmap \
    gobuster \
    whatweb \
    dnsrecon \
    curl \
    wget \
    git \
    iputils-ping && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Utworzenie wirtualnego środowiska Python (rozwiązuje problem PEP 668 w nowym Kali)
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Kopiowanie i instalacja zależności Flaska
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Instalacja INCLUDED (skaner LFI/RFI) do tego samego venv
RUN git clone --depth 1 https://github.com/JJuly02/INCLUDED.git /opt/included && \
    pip install --no-cache-dir /opt/included && \
    included --version

# Kopiowanie kodu aplikacji
COPY . .

# Ekspozycja portu dla interfejsu webowego
EXPOSE 5000

# Produkcyjny serwer WSGI (debug sterowany przez FLASK_DEBUG w app.py)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "600", "app:app"]