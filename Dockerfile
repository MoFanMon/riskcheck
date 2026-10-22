FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/MoFanMon/riskcheck"
LABEL org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY riskcheck.py /app/riskcheck.py
COPY riskcheck_data /app/riskcheck_data
USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["python", "-I", "-S", "/app/riskcheck.py"]
