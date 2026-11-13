FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    WP_VULN_AUDIT_CACHE=/cache
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . && useradd --system --uid 10001 app && mkdir -p /cache && chown app /cache
USER app
VOLUME ["/cache"]
WORKDIR /work
ENTRYPOINT ["wp-vuln-audit"]
CMD ["--help"]
