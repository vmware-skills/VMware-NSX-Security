FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml .
COPY vmware_nsx_security/ vmware_nsx_security/

RUN uv pip install --system .

CMD ["python", "-m", "vmware_nsx_security.mcp_server"]
