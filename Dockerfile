FROM ghcr.io/astral-sh/uv:python3.9-bookworm-slim

# Create a non-root user for security
RUN useradd --create-home appuser
WORKDIR /home/appuser
USER appuser

COPY shadowproxy ./shadowproxy

# The entrypoint is the script installed by the package
ENTRYPOINT ["uv", "run", "-p", "3.11", "python", "-m", "shadowproxy"]
