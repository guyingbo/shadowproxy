# ---- Build Stage ----
FROM python:3.8-slim as builder

WORKDIR /app

# Install uv, our fast installer
RUN pip install uv

# Copy only the files needed for building the package
COPY pyproject.toml README.md ./
COPY shadowproxy ./shadowproxy

# Build the wheel, which is a standard distribution format
RUN uv pip wheel . --wheel-dir /wheels --no-deps

# ---- Final Stage ----
FROM python:3.8-slim

# Create a non-root user for security
RUN useradd --create-home appuser
WORKDIR /home/appuser
USER appuser

# Install uv to install the wheel from the build stage
RUN pip install uv

# Copy the built wheel from the builder stage
COPY --from=builder /wheels /wheels

# Install the wheel. This also installs runtime dependencies defined in pyproject.toml
RUN uv pip install /wheels/*.whl --system

# The entrypoint is the script installed by the package
ENTRYPOINT ["shadowproxy"]