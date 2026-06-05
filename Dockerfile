# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Builder: install ScoutSuite (GPL-2.0) + this MIT wrapper into a venv, pinned
# and hash-verified. Nothing from this stage ships except the finished venv.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Pinned, hash-verified third-party tree (includes ScoutSuite).
COPY requirements.lock ./
RUN pip install --require-hashes -r requirements.lock

# The wrapper itself (out-of-process driver; no GPL linkage).
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps .

# ---------------------------------------------------------------------------
# Runtime: distroless, non-root. Mount the rootfs read-only at run time:
#   docker run --rm --read-only --tmpfs /tmp \
#       -v "$PWD/scoutsuite-report:/report" \
#       -e AWS_PROFILE=auditor presidio-scout aws --report-dir /report
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/python3-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="presidio-hardened-scoutsuite" \
      org.opencontainers.image.source="https://github.com/presidio-v/presidio-hardened-scoutsuite" \
      org.opencontainers.image.licenses="MIT AND GPL-2.0-only" \
      org.opencontainers.image.description="Hardened ScoutSuite distribution (wrapper MIT; bundles ScoutSuite GPL-2.0)"

COPY --from=builder /opt/venv /opt/venv
# GPL-2.0 compliance: ship the license/notice alongside the bundled binary.
COPY LICENSE /licenses/LICENSE.wrapper.MIT
COPY LICENSES/README.md /licenses/THIRD-PARTY-NOTICES.md

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

USER nonroot
WORKDIR /report
ENTRYPOINT ["presidio-scout"]
CMD ["--help"]
