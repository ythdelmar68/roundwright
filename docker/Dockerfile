# The Docker consumer installs only the uploaded Roundwright wheel.  The base
# image and wheel digest are explicit build inputs; no source runtime is copied.
FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2

ARG ROUNDWRIGHT_WHEEL
ARG ROUNDWRIGHT_WHEEL_SHA256

COPY --chown=65532:65532 dist/${ROUNDWRIGHT_WHEEL} /tmp/roundwright.whl
RUN test -n "${ROUNDWRIGHT_WHEEL_SHA256}" \
    && echo "${ROUNDWRIGHT_WHEEL_SHA256}  /tmp/roundwright.whl" | sha256sum --check --strict \
    && python -m pip install --no-index --no-deps /tmp/roundwright.whl \
    && rm /tmp/roundwright.whl

USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["roundwright"]
CMD ["doctor"]
