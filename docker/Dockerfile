# The Docker consumer installs only the uploaded Roundwright wheel.  The base
# image and wheel digest are explicit build inputs; no source runtime is copied.
FROM python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2

ARG ROUNDWRIGHT_WHEEL
ARG ROUNDWRIGHT_WHEEL_SHA256
ARG ROUNDWRIGHT_CANDIDATE_SHA
ARG ROUNDWRIGHT_BASE_IMAGE_DIGEST

COPY --chown=65532:65532 dist/${ROUNDWRIGHT_WHEEL} /tmp/${ROUNDWRIGHT_WHEEL}
RUN test -n "${ROUNDWRIGHT_WHEEL}" \
    && test -n "${ROUNDWRIGHT_WHEEL_SHA256}" \
    && test -n "${ROUNDWRIGHT_CANDIDATE_SHA}" \
    && test "${ROUNDWRIGHT_BASE_IMAGE_DIGEST}" = "sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2" \
    && echo "${ROUNDWRIGHT_WHEEL_SHA256}  /tmp/${ROUNDWRIGHT_WHEEL}" | sha256sum --check --strict \
    && python -m pip install --no-index --no-deps /tmp/${ROUNDWRIGHT_WHEEL} \
    && groupadd --gid 65532 roundwright \
    && useradd --uid 65532 --gid roundwright --create-home --home-dir /home/roundwright --shell /bin/sh roundwright \
    && mkdir -p /usr/local/share/roundwright \
    && printf '{"base_image_digest":"%s","candidate_sha":"%s","package_digest":"sha256:%s"}\\n' "${ROUNDWRIGHT_BASE_IMAGE_DIGEST}" "${ROUNDWRIGHT_CANDIDATE_SHA}" "${ROUNDWRIGHT_WHEEL_SHA256}" > /usr/local/share/roundwright/consumer-identity.json \
    && truncate -s -2 /usr/local/share/roundwright/consumer-identity.json \
    && rm /tmp/${ROUNDWRIGHT_WHEEL}

ENV HOME=/home/roundwright
USER roundwright:roundwright
WORKDIR /workspace
ENTRYPOINT ["python", "-m", "roundwright.docker_entrypoint"]
CMD ["doctor"]
