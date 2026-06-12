FROM alpine/git AS fetch
RUN git clone --depth 1 https://github.com/mukul975/Anthropic-Cybersecurity-Skills /skills-src && \
    ls -la /skills-src/ && \
    echo "Cloning complete"

FROM alpine:3.19
RUN apk add --no-cache coreutils jq
COPY --from=fetch /skills-src /tmp/skills-src
WORKDIR /opt/skills-library
CMD ["sh", "-c", "cp -r /tmp/skills-src/* . && echo \"Skills library ready: $(ls skills | wc -l) skills\""]
