FROM alpine as certs
RUN apk --update --no-cache add ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs /etc/ssl/certs

# default, if running outside of gorelease with a self-compiled binary
ARG DIST_BINARY=src/jetstream/jetstream
COPY ${DIST_BINARY} /epinio-ui

COPY assets/dashboard /assets/dashboard

ENTRYPOINT ["/epinio-ui"]
