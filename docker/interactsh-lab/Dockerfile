# Local acceptance fixture: real upstream server, matching the pinned client.
FROM golang:1.24.2-bookworm AS server
RUN go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@v1.2.4
FROM erlik-integrations:1
COPY --from=server /go/bin/interactsh-server /usr/local/bin/interactsh-server
COPY docker/interactsh-lab/start.py /lab/start.py
ENTRYPOINT ["python", "/lab/start.py"]
