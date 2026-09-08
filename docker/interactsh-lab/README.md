# Real Interactsh acceptance fixture

Build the normal integration worker/proxy images first, then:

```sh
docker build -f docker/interactsh-lab/Dockerfile -t erlik-interactsh-lab:1 .
ERLIK_DOCKER_TESTS=1 ERLIK_REAL_INTERACTSH_TESTS=1 python -m pytest -q tests/test_interactsh_completion.py
```

This starts the actual upstream **Interactsh server v1.2.4**, matching the pinned
client, inside a fresh internal Docker network. It publishes no host ports. The
certificate and token are fixture-only, generated/stored inside the temporary
container. Explicit IP, custom certificate, and disabled update checks prevent
public-IP discovery, ACME registration, and update network calls. Containers and
networks are removed in test teardown.

The controlled target sends a real DNS query and a real HTTPS request to the
callback server. Its wildcard resolver is local to the fixture. Erlik's worker
remains isolated behind the egress proxy; the configured callback origin is a
service, not an assessment target. The test covers token authentication,
registration, encrypted callback polling, separate Nuclei/testcase payloads, and
exact callback attribution. It does not establish internet DNS delegation or a
client application's ability to reach an operator's external callback service.

Server options were checked against [the pinned upstream source](https://github.com/projectdiscovery/interactsh/blob/v1.2.4/cmd/interactsh-server/main.go).
Client registration and output options follow [upstream client documentation](https://github.com/projectdiscovery/interactsh#interactsh-client).
