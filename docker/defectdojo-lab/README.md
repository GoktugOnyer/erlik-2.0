# DefectDojo acceptance deployment

This disposable local deployment runs the actual DefectDojo 2.58.4 Django API and
Nginx image, pinned by digest, with PostgreSQL and Redis. It publishes no ports,
uses an internal Docker network, generates temporary credentials and a trusted
fixture TLS certificate, and deletes its containers and database at teardown.
It contains no client application data. It is a test fixture, not production
hosting configuration.

Build Erlik's worker/proxy images, then run:

```sh
docker compose -f docker-compose.integrations.yml --profile integrations build
ERLIK_DEFECTDOJO_LIVE_TESTS=1 python -m pytest -q tests/test_defectdojo_live.py
```

The test creates an existing engagement, then exercises Erlik's real isolated
HTTPS transport for initial import, unchanged export, changed finding update,
partial assessment export, and local false-positive triage. It verifies that two
findings with the same title and endpoint but distinct fingerprints remain
separate. Database and API credentials stay in temporary runtime files; they are
never included in test output. `ERLIK_DEFECTDOJO_RESULT=/path/result.json` saves a
small result manifest with the service version and checked outcomes.

The fixture enables synchronous Celery processing so it can use deterministic
API assertions without a separate worker. Its Generic Findings parser setting
uses `unique_id_from_tool` for deduplication. Configure the same stable-ID setting
on the selected self-hosted server to preserve distinct rules and authorization
contexts whose titles and locations match:

```python
DEDUPLICATION_ALGORITHM_PER_PARSER = {
    # Preserve your other parser settings here.
    "Generic Findings Import": "unique_id_from_tool",
}
```

Erlik checks that every imported fingerprint can be found afterward; a missing
fingerprint produces an uncertain export requiring inspection, never a completed
sync. Existing ordinary finding fields are updated with an explicit API PATCH
because DefectDojo reimport normally leaves matched findings untouched. API
credentials therefore need access to the configured engagement/test, import and
reimport actions, finding reads, and finding updates. DefectDojo normalizes title
capitalization; Erlik accepts that normalization when verifying updates.

Initial import uses an existing engagement ID plus an explicit test title and
stores the returned test ID. Later exports using that same destination reuse the
stored test. Existing-test reimport accepts a test ID directly. Neither path
creates products/engagements automatically, closes absent findings, follows
redirects, or synchronizes remote triage back into Erlik.

If a write response is lost, subsequent writes to that destination are blocked,
even for a changed report. The explicit reconciliation action only reads the
selected remote test and compares all intended finding fields. It marks the
export completed only when the remote state matches; otherwise it leaves the
export uncertain and replays no requests. For a lost initial-import response,
the operator supplies the exact test ID after checking the remote engagement.

References: [DefectDojo reimport behavior](https://docs.defectdojo.com/import_data/import_intro/reimport/),
[2.58.4 API serializers](https://github.com/DefectDojo/django-DefectDojo/blob/2.58.4/dojo/api_v2/serializers.py),
[2.58.4 Generic JSON parser](https://github.com/DefectDojo/django-DefectDojo/blob/2.58.4/dojo/tools/generic/json_parser.py),
[2.58.4 model normalization](https://github.com/DefectDojo/django-DefectDojo/blob/2.58.4/dojo/models.py).
