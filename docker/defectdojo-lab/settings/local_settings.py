# Synchronous processing makes the acceptance fixture deterministic without
# a Celery worker. Production deployments may keep their regular workers.
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
DEDUPLICATION_ALGORITHM_PER_PARSER = {'Generic Findings Import': 'unique_id_from_tool'}
