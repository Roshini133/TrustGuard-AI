#!/bin/sh
# Usage: docker-entrypoint.sh api | worker
# Only the API service applies database migrations (RUN_MIGRATIONS=1, default) so replicas never race.
set -eu

case "${1:-api}" in
  api)
    if [ "${RUN_MIGRATIONS:-1}" = "1" ]; then
      echo "Applying database migrations..."
      i=0
      until alembic upgrade head; do
        i=$((i + 1))
        if [ "$i" -ge 15 ]; then echo "Database unavailable; giving up."; exit 1; fi
        echo "Database not ready (attempt $i/15); retrying in 3s..."
        sleep 3
      done
    fi
    # exec so SIGTERM reaches uvicorn -> graceful shutdown
    exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" \
      --proxy-headers --forwarded-allow-ips="*" --timeout-graceful-shutdown 20
    ;;
  worker)
    export SERVICE_ROLE=worker
    exec celery -A app.celery_app.celery worker -B --loglevel=INFO --concurrency="${CELERY_CONCURRENCY:-2}" \
      --schedule=/tmp/celerybeat-schedule
    ;;
  *)
    exec "$@"
    ;;
esac
