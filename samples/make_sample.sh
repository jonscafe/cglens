#!/usr/bin/env bash
# Capture the raw (unredacted) sample: samples/workload.py in a fresh
# python:3.12-slim container, frozen, captured by cglime as a v2 bundle.
#
#   sudo samples/make_sample.sh <cglime checkout> <output dir>
#
# Run it on a lab host that runs nothing you would not publish. The capture
# holds whole slab pages, so other workloads' kernel objects come with it until
# redact.py removes them, and redact.py can only remove what the slab map says
# is foreign. The published sample was taken on a throwaway VM.
#
# Output: <output dir>/raw.cglime. Next step: samples/redact.py.
set -euo pipefail

CGLIME=$(realpath "${1:?usage: make_sample.sh <cglime dir> <output dir>}")
OUT=$(realpath -m "${2:?usage: make_sample.sh <cglime dir> <output dir>}")
HERE=$(dirname "$(realpath "$0")")
NAME=cglens-sample
MARK=CGLENS-SAMPLE
IMAGE=python:3.12-slim
PRIV=(--privileged --pid=host --cgroupns=host)

[ -f "$CGLIME/memcg_scan.py" ] || { echo "not a cglime checkout: $CGLIME" >&2; exit 2; }
mkdir -p "$OUT"
rm -f "$OUT"/raw.*

# Memory headroom first: reclaim inside a frozen container evicts its page
# cache before it can be read (cglime README, "The freeze gap"). Done before
# the workload starts, because dropping caches afterwards would evict exactly
# the files it wrote.
sync; echo 3 > /proc/sys/vm/drop_caches

docker rm -f "$NAME" >/dev/null 2>&1 || true
# The workload is copied in rather than bind-mounted, so nothing from this host's
# filesystem layout is visible inside the container.
docker create --name "$NAME" \
    -e CGLENS_SECRET="$MARK-ENV" -e CGLENS_MODE=sample \
    "$IMAGE" python3 /opt/workload.py --marker "$MARK" >/dev/null
docker cp "$HERE/workload.py" "$NAME:/opt/workload.py"
docker start "$NAME" >/dev/null
for _ in $(seq 60); do
    docker logs "$NAME" 2>/dev/null | grep -q READY && break
    sleep 0.5
done
docker logs "$NAME" 2>/dev/null | grep -q READY || { echo "workload never became ready" >&2; exit 1; }
CID=$(docker inspect -f '{{.Id}}' "$NAME")

docker pause "$NAME" >/dev/null
trap 'docker unpause "$NAME" >/dev/null 2>&1 || true; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
docker run --rm "${PRIV[@]}" -v "$CGLIME":/cglime:ro -v "$OUT":/out "$IMAGE" \
    python3 /cglime/memcg_scan.py "$CID" --dump /out/raw.lime --pslist \
    --out /out/raw.scan.json
docker unpause "$NAME" >/dev/null
docker rm -f "$NAME" >/dev/null
trap - EXIT

python3 "$CGLIME/cglime.py" bundle create "$OUT/raw.lime" \
    --case-id CGLENS-SAMPLE --operator cglens-sample \
    --notes "raw capture of samples/workload.py; not for publication before redact.py"
echo "raw capture: $OUT/raw.cglime"
