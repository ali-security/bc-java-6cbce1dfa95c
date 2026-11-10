#!/bin/sh
# Keep the job open until Travis has archived the Gradle result lines of this job's log,
# so a log fetched right after the job finishes is complete. Runs in after_script, which
# cannot change the build result. Polls every 20 s (printing a heartbeat so the 10-minute
# no-output watchdog never fires) and gives up 47 minutes after the job started
# (before_install records the start time), inside Travis' 50-minute job limit.
leg="$1"
url="https://api.travis-ci.com/v3/job/${TRAVIS_JOB_ID}/log.txt"
start=$(cat "$HOME/.seal-job-start" 2>/dev/null || date +%s)
deadline=$((start + 2820))
waited=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -fsSL "$url" 2>/dev/null | grep -Eq 'BUILD (SUCCESSFUL|FAILED) in [0-9]'; then
    echo "log archived after ${waited}s (${leg})"
    exit 0
  fi
  echo "waiting for log archive... (${waited}s, ${leg})"
  sleep 20
  waited=$((waited + 20))
done
echo "log archive still incomplete after ${waited}s (${leg})"
exit 0
