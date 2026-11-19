cd ~/projects/glue-flowlog-etl
pbpaste > glue/jobs/raw_to_curated.py      # Windows Git Bash: cat /dev/clipboard > glue/jobs/raw_to_curated.py
grep -n "^MAX_FAIL_PCT" glue/jobs/raw_to_curated.py   # should show 5.0
git add glue/jobs/raw_to_curated.py tests/
git status                                  # expect raw_to_curated.py and tests/ to be listed
git commit -m "Milestone 4: bookmarks, Glue Data Quality, quarantine, circuit breaker, chaos test"
git push