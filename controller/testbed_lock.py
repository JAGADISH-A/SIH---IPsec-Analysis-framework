"""Single shared-testbed reservation registry for the API process (Module 6).

The Containerlab/StrongSwan environment is sequential: exactly one pipeline
(manual experiment *or* dataset run) may use it at any moment.  This module
provides the ONE reservation registry consulted by both the manual experiment
endpoint (``controller/api.py``) and the dataset-run endpoints
(``controller/dataset_api.py``), so a dataset run never overlaps a manual
experiment and two dataset runs can never run in parallel.

Design notes
------------
* In-memory on purpose.  The existing manual experiment API keeps its active
  job in a module-level dict with ``threading.Lock``; this module follows the
  same convention so no second competing lock system is introduced.
* It is a *consult-based* guard for a single API process.  Durable
  exclusivity across an API restart is the DatasetRun state itself: a restart
  clears the registry, and the dataset endpoints additionally refuse to start
  anything for a DatasetRun whose persisted status is ``RUNNING``.
* ``reserve``/``release`` are idempotent for the owning (kind, owner_id): a
  duplicate release is a no-op, and reserving again after release succeeds.
"""

from threading import Lock

# Kinds of owners that use the shared testbed.
EXPERIMENT = "experiment"
DATASET = "dataset"
VALID_KINDS = (EXPERIMENT, DATASET)


class TestbedLock:
    """Thread-safe reservation of the single shared testbed."""

    def __init__(self):
        self._lock = Lock()
        self._owner = None  # (kind, owner_id) or None

    def try_reserve(self, kind, owner_id):
        """Try to reserve the testbed for ``owner_id``.

        Returns ``(True, None)`` on success.  On conflict returns
        ``(False, (conflicting_kind, conflicting_owner_id))``.
        """
        if kind not in VALID_KINDS:
            raise ValueError(f"testbed owner kind must be one of {VALID_KINDS}")
        with self._lock:
            if self._owner is None:
                self._owner = (kind, owner_id)
                return True, None
            return False, self._owner

    def release(self, kind, owner_id):
        """Release the reservation if it belongs to ``owner_id``.

        Releasing someone else's (or an absent) reservation is a no-op so a
        worker's ``finally`` can never free another owner's testbed.
        """
        with self._lock:
            if self._owner == (kind, owner_id):
                self._owner = None

    def owner(self):
        """Return the current ``(kind, owner_id)`` or ``None``."""
        with self._lock:
            return self._owner


TESTBED_LOCK = TestbedLock()