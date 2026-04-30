"""
batch.py — HTTP Batch reporting system + Challenge (CHAL) system.
Matches DLL: 'BATCH: %d reports processed this cycle'
             'GET /ac/', 'GET /ms/', 'GET /re/', 'GET /sl/', 'GET /sv/'
             'CHAL: IDENT %d chal USER0=...'
"""

import time
import json
import queue
import threading
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Tuple

log = logging.getLogger("batch")


# ======================================================================= #
# HTTP Batch Reporter                                                      #
# ======================================================================= #

class GameReport:
    def __init__(self, game_id: int, participants: List[int], results: Dict):
        self.game_id      = game_id
        self.participants = participants
        self.results      = results
        self.created_at   = time.time()
        self.retries      = 0
        self.state        = "PENDING"   # PENDING / SENT / FAILED

    def to_dict(self) -> dict:
        return {
            "game_id":      self.game_id,
            "participants": self.participants,
            "results":      self.results,
            "created_at":   self.created_at,
        }


class BatchReporter:
    """
    Queues game reports and submits them via HTTP.
    Matches:
      BATCH: %d user batch requests queued in this cycle; outstanding reports=%d
      BATCH: completed processing of game %d
      BATCH: BAD_STATE: ...
      GET /ac/, /ms/, /re/, /sl/, /sv/
    """
    ENDPOINTS = {
        "ac": "/ac/",   # anti-cheat
        "ms": "/ms/",   # master stats
        "re": "/re/",   # reports
        "sl": "/sl/",   # slave
        "sv": "/sv/",   # server
    }

    def __init__(self, cfg):
        self.cfg         = cfg
        self._queue: queue.Queue = queue.Queue()
        self._in_flight: Dict[int, GameReport] = {}
        self._lock       = threading.Lock()
        self._running    = False
        self._thread     = None

        self.http_host   = cfg.get("HTTP_HOST", "")
        self.http_port   = cfg.get("HTTP_PORT", 80)
        self.game_file   = cfg.get("GAMEFILE", "data/game_reports.dat")
        self.cycle_size  = 10   # reports per cycle

        # Load any unprocessed reports from disk
        self._load_pending()

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._batch_loop,
                                         name="BatchReporter", daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def enqueue(self, report: GameReport):
        self._queue.put(report)
        with self._lock:
            pending = self._queue.qsize()
        log.info("BATCH: %d user batch requests queued in this cycle; outstanding reports=%d",
                 1, pending)

    def _batch_loop(self):
        while self._running:
            batch = []
            try:
                # Drain up to cycle_size reports
                for _ in range(self.cycle_size):
                    try:
                        report = self._queue.get_nowait()
                        batch.append(report)
                    except queue.Empty:
                        break

                if batch:
                    self._process_batch(batch)
            except Exception as e:
                log.error("BATCH: BAD_STATE: %s", e)
            time.sleep(5.0)

    def _process_batch(self, batch: List[GameReport]):
        log.info("BATCH: %d reports processed this cycle.", len(batch))
        for report in batch:
            # Check for duplicate users in the same game
            seen = set()
            for uid in report.participants:
                if uid in seen:
                    log.warning("BATCH: queued game %d contains duplicate user for %d",
                                report.game_id, uid)
                seen.add(uid)

            self._submit_report(report)
            log.info("BATCH: completed processing of game %d", report.game_id)

        self._save_log(batch)

    def _submit_report(self, report: GameReport):
        """Send report to HTTP backend (GET /re/)"""
        if not self.http_host:
            return  # no backend configured

        try:
            url = (f"http://{self.http_host}:{self.http_port}"
                   f"{self.ENDPOINTS['re']}?game={report.game_id}")
            req = urllib.request.Request(url, headers={
                "Accept":         "*/*",
                "Cache-Control":  "no-cache",
                "Connection":     "close",
                "Content-Length": "0",
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status != 200:
                    log.warning("Got non-200 HTTP response: %d", resp.status)
                report.state = "SENT"
        except urllib.error.URLError as e:
            log.warning("HTTP transfer error: %s", e)
            report.state  = "FAILED"
            report.retries += 1
        except Exception as e:
            log.error("Network error downloading: %s", e)

    def _save_log(self, batch: List[GameReport]):
        """Persist game reports to disk. Matches GAMEFILE config."""
        import os
        os.makedirs(
            os.path.dirname(self.game_file) if os.path.dirname(self.game_file) else ".",
            exist_ok=True
        )
        try:
            existing = []
            if os.path.exists(self.game_file):
                with open(self.game_file, "r") as f:
                    existing = json.load(f)
            existing.extend([r.to_dict() for r in batch])
            with open(self.game_file, "w") as f:
                json.dump(existing, f)
        except Exception as e:
            log.error("Error opening '%s' game report file for write.", self.game_file)

    def _load_pending(self):
        import os
        if not os.path.exists(self.game_file):
            return
        try:
            with open(self.game_file, "r") as f:
                data = json.load(f)
            count = 0
            for d in data:
                if d.get("state", "SENT") == "FAILED":
                    r = GameReport(d["game_id"], d["participants"], d["results"])
                    self._queue.put(r)
                    count += 1
            if count:
                log.info("Loaded %d pending reports from '%s'", count, self.game_file)
        except Exception as e:
            log.error("Error opening '%s' game report file for read.", self.game_file)

    def outstanding(self) -> int:
        return self._queue.qsize()


# ======================================================================= #
# Challenge System (CHAL / IDENT)                                          #
# ======================================================================= #

CHAL_STATE_PENDING  = "PENDING"
CHAL_STATE_ACCEPTED = "ACCEPTED"
CHAL_STATE_REJECTED = "REJECTED"
CHAL_STATE_IDLE     = "IDLE"


class Challenge:
    def __init__(self, ident: int, uid0: int, uid1: int, room_id: int):
        self.ident    = ident
        self.uid0     = uid0
        self.uid1     = uid1
        self.room_id  = room_id
        self.state    = CHAL_STATE_PENDING
        self.created  = time.time()

    def is_expired(self, timeout: float = 30.0) -> bool:
        return (time.time() - self.created) > timeout


class ChallengeManager:
    """
    Manages player-to-player challenges.
    Matches:
      CHAL: IDENT %d chal USER0='%s' USER1='%s'
      CHAL: IDENT %d error not-in-room '%s'
      CHAL: IDENT %d error unavail '%s'
      CHAL: IDENT=%d USER0=%s USER1=%s IDLE=1
    """
    _counter = 1
    _ctr_lock = threading.Lock()

    def __init__(self, user_mgr, room_mgr):
        self.users   = user_mgr
        self.rooms   = room_mgr
        self._lock   = threading.Lock()
        self._chals: Dict[int, Challenge] = {}

    def _next_id(self) -> int:
        with ChallengeManager._ctr_lock:
            ident = ChallengeManager._counter
            ChallengeManager._counter += 1
        return ident

    def challenge(self, challenger_uid: int, target_name: str) -> Tuple[bool, str]:
        """
        Send a challenge from one user to another.
        Both must be in the same room.
        """
        challenger = self.users.get(challenger_uid)
        if not challenger:
            return False, "No such challenger"

        target = self.users.get_by_name(target_name)
        if not target:
            log.info("CHAL: IDENT %d error unavail '%s'", challenger_uid, target_name)
            return False, f"NOSUCHUSER: {target_name}"

        # Must be in same room
        if challenger.room == 0 or challenger.room != target.room:
            log.info("CHAL: IDENT %d error not-in-room '%s'", challenger_uid, target_name)
            return False, "not-in-room"

        ident = self._next_id()
        chal  = Challenge(ident, challenger_uid, target.uid, challenger.room)
        with self._lock:
            self._chals[ident] = chal

        log.info("CHAL: IDENT %d chal USER0='%s' USER1='%s'",
                 ident, challenger.name, target.name)

        # Notify both users
        msg = (f"+CHAL IDENT={ident} "
               f"USER0={challenger.name} USER1={target.name}\n")
        challenger.send(msg)
        target.send(msg)

        return True, str(ident)

    def respond(self, ident: int, uid: int, accept: bool) -> bool:
        """Target user accepts or rejects challenge."""
        with self._lock:
            chal = self._chals.get(ident)
        if not chal or chal.uid1 != uid:
            return False

        if chal.is_expired():
            log.info("CHAL: IDENT=%d USER0=%s USER1=%s IDLE=1",
                     ident,
                     getattr(self.users.get(chal.uid0), "name", "?"),
                     getattr(self.users.get(chal.uid1), "name", "?"))
            chal.state = CHAL_STATE_IDLE
            return False

        chal.state = CHAL_STATE_ACCEPTED if accept else CHAL_STATE_REJECTED

        u0 = self.users.get(chal.uid0)
        u1 = self.users.get(chal.uid1)
        if u0 and u1:
            status = "ACCEPTED" if accept else "REJECTED"
            msg = f"+CHAL IDENT={ident} STATUS={status}\n"
            u0.send(msg)
            u1.send(msg)

        return accept

    def sweep_expired(self):
        """Remove timed-out challenges."""
        with self._lock:
            for ident in list(self._chals.keys()):
                if self._chals[ident].is_expired():
                    chal = self._chals.pop(ident)
                    u0 = self.users.get(chal.uid0)
                    u1 = self.users.get(chal.uid1)
                    log.info("CHAL: IDENT=%d USER0=%s USER1=%s IDLE=1",
                             ident,
                             u0.name if u0 else "?",
                             u1.name if u1 else "?")
