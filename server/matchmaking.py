"""
matchmaking.py — PlayModule equivalent from server.dll.
Implements: QuickMatch, filtered lobby match, ranking-based match.

DLL exports matched:
  PlayModuleCreate / PlayModuleDestroy
  PlayModuleGameCreateFilter / PlayModuleGameJoinFilter / PlayModuleGameLeaveFilter
  PlayModuleMatchCompare / PlayModuleMatchExtract / PlayModuleMatchGetParams
  PlayModuleQuickJoinCompare / PlayModuleRanker / PlayModuleRanklist
  PlayModulePeriodic / PlayModuleNotify / PlayModuleUserSettings
  PlayModuleBuildRoomCriteria / PlayModuleGameBuildRecord
  PlayModuleGameProcess / PlayModuleGameResultReceived / PlayModuleGameSetFilter
  PlayModuleGameExtract / PlayModuleCustomizePers
  PlayModuleGetCustCmds / PlayModuleGetGameFeatureIds
  PlayModuleUpdateUserRoomEntryCriteria
"""

import time
import threading
import logging
from typing import Optional, List, Dict

log = logging.getLogger("matchmaking")


# ======================================================================= #
# Match criteria                                                            #
# ======================================================================= #

class MatchCriteria:
    """PlayModuleBuildRoomCriteria / PlayModuleMatchGetParams"""
    def __init__(self):
        self.min_players  = 2
        self.max_players  = 8
        self.game_type    = ""          # PUBLIC / PRIVATE / RANKED
        self.skill_min    = 0
        self.skill_max    = 9999
        self.flags        = 0.0
        self.custom       = {}          # arbitrary key:value from game code
        self.require_matched = False
        self.allow_private = False
        self.password     = ""
        self.region       = ""
        self.level_min    = 0
        self.level_max    = 999
        self.ping_max     = 500         # ms

    def matches_user(self, user) -> bool:
        """PlayModuleUpdateUserRoomEntryCriteria"""
        if user.level < self.level_min or user.level > self.level_max:
            return False
        if user.ping > self.ping_max:
            return False
        return True


# ======================================================================= #
# Quickmatch queue entry                                                    #
# ======================================================================= #

class QueueEntry:
    def __init__(self, uid: int, criteria: MatchCriteria):
        self.uid       = uid
        self.criteria  = criteria
        self.enqueued  = time.time()
        self.matched   = False

    def wait_seconds(self) -> float:
        return time.time() - self.enqueued


# ======================================================================= #
# PlayModule — full matchmaking engine                                      #
# ======================================================================= #

class PlayModule:
    """
    PlayModuleCreate equivalent — instantiated once per server.
    All PlayModule* functions are methods here.
    """

    def __init__(self, cfg, user_mgr, room_mgr, game_mgr, ranking):
        self.cfg       = cfg
        self.users     = user_mgr
        self.rooms     = room_mgr
        self.games     = game_mgr
        self.ranking   = ranking

        self._lock      = threading.Lock()
        self._queue: List[QueueEntry] = []
        self._custom_cmds: List[str]  = ["QUIK", "MATCH", "CHAL"]
        self._feature_ids: List[int]  = [1, 2, 3]

        self.timeout    = cfg.get("QUICKMATCH_TIMEOUT", 30)
        self._running   = False
        self._thread    = None

    # ------------------------------------------------------------------ #
    # Lifecycle                                                            #
    # ------------------------------------------------------------------ #

    def create(self):
        """PlayModuleCreate"""
        self._running = True
        self._thread  = threading.Thread(target=self._periodic_loop,
                                         name="PlayModule", daemon=True)
        self._thread.start()
        log.info("PlayModule created.")

    def destroy(self):
        """PlayModuleDestroy"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        log.info("PlayModule destroyed.")

    # ------------------------------------------------------------------ #
    # Quick Join                                                           #
    # ------------------------------------------------------------------ #

    def quick_join_enqueue(self, uid: int, criteria: MatchCriteria) -> bool:
        """
        PlayModuleQuickJoinExtract — add user to matchmaking queue.
        Matches: QUIK: IDENT=%d KIND=%s USER0=%s USER1=%s
        """
        with self._lock:
            # Don't double-queue
            if any(e.uid == uid for e in self._queue):
                return False
            entry = QueueEntry(uid, criteria)
            self._queue.append(entry)
            log.info("QUIK: IDENT=%d KIND=QUICK_JOIN queued", uid)
            return True

    def quick_join_dequeue(self, uid: int):
        with self._lock:
            self._queue = [e for e in self._queue if e.uid != uid]

    def _try_match_queue(self):
        """
        PlayModuleQuickJoinCompare — attempt to pair queued users.
        Called periodically from PlayModulePeriodic.
        """
        with self._lock:
            unmatched = [e for e in self._queue if not e.matched]

        matched_pairs = []
        used = set()

        for i, a in enumerate(unmatched):
            if a.uid in used:
                continue
            for b in unmatched[i+1:]:
                if b.uid in used:
                    continue
                if self._compare(a, b):
                    matched_pairs.append((a, b))
                    used.add(a.uid)
                    used.add(b.uid)
                    break

        for a, b in matched_pairs:
            self._notify_match(a, b)

        # Expire timed-out entries
        now = time.time()
        with self._lock:
            expired = [e for e in self._queue
                       if e.wait_seconds() > self.timeout and not e.matched]
            for e in expired:
                self._queue.remove(e)
                log.info("QUIK: IDENT=%d KIND=QUICK_JOIN IDLE=1 (timeout)", e.uid)
                user = self.users.get(e.uid)
                if user:
                    user.send("+QUIK TEXT=\"No match found\"\n")

    def _compare(self, a: QueueEntry, b: QueueEntry) -> bool:
        """PlayModuleQuickJoinCompare — compatibility check."""
        ca, cb = a.criteria, b.criteria
        # Skill ranges must overlap
        if ca.skill_max < cb.skill_min or cb.skill_max < ca.skill_min:
            return False
        # Ping tolerance
        if ca.ping_max < 50 or cb.ping_max < 50:
            return False
        return True

    def _notify_match(self, a: QueueEntry, b: QueueEntry):
        """PlayModuleNotify — tell both users they've been matched."""
        ua = self.users.get(a.uid)
        ub = self.users.get(b.uid)
        if not ua or not ub:
            return

        game = self.games.create(room_id=0, host_uid=a.uid, limit=2,
                                 game_type="RANKED", private=True, matched=True)
        if not game:
            return

        self.games.join(game.id, a.uid)
        self.games.join(game.id, b.uid)

        msg_a = (f"+QUIK IDENT={game.id} KIND=MATCH "
                 f"USER0={ua.name} USER1={ub.name}\n")
        msg_b = (f"+QUIK IDENT={game.id} KIND=MATCH "
                 f"USER0={ua.name} USER1={ub.name}\n")
        ua.send(msg_a)
        ub.send(msg_b)

        log.info("QUIK: IDENT=%d KIND=MATCH USER0=%s USER1=%s",
                 game.id, ua.name, ub.name)

        with self._lock:
            a.matched = True
            b.matched = True
            self._queue = [e for e in self._queue
                           if e.uid not in (a.uid, b.uid)]

    # ------------------------------------------------------------------ #
    # Lobby match (room-based)                                             #
    # ------------------------------------------------------------------ #

    def find_best_room(self, uid: int, criteria: MatchCriteria) -> Optional[int]:
        """
        PlayModuleMatchCompare — score all available rooms and pick best.
        Matches: LOBBY_MATCH config.
        """
        best_room  = None
        best_score = -1

        for room in self.rooms.list_rooms():
            if room.full:
                continue
            score = self._score_room(room, criteria)
            if score < 0:
                continue
            if score > best_score:
                best_score = score
                best_room  = room

        if best_room:
            log.info("MATCH: %d for reporting", uid)
            return best_room.id

        return None

    def _score_room(self, room, criteria: MatchCriteria) -> int:
        """PlayModuleMatchExtract — extract match score from room."""
        if getattr(room, "private", False) and not getattr(criteria, "allow_private", False):
            return -1
        if getattr(room, "secret", "") and str(getattr(criteria, "password", "") or "") != str(getattr(room, "secret", "") or ""):
            return -1
        if getattr(criteria, "require_matched", False) and not getattr(room, "matched", False):
            return -1
        wanted_type = str(getattr(criteria, "game_type", "") or "").strip().upper()
        room_type = str(getattr(room, "type", "") or "").strip().upper()
        if wanted_type and room_type and wanted_type not in {room_type, "ANY", "ALL"}:
            return -1
        score = 0
        score += room.count * 10        # prefer rooms with players
        if room.count >= criteria.min_players:
            score += 50
        return score

    # ------------------------------------------------------------------ #
    # Game filters                                                         #
    # ------------------------------------------------------------------ #

    def game_create_filter(self, uid: int, params: dict) -> bool:
        """PlayModuleGameCreateFilter — approve/reject game creation."""
        user = self.users.get(uid)
        if not user:
            return False
        # Block banned users from creating games (example)
        if user.flags < 0:
            return False
        return True

    def game_join_filter(self, uid: int, game_id: int) -> bool:
        """PlayModuleGameJoinFilter"""
        from room_manager import GAME_STATE_OPEN
        game = self.games.get(game_id)
        if not game or game.state != GAME_STATE_OPEN:
            return False
        user = self.users.get(uid)
        if not user:
            return False
        return True

    def game_leave_filter(self, uid: int, game_id: int) -> bool:
        """PlayModuleGameLeaveFilter"""
        return True     # always allow leave

    def game_set_filter(self, uid: int, game_id: int, params: dict) -> bool:
        """PlayModuleGameSetFilter"""
        return True

    # ------------------------------------------------------------------ #
    # Game processing & results                                            #
    # ------------------------------------------------------------------ #

    def game_build_record(self, game_id: int) -> dict:
        """PlayModuleGameBuildRecord — build the game result record."""
        game = self.games.get(game_id)
        if not game:
            return {}
        return {
            "IDENT":    game.id,
            "WHEN":     game.finished_at or time.time(),
            "NUMPART":  game.count,
            "EVID":     game.evid,
            "EVGID":    game.evgid,
            "CUSTFLAGS":int(game.flags),
        }

    def game_process(self, game_id: int, data: dict):
        """PlayModuleGameProcess — process in-progress game events."""
        game = self.games.get(game_id)
        if not game:
            return
        log.debug("GameProcess: game=%d data=%s", game_id, data)

    def game_result_received(self, game_id: int, results: Dict[int, dict]):
        """
        PlayModuleGameResultReceived — handle end-of-game results.
        Triggers ranking evaluation.
        """
        game = self.games.get(game_id)
        if not game:
            return

        # Check for mismatched player counts
        expected = game.count
        got      = len(results)
        if expected != got:
            log.warning("PLAYERMISMATCH: %d expected=%d got=%d",
                        game_id, expected, got)

        self.games.finish_game(game_id, results)
        self.ranking.evaluate_game(game_id, game.participants, results)

    # ------------------------------------------------------------------ #
    # Persona customization                                                #
    # ------------------------------------------------------------------ #

    def customize_pers(self, uid: int, settings: dict) -> dict:
        """PlayModuleCustomizePers — apply game-specific persona settings."""
        user = self.users.get(uid)
        if not user:
            return {}
        # Apply allowed settings
        if "LEVEL" in settings:
            user.level  = int(settings["LEVEL"])
        if "MEDALS" in settings:
            user.medals = int(settings["MEDALS"])
        return user.to_dict()

    def user_settings(self, uid: int) -> dict:
        """PlayModuleUserSettings"""
        user = self.users.get(uid)
        if not user:
            return {}
        return {"level": user.level, "medals": user.medals, "rep": user.rep}

    # ------------------------------------------------------------------ #
    # Custom commands                                                      #
    # ------------------------------------------------------------------ #

    def get_cust_cmds(self) -> List[str]:
        """PlayModuleGetCustCmds"""
        return self._custom_cmds

    def get_game_feature_ids(self) -> List[int]:
        """PlayModuleGetGameFeatureIds"""
        return self._feature_ids

    # ------------------------------------------------------------------ #
    # Periodic                                                             #
    # ------------------------------------------------------------------ #

    def periodic(self):
        """PlayModulePeriodic — called every tick."""
        self._try_match_queue()

    def _periodic_loop(self):
        while self._running:
            try:
                self.periodic()
            except Exception as e:
                log.error("PlayModule periodic error: %s", e)
            time.sleep(1.0)
