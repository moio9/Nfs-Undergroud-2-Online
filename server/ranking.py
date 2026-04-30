"""
ranking.py — Ranking and Statistics systems.
Matches DLL: RANK_*, STAT_*, PlayModuleRanker, PlayModuleRanklist
"""

import os
import time
import json
import threading
import logging
from typing import Dict, List, Optional, Any, Iterable

log = logging.getLogger("ranking")


def _limit_value(value: Any, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return max(0, int(default))


NFSU2_STAT_CATEGORIES = ("all", "circuit", "sprint", "drag", "drift")
NFSU2_STAT_FIELDS = ("rating", "wins", "losses", "disconnects", "rep", "opps_rep", "opps_rating")
NFSU2_DEFAULT_CATEGORY = (9999, 0, 0, 0, 100, 101, 101)
NFSU2_CATEGORY_SIZE = len(NFSU2_STAT_FIELDS)
NFSU2_STAT_VALUE_COUNT = len(NFSU2_STAT_CATEGORIES) * NFSU2_CATEGORY_SIZE


class NFSU2PlayerStats:
    """NFSU2 lobby stats: 5 categories x 7 hex values."""

    def __init__(self, persona: str, values: Optional[Iterable[Any]] = None):
        self.persona = str(persona or "").strip()
        base = list(NFSU2_DEFAULT_CATEGORY) * len(NFSU2_STAT_CATEGORIES)
        if values is not None:
            parsed = []
            for value in values:
                try:
                    parsed.append(max(0, int(value)))
                except Exception:
                    parsed.append(0)
            for idx, value in enumerate(parsed[:NFSU2_STAT_VALUE_COUNT]):
                base[idx] = value
        self.values = base

    def _offset(self, category_index: int) -> int:
        category_index = max(0, min(len(NFSU2_STAT_CATEGORIES) - 1, int(category_index)))
        return category_index * NFSU2_CATEGORY_SIZE

    def category(self, category_index: int) -> List[int]:
        off = self._offset(category_index)
        return list(self.values[off : off + NFSU2_CATEGORY_SIZE])

    def get(self, category_index: int, field: str) -> int:
        off = self._offset(category_index)
        try:
            field_idx = NFSU2_STAT_FIELDS.index(field)
        except ValueError:
            field_idx = 0
        return int(self.values[off + field_idx])

    def set(self, category_index: int, field: str, value: int):
        off = self._offset(category_index)
        try:
            field_idx = NFSU2_STAT_FIELDS.index(field)
        except ValueError:
            return
        self.values[off + field_idx] = max(0, int(value))

    def bump_result(self, category_index: int, outcome: str):
        outcome = str(outcome or "").strip().upper()
        for cat_idx in {0, max(0, min(4, int(category_index)))}:
            if outcome == "WIN":
                self.set(cat_idx, "wins", self.get(cat_idx, "wins") + 1)
                self.set(cat_idx, "rep", self.get(cat_idx, "rep") + 100)
            elif outcome in ("DISC", "DISCONNECT", "DNF"):
                self.set(cat_idx, "disconnects", self.get(cat_idx, "disconnects") + 1)
                self.set(cat_idx, "rep", max(0, self.get(cat_idx, "rep") - 25))
            else:
                self.set(cat_idx, "losses", self.get(cat_idx, "losses") + 1)
                self.set(cat_idx, "rep", max(0, self.get(cat_idx, "rep") - 5))

    def to_dict(self) -> dict:
        return {"persona": self.persona, "values": list(self.values)}

    def full_hex_csv(self) -> str:
        return ",".join(f"{max(0, int(value)):x}" for value in self.values)

    def snap_hex_csv(self, index: int, rank: int) -> str:
        category_index = max(0, min(4, int(index) - 1))
        values = self.category(category_index)
        # For non-overall boards the client reads the category values from the
        # same offset as the full 5x7 stats block, so keep leading empty slots.
        prefix = [""] * (category_index * NFSU2_CATEGORY_SIZE)
        # nfsuserver sends the visible list rank in the category's rating slot.
        row = [
            max(1, int(rank)),
            values[1],  # wins
            values[2],  # losses
            values[3],  # disconnects
            values[4],  # rep
            values[5],  # average opponent rep
            values[6],  # average opponent rating
        ]
        encoded = [f"{max(0, int(value)):x}" for value in row]
        return ",".join(prefix + encoded)


# ======================================================================= #
# Ranking System                                                           #
# ======================================================================= #

class RankEntry:
    def __init__(self, uid: int, name: str):
        self.uid        = uid
        self.name       = name
        self.score      = 0.0
        self.wins       = 0
        self.losses     = 0
        self.draws      = 0
        self.games      = 0
        self.play_time  = 0.0       # seconds
        self.last_game  = 0.0
        self.raw_data   = {}        # RANK_OUTPUT_RAW

    @property
    def win_rate(self) -> float:
        if self.games == 0:
            return 0.0
        return self.wins / self.games

    @property
    def rank(self) -> int:
        return max(1, int(self.score / 100))

    def to_dict(self) -> dict:
        return {
            "uid":       self.uid,
            "name":      self.name,
            "score":     self.score,
            "wins":      self.wins,
            "losses":    self.losses,
            "draws":     self.draws,
            "games":     self.games,
            "win_rate":  round(self.win_rate, 4),
            "rank":      self.rank,
            "last_game": self.last_game,
        }


class RankingSystem:
    """
    Matches DLL ranking subsystem.
    Config keys: RANK_AUTHENT, RANK_EVALUATE_GAME, RANK_MINIMUM_TIME,
                 RANK_REPORT_TIME, RANK_SAVE_TIME, RANKFILE, RANKLIM
    """

    def __init__(self, cfg):
        self.cfg        = cfg
        self._lock      = threading.Lock()
        self._entries: Dict[int, RankEntry] = {}   # uid -> RankEntry
        self._lists: Dict[str, List[int]] = {}     # list_name -> [uid,...]
        self._dirty     = False
        self._last_save = time.time()

        self.rank_file      = cfg.get("RANKFILE", "data/rankings.dat")
        self.rank_lim       = _limit_value(cfg.get("RANKLIM", 10000), 10000)
        self.save_interval  = cfg.get("RANK_SAVE_TIME", 600)
        self.min_game_time  = cfg.get("RANK_MINIMUM_TIME", 60)
        self.do_evaluate    = bool(cfg.get("RANK_EVALUATE_GAME", 1))
        self.do_authent     = bool(cfg.get("RANK_AUTHENT", 1))
        self.output_raw     = bool(cfg.get("RANK_OUTPUT_RAW", 0))
        self.unrank_fields  = cfg.get("UNRANKALL_FIELDS", "")

        # Load persisted rankings
        self._load()

    # ------------------------------------------------------------------ #
    # CRUD                                                                 #
    # ------------------------------------------------------------------ #

    def get_or_create(self, uid: int, name: str) -> RankEntry:
        with self._lock:
            if uid not in self._entries:
                if self.rank_lim > 0 and len(self._entries) >= self.rank_lim:
                    log.warning("MasterPlayCreate: maximum number of ranking lists (%d) exceeded.",
                                self.rank_lim)
                    return RankEntry(uid, name)
                self._entries[uid] = RankEntry(uid, name)
                self._dirty = True
                self._rebuild_lists()
            elif name and self._entries[uid].name != name:
                self._entries[uid].name = name
                self._dirty = True
            return self._entries[uid]

    def get(self, uid: int) -> Optional[RankEntry]:
        return self._entries.get(uid)

    # ------------------------------------------------------------------ #
    # Game evaluation — PlayModuleRanker                                   #
    # ------------------------------------------------------------------ #

    def evaluate_game(self, game_id: int, participants: List[int],
                      results: Dict[int, dict]):
        """
        RANK_EVALUATE_GAME — update rankings after a game finishes.
        Matches: 'MATCH: %d for reporting', 'BATCH: completed processing of game %d'
        """
        if not self.do_evaluate:
            return

        log.info("MATCH: %d for reporting", game_id)

        now = time.time()
        for uid, result in results.items():
            entry = self.get_or_create(uid, str(result.get("name", f"uid:{uid}")))

            # Check minimum game time
            game_duration = result.get("duration", 0)
            if game_duration < self.min_game_time:
                log.info("RANK: game %d uid %d below min time (%ds < %ds)",
                         game_id, uid, game_duration, self.min_game_time)
                continue

            outcome  = result.get("outcome", "LOSS")   # WIN/LOSS/DRAW
            score_d  = result.get("score_delta", 0.0)
            outcome_key = str(outcome or "").strip().upper()

            if outcome_key == "WIN":
                entry.wins  += 1
                entry.score += max(10.0, score_d)
            elif outcome_key in ("DRAW", "TIE"):
                entry.draws += 1
                entry.score += 1.0
            else:
                entry.losses += 1
                entry.score  = max(0.0, entry.score - 5.0 + score_d)

            entry.games     += 1
            entry.play_time += game_duration
            entry.last_game  = now

            if self.output_raw:
                entry.raw_data[str(game_id)] = result

        self._dirty = True
        self._rebuild_lists()
        log.info("BATCH: %d reports processed this cycle.", len(results))

    # ------------------------------------------------------------------ #
    # Ranklist — PlayModuleRanklist                                        #
    # ------------------------------------------------------------------ #

    def _rebuild_lists(self):
        """Rebuild sorted ranking lists by score."""
        all_entries = sorted(self._entries.values(),
                             key=lambda e: e.score, reverse=True)
        self._lists["global"] = [e.uid for e in all_entries]

    def get_leaderboard(self, list_name: str = "global",
                        limit: int = 100) -> List[dict]:
        uids = self._lists.get(list_name, [])[:limit]
        result = []
        for rank_pos, uid in enumerate(uids, 1):
            entry = self._entries.get(uid)
            if entry:
                d = entry.to_dict()
                d["position"] = rank_pos
                result.append(d)
        return result

    def get_user_rank(self, uid: int, list_name: str = "global") -> int:
        uids = self._lists.get(list_name, [])
        try:
            return uids.index(uid) + 1
        except ValueError:
            return -1

    # ------------------------------------------------------------------ #
    # Persistence                                                          #
    # ------------------------------------------------------------------ #

    def _load(self):
        path = self.rank_file
        if not os.path.exists(path):
            return
        log.info("Loading ranking lists from '%s'", path)
        try:
            with open(path, "r") as f:
                data = json.load(f)
            entries = data.get("entries", [])
            for d in entries:
                if self.rank_lim > 0 and len(self._entries) >= self.rank_lim:
                    log.warning("Ranking load capped at RANKLIM=%d; remaining entries ignored.", self.rank_lim)
                    break
                e = RankEntry(d["uid"], d["name"])
                e.score     = d.get("score", 0.0)
                e.wins      = d.get("wins", 0)
                e.losses    = d.get("losses", 0)
                e.draws     = d.get("draws", 0)
                e.games     = d.get("games", 0)
                e.play_time = d.get("play_time", 0.0)
                e.last_game = d.get("last_game", 0.0)
                self._entries[e.uid] = e
            log.info("Loaded %d ranking lists from '%s'", len(self._entries), path)
            self._rebuild_lists()
        except Exception as ex:
            log.error("Loaded ranking lists from '%s' failed: %s", path, ex)

    def save(self, force: bool = False):
        if not self._dirty and not force:
            return
        now = time.time()
        if not force and (now - self._last_save) < self.save_interval:
            return

        path = self.rank_file
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        try:
            data = {"entries": [e.to_dict() for e in self._entries.values()],
                    "saved_at": now}
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            self._dirty     = False
            self._last_save = now
            log.info("Rankings saved to '%s' (%d entries)", path, len(self._entries))
        except Exception as ex:
            log.error("Failed to save rankings to '%s': %s", path, ex)


# ======================================================================= #
# Statistics System                                                        #
# ======================================================================= #

class StatCategory:
    """Matches: Category %d %s / Column %s '%s' %d %s"""
    def __init__(self, cat_id: int, name: str):
        self.id       = cat_id
        self.name     = name
        self.columns: Dict[str, Any] = {}

    def set(self, col: str, value: Any):
        self.columns[col] = value

    def get(self, col: str, default=None):
        return self.columns.get(col, default)


class StatsSystem:
    """
    Matches DLL stats subsystem.
    Config keys: STATSFILE, STATLIM, STATLOG
    """

    def __init__(self, cfg):
        self.cfg        = cfg
        self._lock      = threading.Lock()
        self._user_stats: Dict[int, Dict[int, StatCategory]] = {}   # uid -> {cat_id -> StatCategory}
        self._player_stats: Dict[str, NFSU2PlayerStats] = {}         # normalized persona -> stats
        self._global: Dict[str, Any] = {}
        self._dirty     = False

        self.stats_file     = cfg.get("STATSFILE", "data/stats.dat")
        self.stats_lim      = _limit_value(cfg.get("STATLIM", 10000), 10000)
        self.stat_refresh   = cfg.get("SERVER_STAT_REFRESH", 60)

        self._load()

    # ------------------------------------------------------------------ #

    def get_user_stat(self, uid: int, cat_id: int) -> StatCategory:
        with self._lock:
            if uid not in self._user_stats:
                if self.stats_lim > 0 and len(self._user_stats) >= self.stats_lim:
                    log.warning("STAT: maximum number of user stats (%d) exceeded.", self.stats_lim)
                    return StatCategory(cat_id, f"Cat{cat_id}")
                self._user_stats[uid] = {}
            if cat_id not in self._user_stats[uid]:
                self._user_stats[uid][cat_id] = StatCategory(cat_id, f"Cat{cat_id}")
            return self._user_stats[uid][cat_id]

    def set_stat(self, uid: int, cat_id: int, col: str, value: Any):
        """stat %s(%s) param %d"""
        cat = self.get_user_stat(uid, cat_id)
        cat.set(col, value)
        with self._lock:
            stored = uid in self._user_stats and cat_id in self._user_stats.get(uid, {})
        if stored:
            self._dirty = True
        log.debug("stat %s(%s) uid=%d = %s", cat.name, col, uid, value)

    def get_stat(self, uid: int, cat_id: int, col: str, default=None):
        cat = self.get_user_stat(uid, cat_id)
        return cat.get(col, default)

    def increment_stat(self, uid: int, cat_id: int, col: str, delta=1):
        cur = self.get_stat(uid, cat_id, col, 0)
        self.set_stat(uid, cat_id, col, cur + delta)

    def get_all_stats(self, uid: int) -> List[dict]:
        with self._lock:
            cats = self._user_stats.get(uid, {})
        result = []
        for cat_id, cat in cats.items():
            for col, val in cat.columns.items():
                result.append({"cat": cat.name, "col": col, "val": val})
        return result

    def set_global(self, key: str, value: Any):
        self._global[key] = value

    def get_global(self, key: str, default=None):
        return self._global.get(key, default)

    # ------------------------------------------------------------------ #
    # NFSU2 lobby player stats                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _norm_persona(persona: str) -> str:
        return str(persona or "").strip().lower()

    def get_player_stats(self, persona: str, create: bool = True) -> Optional[NFSU2PlayerStats]:
        persona = str(persona or "").strip()
        key = self._norm_persona(persona)
        if not key:
            return None
        with self._lock:
            stat = self._player_stats.get(key)
            if stat is None and create:
                if self.stats_lim > 0 and len(self._player_stats) >= self.stats_lim:
                    log.warning("STAT: maximum number of player stats (%d) exceeded.", self.stats_lim)
                    return None
                stat = NFSU2PlayerStats(persona)
                self._player_stats[key] = stat
                self._dirty = True
            elif stat is not None and persona and stat.persona != persona:
                stat.persona = persona
            return stat

    def player_stat_csv(self, persona: str) -> str:
        stat = self.get_player_stats(persona, create=True)
        if stat is None:
            stat = NFSU2PlayerStats(persona or "Player")
        with self._lock:
            self._refresh_ratings_locked()
        return stat.full_hex_csv()

    def profile_stat_csv(self, persona: str) -> str:
        stat = self.get_player_stats(persona, create=True)
        if stat is None:
            stat = NFSU2PlayerStats(persona or "Player")
        with self._lock:
            self._refresh_ratings_locked()
            values = list(stat.values)
        # The captured USER profile frame carries three extra profile/car slots
        # after the 5x7 race stat block.
        values.extend([0, 0, 0])
        return ",".join(f"{max(0, int(value)):x}" for value in values) + ","

    def player_summary(self, persona: str) -> dict:
        stat = self.get_player_stats(persona, create=True)
        if stat is None:
            stat = NFSU2PlayerStats(persona or "Player")
        with self._lock:
            self._refresh_ratings_locked()
            return {
                "rank": stat.get(0, "rating"),
                "wins": stat.get(0, "wins"),
                "losses": stat.get(0, "losses"),
                "disconnects": stat.get(0, "disconnects"),
                "rep": stat.get(0, "rep"),
            }

    def player_personas(self) -> List[str]:
        with self._lock:
            return [stat.persona for stat in self._player_stats.values() if stat.persona]

    def record_player_result(
        self,
        persona: str,
        outcome: str,
        category_index: int = 0,
        opponent_personas: Optional[Iterable[str]] = None,
    ):
        stat = self.get_player_stats(persona, create=True)
        if stat is None:
            return
        norm_persona = self._norm_persona(persona)
        opponent_stats = []
        seen_opponents = set()
        for opponent in opponent_personas or ():
            opponent_key = self._norm_persona(opponent)
            if not opponent_key or opponent_key == norm_persona or opponent_key in seen_opponents:
                continue
            opponent_stat = self.get_player_stats(opponent, create=True)
            if opponent_stat is None:
                continue
            seen_opponents.add(opponent_key)
            opponent_stats.append(opponent_stat)
        with self._lock:
            self._refresh_ratings_locked()
            opponent_avgs = {}
            for cat_idx in {0, max(0, min(4, int(category_index)))}:
                if not opponent_stats:
                    continue
                rep_values = [item.get(cat_idx, "rep") for item in opponent_stats]
                rating_values = [item.get(cat_idx, "rating") for item in opponent_stats]
                if rep_values and rating_values:
                    opponent_avgs[cat_idx] = (
                        int(round(sum(rep_values) / len(rep_values))),
                        int(round(sum(rating_values) / len(rating_values))),
                    )
            stat.bump_result(category_index, outcome)
            for cat_idx, (opps_rep, opps_rating) in opponent_avgs.items():
                stat.set(cat_idx, "opps_rep", opps_rep)
                stat.set(cat_idx, "opps_rating", opps_rating)
            self._refresh_ratings_locked()
            self._dirty = True

    def _refresh_ratings_locked(self):
        stats = list(self._player_stats.values())
        for cat_idx in range(len(NFSU2_STAT_CATEGORIES)):
            stats.sort(
                key=lambda item: (
                    -item.get(cat_idx, "rep"),
                    item.get(cat_idx, "losses"),
                    item.persona.lower(),
                )
            )
            for rank, stat in enumerate(stats, 1):
                stat.set(cat_idx, "rating", rank)

    def nfsu2_leaderboard(
        self,
        index: int,
        *,
        start: int = 0,
        limit: int = 100,
        include_personas: Iterable[str] = (),
    ) -> List[tuple[int, NFSU2PlayerStats]]:
        try:
            index = int(index)
        except Exception:
            index = 1
        if index < 1 or index > 5:
            return []
        cat_idx = index - 1
        for persona in include_personas or ():
            self.get_player_stats(str(persona or "").strip(), create=True)
        with self._lock:
            self._refresh_ratings_locked()
            stats = list(self._player_stats.values())
        stats.sort(
            key=lambda item: (
                -item.get(cat_idx, "rep"),
                item.get(cat_idx, "losses"),
                item.persona.lower(),
            )
        )
        try:
            start = int(start)
        except Exception:
            start = 0
        try:
            limit = int(limit)
        except Exception:
            limit = 100
        offset = max(0, start - 1 if start > 0 else 0)
        limit = max(1, min(100, limit))
        return [(rank, stat) for rank, stat in enumerate(stats, 1)][offset : offset + limit]

    # ------------------------------------------------------------------ #
    # Persistence                                                          #
    # ------------------------------------------------------------------ #

    def _load(self):
        path = self.stats_file
        if not os.path.exists(path):
            return
        log.info("Loading stats configuration from '%s'", path)
        try:
            with open(path, "r") as f:
                data = json.load(f)
            for uid_str, cats in data.get("user_stats", {}).items():
                if self.stats_lim > 0 and len(self._user_stats) >= self.stats_lim:
                    log.warning("Stats load capped at STATLIM=%d for user stats; remaining entries ignored.", self.stats_lim)
                    break
                uid = int(uid_str)
                self._user_stats[uid] = {}
                for cat_id_str, cat_data in cats.items():
                    cat_id = int(cat_id_str)
                    cat = StatCategory(cat_id, cat_data.get("name", f"Cat{cat_id}"))
                    cat.columns = cat_data.get("columns", {})
                    self._user_stats[uid][cat_id] = cat
            for persona, stat_data in data.get("player_stats", {}).items():
                if self.stats_lim > 0 and len(self._player_stats) >= self.stats_lim:
                    log.warning("Stats load capped at STATLIM=%d for player stats; remaining entries ignored.", self.stats_lim)
                    break
                if isinstance(stat_data, dict):
                    stat_persona = stat_data.get("persona", persona)
                    values = stat_data.get("values", [])
                else:
                    stat_persona = persona
                    values = stat_data
                stat = NFSU2PlayerStats(stat_persona, values)
                key = self._norm_persona(stat.persona)
                if key:
                    self._player_stats[key] = stat
            self._global = data.get("global", {})
            log.info("Loaded stats configuration from '%s'", path)
        except Exception as ex:
            log.error("Loading stats configuration from '%s' failed: %s", path, ex)

    def save(self, force: bool = False):
        if not self._dirty and not force:
            return
        path = self.stats_file
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        try:
            data = {
                "global": self._global,
                "user_stats": {
                    str(uid): {
                        str(cat_id): {"name": cat.name, "columns": cat.columns}
                        for cat_id, cat in cats.items()
                    }
                    for uid, cats in self._user_stats.items()
                },
                "player_stats": {
                    stat.persona: stat.to_dict()
                    for stat in self._player_stats.values()
                },
            }
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            self._dirty = False
            log.info("Stats saved to '%s'", path)
        except Exception as ex:
            log.error("Failed to save stats: %s", ex)
