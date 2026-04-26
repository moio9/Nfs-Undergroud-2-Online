"""
ea_messenger.py - EA Messenger control/social TCP listeners.
"""

import json
import logging
import os
import socket
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

from control_handler import ControlHandler

log = logging.getLogger("server")


class EAMessengerServer:
    def __init__(self, server):
        self.srv = server
        self._control_sock: Optional[socket.socket] = None
        self._control_alias_sock: Optional[socket.socket] = None
        self._control_thread: Optional[threading.Thread] = None
        self._control_alias_thread: Optional[threading.Thread] = None
        self._control_profile = {
            "name": "",
            "persona": "",
            "client_addr": "",
        }
        self._control_profile_events: List[dict] = []
        self._control_profile_lock = threading.Lock()
        self._social_lock = threading.Lock()
        self._social_handlers: Dict[str, Set[object]] = {}
        self._social_handler_user: Dict[object, str] = {}
        self._social_display: Dict[str, str] = {}
        self._social_presence: Dict[str, dict] = {}
        self._social_buddies: Dict[str, Set[str]] = {}
        self._social_pending: Dict[str, Set[str]] = {}
        self._social_blocks: Dict[str, Set[str]] = {}
        self._social_reports: List[dict] = []

    @staticmethod
    def _bind_tcp(host: str, port: int, backlog: int = 32) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(backlog)
        sock.settimeout(1.0)
        return sock

    def start(
        self,
        *,
        control_host: str,
        control_port: int,
        alias_host: str,
        alias_port: int,
    ) -> None:
        if control_port > 0:
            try:
                self._control_sock = self._bind_tcp(control_host, control_port)
                log.info(
                    "Control server is setup (listening on %s:%d, public %s:%d)",
                    control_host,
                    control_port,
                    self.srv.control_host(),
                    self.srv.control_port(),
                )
            except OSError as exc:
                self.stop()
                raise OSError(f"Control server port ({control_port}) incorrect: {exc}") from exc

        if alias_port > 0 and alias_port != control_port:
            try:
                self._control_alias_sock = self._bind_tcp(alias_host, alias_port)
                log.info(
                    "Control alias server is setup (listening on %s:%d, public %s:%d)",
                    alias_host,
                    alias_port,
                    self.srv.control_alias_host(),
                    self.srv.control_alias_port(),
                )
            except OSError as exc:
                self.stop()
                raise OSError(f"Control alias server port ({alias_port}) incorrect: {exc}") from exc

    def start_threads(self) -> None:
        if self._control_sock:
            self._control_thread = threading.Thread(
                target=self._accept_loop,
                args=(self._control_sock, "Control"),
                name="ControlAcceptLoop",
                daemon=True,
            )
            self._control_thread.start()
        if self._control_alias_sock:
            self._control_alias_thread = threading.Thread(
                target=self._accept_loop,
                args=(self._control_alias_sock, "ControlAlias"),
                name="ControlAliasAcceptLoop",
                daemon=True,
            )
            self._control_alias_thread.start()

    def stop(self) -> None:
        for attr in ("_control_sock", "_control_alias_sock"):
            sock = getattr(self, attr)
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
                setattr(self, attr, None)

    def join(self, timeout: float = 3.0) -> None:
        for thread in (self._control_thread, self._control_alias_thread):
            if thread:
                thread.join(timeout=timeout)

    def format_admin_social(self, target: str = "") -> str:
        target_key = self._social_key(target)
        users = sorted(self.srv.users.all_users(), key=lambda user: int(user.uid))
        with self._control_profile_lock:
            profile = dict(self._control_profile)
            profile_events = list(self._control_profile_events[-8:])
        with self._social_lock:
            display = dict(self._social_display)
            handler_rows = []
            for key, handlers in self._social_handlers.items():
                if target_key and target_key != key:
                    continue
                for handler in handlers:
                    handler_rows.append(
                        {
                            "key": key,
                            "user": display.get(key, key),
                            "addr": f"{getattr(handler, 'peer_ip', '-')}:"
                                    f"{int(getattr(handler, 'peer_port', 0) or 0)}",
                            "boot": bool(getattr(handler, "_session_bootstrapped", False)),
                            "peer_user": str(getattr(handler, "_peer_user", "") or ""),
                        }
                    )
            presence = {
                key: dict(value)
                for key, value in self._social_presence.items()
                if not target_key or target_key == key
            }
            buddies = {
                key: set(value)
                for key, value in self._social_buddies.items()
                if not target_key or target_key == key or target_key in value
            }
            pending = {
                key: set(value)
                for key, value in self._social_pending.items()
                if not target_key or target_key == key or target_key in value
            }
            blocks = {
                key: set(value)
                for key, value in self._social_blocks.items()
                if not target_key or target_key == key or target_key in value
            }

        def display_name(key: str) -> str:
            return display.get(key, key)

        def relation_lines(label: str, rel: Dict[str, Set[str]]) -> List[str]:
            out = []
            for owner in sorted(rel):
                targets = sorted(key for key in rel[owner] if key)
                if not targets:
                    continue
                out.append(
                    f"{label} {display_name(owner)} -> "
                    + ", ".join(display_name(key) for key in targets)
                )
            return out

        lines = [
            "Social",
            f"enabled={'yes' if self._social_cfg_enabled() else 'no'} "
            f"all_online={'yes' if self.srv._cfg_flag('CONTROL_SOCIAL_ALL_ONLINE_ENABLE') else 'no'} "
            f"file={self._social_relations_file_path()}",
            f"last_profile name={profile.get('name') or '-'} "
            f"persona={profile.get('persona') or '-'} addr={profile.get('client_addr') or '-'}",
        ]
        if profile_events:
            recent = []
            now = time.time()
            for event in reversed(profile_events):
                age = max(0, int(now - float(event.get("time", 0.0) or now)))
                recent.append(
                    f"{event.get('persona') or event.get('name') or '-'}"
                    f"@{event.get('client_addr') or '-'}:{age}s"
                )
            lines.append("recent_profiles " + "; ".join(recent))

        lines.append("handlers:")
        if handler_rows:
            for row in sorted(handler_rows, key=lambda item: (item["key"], item["addr"])):
                all_rows = self.control_social_snapshot(row["user"], "ALL")
                buddy_rows = self.control_social_snapshot(row["user"], "B")
                all_names = ", ".join(str(item.get("user") or "-") for item in all_rows) or "-"
                buddy_names = ", ".join(
                    (
                        f"{item.get('user')}(req)"
                        if str(item.get("attr") or "") == "R"
                        else str(item.get("user") or "-")
                    )
                    for item in buddy_rows
                ) or "-"
                lines.append(
                    f"  {row['user']} key={row['key']} addr={row['addr']} "
                    f"boot={'yes' if row['boot'] else 'no'} peer={row['peer_user'] or '-'} "
                    f"ALL=[{all_names}] B=[{buddy_names}]"
                )
        else:
            lines.append("  none")

        lines.append("lobby_users:")
        lobby_count = 0
        for user in users:
            persona = str(getattr(user, "pers", "") or getattr(user, "name", "") or "").strip()
            user_key = self._social_key(persona)
            if target_key and target_key not in {user_key, self._social_key(getattr(user, "name", ""))}:
                continue
            lobby_count += 1
            lines.append(
                f"  uid={int(user.uid)} name={user.name or '-'} pers={persona or '-'} "
                f"conn={'yes' if user.connected else 'no'} stat={user.stat or '-'} "
                f"addr={user.ip or '-'}:{int(user.port or 0)}"
            )
        if lobby_count == 0:
            lines.append("  none")

        lines.append("presence:")
        if presence:
            for key in sorted(presence):
                row = presence[key]
                lines.append(
                    f"  {display_name(key)} addr={row.get('addr') or '-'} "
                    f"show={row.get('show') or '-'} updated={int(time.time() - float(row.get('updated', time.time()) or time.time()))}s"
                )
        else:
            lines.append("  none")

        relation_output = (
            relation_lines("buddy", buddies)
            + relation_lines("pending", pending)
            + relation_lines("block", blocks)
        )
        lines.append("relations:")
        if relation_output:
            lines.extend(f"  {line}" for line in relation_output)
        else:
            lines.append("  none")
        return "\n".join(lines)

    def remember_control_profile(
        self,
        *,
        name: str = "",
        persona: str = "",
        client_addr: str = "",
    ):
        now = time.time()
        with self._control_profile_lock:
            if name:
                self._control_profile["name"] = name
            if persona:
                self._control_profile["persona"] = persona
            if client_addr:
                self._control_profile["client_addr"] = client_addr
            event = {
                "name": str(name or self._control_profile.get("name", "") or "").strip(),
                "persona": str(persona or self._control_profile.get("persona", "") or "").strip(),
                "client_addr": str(client_addr or self._control_profile.get("client_addr", "") or "").strip(),
                "time": now,
            }
            if event["name"] or event["persona"]:
                self._control_profile_events.append(event)
                cutoff = now - 90.0
                self._control_profile_events = self._control_profile_events[-32:]
                self._control_profile_events = [
                    item for item in self._control_profile_events
                    if float(item.get("time", 0.0) or 0.0) >= cutoff
                ]

    def get_control_profile(self, client_addr: str = "") -> dict:
        now = time.time()
        with self._control_profile_lock:
            profile = dict(self._control_profile)
            profile_events = list(self._control_profile_events)
        peer_ip = str(client_addr or "").strip()
        if not peer_ip:
            return profile
        with self._social_lock:
            used = set(self._social_handler_user.values())

        def profile_from_event(event: dict) -> Optional[dict]:
            persona = str(event.get("persona", "") or event.get("name", "") or "").strip()
            event_addr = str(event.get("client_addr", "") or "").strip()
            if not persona or self._social_key(persona) in used:
                return None
            if event_addr and event_addr != peer_ip:
                return None
            return {
                "name": str(event.get("name", "") or ""),
                "persona": persona,
                "client_addr": peer_ip,
            }

        try:
            candidates = [
                user
                for user in self.srv.users.all_users()
                if bool(getattr(user, "connected", False))
                and peer_ip
                in {
                    str(getattr(user, "ip", "") or "").strip(),
                    str(getattr(user, "addr", "") or "").strip(),
                    str(getattr(user, "laddr", "") or "").strip(),
                }
            ]
        except Exception:
            candidates = []
        recent_events = [
            event for event in profile_events
            if now - float(event.get("time", 0.0) or 0.0) <= 90.0
        ]
        for event in reversed(recent_events):
            selected = profile_from_event(event)
            if selected is not None:
                log.info(
                    "CONTROL profile peer=%s selected=%s source=recent candidates=%d used=%d",
                    peer_ip,
                    selected.get("persona") or "-",
                    len(candidates),
                    len(used),
                )
                return selected

        candidates.sort(key=lambda user: int(getattr(user, "uid", 0) or 0))
        for user in candidates:
            persona = str(getattr(user, "pers", "") or getattr(user, "name", "") or "").strip()
            if persona and self._social_key(persona) not in used:
                selected = {
                    "name": str(getattr(user, "name", "") or ""),
                    "persona": persona,
                    "client_addr": peer_ip,
                }
                log.info(
                    "CONTROL profile peer=%s selected=%s source=lobby candidates=%d used=%d",
                    peer_ip,
                    persona,
                    len(candidates),
                    len(used),
                )
                return selected

        fallback_persona = str(profile.get("persona", "") or profile.get("name", "") or "").strip()
        if fallback_persona and self._social_key(fallback_persona) not in used:
            return {
                "name": str(profile.get("name", "") or ""),
                "persona": fallback_persona,
                "client_addr": peer_ip,
            }
        log.info(
            "CONTROL profile peer=%s selected=- source=none candidates=%d used=%d fallback=%s",
            peer_ip,
            len(candidates),
            len(used),
            fallback_persona or "-",
        )
        return {"name": "", "persona": "", "client_addr": peer_ip}

    def _social_relations_file_path(self) -> str:
        path = str(self.srv.cfg.get("CONTROL_SOCIAL_FILE", "data/social_relations.json") or "data/social_relations.json").strip()
        if os.path.isabs(path):
            return path
        return os.path.abspath(os.path.join(os.path.dirname(self.srv._config_path), path))

    @staticmethod
    def _social_raw_text(value: str) -> str:
        text = str(value or "").strip()
        if "/" in text and not text.startswith("/"):
            text = text.split("/", 1)[0].strip()
        return text

    def _social_canonical_name(self, value: str) -> str:
        text = self._social_raw_text(value)
        norm = text.lower()
        if not norm:
            return ""

        try:
            active_users = self.srv.users.all_users()
        except Exception:
            active_users = []
        for user in active_users:
            aliases = []
            for candidate in (
                getattr(user, "pers", ""),
                getattr(user, "name", ""),
            ):
                candidate_text = self._social_raw_text(candidate)
                if candidate_text:
                    aliases.append(candidate_text)
            if norm in {alias.lower() for alias in aliases}:
                for preferred in aliases:
                    if preferred:
                        return preferred

        try:
            accounts = self.srv._load_lan_auth_accounts()
        except Exception:
            accounts = []
        for account in accounts:
            aliases = set()
            for candidate in (
                account.get("display_name"),
                account.get("name"),
                account.get("email"),
            ):
                candidate_text = self._social_raw_text(candidate)
                if candidate_text:
                    aliases.add(candidate_text)
            for key in ("personas", "persona", "pers", "aliases", "names", "emails", "usernames", "logins"):
                for candidate in self.srv._lan_auth_list(account.get(key)):
                    candidate_text = self._social_raw_text(candidate)
                    if candidate_text:
                        aliases.add(candidate_text)
            if norm not in {alias.lower() for alias in aliases}:
                continue
            for key in ("personas", "persona", "pers", "display_name", "name", "email"):
                for candidate in self.srv._lan_auth_list(account.get(key)):
                    candidate_text = self._social_raw_text(candidate)
                    if candidate_text:
                        return candidate_text
            return text

        return text

    def _social_key(self, value: str) -> str:
        return self._social_canonical_name(value).lower()

    def _social_display_name(self, value: str) -> str:
        canonical = self._social_canonical_name(value)
        if canonical:
            return canonical
        return self._social_raw_text(value)

    def control_social_same_identity(self, lhs: str, rhs: str) -> bool:
        left_key = self._social_key(lhs)
        right_key = self._social_key(rhs)
        return bool(left_key and right_key and left_key == right_key)

    def _social_cfg_enabled(self) -> bool:
        return self.srv._cfg_flag("CONTROL_SOCIAL_ENABLE")

    def _social_outgoing_request_attr(self) -> str:
        attr = str(self.srv.cfg.get("CONTROL_SOCIAL_OUTGOING_REQUEST_ATTR", "P") or "P").strip().upper()
        return attr[:1] or "P"

    @staticmethod
    def _social_presence_lines(row: dict) -> List[str]:
        presence = row.get("presence", {}) if isinstance(row.get("presence"), dict) else {}
        user = str(row.get("user", "") or "")
        show = "AWAY" if not row.get("online") else (presence.get("show") or "PASS")
        lines = [
            "EXTR=NFS-CONSOLE-2005",
            f"STAT={presence.get('stat') or 'EX%3d0%0aP%3dnfs5%0a'}",
            f"PROD={presence.get('prod') or 'is playing Underground 2'}",
            f"TITL={presence.get('title') or 'Need for Speed Underground 2 [PC]'}",
            f"SHOW={show}",
            f"USER={user}",
        ]
        attr = str(row.get("attr") or "")
        if attr:
            lines.append(f"ATTR={attr}")
        elif not bool(row.get("friend", False)):
            lines.append("ATTR=D")
        return lines

    def _social_visible_row_locked(self, owner_key: str, user_key: str) -> Optional[dict]:
        if not owner_key or not user_key or owner_key == user_key:
            return None
        if (
            user_key in self._social_blocks.get(owner_key, set())
            or owner_key in self._social_blocks.get(user_key, set())
        ):
            return None
        is_buddy = user_key in self._social_buddies.get(owner_key, set())
        if not is_buddy and not self.srv._cfg_flag("CONTROL_SOCIAL_ALL_ONLINE_ENABLE"):
            return None
        presence = dict(self._social_presence.get(user_key, {}))
        return {
            "user": self._social_display.get(user_key, presence.get("user", user_key)),
            "attr": "" if is_buddy else "D",
            "online": user_key in self._social_handlers,
            "presence": presence,
            "friend": is_buddy,
        }

    def _social_presence_row_locked(self, owner_key: str, user_key: str) -> Optional[dict]:
        if not owner_key or not user_key or owner_key == user_key:
            return None
        if (
            user_key in self._social_blocks.get(owner_key, set())
            or owner_key in self._social_blocks.get(user_key, set())
        ):
            return None
        is_buddy = user_key in self._social_buddies.get(owner_key, set())
        presence = dict(self._social_presence.get(user_key, {}))
        return {
            "user": self._social_display.get(user_key, presence.get("user", user_key)),
            "attr": "" if is_buddy else "D",
            "online": user_key in self._social_handlers,
            "presence": presence,
            "friend": is_buddy,
        }

    def _social_notify_targets_locked(self, user_key: str) -> List[Tuple[object, dict]]:
        out: List[Tuple[object, dict]] = []
        for owner_key, handlers in self._social_handlers.items():
            row = self._social_visible_row_locked(owner_key, user_key)
            if row is None:
                continue
            row = dict(row)
            row["_user_key"] = user_key
            for handler in handlers:
                out.append((handler, row))
        return out

    def _social_active_user_for_key(self, key: str):
        wanted = self._social_key(key)
        if not wanted:
            return None
        for user in self.srv.users.all_users():
            if wanted in {
                self._social_key(getattr(user, "name", "")),
                self._social_key(getattr(user, "pers", "")),
            }:
                return user
        return None

    def _social_same_game_presence_suppressed(self, handler: object, row: dict) -> bool:
        if bool(row.get("friend", False)):
            return False
        owner_key = ""
        with self._social_lock:
            owner_key = str(self._social_handler_user.get(handler, "") or "")
        target_key = str(row.get("_user_key", "") or "")
        if not owner_key or not target_key or owner_key == target_key:
            return False
        owner_user = self._social_active_user_for_key(owner_key)
        target_user = self._social_active_user_for_key(target_key)
        if owner_user is None or target_user is None:
            return False
        owner_game = int(getattr(owner_user, "game", 0) or 0)
        target_game = int(getattr(target_user, "game", 0) or 0)
        return owner_game > 0 and owner_game == target_game

    def _social_send_presence_notifications(self, targets: List[Tuple[object, dict]], *, online: bool) -> None:
        if not targets:
            return
        change = "A" if online else "D"
        for handler, row in targets:
            if online and self._social_same_game_presence_suppressed(handler, row):
                continue
            send = getattr(handler, "_send_message", None)
            if not callable(send):
                continue
            user = str(row.get("user", "") or "")
            attr = str(row.get("attr", "") or "")
            try:
                if not online and bool(row.get("friend", False)):
                    send("RNOT", [f"CHNG=A", f"USER={user}"])
                    send("ROST", ["ID=-1", f"USER={user}"])
                    continue
                notify_lines = [f"CHNG={change}", f"USER={user}"]
                if attr:
                    notify_lines.append(f"ATTR={attr}")
                elif not bool(row.get("friend", False)):
                    notify_lines.append("ATTR=D")
                send("RNOT", notify_lines)
                if online:
                    roster_lines = ["ID=-1", f"USER={user}"]
                    if attr:
                        roster_lines.append(f"ATTR={attr}")
                    elif not bool(row.get("friend", False)):
                        roster_lines.append("ATTR=D")
                    send("ROST", roster_lines)
                send("PGET", self._social_presence_lines({**row, "online": online}))
            except Exception:
                continue

    def _social_relation_payload_locked(self) -> dict:
        buddies = {
            owner: sorted(target for target in targets if target and target != owner)
            for owner, targets in self._social_buddies.items()
            if owner and any(target and target != owner for target in targets)
        }
        pending = {
            owner: sorted(target for target in targets if target and target != owner)
            for owner, targets in self._social_pending.items()
            if owner and any(target and target != owner for target in targets)
        }
        blocks = {
            owner: sorted(target for target in targets if target and target != owner)
            for owner, targets in self._social_blocks.items()
            if owner and any(target and target != owner for target in targets)
        }
        related_keys = set(buddies.keys()) | set(pending.keys()) | set(blocks.keys())
        for targets in buddies.values():
            related_keys.update(targets)
        for targets in pending.values():
            related_keys.update(targets)
        for targets in blocks.values():
            related_keys.update(targets)
        display = {
            key: value
            for key, value in self._social_display.items()
            if key in related_keys and str(value or "").strip()
        }
        return {
            "version": 1,
            "display": display,
            "buddies": buddies,
            "pending": pending,
            "blocks": blocks,
            "saved_at": time.time(),
        }

    def save_social_relations(self) -> None:
        if not self._social_cfg_enabled():
            return
        path = self._social_relations_file_path()
        try:
            with self._social_lock:
                payload = self._social_relation_payload_locked()
            os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
        except Exception as exc:
            log.warning("Failed to save social relations to '%s': %s", path, exc)

    def load_social_relations(self) -> None:
        path = self._social_relations_file_path()
        with self._social_lock:
            self._social_buddies.clear()
            self._social_pending.clear()
            self._social_blocks.clear()
            self._social_display.clear()
        if not self._social_cfg_enabled() or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            raw_display = data.get("display", {}) if isinstance(data, dict) else {}
            raw_buddies = data.get("buddies", {}) if isinstance(data, dict) else {}
            raw_pending = data.get("pending", {}) if isinstance(data, dict) else {}
            raw_blocks = data.get("blocks", {}) if isinstance(data, dict) else {}

            display: Dict[str, str] = {}
            if isinstance(raw_display, dict):
                for key, value in raw_display.items():
                    norm = self._social_key(key)
                    text = str(value or "").strip()
                    if norm and text:
                        display[norm] = text

            def load_relation_map(raw) -> Dict[str, Set[str]]:
                out: Dict[str, Set[str]] = {}
                if not isinstance(raw, dict):
                    return out
                for owner, targets in raw.items():
                    owner_key = self._social_key(owner)
                    if not owner_key:
                        continue
                    if isinstance(targets, (list, tuple, set)):
                        values = targets
                    else:
                        values = [targets]
                    clean = {
                        self._social_key(target)
                        for target in values
                        if self._social_key(target) and self._social_key(target) != owner_key
                    }
                    if clean:
                        out[owner_key] = clean
                return out

            buddies = load_relation_map(raw_buddies)
            pending = load_relation_map(raw_pending)
            blocks = load_relation_map(raw_blocks)
            with self._social_lock:
                self._social_display.update(display)
                self._social_buddies.update(buddies)
                self._social_pending.update(pending)
                self._social_blocks.update(blocks)
            log.info(
                "Loaded social relations from '%s' (buddies=%d pending=%d blocks=%d)",
                path,
                sum(len(v) for v in buddies.values()),
                sum(len(v) for v in pending.values()),
                sum(len(v) for v in blocks.values()),
            )
        except Exception as exc:
            log.warning("Failed to load social relations from '%s': %s", path, exc)

    def control_social_register(self, handler: object, persona: str, *, addr: str = "") -> str:
        display = str(persona or "").strip()
        key = self._social_key(display)
        if not self._social_cfg_enabled() or not key:
            return ""
        notify_targets: List[Tuple[object, dict]] = []
        with self._social_lock:
            old_key = self._social_handler_user.get(handler, "")
            if old_key and old_key != key:
                old_handlers = self._social_handlers.get(old_key)
                if old_handlers is not None:
                    old_handlers.discard(handler)
                    if not old_handlers:
                        self._social_handlers.pop(old_key, None)
                        self._social_presence.pop(old_key, None)
            was_offline = key not in self._social_handlers or not self._social_handlers.get(key)
            self._social_handler_user[handler] = key
            self._social_handlers.setdefault(key, set()).add(handler)
            self._social_display[key] = display
            presence = self._social_presence.setdefault(key, {})
            presence.update(
                {
                    "user": display,
                    "addr": addr,
                    "show": presence.get("show", "PASS"),
                    "stat": presence.get("stat", "EX%3d0%0aP%3dnfs5%0a"),
                    "prod": presence.get("prod", "is playing Underground 2"),
                    "title": presence.get("title", "Need for Speed Underground 2 [PC]"),
                    "updated": time.time(),
                }
            )
            if was_offline:
                notify_targets = self._social_notify_targets_locked(key)
            handler_count = len(self._social_handlers.get(key, set()))
        log.info(
            "CONTROL social-register persona=%s addr=%s handlers=%d was_offline=%s",
            display,
            addr or "-",
            handler_count,
            "yes" if was_offline else "no",
        )
        self._social_send_presence_notifications(notify_targets, online=True)
        return display

    def control_social_unregister(self, handler: object) -> None:
        notify_targets: List[Tuple[object, dict]] = []
        with self._social_lock:
            key = self._social_handler_user.pop(handler, "")
            if not key:
                return
            handlers = self._social_handlers.get(key)
            if handlers is not None:
                handlers.discard(handler)
                if not handlers:
                    notify_targets = self._social_notify_targets_locked(key)
                    self._social_handlers.pop(key, None)
                    self._social_presence.pop(key, None)
        self._social_send_presence_notifications(notify_targets, online=False)

    def control_social_update_presence(
        self,
        handler: object,
        *,
        show: str = "",
        stat: str = "",
        prod: str = "",
        title: str = "",
    ) -> None:
        notify_targets: List[Tuple[object, dict]] = []
        with self._social_lock:
            key = self._social_handler_user.get(handler, "")
            if not key:
                return
            presence = self._social_presence.setdefault(key, {})
            if show:
                presence["show"] = show
            if stat:
                presence["stat"] = stat
            if prod:
                presence["prod"] = prod
            if title:
                presence["title"] = title
            presence["updated"] = time.time()
            notify_targets = self._social_notify_targets_locked(key)
        self._social_send_presence_notifications(notify_targets, online=True)

    def control_social_snapshot(self, owner: str, list_tag: str = "B") -> List[dict]:
        owner_key = self._social_key(owner)
        tag = str(list_tag or "B").strip().upper()
        rows: List[dict] = []
        with self._social_lock:
            if tag == "I":
                for key in sorted(k for k in self._social_blocks.get(owner_key, set()) if k and k != owner_key):
                    rows.append(
                        {
                            "user": self._social_display.get(key, key),
                            "attr": "B",
                            "online": key in self._social_handlers,
                        }
                    )
                return rows

            buddies = set(self._social_buddies.get(owner_key, set()))
            incoming = {
                sender
                for sender, targets in self._social_pending.items()
                if owner_key in targets and sender and sender != owner_key
            }
            if tag in ("A", "ALL", "O", "ONLINE", "U", "USERS"):
                wanted = set(buddies)
                wanted.update(self._social_handlers.keys())
            else:
                wanted = set(buddies)
                wanted.update(incoming)
            wanted.discard(owner_key)
            wanted.difference_update(self._social_blocks.get(owner_key, set()))
            for key in sorted(k for k in wanted if k and k != owner_key):
                presence = dict(self._social_presence.get(key, {}))
                is_buddy = key in buddies
                is_request = key in incoming and not is_buddy
                attr = "R" if is_request else ("" if is_buddy else "D")
                rows.append(
                    {
                        "user": self._social_display.get(key, presence.get("user", key)),
                        "attr": attr,
                        "online": key in self._social_handlers,
                        "presence": presence,
                        "friend": is_buddy,
                        "request": is_request,
                    }
                )
        return rows

    def control_social_search_users(self, owner: str, query: str = "", limit: int = 20) -> List[dict]:
        owner_key = self._social_key(owner)
        query_norm = str(query or "").strip().lower()
        try:
            max_results = max(1, min(100, int(limit or 20)))
        except Exception:
            max_results = 20

        candidates: Dict[str, str] = {}

        def add_candidate(name: str) -> None:
            display = self._social_display_name(name)
            key = self._social_key(display)
            if not key or key == owner_key:
                return
            if query_norm and query_norm not in display.lower():
                return
            candidates.setdefault(key, display)

        with self._social_lock:
            display_names = dict(self._social_display)
            online_keys = set(self._social_handlers.keys())
            presence_rows = {key: dict(value) for key, value in self._social_presence.items()}
            buddies = {key: set(value) for key, value in self._social_buddies.items()}
            pending = {key: set(value) for key, value in self._social_pending.items()}
            blocks = {key: set(value) for key, value in self._social_blocks.items()}

        for key, display in display_names.items():
            add_candidate(display or key)
        for key, presence in presence_rows.items():
            add_candidate(str(presence.get("user") or display_names.get(key) or key))
        for key in online_keys:
            add_candidate(display_names.get(key, key))
        for rel_map in (buddies, pending, blocks):
            for key, values in rel_map.items():
                add_candidate(display_names.get(key, key))
                for value in values:
                    add_candidate(display_names.get(value, value))

        for account in self.srv._load_lan_auth_accounts():
            persona_values: List[str] = []
            for key in ("personas", "persona", "pers", "display_name", "display"):
                persona_values.extend(self.srv._lan_auth_list(account.get(key)))
            if not persona_values:
                for key in ("name", "username", "user"):
                    persona_values.extend(self.srv._lan_auth_list(account.get(key)))
            for value in persona_values:
                add_candidate(value)

        try:
            for persona in self.srv.stats.player_personas():
                add_candidate(persona)
        except Exception:
            pass

        try:
            active_users = self.srv.users.all_users()
        except Exception:
            active_users = []
        for user in active_users:
            add_candidate(str(getattr(user, "pers", "") or getattr(user, "name", "") or ""))

        blocked = set(blocks.get(owner_key, set()))
        blocked.update(key for key, values in blocks.items() if owner_key in values)
        rows = []
        for key in sorted(candidates, key=lambda item: candidates[item].lower()):
            if key in blocked:
                continue
            rows.append({"user": candidates[key], "online": key in online_keys})
            if len(rows) >= max_results:
                break
        return rows

    def control_social_presence_row(self, owner: str, target: str) -> Optional[dict]:
        owner_key = self._social_key(owner)
        target_key = self._social_key(target)
        if not owner_key or not target_key:
            return None
        with self._social_lock:
            row = self._social_presence_row_locked(owner_key, target_key)
            if row is None:
                return None
            return dict(row)

    def control_social_roster_row(self, owner: str, target: str, list_tag: str = "B") -> Optional[dict]:
        target_key = self._social_key(target)
        if not target_key:
            return None
        for row in self.control_social_snapshot(owner, list_tag):
            if self._social_key(str(row.get("user", "") or "")) == target_key:
                return dict(row)
        return None

    def control_social_add_relation(self, owner: str, target: str, list_tag: str) -> str:
        owner_key = self._social_key(owner)
        target_display = self._social_display_name(target)
        target_key = self._social_key(target_display)
        if not owner_key or not target_key or owner_key == target_key:
            return "N"
        tag = str(list_tag or "B").strip().upper()
        with self._social_lock:
            self._social_display.setdefault(target_key, target_display)
            if tag == "I":
                self._social_blocks.setdefault(owner_key, set()).add(target_key)
                self._social_buddies.get(owner_key, set()).discard(target_key)
                self._social_buddies.get(target_key, set()).discard(owner_key)
                self._social_pending.get(owner_key, set()).discard(target_key)
                self._social_pending.get(target_key, set()).discard(owner_key)
                attr = "B"
            else:
                if owner_key in self._social_pending.get(target_key, set()):
                    self._social_pending.get(target_key, set()).discard(owner_key)
                    self._social_pending.get(owner_key, set()).discard(target_key)
                    self._social_buddies.setdefault(owner_key, set()).add(target_key)
                    self._social_buddies.setdefault(target_key, set()).add(owner_key)
                    attr = ""
                elif target_key in self._social_buddies.get(owner_key, set()):
                    attr = ""
                else:
                    self._social_pending.setdefault(owner_key, set()).add(target_key)
                    attr = "R"
        self.save_social_relations()
        return attr

    def control_social_remove_relation(self, owner: str, target: str, list_tag: str) -> str:
        owner_key = self._social_key(owner)
        target_key = self._social_key(target)
        if not owner_key or not target_key or owner_key == target_key:
            return "N"
        tag = str(list_tag or "B").strip().upper()
        changed = False
        with self._social_lock:
            if tag == "I":
                targets = self._social_blocks.get(owner_key)
                if targets is not None and target_key in targets:
                    targets.discard(target_key)
                    changed = True
                    if not targets:
                        self._social_blocks.pop(owner_key, None)
                attr = "B"
            else:
                targets = self._social_buddies.get(owner_key)
                if targets is not None and target_key in targets:
                    targets.discard(target_key)
                    changed = True
                    if not targets:
                        self._social_buddies.pop(owner_key, None)
                targets = self._social_buddies.get(target_key)
                if targets is not None and owner_key in targets:
                    targets.discard(owner_key)
                    changed = True
                    if not targets:
                        self._social_buddies.pop(target_key, None)
                targets = self._social_pending.get(owner_key)
                if targets is not None and target_key in targets:
                    targets.discard(target_key)
                    changed = True
                    if not targets:
                        self._social_pending.pop(owner_key, None)
                targets = self._social_pending.get(target_key)
                if targets is not None and owner_key in targets:
                    targets.discard(owner_key)
                    changed = True
                    if not targets:
                        self._social_pending.pop(target_key, None)
                attr = ""
        if changed:
            self.save_social_relations()
            return attr
        return "N"

    def control_social_is_blocked(self, sender: str, target: str) -> bool:
        sender_key = self._social_key(sender)
        target_key = self._social_key(target)
        if not sender_key or not target_key:
            return False
        with self._social_lock:
            return (
                target_key in self._social_blocks.get(sender_key, set())
                or sender_key in self._social_blocks.get(target_key, set())
            )

    def control_social_report(self, reporter: str, target: str, reason: str) -> None:
        with self._social_lock:
            self._social_reports.append(
                {
                    "time": time.time(),
                    "reporter": str(reporter or ""),
                    "target": str(target or ""),
                    "reason": str(reason or ""),
                }
            )
            del self._social_reports[:-128]

    def control_social_deliver(self, target: str, verb: str, lines: List[str]) -> int:
        target_key = self._social_key(target)
        if not self._social_cfg_enabled() or not target_key:
            return 0
        with self._social_lock:
            handlers = list(self._social_handlers.get(target_key, set()))
        delivered = 0
        for handler in handlers:
            send = getattr(handler, "_send_message", None)
            if callable(send) and send(verb, lines):
                delivered += 1
        return delivered

    def _accept_loop(self, listen_sock: socket.socket, prefix: str) -> None:
        while self.srv.is_running:
            try:
                conn, addr = listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            handler = ControlHandler(self.srv, conn, addr)
            thread = threading.Thread(
                target=handler.run,
                name=f"{prefix}-{addr[0]}:{addr[1]}",
                daemon=True,
            )
            thread.start()
