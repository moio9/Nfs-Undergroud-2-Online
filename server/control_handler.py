"""
control_handler.py - Plaintext 20923 control/social channel.
Implements AUTH/EPGT/RGET/PSET plus lightweight roster, ignore, invite, and
private-message handling observed after the 20922 login path.
"""

import logging
import os
import socket
import struct
import threading
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from server import GameServer

log = logging.getLogger("control")


class ControlHandler:
    def __init__(self, server: "GameServer", conn: socket.socket, addr: tuple):
        self.srv = server
        self.conn = conn
        self.addr = addr
        self.peer_ip = str(addr[0])
        self.peer_port = int(addr[1])
        self._disconnect_reason = "loop_exit"
        self._session_bootstrapped = False
        self._prel_seen = False
        self._post_prel_idle = 0
        self._send_lock = threading.Lock()

        profile = self.srv.get_control_profile(self.peer_ip)
        self._peer_user = str(profile.get("persona") or profile.get("name") or "")
        self._auth_prod = "NFS-CONSOLE-2005"
        self._pget_stat = "EX%3d0%0aP%3dnfs5%0a"
        self._pget_prod = "is playing Underground 2"
        self._pget_title = "Need for Speed Underground 2 [PC]"
        self._pget_show = "PASS"
        self._pget_attr = "D"
        self._pget_sent = False
        self._social_registered = False

    @staticmethod
    def _is_upper_verb4(buf: bytes) -> bool:
        return len(buf) == 4 and all(65 <= b <= 90 for b in buf)

    @staticmethod
    def _is_http_prefix(buf: bytes) -> bool:
        return buf.startswith((b"GET ", b"HEAD ", b"POST "))

    @staticmethod
    def _parse_kv(body: bytes):
        txt = body.decode("utf-8", errors="replace").rstrip("\x00")
        out = {}
        for ln in txt.replace("\r", "").split("\n"):
            if "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            out[k.strip()] = v.strip()
        return out

    @staticmethod
    def _strip_quotes(v: str) -> str:
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            return v[1:-1]
        return v

    @classmethod
    def _make_message(cls, verb: str, lines) -> bytes:
        if len(verb) != 4 or not all("A" <= c <= "Z" for c in verb):
            raise ValueError(f"invalid 20923 verb: {verb!r}")
        if lines:
            body = ("\n".join(lines) + "\n").encode("utf-8") + b"\x00"
        else:
            body = b"\x00"
        total_len = 12 + len(body)
        return verb.encode("ascii") + b"\x00\x00\x00\x00" + struct.pack(">I", total_len) + body

    def _send_message(self, verb: str, lines) -> bool:
        try:
            msg = self._make_message(verb, lines)
            with self._send_lock:
                self.conn.sendall(msg)
            detail = ""
            if verb == "PGET":
                detail = " " + " ".join(
                    line
                    for line in lines
                    if str(line).startswith(("USER=", "SHOW=", "ATTR="))
                )
            elif verb == "ROST":
                detail = " " + " ".join(
                    line
                    for line in lines
                    if str(line).startswith(("USER=", "ATTR="))
                )
            elif verb == "RNOT":
                detail = " " + " ".join(str(line) for line in lines)
            log.info(
                "CONTROL send peer=%s:%d verb=%s len=%d%s",
                self.peer_ip,
                self.peer_port,
                verb,
                len(msg),
                detail,
            )
            return True
        except Exception as exc:
            self._disconnect_reason = f"send_error:{exc.__class__.__name__}"
            return False

    @staticmethod
    def _first_kv(kv: dict, *keys: str) -> str:
        for key in keys:
            value = kv.get(key, "")
            if value:
                return str(value)
        return ""

    @staticmethod
    def _looks_like_product_user(value: str) -> bool:
        text = str(value or "").strip()
        upper = text.upper()
        return (
            not text
            or text.startswith("/")
            or "NFS-CONSOLE" in upper
            or "EA MESSENGER" in upper
        )

    def _register_social(self) -> None:
        persona = str(self._peer_user or "").strip()
        if not persona:
            return
        registered = self.srv.control_social_register(
            self,
            persona,
            addr=f"{self.peer_ip}:{self.peer_port}",
        )
        self._social_registered = bool(registered)

    def _claim_peer_profile(self, reason: str = "") -> None:
        if self._peer_user and self._social_registered:
            return
        profile = self.srv.get_control_profile(self.peer_ip)
        candidate = str(profile.get("persona") or profile.get("name") or "").strip()
        if not candidate or self._looks_like_product_user(candidate):
            return
        if candidate != self._peer_user:
            old_user = self._peer_user
            self._peer_user = candidate
            log.info(
                "CONTROL social-claim peer=%s:%d old=%s new=%s reason=%s",
                self.peer_ip,
                self.peer_port,
                old_user or "-",
                self._peer_user,
                reason or "-",
            )
        self._register_social()

    def _maybe_update_peer_user(self, kv: dict) -> None:
        candidate = self._first_kv(kv, "PERS", "PERSONA", "NAME", "NICK", "ALIAS", "FROM")
        if not candidate:
            user = self._first_kv(kv, "USER")
            if user and not self._looks_like_product_user(user):
                candidate = user
        candidate = self._strip_quotes(candidate).strip()
        if not candidate or self._looks_like_product_user(candidate):
            self._claim_peer_profile("kv-empty")
            return
        if candidate != self._peer_user:
            old_user = self._peer_user
            self._peer_user = candidate
            log.info(
                "CONTROL social-user peer=%s:%d old=%s new=%s",
                self.peer_ip,
                self.peer_port,
                old_user or "-",
                self._peer_user,
            )
        self._register_social()

    def _presence_lines_for_row(self, row: dict) -> list[str]:
        presence = row.get("presence", {}) if isinstance(row.get("presence"), dict) else {}
        user = str(row.get("user", "") or "")
        show = "AWAY" if not row.get("online") else (presence.get("show") or "PASS")
        lines = [
            f"EXTR={self._auth_prod}",
            f"STAT={presence.get('stat') or self._pget_stat}",
            f"PROD={presence.get('prod') or self._pget_prod}",
            f"TITL={presence.get('title') or self._pget_title}",
            f"SHOW={show}",
            f"USER={user}",
        ]
        attr = str(row.get("attr") or "")
        if attr:
            lines.append(f"ATTR={attr}")
        elif not bool(row.get("friend", False)):
            lines.append(f"ATTR={self._pget_attr}")
        return lines

    def _ack_lines(self, kv: dict, *, status: bool = False) -> list[str]:
        lines = []
        req_id = kv.get("ID", "")
        if req_id:
            lines.append(f"ID={req_id}")
        if status:
            lines.extend(["STAT=OK", "RESULT=OK"])
        return lines

    def _send_simple_ack(self, verb: str, kv: dict, *, status: bool = False) -> bool:
        return self._send_message(verb, self._ack_lines(kv, status=status))

    def _send_roster_ack(self, verb: str, kv: dict, target: str, list_tag: str) -> bool:
        lines = []
        lrsc = kv.get("LRSC") or kv.get("RSRC")
        if lrsc:
            lines.append(f"LRSC={lrsc}")
        if kv.get("PRES"):
            lines.append(f"PRES={kv.get('PRES')}")
        req_id = kv.get("ID", "")
        if req_id:
            lines.append(f"ID={req_id}")
        if target:
            lines.append(f"USER={target}")
        if list_tag:
            lines.append(f"LIST={list_tag}")
        return self._send_message(verb, lines or self._ack_lines(kv, status=True))

    def _send_roster_change(self, chng: str, user: str, attr: str = "") -> bool:
        lines = [f"CHNG={chng}", f"USER={user}"]
        if attr:
            lines.append(f"ATTR={attr}")
        return self._send_message("RNOT", lines)

    @staticmethod
    def _roster_lines_for_row(row: dict, rid: str) -> list[str]:
        lines = [f"ID={rid}", f"USER={row.get('user')}"]
        row_attr = str(row.get("attr") or "")
        if row_attr:
            lines.append(f"ATTR={row_attr}")
        return lines

    def _online_roster_presence_lines(self, row: dict) -> tuple[Optional[list[str]], Optional[list[str]]]:
        if row is None or not bool(row.get("online", False)):
            return None, None
        user = str(row.get("user") or "").strip()
        if not user:
            return None, None
        attr = str(row.get("attr") or "D")
        roster_lines = [f"ID=-1", f"USER={user}"]
        if attr:
            roster_lines.append(f"ATTR={attr}")
        presence_lines = self._presence_lines_for_row({**row, "user": user, "attr": attr})
        return roster_lines, presence_lines

    def _presence_lines_for_target(self, target: str, attr: str = "") -> Optional[list[str]]:
        row = self.srv.control_social_presence_row(self._peer_user, target)
        if row is None:
            return None
        if attr:
            row = {**row, "attr": attr}
        return self._presence_lines_for_row(row)

    @staticmethod
    def _should_send_presence_for_row(row: dict) -> bool:
        if row.get("online"):
            return True
        if row.get("request"):
            return True
        return not bool(row.get("friend", False))

    def _handle_user_search(self, kv: dict) -> bool:
        rid = kv.get("ID", "1")
        query = self._social_target_name(self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO"))
        try:
            max_results = max(1, min(100, int(kv.get("MAXR", "20") or "20")))
        except Exception:
            max_results = 20

        rows = self.srv.control_social_search_users(self._peer_user, query, max_results)

        lines = [f"SIZE={len(rows)}", f"ID={rid}"]
        if not self._send_message("USCH", lines):
            return False
        for row in rows:
            if not self._send_message("USER", ["RSRC=PC", f"ID={rid}", f"USER={row.get('user')}"]):
                return False
        log.info(
            "CONTROL user-search peer=%s:%d owner=%s query=%s results=%d online=%d offline=%d",
            self.peer_ip,
            self.peer_port,
            self._peer_user or "-",
            query or "*",
            len(rows),
            sum(1 for row in rows if row.get("online")),
            sum(1 for row in rows if not row.get("online")),
        )
        return True

    def _outgoing_request_attr(self) -> str:
        attr = str(self.srv.cfg.get("CONTROL_SOCIAL_OUTGOING_REQUEST_ATTR", "P") or "P").strip().upper()
        return attr[:1] or "P"

    @staticmethod
    def _social_target_name(value: str) -> str:
        text = str(value or "").strip()
        if "/" in text and not text.startswith("/"):
            text = text.split("/", 1)[0].strip()
        return text

    def _handle_report(self, verb: str, kv: dict) -> bool:
        target = self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO")
        reason = self._first_kv(kv, "REASON", "TYPE", "TEXT", "BODY", "MESG")
        self.srv.control_social_report(self._peer_user, target, reason)
        log.info(
            "CONTROL report peer=%s:%d verb=%s reporter=%s target=%s reason=%s",
            self.peer_ip,
            self.peer_port,
            verb,
            self._peer_user or "-",
            target or "-",
            reason or "-",
        )
        return self._send_simple_ack(verb, kv, status=True)

    def _handle_roster_add(self, verb: str, kv: dict, *, force_block: bool = False) -> bool:
        list_tag = str(kv.get("LIST", "") or ("I" if force_block else "B")).upper()
        target = self._social_target_name(self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO"))
        attr = self.srv.control_social_add_relation(
            self._peer_user,
            target,
            "I" if force_block else list_tag,
        )
        log.info(
            "CONTROL roster-add peer=%s:%d verb=%s owner=%s list=%s target=%s attr=%s",
            self.peer_ip,
            self.peer_port,
            verb,
            self._peer_user or "-",
            "I" if force_block else (list_tag or "-"),
            target or "-",
            attr,
        )
        if not self._send_roster_ack(verb, kv, target, "I" if force_block else list_tag):
            return False
        if target and attr != "N":
            if attr != "R" and not self._send_roster_change("A", target, attr):
                return False
            notify_lines = [f"CHNG=A", f"USER={self._peer_user}"]
            if attr:
                notify_lines.append(f"ATTR={attr}")
            delivered_not = self.srv.control_social_deliver(target, "RNOT", notify_lines)
            roster_row = self.srv.control_social_roster_row(target, self._peer_user, list_tag)
            if roster_row is not None:
                self.srv.control_social_deliver(
                    target,
                    "ROST",
                    self._roster_lines_for_row(roster_row, "-1"),
                )
                self.srv.control_social_deliver(target, "PGET", self._presence_lines_for_row(roster_row))
            else:
                row = self.srv.control_social_presence_row(target, self._peer_user)
                if row is not None:
                    self.srv.control_social_deliver(target, "PGET", self._presence_lines_for_row(row))
            log.info(
                "CONTROL roster-add notify owner=%s target=%s attr=%s delivered=%d roster_row=%s",
                self._peer_user or "-",
                target or "-",
                attr or "-",
                delivered_not,
                "yes" if roster_row is not None else "no",
            )
        return True

    def _handle_roster_remove(self, verb: str, kv: dict, *, force_block: bool = False) -> bool:
        list_tag = str(kv.get("LIST", "") or ("I" if force_block else "B")).upper()
        target = self._social_target_name(self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO"))
        effective_list = "I" if force_block else list_tag
        attr = self.srv.control_social_remove_relation(
            self._peer_user,
            target,
            effective_list,
        )
        log.info(
            "CONTROL roster-remove peer=%s:%d verb=%s owner=%s list=%s target=%s attr=%s",
            self.peer_ip,
            self.peer_port,
            verb,
            self._peer_user or "-",
            effective_list or "-",
            target or "-",
            attr,
        )
        if not self._send_simple_ack(verb, kv, status=True):
            return False
        if not target or attr == "N":
            return True

        if not self._send_roster_change("D", target, attr):
            return False

        notify_lines = [f"CHNG=D", f"USER={self._peer_user}"]
        if attr:
            notify_lines.append(f"ATTR={attr}")
        self.srv.control_social_deliver(target, "RNOT", notify_lines)

        if not force_block and list_tag == "B":
            peer_remove_lines = []
            lrsc = kv.get("LRSC") or "PC"
            pres = kv.get("PRES")
            if lrsc:
                peer_remove_lines.append(f"LRSC={lrsc}")
            if pres:
                peer_remove_lines.append(f"PRES={pres}")
            peer_remove_lines.extend([
                "ID=-1",
                f"USER={self._peer_user}",
                "LIST=B",
            ])
            # The legacy client keeps the buddy row unless it receives an
            # explicit roster delete, not just the RNOT CHNG=D notify.
            self.srv.control_social_deliver(target, "RDEM", peer_remove_lines)
            self.srv.control_social_deliver(target, "RDEL", peer_remove_lines)

            own_presence = self.srv.control_social_presence_row(self._peer_user, target)
            own_roster, own_pget = self._online_roster_presence_lines(own_presence)
            if own_roster is not None and own_pget is not None:
                own_user = str(own_presence.get("user") or target)
                own_attr = str(own_presence.get("attr") or "D")
                self._send_roster_change("A", own_user, own_attr)
                self._send_message("ROST", own_roster)
                self._send_message("PGET", own_pget)
            target_presence = self.srv.control_social_presence_row(target, self._peer_user)
            target_roster, target_pget = self._online_roster_presence_lines(target_presence)
            if target_roster is not None and target_pget is not None:
                target_user = str(target_presence.get("user") or self._peer_user)
                target_attr = str(target_presence.get("attr") or "D")
                self.srv.control_social_deliver(target, "RNOT", [f"CHNG=A", f"USER={target_user}", f"ATTR={target_attr}"])
                self.srv.control_social_deliver(target, "ROST", target_roster)
                self.srv.control_social_deliver(target, "PGET", target_pget)
        return True

    @staticmethod
    def _rrsp_accepts(value: str) -> bool:
        text = str(value or "").strip().upper()
        if text in ("0", "N", "NO", "F", "FALSE", "D", "DECLINE", "DENY", "REJECT", "REJECTED"):
            return False
        if text in ("1", "Y", "YES", "T", "TRUE", "A", "ACCEPT", "ACCEPTED", "OK"):
            return True
        return bool(text)

    def _push_roster_row_to(self, target: str, row_owner: str, row_target: str, rid: str = "-1") -> bool:
        row = self.srv.control_social_roster_row(row_owner, row_target, "B")
        if row is None:
            return False
        self.srv.control_social_deliver(target, "ROST", self._roster_lines_for_row(row, rid))
        self.srv.control_social_deliver(target, "PGET", self._presence_lines_for_row(row))
        return True

    def _handle_roster_response(self, verb: str, kv: dict) -> bool:
        target = self._social_target_name(self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO"))
        answer = self._first_kv(kv, "ANSW", "ANSWER", "ACPT", "ACCEPT", "STATUS")
        accepted = self._rrsp_accepts(answer)
        attr = (
            self.srv.control_social_add_relation(self._peer_user, target, "B")
            if accepted
            else self.srv.control_social_remove_relation(self._peer_user, target, "B")
        )
        log.info(
            "CONTROL roster-response peer=%s:%d owner=%s target=%s answer=%s accepted=%s attr=%s",
            self.peer_ip,
            self.peer_port,
            self._peer_user or "-",
            target or "-",
            answer or "-",
            "yes" if accepted else "no",
            attr or "-",
        )
        if not self._send_simple_ack(verb, kv, status=True):
            return False
        if not target or attr == "N":
            return True

        if accepted:
            if not self._send_roster_change("A", target, ""):
                return False
            self._push_roster_row_to(self._peer_user, self._peer_user, target)
            self.srv.control_social_deliver(target, "RNOT", [f"CHNG=A", f"USER={self._peer_user}"])
            self._push_roster_row_to(target, target, self._peer_user)
        else:
            if not self._send_roster_change("D", target, "R"):
                return False
            self.srv.control_social_deliver(target, "RNOT", [f"CHNG=D", f"USER={self._peer_user}", "ATTR=P"])
            row = self.srv.control_social_presence_row(target, self._peer_user)
            if row is not None:
                row_user = str(row.get("user") or self._peer_user)
                row_attr = str(row.get("attr") or "D")
                self.srv.control_social_deliver(target, "RNOT", [f"CHNG=A", f"USER={row_user}", f"ATTR={row_attr}"])
                self.srv.control_social_deliver(target, "PGET", self._presence_lines_for_row(row))
        return True

    def _handle_invite(self, verb: str, kv: dict) -> bool:
        target = self._social_target_name(self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO"))
        text = self._strip_quotes(self._first_kv(kv, "TEXT", "BODY", "MESG", "MSG"))
        if target and self.srv.control_social_same_identity(self._peer_user, target):
            log.info(
                "CONTROL invite self-block peer=%s:%d from=%s target=%s",
                self.peer_ip,
                self.peer_port,
                self._peer_user or "-",
                target,
            )
            return self._send_message(verb, self._ack_lines(kv, status=True) + ["DELIVERED=0"])
        sender_handler = self._lan_handler_for_social_name(self._peer_user)
        game = None
        if sender_handler is not None and getattr(sender_handler.user, "game", 0):
            game = self.srv.games.get(int(getattr(sender_handler.user, "game", 0) or 0))
        game_id = int(getattr(game, "id", 0) or 0) if game is not None else 0
        game_name = str(getattr(game, "custom", "") or self._peer_user or "game") if game is not None else ""
        invite_text = text or f"{self._peer_user} invited you to join {game_name or 'their game'}"
        invite_lines = [
            f"USER={self._peer_user}",
            f"FROM={self._peer_user}",
            f"N={self._peer_user}",
            f"T={invite_text}",
            f"TEXT={invite_text}",
            "TYPE=I",
            f"BODY={invite_text}",
        ]
        if game_id:
            invite_lines.extend(
                [
                    f"IDENT={game_id}",
                    f"GAME={game_id}",
                    f"GID={game_id}",
                    f"LIDENT={game_id}",
                    f"ROOM={int(getattr(game, 'room_id', 0) or 0)}",
                    f"NAME={game_name}",
                    f"LCOUNT={max(1, len(getattr(game, 'participants', []) or []))}",
                ]
            )
        delivered = 0
        lan_delivered = 0
        if target and not self.srv.control_social_is_blocked(self._peer_user, target):
            row = self.srv.control_social_presence_row(target, self._peer_user)
            if row is not None:
                delivered += self.srv.control_social_deliver(target, "PGET", self._presence_lines_for_row(row))
            delivered += self.srv.control_social_deliver(target, "PADD", ["LRSC=PC", f"USER={self._peer_user}"])
            delivered += self.srv.control_social_deliver(target, "INVT", invite_lines)
            if sender_handler is not None:
                deliver_invite = getattr(sender_handler, "_lan_deliver_invite", None)
                if callable(deliver_invite):
                    try:
                        lan_delivered = int(deliver_invite(target, invite_text) or 0)
                    except Exception:
                        lan_delivered = 0
        log.info(
            "CONTROL invite peer=%s:%d verb=%s from=%s target=%s delivered=%d lan=%d game=%d text=%s",
            self.peer_ip,
            self.peer_port,
            verb,
            self._peer_user or "-",
            target or "-",
            delivered,
            lan_delivered,
            game_id,
            invite_text or "-",
        )
        return self._send_message(
            verb,
            self._ack_lines(kv, status=True) + [f"DELIVERED={max(delivered, lan_delivered)}"],
        )

    def _handle_message(self, verb: str, kv: dict) -> bool:
        target = self._social_target_name(self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO"))
        text = self._first_kv(kv, "TEXT", "BODY", "MESG", "MSG")
        if target and self.srv.control_social_same_identity(self._peer_user, target):
            log.info(
                "CONTROL message self-block peer=%s:%d verb=%s from=%s target=%s",
                self.peer_ip,
                self.peer_port,
                verb,
                self._peer_user or "-",
                target,
            )
            return self._send_message(verb, self._ack_lines(kv, status=True) + ["DELIVERED=0"])
        if target and self.srv.control_social_is_blocked(self._peer_user, target):
            log.info(
                "CONTROL message blocked peer=%s:%d verb=%s from=%s target=%s",
                self.peer_ip,
                self.peer_port,
                verb,
                self._peer_user or "-",
                target,
            )
            return self._send_message(verb, self._ack_lines(kv, status=True) + ["DELIVERED=0"])
        delivered = 0
        if target:
            delivered = self.srv.control_social_deliver(
                target,
                "PMSG",
                [
                    f"USER={self._peer_user}",
                    f"FROM={self._peer_user}",
                    f"TEXT={text}",
                ],
            )
        log.info(
            "CONTROL message peer=%s:%d verb=%s from=%s target=%s delivered=%d text=%s",
            self.peer_ip,
            self.peer_port,
            verb,
            self._peer_user or "-",
            target or "-",
            delivered,
            text or "-",
        )
        return self._send_message(
            verb,
            self._ack_lines(kv, status=True) + [f"DELIVERED={delivered}"],
        )

    def _lan_handler_for_social_name(self, name: str):
        key_fn = getattr(self.srv, "_social_key", None)
        wanted = key_fn(name) if callable(key_fn) else str(name or "").strip().lower()
        if not wanted:
            return None
        users = getattr(getattr(self.srv, "users", None), "all_users", lambda: [])()
        find_handler = getattr(self.srv, "_admin_find_handler", None)
        for user in users:
            handler = find_handler(int(getattr(user, "uid", 0) or 0)) if callable(find_handler) else None
            candidates = [
                getattr(user, "name", ""),
                getattr(user, "pers", ""),
            ]
            if handler is not None:
                try:
                    candidates.append(handler._lan_display_name_for(user))
                except Exception:
                    pass
                try:
                    candidates.append(handler._lan_persona_for(user))
                except Exception:
                    pass
            for candidate in candidates:
                candidate_key = key_fn(candidate) if callable(key_fn) else str(candidate or "").strip().lower()
                if candidate_key and candidate_key == wanted:
                    return handler
        return None

    def _deliver_lan_private_message(self, target: str, text: str) -> int:
        target_handler = self._lan_handler_for_social_name(target)
        if target_handler is None or not bool(getattr(target_handler.user, "connected", False)):
            return 0
        sender_handler = self._lan_handler_for_social_name(self._peer_user)
        if sender_handler is not None and int(getattr(target_handler.user, "uid", 0) or 0) == int(getattr(sender_handler.user, "uid", 0) or 0):
            return 0
        try:
            target_burst = target_handler._make_20922_tab_message(
                "+msg",
                target_handler._lan_msg_fields(
                    text,
                    sender=self._peer_user,
                    flag="P",
                ),
            )
            target_handler._send_later_bytes(0.01, target_burst, label="control-send-private-target")
        except Exception:
            return 0

        if (
            sender_handler is not None
            and sender_handler is not target_handler
            and bool(getattr(sender_handler.user, "connected", False))
        ):
            try:
                sender_burst = sender_handler._make_20922_tab_message(
                    "+msg",
                    sender_handler._lan_msg_fields(
                        text,
                        sender=f"\"To {target}\"",
                        flag="PU",
                    ),
                )
                sender_handler._send_later_bytes(0.01, sender_burst, label="control-send-private-self")
            except Exception:
                pass
        return 1

    def _chat_delivery_lines(self, msg_type: str, body: str, text: str, secs: str) -> list[str]:
        lines = [
            f"USER={self._peer_user}",
            f"N={self._peer_user}",
            f"T={text}",
            "F=P",
            f"TYPE={msg_type or 'C'}",
            f"BODY={body}",
        ]
        if secs:
            lines.append(f"SECS={secs}")
        return lines

    def _handle_send(self, verb: str, kv: dict) -> bool:
        msg_type = str(kv.get("TYPE", "") or "").strip().upper()
        target = self._social_target_name(self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO"))
        if target and self.srv.control_social_same_identity(self._peer_user, target):
            log.info(
                "CONTROL send self-block peer=%s:%d type=%s owner=%s target=%s",
                self.peer_ip,
                self.peer_port,
                msg_type or "-",
                self._peer_user or "-",
                target,
            )
            return self._send_message(verb, self._ack_lines(kv, status=True) + ["DELIVERED=0"])
        if msg_type in ("F", "FR", "REQ", "B"):
            add_kv = dict(kv)
            add_kv["USER"] = target
            add_kv["LIST"] = "B"
            log.info(
                "CONTROL send-friend peer=%s:%d type=%s owner=%s target=%s",
                self.peer_ip,
                self.peer_port,
                msg_type or "-",
                self._peer_user or "-",
                target or "-",
            )
            return self._handle_roster_add("RADD", add_kv)
        if msg_type in ("C", "M", "P", ""):
            body = self._first_kv(kv, "BODY", "TEXT", "MESG", "MSG")
            text = self._strip_quotes(body)
            secs = str(kv.get("SECS", "") or "").strip()
            original_user = str(kv.get("USER", "") or "").strip()
            ack_user = original_user or (f"{target}/PC" if target else "")
            ack_lines = []
            if secs:
                ack_lines.append(f"SECS={secs}")
            if ack_user:
                ack_lines.append(f"USER={ack_user}")
            ack_lines.extend(
                [
                    f"TYPE={msg_type or 'C'}",
                    f"BODY={body}",
                ]
            )
            chat_lines = self._chat_delivery_lines(msg_type, body, text, secs)
            delivered = 0
            lan_delivered = 0
            if target and not self.srv.control_social_is_blocked(self._peer_user, target):
                row = self.srv.control_social_presence_row(target, self._peer_user)
                if row is not None:
                    delivered += self.srv.control_social_deliver(target, "PGET", self._presence_lines_for_row(row))
                delivered += self.srv.control_social_deliver(target, "PADD", ["LRSC=PC", f"USER={self._peer_user}"])
                delivered += self.srv.control_social_deliver(target, "RECV", chat_lines)
                lan_delivered = self._deliver_lan_private_message(target, text)
            log.info(
                "CONTROL send-chat peer=%s:%d from=%s target=%s delivered=%d lan=%d type=%s body=%s",
                self.peer_ip,
                self.peer_port,
                self._peer_user or "-",
                target or "-",
                delivered,
                lan_delivered,
                msg_type or "C",
                body or "-",
            )
            return self._send_message(verb, ack_lines)
        log.info(
            "CONTROL send-unhandled peer=%s:%d type=%s owner=%s target=%s keys=%s",
            self.peer_ip,
            self.peer_port,
            msg_type or "-",
            self._peer_user or "-",
            target or "-",
            ",".join(sorted(kv.keys())) if kv else "-",
        )
        return self._send_simple_ack(verb, kv, status=True)

    def _handle_presence_add(self, verb: str, kv: dict) -> bool:
        target = self._social_target_name(self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO"))
        lines = []
        lrsc = kv.get("LRSC") or kv.get("RSRC")
        if lrsc:
            lines.append(f"LRSC={lrsc}")
        if target:
            lines.append(f"USER={target}")
        return self._send_message(verb, lines)

    def _send_roster_notify(self) -> bool:
        try:
            enabled = int(self.srv.cfg.get("CONTROL_RNOT_ENABLE", 1) or 0) != 0
        except (TypeError, ValueError):
            enabled = True
        if not enabled:
            return True
        try:
            self_notify = int(self.srv.cfg.get("CONTROL_RNOT_SELF_ENABLE", 0) or 0) != 0
        except (TypeError, ValueError):
            self_notify = False
        if not self_notify:
            return True
        return self._send_message(
            "RNOT",
            [f"CHNG=A", f"USER={self._peer_user}", "ATTR=R"],
        )

    def _recv_exact(self, size: int) -> Optional[bytes]:
        data = bytearray()
        while len(data) < size:
            try:
                chunk = self.conn.recv(size - len(data))
            except socket.timeout:
                self._disconnect_reason = "timeout"
                return None
            except Exception as exc:
                self._disconnect_reason = f"recv_error:{exc.__class__.__name__}"
                return None
            if not chunk:
                self._disconnect_reason = "peer_closed"
                return None
            data.extend(chunk)
        return bytes(data)

    def _recv_until_nul(self, initial: bytes, limit: int = 1024) -> Optional[bytes]:
        data = bytearray(initial)
        while b"\x00" not in data and len(data) < limit:
            try:
                chunk = self.conn.recv(min(256, limit - len(data)))
            except socket.timeout:
                self._disconnect_reason = "timeout"
                return None
            except Exception as exc:
                self._disconnect_reason = f"recv_error:{exc.__class__.__name__}"
                return None
            if not chunk:
                self._disconnect_reason = "peer_closed"
                return None
            data.extend(chunk)
        return bytes(data)

    def _recv_http_request(self, initial: bytes, limit: int = 0x4000) -> Optional[bytes]:
        data = bytearray(initial)
        while b"\r\n\r\n" not in data and len(data) < limit:
            try:
                chunk = self.conn.recv(min(1024, limit - len(data)))
            except socket.timeout:
                self._disconnect_reason = "timeout"
                return None
            except Exception as exc:
                self._disconnect_reason = f"recv_error:{exc.__class__.__name__}"
                return None
            if not chunk:
                break
            data.extend(chunk)
        header_end = data.find(b"\r\n\r\n")
        if header_end < 0:
            self._disconnect_reason = "invalid_http"
            return None

        content_length = 0
        header_text = bytes(data[: header_end + 4]).decode("latin1", errors="replace")
        for raw_line in header_text.split("\r\n")[1:]:
            if ":" not in raw_line:
                continue
            key, value = raw_line.split(":", 1)
            if key.strip().lower() == "content-length":
                try:
                    content_length = int(value.strip() or "0")
                except ValueError:
                    content_length = 0
                break

        body_have = len(data) - (header_end + 4)
        missing = content_length - body_have
        while missing > 0 and len(data) < limit + content_length:
            chunk = self._recv_exact(min(1024, missing))
            if chunk is None:
                return None
            data.extend(chunk)
            missing -= len(chunk)
        return bytes(data)

    def _read_content_file(self, key: str, fallback_name: str, fallback_body: bytes) -> bytes:
        raw_path = str(self.srv.cfg.get(key, "") or fallback_name).strip()
        if not raw_path:
            return fallback_body
        candidates = [raw_path]
        if not os.path.isabs(raw_path):
            candidates.append(os.path.join(os.getcwd(), raw_path))
            config_path = str(getattr(self.srv, "_config_path", "") or "")
            if config_path:
                candidates.append(os.path.join(os.path.dirname(config_path), raw_path))
                candidates.append(os.path.join(os.path.dirname(os.path.dirname(config_path)), raw_path))
        for path in candidates:
            try:
                with open(path, "rb") as fh:
                    return fh.read()
            except OSError:
                continue
        return fallback_body

    def _http_body_for_target(self, target: str) -> tuple[str, bytes]:
        path = target.split("?", 1)[0].strip() or "/"
        if path.endswith("/tos") or path == "/tos" or "tos" in path.lower():
            return "text/plain; charset=iso-8859-1", self._read_content_file(
                "LAN_TOS_FILE",
                "tos",
                b'%{ CMD=news TITLE="Terms of Service" BTN1="Agree" BTN1-GOTO="$quit" BTN2="Disagree" BTN2-GOTO="$exit=-1" %}\r\nTerms of Service\r\n',
            )
        if path.endswith("/news") or path == "/news" or "news" in path.lower():
            return "text/plain; charset=utf-8", self._read_content_file(
                "LAN_NEWS_FILE",
                "news",
                b'%{ CMD=news TITLE="News" BTN1="Close" BTN1-GOTO="$quit"%}\r\nWelcome back online.\r\n',
            )
        return "text/plain; charset=utf-8", b"OK\n"

    def _send_http_response(self, status: str, body: bytes, *, content_type: str, include_body: bool) -> bool:
        headers = [
            f"HTTP/1.0 {status}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body) if include_body else 0}",
            "Cache-Control: no-cache",
            "Connection: close",
        ]
        payload = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii", errors="ignore")
        if include_body:
            payload += body
        try:
            with self._send_lock:
                self.conn.sendall(payload)
            log.info(
                "CONTROL send peer=%s:%d HTTP %s len=%d",
                self.peer_ip,
                self.peer_port,
                status,
                len(payload),
            )
            return True
        except Exception as exc:
            self._disconnect_reason = f"send_error:{exc.__class__.__name__}"
            return False

    def _read_client_message(self):
        hdr = self._recv_exact(12)
        if hdr is None:
            return None

        if self._is_http_prefix(hdr):
            payload = self._recv_http_request(hdr)
            if payload is None:
                return None
            return "HTTP", payload

        if hdr[:4] == b"PREL" and hdr[4:5] in (b"\t", b"\x00"):
            payload = self._recv_until_nul(hdr)
            if payload is None:
                return None
            return "PREL", payload

        verb_raw = hdr[:4]
        if not self._is_upper_verb4(verb_raw):
            log.warning(
                "CONTROL invalid_verb peer=%s:%d hdr=%s ascii=%r",
                self.peer_ip,
                self.peer_port,
                hdr.hex(),
                hdr,
            )
            self._disconnect_reason = f"invalid_verb:{verb_raw.hex()}"
            return None
        if hdr[4:8] != b"\x00\x00\x00\x00":
            log.warning(
                "CONTROL invalid_zero peer=%s:%d hdr=%s",
                self.peer_ip,
                self.peer_port,
                hdr.hex(),
            )
            self._disconnect_reason = f"invalid_zero:{hdr[4:8].hex()}"
            return None

        declared = struct.unpack(">I", hdr[8:12])[0]
        if declared < 12 or declared > 65535:
            self._disconnect_reason = f"invalid_len:{declared}"
            return None

        body = self._recv_exact(declared - 12)
        if body is None:
            return None
        return verb_raw.decode("ascii", errors="replace"), body

    def run(self):
        self.conn.settimeout(300.0)
        try:
            log.info("CONTROL active peer=%s:%d", self.peer_ip, self.peer_port)
            while self.srv.is_running:
                msg = self._read_client_message()
                if msg is None:
                    break
                verb, body = msg

                if verb == "PREL":
                    txt = body.decode("utf-8", errors="replace").rstrip("\x00")
                    log.info(
                        "CONTROL recv peer=%s:%d verb=PREL raw=%s",
                        self.peer_ip,
                        self.peer_port,
                        txt.replace("\t", " | "),
                    )
                    host = self.srv.advertised_host(self.conn)
                    ctrl_port = int(getattr(self.srv, "control_port", lambda: 20923)())
                    # Control-channel PREL is not the same as the old custom bootstrap PREL.
                    # Reusing the normal bootstrap payload advertises CLOSE=1, which makes
                    # the client tear down the control socket immediately after PRELRESP.
                    reply = "	".join([
                        "PRELRESP",
                        "VER=1",
                        f"LOBBYHOST={host}",
                        f"LOBBYTCP={ctrl_port}",
                        "STATUS=OK",
                    ]) + "\x00"
                    try:
                        raw = reply.encode("utf-8")
                        with self._send_lock:
                            self.conn.sendall(raw)
                        log.info(
                            "CONTROL send peer=%s:%d verb=PRELRESP len=%d",
                            self.peer_ip,
                            self.peer_port,
                            len(raw),
                        )
                        self._prel_seen = True
                        self._session_bootstrapped = True
                        log.info(
                            "CONTROL keep-open peer=%s:%d after PRELRESP",
                            self.peer_ip,
                            self.peer_port,
                        )
                    except Exception as exc:
                        self._disconnect_reason = f"send_error:{exc.__class__.__name__}"
                        break
                    continue

                if verb == "DISC":
                    log.info("CONTROL recv peer=%s:%d verb=DISC", self.peer_ip, self.peer_port)
                    if not self._session_bootstrapped and not self._send_message(
                        "AUTH", ["TITL=EA MESSENGER"]
                    ):
                        break
                    continue

                if verb == "HTTP":
                    req_text = body.decode("latin1", errors="replace")
                    req_line = req_text.split("\r\n", 1)[0].strip()
                    parts = req_line.split(" ")
                    method = parts[0].upper() if parts else "GET"
                    target = parts[1] if len(parts) >= 2 else "/"
                    log.info(
                        "CONTROL recv peer=%s:%d HTTP method=%s target=%s",
                        self.peer_ip,
                        self.peer_port,
                        method,
                        target,
                    )
                    content_type, http_body = self._http_body_for_target(target)
                    self._send_http_response(
                        "200 OK",
                        http_body,
                        content_type=content_type,
                        include_body=method != "HEAD",
                    )
                    break

                kv = self._parse_kv(body)
                log.info(
                    "CONTROL recv peer=%s:%d verb=%s keys=%s%s",
                    self.peer_ip,
                    self.peer_port,
                    verb,
                    ",".join(sorted(kv.keys())) if kv else "-",
                    (
                        f" list={kv.get('LIST', '-') or '-'} id={kv.get('ID', '-') or '-'}"
                        if verb == "RGET"
                        else ""
                    ),
                )

                if verb == "AUTH":
                    self._session_bootstrapped = True
                    self._auth_prod = kv.get("PROD", self._auth_prod)
                    self._maybe_update_peer_user(kv)
                    if not self._send_message("AUTH", ["TITL=EA MESSENGER"]):
                        break
                    continue

                if verb == "EPGT":
                    self._session_bootstrapped = True
                    mid = kv.get("ID", "4")
                    host = str(
                        self.srv.cfg.get("CONTROL_EPGT_ADDR", "")
                        or self.srv.control_alias_host(self.conn)
                        or self.srv.control_host(self.conn)
                        or self.srv.advertised_host(self.conn)
                        or "127.0.0.1"
                    ).strip()
                    if not self._send_message("EPGT", [f"ENAB=t", f"ID={mid}", f"ADDR={host}"]):
                        break
                    continue

                if verb == "RGET":
                    self._session_bootstrapped = True
                    self._maybe_update_peer_user(kv)
                    rid = kv.get("ID", "1")
                    list_tag = kv.get("LIST", "")
                    if list_tag == "B":
                        roster = self.srv.control_social_snapshot(self._peer_user, "B")
                        roster_users = {str(row.get("user", "") or "").strip().lower() for row in roster}
                        online_rows = []
                        for row in self.srv.control_social_snapshot(self._peer_user, "ALL"):
                            row_user = str(row.get("user", "") or "").strip().lower()
                            if not row_user or row_user in roster_users:
                                continue
                            online_rows.append(row)
                        log.info(
                            "CONTROL roster-snapshot peer=%s:%d owner=%s list=B friends_or_requests=%d online=%d total=%d",
                            self.peer_ip,
                            self.peer_port,
                            self._peer_user or "-",
                            len(roster),
                            len(online_rows),
                            len(roster) + len(online_rows),
                        )
                        # Do not include online non-friends in the LIST=B snapshot itself.
                        # The legacy client can treat snapshot entries as buddy rows even when
                        # ATTR=D is present. Send the real buddy/request roster in RGET, then
                        # announce online non-friends as live presence updates.
                        if not self._send_message("RGET", [f"SIZE={len(roster)}", f"ID={rid}"]):
                            break
                        for row in roster:
                            if not self._send_message("ROST", self._roster_lines_for_row(row, rid)):
                                break
                            if self._should_send_presence_for_row(row) and not self._send_message("PGET", self._presence_lines_for_row(row)):
                                break
                        self._pget_sent = True
                        if not self._send_roster_notify():
                            break
                        for row in online_rows:
                            row_user = str(row.get("user") or "")
                            row_attr = str(row.get("attr") or "D")
                            if not self._send_roster_change("A", row_user, row_attr):
                                break
                            if not self._send_message("ROST", ["ID=-1", f"USER={row_user}", f"ATTR={row_attr}"]):
                                break
                            if not self._send_message("PGET", self._presence_lines_for_row(row)):
                                break
                        continue

                    if list_tag == "I":
                        roster = self.srv.control_social_snapshot(self._peer_user, "I")
                        if not self._send_message("RGET", [f"SIZE={len(roster)}", f"ID={rid}"]):
                            break
                        for row in roster:
                            if not self._send_message(
                                "ROST",
                                [
                                    f"ID={rid}",
                                    f"USER={row.get('user')}",
                                    f"ATTR={row.get('attr') or 'B'}",
                                ],
                            ):
                                break
                        if not self._pget_sent and not self._send_message(
                            "PGET",
                            self._presence_lines_for_row(
                                {
                                    "user": self._peer_user,
                                    "attr": self._pget_attr,
                                    "online": True,
                                }
                            ),
                        ):
                            break
                        self._pget_sent = True
                        continue

                    if not self._send_message("RGET", [f"SIZE=0", f"ID={rid}"]):
                        break
                    continue

                if verb == "PSET":
                    self._session_bootstrapped = True
                    self._maybe_update_peer_user(kv)
                    show = kv.get("SHOW", "")
                    if show:
                        self._pget_show = show
                    stat = kv.get("STAT", "")
                    if stat:
                        self._pget_stat = stat
                    prod = kv.get("PROD", "")
                    if prod:
                        self._pget_prod = self._strip_quotes(prod)
                    title = kv.get("TITL", "")
                    if title:
                        self._pget_title = self._strip_quotes(title)
                    self.srv.control_social_update_presence(
                        self,
                        show=self._pget_show,
                        stat=self._pget_stat,
                        prod=self._pget_prod,
                        title=self._pget_title,
                    )
                    if not self._send_message("PSET", []):
                        break
                    continue

                if verb == "PADD":
                    self._session_bootstrapped = True
                    if not self._handle_presence_add(verb, kv):
                        break
                    continue

                if verb == "USCH":
                    self._session_bootstrapped = True
                    if not self._handle_user_search(kv):
                        break
                    continue

                if verb in ("RADD", "RDEL", "RREM", "RSET"):
                    self._session_bootstrapped = True
                    list_tag = str(kv.get("LIST", "") or "").upper()
                    target = self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO")
                    log.info(
                        "CONTROL roster peer=%s:%d verb=%s list=%s target=%s",
                        self.peer_ip,
                        self.peer_port,
                        verb,
                        list_tag or "-",
                        target or "-",
                    )
                    if list_tag == "B":
                        ok = self._handle_roster_remove(verb, kv) if verb in ("RDEL", "RREM") else self._handle_roster_add(verb, kv)
                    elif list_tag == "I":
                        ok = self._handle_roster_remove(verb, kv, force_block=True) if verb in ("RDEL", "RREM") else self._handle_roster_add(verb, kv, force_block=True)
                    else:
                        ok = self._send_simple_ack(verb, kv, status=True)
                        if ok and target:
                            chng = "D" if verb in ("RDEL", "RREM") else "A"
                            ok = self._send_message("RNOT", [f"CHNG={chng}", f"USER={target}", f"ATTR=R"])
                    if not ok:
                        break
                    continue

                if verb == "RDEM":
                    self._session_bootstrapped = True
                    log.info(
                        "CONTROL roster-delete-member peer=%s:%d owner=%s target=%s",
                        self.peer_ip,
                        self.peer_port,
                        self._peer_user or "-",
                        self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO") or "-",
                    )
                    if not self._handle_roster_remove(verb, kv):
                        break
                    continue

                if verb == "RADM":
                    self._session_bootstrapped = True
                    log.info(
                        "CONTROL roster-add-member peer=%s:%d owner=%s target=%s",
                        self.peer_ip,
                        self.peer_port,
                        self._peer_user or "-",
                        self._first_kv(kv, "USER", "PERS", "NAME", "TARGET", "TARG", "TO") or "-",
                    )
                    if not self._handle_roster_add(verb, kv):
                        break
                    continue

                if verb == "RRSP":
                    self._session_bootstrapped = True
                    if not self._handle_roster_response(verb, kv):
                        break
                    continue

                if verb in ("ABUS", "RPRT", "REPT", "CMPL"):
                    self._session_bootstrapped = True
                    if not self._handle_report(verb, kv):
                        break
                    continue

                if verb in ("BLCK", "BLOK", "RBLK", "RBLO"):
                    self._session_bootstrapped = True
                    if not self._handle_roster_add(verb, kv, force_block=True):
                        break
                    continue

                if verb in ("UBLK", "UBLO", "UNBL", "BDEL"):
                    self._session_bootstrapped = True
                    if not self._handle_roster_remove(verb, kv, force_block=True):
                        break
                    continue

                if verb in ("INVT", "INVI", "INVL", "GINV", "PINV"):
                    self._session_bootstrapped = True
                    if not self._handle_invite(verb, kv):
                        break
                    continue

                if verb in ("PMSG", "MMSG", "MESG"):
                    self._session_bootstrapped = True
                    if not self._handle_message(verb, kv):
                        break
                    continue

                if verb == "SEND":
                    self._session_bootstrapped = True
                    if not self._handle_send(verb, kv):
                        break
                    continue

                log.info("CONTROL unhandled peer=%s:%d verb=%s", self.peer_ip, self.peer_port, verb)
                try:
                    generic_ack = int(self.srv.cfg.get("CONTROL_GENERIC_ACK_ENABLE", 1) or 0) != 0
                except (TypeError, ValueError):
                    generic_ack = True
                if generic_ack:
                    if not self._send_simple_ack(verb, kv, status=False):
                        break
                    continue
        finally:
            self.srv.control_social_unregister(self)
            try:
                self.conn.close()
            except Exception:
                pass
            log.info(
                "CONTROL close peer=%s:%d reason=%s",
                self.peer_ip,
                self.peer_port,
                self._disconnect_reason,
            )
