# Changing a computer's role without losing other computers (proposal, 2026-10-28)

Status: proposal for owner review. Not implemented. What exists today is the plain role switch (`retireRole` /
`styx role retire`), which refuses to retire a Gateway that other computers still use unless the owner confirms
losing them.

## Problem

A Gateway (shown later as the hub) is the only place other computers (Hosts) are paired. If the owner turns the hub
into a Host-only machine, every other Host loses its Gateway at once and must be re-paired by hand, often from
another room. Access must not drop silently.

## Prerequisite: Hosts on other computers can reach the hub

Today a fresh Gateway listens on loopback only (`management/native_gateway.rs` refuses any non-loopback address and
`allowRemoteHosts`). So a MacBook cannot join a Mac mini hub at all yet. The v1 two-computer story (Mac mini hub,
MacBook joins) needs:

- The Gateway listens on a LAN address chosen at setup, in addition to loopback, with the existing pinned Gateway CA
  and device keys (no new trust model).
- Hosts connect to that address; the join invitation carries it.
- Reachability is the user's network (same LAN, or an overlay such as Tailscale the user already runs). Styx does
  not open router ports. ChatGPT still reaches the hub only through OpenAI's Secure MCP Tunnel.

## Rules

1. Access never drops as a side effect. A hub stops being a hub only after every Host it serves has either moved to a
   new hub or been explicitly let go by the owner, by name.
2. Pairing stays per hub. The old hub's CA private key and device registry never leave its machine; Hosts get a new
   pairing with the new hub. (Same reason as "never transfer private keys": a copied hub identity cannot be revoked
   cleanly.)
3. Make before break. A Host keeps its old pairing until it is connected to the new hub, then drops the old one.
4. The owner approves once, on the old hub, with the list of computers that will move.
5. Nothing is deleted. Retired roots are renamed aside, as today.

## Flows

### A. Move the hub to another computer (the common case)

1. On the new computer: "Make this the hub". It creates a fresh Gateway (own CA) and shows a one-time
   **handover code** (address, CA fingerprint, short-lived secret).
2. On the old hub: Settings → "Move the hub to another computer…", enter the handover code. The old hub connects to
   the new hub over TLS pinned to that CA fingerprint and shows: the computers that will move (online / offline), any
   pending pairing requests (they will be cancelled), and that ChatGPT must be reconnected on the new hub.
3. The owner confirms once. For each online Host the old hub asks the new hub for a single-use, device-bound
   invitation and sends it to that Host over the Host's existing authenticated link. The new hub marks these
   invitations as pre-approved by the handover (the owner's confirmation in step 3 is the approval).
4. Each Host runs the normal join against the new hub with that invitation, connects, and only then drops its old
   pairing. The old hub shows progress per computer: moved / waiting (offline) / failed (with reason).
5. Offline Hosts stay listed as waiting. The old hub keeps running as hub for them until they come online and move,
   or until the owner explicitly chooses "Leave these computers behind" for named ones (they will need to be paired
   again by hand; the screen says so).
6. When nothing is waiting, the old hub retires its Gateway role (renamed aside) and its own Host joins the new hub
   by the same flow, so this computer keeps working as a Host.
7. ChatGPT: the owner configures the tunnel on the new hub (tunnel id and key are account secrets; they are not
   copied between machines). Until then ChatGPT reaches nothing; the handover screen shows this as the last step.

### B. Stop being a hub, with no new hub

Only when no other computer depends on it, or after the owner disconnects each named computer explicitly
("Disconnect MacBook — it will need to be paired again"). This is today's `retireRole` with its confirmation.

### C. A Host-only computer becomes the hub

It retires its Host pairing and runs "Make this the hub". If its old hub still serves other computers, that is
Flow A started from the other side: the screen sends the owner to the old hub to move them.

## What is new to build

- Gateway LAN listening and remote Host connections (prerequisite; needed for v1 anyway).
- Handover code on a new hub; hub-to-hub pinned TLS request for device-bound, pre-approved invitations.
- Gateway → Host "rejoin" instruction over the existing link; Host runs join, connects, then drops the old pairing.
- Old-hub progress view and "leave behind" per computer; final retire.
- App screens on macOS and Windows; CLI commands for Linux (`styx gateway handover start|status|finish`).

## Open questions for the owner

1. Is LAN (plus a user-run overlay such as Tailscale) enough reachability for v1, or must a MacBook away from home
   reach the hub too?
2. Is Flow A in v1, or is v1 Flow B only (move computers by re-pairing them by hand) with Flow A right after?
