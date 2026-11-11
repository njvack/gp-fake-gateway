# Scenarios

Each file here reproduces one gateway behaviour, usually one first seen in an [Albi](https://github.com/njvack/albi) incident file. `fakegp -scenario FILE` runs one; `PUT /scenario` on the control API loads one into a running fake. Albi's `e2e/scenarios.sh` runs albi-cli against every file here and checks `expect`.

## Adding one from an incident

1. Read the incident file and check its redaction: `albi-diag check FILE --scrub YOUR-ORG`. If anything identifying is left, that is an Albi bug: file it, and don't post the file.
2. Attach the file to an issue.
3. Draft a scenario: `albi-diag scenario FILE --name "what the gateway did" > scenarios/NAME.json`.
4. Trim it: delete rules until the client stops failing, then put the last one back. Drop the `_` note fields once you've read them. Request counts (`nth`) are counted from the gateway's start, as the fake counts them.
5. Set `issue`, and `expect` to what a correct client does.
6. Fix the client until `e2e/scenarios.sh` passes with the new file.

## Format

| Field | Meaning |
| --- | --- |
| `name` | one line: what the gateway does |
| `issue` | the issue with the incident file |
| `profile` | base gateway behaviour, from `gateway/profiles/` (default: `default`) |
| `transport` | `https`; ESP scenarios wait until the fake and the client speak ESP |
| `config` | fields of the fake's config (see the main README) merged over the profile's |
| `rules` | see below; the profile's rules run first |
| `expect.connected_within` | after the last rule has fired, seconds until the client has a working tunnel |
| `expect.exit_code` | instead: the client should give up with this exit status |

A rule picks requests with `when`: `request` is one of `portal-prelogin`, `portal-getconfig`, `prelogin`, `login`, `getconfig`, `hipreportcheck`, `hipreport`, `logout`, `tunnel`; `nth` picks the nth such request since the fake started, `from` and `to` a range, neither all of them. Then:

| Field | Does |
| --- | --- |
| `respond` | `{"status": 503, "body": "..."}` replaces the answer. For `tunnel`, the tunnel is refused with that status. |
| `delay` | waits this many seconds before answering |
| `do: close` | closes the connection without answering |
| `do: drop_tunnels`, `do: expire_sessions` | after answering, as the control API does |
| `do: drop_tunnel`, `after` | for `tunnel`: closes this tunnel `after` seconds in |
| `do: ignore_keepalive`, `after` | for `tunnel`: stops answering keepalives `after` seconds in |

## Profiles

`gateway/profiles/NAME.json` holds a `description`, a `config` and `rules` that describe one kind of real gateway, so scenarios can say which gateway they were seen on. Only `default` exists so far; add one when an incident shows a gateway version behaving differently, named for the version its incident header reports.
