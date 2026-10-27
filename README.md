# CrowdSec (Hisho add-on)

## What it does

Shows what CrowdSec blocks in front of your sites (bans and web-firewall blocks), the bouncer that
enforces them, and whether CrowdSec is still reading logs, so protection can't silently stop. An
Unban button removes one decision. It reaches CrowdSec through a Servers (SSH) entry.

## What it needs

- You need:
  - CrowdSec running in Docker on a server you have
  - That server set up in the Servers (SSH) add-on
- Runs on: the Core machine, inside Hisho Core
- Other add-ons: `server`
- One entry per CrowdSec install, each with:
  - `server` (str, required)
  - `container` (str, optional)
  - `note` (str, optional)

## How to install

On the dashboard: **Add-ons > Store > CrowdSec > Install**. Or from a terminal:

```bash
hisho addon install crowdsec
```

Hisho takes the newest version from this repository and turns it on inside Hisho Core. Updates show as **Update
available** on its Store card; **Roll back** returns to the version before.

## How to use

Its card says whether CrowdSec is still reading logs and how much it blocked today. Its page (**Add-ons > CrowdSec**) lists the bans and blocks; **Unban** removes one (asks first).

## Settings

Needs the Servers (SSH) add-on with an entry for the server CrowdSec runs on. Then add a CrowdSec
install on its page: the server's name on the Servers (SSH) page and, if it isn't `crowdsec`, the
Docker container's name. Entries are kept in `~/Hisho/System/Config/Addons/crowdsec.yaml`.

## How to remove

**Add-ons > Store > CrowdSec > Remove**, or `hisho addon remove crowdsec`. Its card and page go away; your settings stay in `~/Hisho/System/Config/Addons/crowdsec.yaml`, so installing it again picks up where you left off.

## License

Source-available under the [PolyForm Shield License 1.0.0](LICENSE.md): free to use, change and share,
for any purpose except offering a product that competes with Hisho (reselling it, for example).
