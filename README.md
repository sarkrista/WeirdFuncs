# WeirdFuncs

A simple script written for personal use, may come in handy for somebody as well. Requires the GTA SA:COOP mod.

## Commands

* `/whelp` — Prints commands list in chat.
* `/droparmor` — Drops armor. You can drop 100% full armor only, otherwise it requires logic I'm lazy to work through.
* `/dropmoney <amount>` — Drops the specified amount of money.
* `/dropgun <ammo>` — Drops your current weapon. The `ammo` parameter is optional; if omitted, all ammo will be dropped.
* `/skin <id>` — Changes your character's skin to the specified ID. Doesn't change voice so it's still possible to use `/sing` and `/taunt` commands with it. Better not to change clothes, tattoos, haircut while this is active...
* `/paint <color1> <color2>` — Paints a vehicle using a spray can. 
  * You can skip a color slot by using `-` (e.g., `/paint - 1`) or just enter the first color.
  * The vehicle must belong to you (get into the car at least once to claim ownership).
* `/sing` — Makes CJ hum a song.
* `/taunt` — Makes CJ say some weird phrase.
* `/distortcars` — Applies funny squashing effect on vehicle models.

## Features
Added unnecessary tuned Hermes spawn chance because I like Hermes. :›

If you found one note that its unique headlights will disappear after world loaded. :‹

## Installation
Drop WeirdFuncsSA.asi in the root game directory.

Also make sure you fetched compatible with original mod version.

## Contributing & Issues

Bug reports and feature suggestions are welcome. However, unless a bug is game-breaking or an idea really catches my eye, it's unlikely to be implemented.
Attach weird_log.txt from the root folder to your report please.

## License

This project is released under the [Unlicense](https://unlicense.org).
