"""Omini plugin for ZTE ONTs (run by the Omini core)."""

from omini_sdk import plugin

from omini_zte.backup import backup
from omini_zte.changes import apply
from omini_zte.collect import collect, test

plugin.collect(collect)
plugin.test(test)
plugin.apply(apply)
plugin.backup(backup)

if __name__ == "__main__":
    plugin.run()
