# yakc

Displays a random webm from a large collection, and prompts users to moderate
them as good or bad, for future use.

One can vist `/` for a random unmoderated webm, or `/good` and `/bad` to
view moderated ones. Quorum is one; this may change at a later date.

Users can also report particularly bad webms, which will immediately
remove them from rotation and prevent them from being served.

## Housekeeping
### Dependencies

    $ pip install flask
