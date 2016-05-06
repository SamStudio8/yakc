# yakc

Displays a random webm from a large collection, and prompts users to moderate
them as good or bad, for future use.

One can vist `/` for a random unmoderated webm, or `/good` and `/bad` to
view moderated ones. Quorum is one; this may change at a later date.

Users can also report particularly bad webms, which will immediately
remove them from rotation and prevent them from being served.

For MD5 lookup to work, you need to precompute the hashes.
To do so, run `md5sum all/*.webm | tee md5.txt`.
