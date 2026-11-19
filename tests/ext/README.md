Manual field-detection check for `extension/content.js` (no browser automation dependency).

    python3 -m http.server 8765        # from the repo root
    # open http://127.0.0.1:8765/tests/ext/fixtures.html and run in the console:
    ['ef-email','cl-user','cl-pass','so1','so6','otp1','srch','zipf'].map(i => [i, !!document.getElementById(i).__applepw])

Expected: everything true except `srch` (search box) and `zipf` (postal code), which must be false.
The shadow-DOM fields `sh-user` / `sh-pass` live in `#host`'s shadow root and must also be true.
