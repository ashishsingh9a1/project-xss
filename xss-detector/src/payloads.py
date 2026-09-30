"""
payloads.py

The three test inputs for today's task, in the exact structure the
trainer specified in "Attack Stage Task | ABES - Ashish Singh":

    ("normal", ...)      -> should be Allowed
    ("rule_match", ...)  -> regex should Block
    ("no_rule", ...)     -> no regex -> anomaly should Flag

NOTE on the no_rule payload: the trainer's example, <svg onload=alert(1)>,
is explicitly called out in his own "IF IT BREAKS" section as a payload
to swap out IF your rules already catch it: "pick a payload your rules
miss on purpose ... <svg onload=...> works if your rules only look for
<script> and onerror." This project's rule set is broader than that --
it includes an explicit svg_or_img_vector rule -- so <svg onload=alert(1)>
matches TWO rules here (event_handler, svg_or_img_vector) and would
Block, not Flag.

Following the trainer's own fallback instruction, the no_rule payload
below is swapped for one this project's rule engine genuinely does not
match: ';alert(String.fromCharCode(88,83,83))// -- a JS-context payload
with no <script> tag and no event handler. This is also not a made-up
substitution: it's a real gap this project's own Week 2 evaluation
already measured and documented.
"""

TESTS = [
    ("normal", "Rahul Kumar"),  # should be Allowed
    ("rule_match", "<script>alert(1)</script>"),  # regex should Block
    ("no_rule", "';alert(String.fromCharCode(88,83,83))//"),  # no regex match -> anomaly should Flag
]

if __name__ == "__main__":
    for label, s in TESTS:
        print(label, "->", s)
