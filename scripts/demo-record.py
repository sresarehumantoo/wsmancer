#!/usr/bin/env python3
"""Record the README demo against a live target, as an asciicast.

    WSMANCER_PASSWORD='...' scripts/demo-record.py forest.htb.local svc-alfresco htb.local
    agg --cols 100 --rows 28 --font-size 16 --theme dracula demo.cast docs/demo.gif

The demo is scripted rather than hand-recorded so it can be re-shot verbatim
when behavior changes -- a GIF showing output the tool no longer produces is
worse than no GIF. Nothing is drawn by hand: every frame is what the programs
actually printed, driven against a real box.

**Why tmux and not a bare pty.** The obvious implementation -- openpty, pump
keystrokes, record the bytes -- produces a subtly corrupt recording, and the
reason is this repo's oldest trap wearing a new hat. reeflective asks the
terminal where the cursor is (`ESC[6n`) and lays out its redraws around the
answer. The test harnesses in this directory answer with a constant
`ESC[24;1R`, which is fine for them because they assert on *semantic* content:
which command ran, what came back. A recording is different -- it is the
rendering itself -- and a false cursor position makes the editor overdraw its
own output, so typed commands vanish under later repaints. Answering honestly
means modeling the screen, i.e. writing a terminal emulator.

tmux already is one. It answers DSR truthfully because it genuinely knows, so
the geometry is right by construction, and it gives the shell a controlling
terminal (no "no job control" noise on camera). This script therefore drives
keys in with `send-keys` and samples `capture-pane`, emitting a frame whenever
the screen changes. Idle time costs nothing, because an unchanged screen emits
nothing.

Two conventions kept from the harnesses:

  * the password is never on a command line -- it comes from
    $WSMANCER_PASSWORD, so it cannot be rendered into a published GIF;
  * target and account are referenced on camera as `$TARGET`, `$USER` and
    `$REALM`, exported before recording. The shell expands them for real; what
    a viewer sees is the shape of the command rather than one lab's hostname.
    Everything after the handshake is the target's own output, shown as-is.
"""
import json, os, subprocess, sys, time

if len(sys.argv) != 4:
    sys.exit(__doc__)
HOST, USER, REALM = sys.argv[1:4]
if not os.environ.get("WSMANCER_PASSWORD"):
    sys.exit("set WSMANCER_PASSWORD (kept off camera; never pass -p here)")

SESSION = os.environ.get("WSM_TMUX_SESSION", "wsmancer-demo")
CAST = os.environ.get("WSM_CAST", "demo.cast")
COLS, ROWS = 100, 28
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tmux(*args, capture=False):
    cmd = ["tmux", *args]
    if capture:
        return subprocess.run(cmd, capture_output=True, text=True).stdout
    subprocess.run(cmd, check=True, capture_output=True)


class Recorder:
    def __init__(self):
        subprocess.run(["tmux", "kill-session", "-t", SESSION],
                       capture_output=True)
        # PS1 and PATH are deliberately absent here: an interactive bash sets
        # its own PS1 regardless, and tmux manages PATH for new panes, so
        # neither survives -e. Both are set inside the shell by setup(), off
        # camera.
        env = {
            "TERM": "xterm-256color",
            "TARGET": HOST, "USER": USER, "REALM": REALM,
            "WSMANCER_PASSWORD": os.environ["WSMANCER_PASSWORD"],
        }
        args = ["new-session", "-d", "-s", SESSION, "-x", str(COLS), "-y", str(ROWS)]
        for k, v in env.items():
            args += ["-e", f"{k}={v}"]
        args += ["bash", "--norc", "--noprofile", "-i"]
        tmux(*args)
        tmux("set-option", "-t", SESSION, "status", "off")
        self.t0 = time.time()
        self.events = []
        self.last = None

    # -- recording ---------------------------------------------------------
    def frame(self):
        """Emit a frame if the screen changed since the last one."""
        pane = tmux("capture-pane", "-t", SESSION, "-p", "-e", capture=True)
        pos = tmux("display-message", "-t", SESSION, "-p",
                   "#{cursor_x} #{cursor_y}", capture=True).split()
        body = pane.rstrip("\n").replace("\n", "\r\n")
        cx, cy = (int(pos[0]), int(pos[1])) if len(pos) == 2 else (0, 0)
        painted = f"\x1b[H\x1b[2J{body}\x1b[{cy + 1};{cx + 1}H"
        if painted != self.last:
            self.last = painted
            self.events.append([round(time.time() - self.t0, 6), "o", painted])

    def pump(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            self.frame()
            time.sleep(0.05)

    def wait_for(self, needle, timeout=45.0):
        end = time.time() + timeout
        while time.time() < end:
            if needle in tmux("capture-pane", "-t", SESSION, "-p", capture=True):
                return True
            self.pump(0.15)
        return False

    # -- driving -----------------------------------------------------------
    def send(self, *keys):
        tmux("send-keys", "-t", SESSION, *keys)

    def type(self, text, cps=20, settle=0.35):
        """Type like a person. -H sends raw bytes, so $ and \\ mean themselves."""
        for ch in text:
            self.send("-H", *[f"{b:02x}" for b in ch.encode()])
            self.pump(1.0 / cps)
        self.pump(settle)

    def key(self, name, settle=0.9):
        self.send(name)
        self.pump(settle)

    def run(self, line, wait=6.0):
        self.type(line)
        self.key("Enter", 0.2)
        self.pump(wait)

    def beat(self, seconds=1.0):
        self.pump(seconds)

    def setup(self):
        """Prepare the shell off camera, then start the clock on a clean screen.

        Everything here would be noise in a demo: putting the built binary on
        PATH so the command reads as an installed tool, and a prompt that is a
        bare `$` rather than this machine's. The screen is cleared and the
        event list discarded afterwards, so the recording opens on an empty
        terminal.
        """
        self.send("-H", *[f"{b:02x}" for b in
                          f"export PATH={REPO}:$PATH; export PS1='$ '".encode()])
        self.send("Enter")
        time.sleep(0.5)
        self.send("-H", *[f"{b:02x}" for b in b"clear"])
        self.send("Enter")
        time.sleep(0.5)
        self.events.clear()
        self.last = None
        self.t0 = time.time()

    def save(self, path):
        header = {"version": 2, "width": COLS, "height": ROWS,
                  "timestamp": int(self.t0),
                  "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}}
        with open(path, "w") as f:
            f.write(json.dumps(header) + "\n")
            for e in self.events:
                f.write(json.dumps(e) + "\n")
        subprocess.run(["tmux", "kill-session", "-t", SESSION], capture_output=True)


r = Recorder()
r.setup()
r.beat(1.0)

# 0. Connect. Credentials are in the environment; the password never appears.
r.type("# target and credentials come from the environment")
r.key("Enter", 0.3)
r.type("wsmancer -i $TARGET -u $USER -r $REALM")
r.key("Enter", 0.2)
if not r.wait_for("wsmancer shell") or not r.wait_for("PS "):
    sys.exit("shell never came up:\n" +
             tmux("capture-pane", "-t", SESSION, "-p", capture=True))
r.beat(1.6)

# 1. A real runspace. The identity came from the sealed handshake.
r.run("whoami", 3.0)
r.beat(0.8)

# 2. Command-name completion: the target's own cmdlet names, cached on connect.
#    The pause before Tab is what makes this legible in a GIF; the hold after
#    it lets a frame land on the completed name before the line is cleared.
r.type("stop-serv")
r.beat(1.0)
r.key("Tab", 1.6)
r.beat(1.6)
r.key("C-u", 0.6)             # clear the line rather than run it

# 3. Parameter *and* value completion, from the target's own TabExpansion2 --
#    chosen so the completer actually fires (Get-Service -Name has none on
#    2016; Get-Process does). First the parameter name, then a live value.
r.type("Get-Process -Na")
r.beat(0.8)
r.key("Tab", 1.6)            # -Na -> -Name (no trailing space, so add one)
r.beat(0.7)
r.type(" con")
r.beat(0.7)
r.key("Tab", 1.6)            # con -> conhost (a running process on the box)
r.beat(0.6)
r.key("Enter", 0.2)
r.pump(6.0)
r.beat(0.8)

# 4. Remote path completion: a Windows backslash path, completed off the box.
r.type("dir C:\\Us")
r.beat(0.8)
r.key("Tab", 1.7)
r.key("Enter", 0.2)
r.pump(6.0)
r.beat(1.0)

# 5. Ghost text: a previous command suggested inline, accepted with one key.
r.type("who")
r.beat(1.3)
r.key("Right", 0.6)
r.key("Enter", 0.2)
r.pump(4.0)
r.beat(1.0)

# 6. Ctrl-C stops the remote command, not the session. The point is the prompt
#    that comes back -- and the command that still works after it.
r.type("Start-Sleep 60")
r.key("Enter", 0.2)
r.pump(2.5)
r.key("C-c", 3.0)
r.beat(1.2)
r.run("Get-Date -Format HH:mm:ss", 4.0)
r.beat(1.8)

r.key("C-d", 2.0)
r.pump(1.5)
r.save(CAST)
print(f"wrote {CAST}: {len(r.events)} frames, "
      f"{r.events[-1][0] if r.events else 0:.1f}s")
