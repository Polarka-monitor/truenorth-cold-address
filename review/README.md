# Review material

- `evidence-1.1/`: output of the measurements on version 1.1 (the version that was reviewed).
- `evidence-1.2/`: the same measurements repeated on version 1.2.
- `scripts/`: the programs that made them. Each takes the folder of the tool, the folder with the official
  TrueNorth Core programs and a work folder; `repeat.sh TOOLDIR BINDIR OUTDIR` runs the ones that were repeated.
  They need Linux; the traces need `strace`, the terminal check needs `tmux` and `screen`, the network cases
  need root.
- `second-review.md`: the report of the second, separate review, unchanged.

Reading the evidence:

- `04-trace-*`: one run under `strace`. Section C lists every write that contained secret material and
  where it went. In 1.1 the private descriptor goes to a pipe and to a loopback connection; in 1.2 only the
  words go to the terminal.
- `05-terminal`: what a terminal multiplexer still holds after a dry run. The words left in GNU screen are
  those of a dry run; the line "a REAL run here is refused" shows what 1.2 does with a real one.
- `06-failures`: in the row "terminal window closed", "alt screen NOT LEFT" means that the terminal no longer
  exists, so there is nothing left to wipe; the columns that matter there are the node and the folder.
- `08-port-owner`: a second program takes the port of the tool's helper node.

The phrases in all of this are throw-away phrases made by the tool in dry runs or in a sandbox without a
network. None of them is printed in the evidence.
