import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("coldaddress", os.path.join(sys.argv[1], "cold-address.py"))
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
reasons, hints = tool.net_status()
print("      net_status() -> reasons: %s; hints: %s  => a real run would %s" % (
    reasons or "none", hints or "none", "STOP" if reasons else ("ASK" if hints else "CONTINUE as offline")))
