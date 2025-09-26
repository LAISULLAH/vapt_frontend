
# Demo scanner plugin
name = "Demo Scanner"

def run(target, emit):
    emit('info', f"Demo Scanner: Starting demo scan for {target}")
    emit('warning', "Demo Scanner: Outdated library: example-lib 1.2.3")
    emit('critical', "Demo Scanner: Possible SQL Injection at /login")
    emit('info', "Demo Scanner: Demo complete")
