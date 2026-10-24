"""Make this nodo a dishonest peer, for the two-node test only (run.sh overcharge).

Its maintenance tick charges five times the price. A quote prices with no launch_bp
and the tick passes the one of the instance, so only the tick changes: the quotes stay
honest, and a node that delegates here sees a peer that charges more than it quoted.
Run in /nodo.
"""
PATH = "src/utils/cost_functions/execution_cost.py"
OLD = "    return _charge_at(system_resources, seconds, bps, arch, p)\n"
NEW = ("    return (5 if launch_bp is not None else 1) * _charge_at(system_resources, seconds, "
       "bps, arch, p)  # TEST: a dishonest peer\n")

source = open(PATH).read()
start = source.index("def maintenance_charge_mu(")
at = source.index(OLD, start)
open(PATH, "w").write(source[:at] + NEW + source[at + len(OLD):])
print("patched", PATH)
