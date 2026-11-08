#!/usr/bin/env python3
"""Name the workloads of a pack root by the service ids of its children (nodo #538).

    stamp.py <pack root> <role> <out dir> NAME=<service id> ...

A workload of `initial_environment_workload` is priced with the build of its child only
when it names the child by hash: a workload with no hash names no service, so the node
quotes no build for it (src/utils/cost_functions/start_funding.py). The ids of the
children change with every pack, so the service.json files of this repository carry no
hash. This copies <pack root> to <out dir> (symlinks followed, as nodo's copytree does),
then, in the copy:

* each dependency of .service/pack_config.json that is given becomes that service id,
  so the packer takes the child from the registry instead of packing it again, and
* each workload of .service/service.json gets `dependency.hash` = the id of its child,
  from tools/pack/workload_children.json (<role> is a key of that file).

Pack the copy, not the root: `nodo pack <out dir> --local`.
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main(argv):
    if len(argv) < 4:
        sys.exit(__doc__)
    root, role, out = argv[1], argv[2], argv[3]
    ids = dict(arg.split("=", 1) for arg in argv[4:])
    with open(os.path.join(HERE, "workload_children.json")) as fh:
        children = json.load(fh)[role]
    if os.path.exists(out):
        shutil.rmtree(out)
    shutil.copytree(root, out, symlinks=False)

    pack_config_path = os.path.join(out, ".service", "pack_config.json")
    with open(pack_config_path) as fh:
        pack_config = json.load(fh)
    for name in list(pack_config.get("dependencies", {})):
        if name in ids:
            # The packer looks a dependency up in the registry first; the copy of the
            # child's tree is not needed any more.
            path = os.path.join(out, pack_config["dependencies"][name])
            if os.path.isdir(path):
                shutil.rmtree(path)
            pack_config["dependencies"][name] = ids[name]
    with open(pack_config_path, "w") as fh:
        json.dump(pack_config, fh, indent=2)
        fh.write("\n")

    service_path = os.path.join(out, ".service", "service.json")
    with open(service_path) as fh:
        service = json.load(fh)
    for field, clauses in children.items():
        declared = service.get(field, [])
        if len(declared) != len(clauses):
            sys.exit(f"{service_path}: {field} has {len(declared)} clauses, "
                     f"workload_children.json names {len(clauses)}")
        for clause, names_of_clause in zip(declared, clauses):
            for group, names in zip(clause["any_of"], names_of_clause):
                if len(group["workloads"]) != len(names):
                    sys.exit(f"{service_path}: a group of {field} has {len(group['workloads'])} "
                             f"workloads, workload_children.json names {names}")
                for workload, name in zip(group["workloads"], names):
                    if name not in ids:
                        sys.exit(f"no service id given for {name}")
                    workload["dependency"]["hash"] = [ids[name]]
    with open(service_path, "w") as fh:
        json.dump(service, fh, indent=4)
        fh.write("\n")
    print(out)


if __name__ == "__main__":
    main(sys.argv)
