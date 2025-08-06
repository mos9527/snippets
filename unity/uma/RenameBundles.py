import sys, os, shutil, tqdm

csv = sys.argv[-1]
with open(csv, "r") as f:
    assert f.readline().strip() == "n,h", (
        "usage: python RenameBundles.py <csv_file>\n"
        "Generate the CSV from meta with e.g. SQLite Browser:\n"
        "SELECT n,h FROM a WHERE n LIKE '%3d%'"
        "This script will copy files listed in the CSV to the current directory.\n"
    )
    for ln in tqdm.tqdm(f.readlines(), desc="Copying files"):
        n, h = ln.strip().split(",")
        if n.startswith("/"):
            continue
        p = os.path.join("dat", h[:2], h)
        os.makedirs(os.path.dirname(n), exist_ok=True)
        if os.path.exists(p):
            shutil.copyfile(p, n)