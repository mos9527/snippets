import os, tqdm, sys
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

assert os.path.isdir(
    sys.argv[-1]
), "usage: python cabmap.py <folder to Unity bundle folder>"
NUM_THREADS = 8
FILENAME = "cabmap.csv"
print("enumerating files")
files = [
    os.path.join(folder, file)
    for folder, subfolders, files in os.walk(sys.argv[-1])
    for file in files
]
slices = [
    files[i : i + len(files) // NUM_THREADS]
    for i in range(0, len(files), len(files) // NUM_THREADS)
]

cabmap_lock = Lock()


# !! NOTE: This is non-exhaustive and will not find all CAB files.
# Headers containing these information could be compressed
# Proper decode would require a full read and decompression.
def process_file(slice):
    # Process the CAB files in the slice
    results = [""] * len(slice)
    for i, file in tqdm.tqdm(enumerate(slice), total=len(slice)):
        f = open(file, "rb")
        hdr = f.read(0x10000)  # 64 K
        o = hdr.find(b"CAB-")
        if o > 0:
            hdr = hdr[o:]
            e = hdr.find(0x00)
            results[i] = hdr[:e].decode()
    with cabmap_lock:
        with open(FILENAME, "a") as f:
            for fn, cab in zip(slice, results):
                f.write(f"{fn},{cab}\n")


with open(FILENAME, "w") as f:
    f.write("filename,cab\n")
with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
    for _ in executor.map(process_file, slices):
        pass