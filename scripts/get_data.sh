#!/usr/bin/env bash

if [ ! -d "data" ]; then
    echo "Usage: ./scripts/get_data.sh"
    echo "Please run this in the project root (folder containing the data subdirectory)"
    exit 1
fi

cd data && mkdir traces
cd traces

echo "Downloading archives..."
cat "../filelist.txt" | egrep -v "(^#.*|^$)" | xargs -n 1 wget -nc -nv

echo "Extracting..."
cat *.tar.gz | tar -xzfv - -i && rm *.tar.gz

echo "Done! :\)"


