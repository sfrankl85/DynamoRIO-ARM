FILE(REMOVE_RECURSE
  "CMakeFiles/drwrap.dir/drwrap.c.o"
  "CMakeFiles/drwrap.dir/drwrap_asm.asm.o"
  "../lib32/release/libdrwrap.pdb"
  "../lib32/release/libdrwrap.so"
)

# Per-language clean rules from dependency scanning.
FOREACH(lang ASM C)
  INCLUDE(CMakeFiles/drwrap.dir/cmake_clean_${lang}.cmake OPTIONAL)
ENDFOREACH(lang)
