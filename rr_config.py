#(libc_name, shmat_offset, shmdt_offset)
HOOK_SHM_OFFSET=(
    None,
    None,
    ('/lib/libc-2.3.2.so', 934752, 934848),
    None
)

# nm -D `find /lib/ -name 'libc.so.*'` | grep 'T malloc$' | awk '{{print $1}}'
# nm -D `find /lib/ -name 'libc.so.*'` | grep 'T free$' | awk '{{print $1}}'
# (libc_name, malloc_offset, calloc_offset, realloc_offset, memalign_offset, free_offset)
HOOK_MF_OFFSET=(
    None,
    None,
    ('/lib/libc-2.3.2.so', 470400, 472432, 471040, 471504, 470848),
    None
)

ANALYSIS_RANGE={
    #rr_name -> (asid, rr_start, rr_end)
    'rr_tgt2_test': (933318656, 0, 130261762),
    'rr_tgt2_apt1': (921120768, 3687312973, 3705872226),
    'rr_tgt2_ELECTRICSLIDE_as1': (914288640, 1383797001, 1409868968),
    'rr_tgt2_calloc_1031_0644': (926294016, 0, 9582722),
    'rr_tgt2_calloc_1031_0912': (926277632, 0, 3901935),
    'rr_tgt2_calloc_strcat_111': (926232576, 8864339, 9312805),
    'rr_tgt2_calloc_1101_1734': (926294016, 0, 10131289),
    'rr_tgt2_calloc_1101_1808': (926257152, 0, 4033189)
}

# find / -perm -u=s -type f 2>/dev/null
