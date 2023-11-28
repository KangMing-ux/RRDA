import time
from sys import argv
from rr_config import *
from pandare import Panda
from rr_memory_block import *

if len(argv)==7:
    panda_instance=Panda(arch=argv[2], mem=argv[3], expect_prompt=None, serial_kwargs=None, \
    os_version=argv[4], os=argv[5], qcow=argv[6], generic=None, raw_monitor=False, \
    extra_args=['-netdev', 'user,id=nd0', '-device', 'rtl8139,netdev=nd0', '-nographic'], \
    catch_exceptions=True, libpanda_path=None)
elif len(argv)==8:
    panda_instance=Panda(arch=argv[2], mem=argv[3], expect_prompt=None, serial_kwargs=None, \
    os_version=argv[4], os=argv[5], qcow=argv[6], generic=None, raw_monitor=False, \
    extra_args=['-netdev', 'user,id=nd0', '-device', '%s,netdev=nd0'%(argv[7]), '-nographic'], \
    catch_exceptions=True, libpanda_path=None)
else:
    panda_instance=Panda(arch=argv[2], mem=argv[3], expect_prompt=None, serial_kwargs=None, \
    os_version=argv[4], os=argv[5], qcow=None, generic=None, raw_monitor=False, \
    extra_args=['-drive', 'file=%s,if=%s'%(argv[6], argv[8]), '-netdev', 'user,id=nd0', '-device', '%s,netdev=nd0'%(argv[7]), '-nographic'], \
    catch_exceptions=True, libpanda_path=None)

panda_instance.load_plugin(name='syscalls2', args={'load-info' : 'true'})
panda_instance.load_plugin(name='osi')
panda_instance.load_plugin(name='hooks')
panda_instance.load_plugin(name='dynamic_symbols')

class STRUCT(dict):
    def __getattr__(self, key):
        return self[key]
    
    def __setattr__(self, key, value):
        self[key]=value

analysis_range=ANALYSIS_RANGE[argv[1]]

ctl_prfrcs=STRUCT([
    ('debug_mf', False),
    ('debug_check', True),
    ('enable_memcb', True),
    ('memcb_on', False),
    ('check_on', False),
    ('hook_asid', analysis_range[0]),
    ('rr_start', analysis_range[1]),
    ('rr_end', analysis_range[2]),
    ('tgt_asid', 0x36e73000),
    ('tgt_idx', int(argv[6][argv[6].rfind('_')+1 : argv[6].rfind('.')]))
])

if argv[2]=='i386':
    ctl_prfrcs.SIZE_SZ=4
    ctl_prfrcs.demarcation=0xC0000000
elif argv[2]=='x86_64':
    ctl_prfrcs.SIZE_SZ=8
    ctl_prfrcs.demarcation=0x800000000000
else:
    print('unsupported arch')

memory_block=MemoryBlock(ctl_prfrcs.SIZE_SZ)

statis_prfrcs=STRUCT([('malloc_times', 0), ('free_times', 0), ('read_times', 0), ('write_times', 0), ('libc_mapping_base', 0)])
if ctl_prfrcs.debug_mf is False and ctl_prfrcs.debug_check is False:
    statis_prfrcs.info=''
else:
    assert (ctl_prfrcs.debug_mf and ctl_prfrcs.enable_memcb) is False
    statis_prfrcs.fn=open('output/mainfo', 'w')

old_buf=dict()

# i386:
#            |---------|  High address
#            |   argn  |
#            |---------|
#            |   ...   |
#            |---------|     |
#            |   arg0  |     v
#            |---------|
#            |saved ret|
# rsp/esp -> |---------|  Low address
def get_return_addr_on_call(env: panda_instance.ffi.CData):
    global panda_instance, argv
    if argv[2]=='i386':
        data=panda_instance.virtual_memory_read(env, panda_instance.arch.get_reg(env, 'esp'), 4, fmt='bytearray')
    elif argv[2]=='x86_64':
        data=panda_instance.virtual_memory_read(env, panda_instance.arch.get_reg(env, 'rsp'), 8, fmt='bytearray')
    return int.from_bytes(data, byteorder='little', signed=False)

def get_arg0_intval_on_call(env: panda_instance.ffi.CData):
    global panda_instance, argv
    if argv[2]=='i386':
        data=panda_instance.virtual_memory_read(env, panda_instance.arch.get_reg(env, 'esp')+4, 4, fmt='bytearray')
        return int.from_bytes(data, byteorder='little', signed=True)
    elif argv[2]=='x86_64':
        return panda_instance.arch.get_arg(env, 0)

def get_arg1_intval_on_call(env: panda_instance.ffi.CData):
    global panda_instance, argv
    if argv[2]=='i386':
        data=panda_instance.virtual_memory_read(env, panda_instance.arch.get_reg(env, 'esp')+8, 4, fmt='bytearray')
        return int.from_bytes(data, byteorder='little', signed=True)
    elif argv[2]=='x86_64':
        return panda_instance.arch.get_arg(env, 1)

def get_chunk_size(env: panda_instance.ffi.CData, fake_chunk_addr: int):
    global panda_instance, ctl_prfrcs
    data=panda_instance.virtual_memory_read(env, fake_chunk_addr, ctl_prfrcs.SIZE_SZ, fmt='bytearray')
    chunk_size=int.from_bytes(data, byteorder='little', signed=False)
    chunk_size=(chunk_size>>3)<<3 # eliminate the impact of the lower 3 bits of this field
    return chunk_size

def on_xalloc_return(env: panda_instance.ffi.CData):
    global panda_instance, memory_block, ctl_prfrcs, statis_prfrcs
    statis_prfrcs.malloc_times+=1
    fake_chunk_addr=panda_instance.arch.get_retval(env)-ctl_prfrcs.SIZE_SZ
    chunk_size=get_chunk_size(env, fake_chunk_addr)
    if ctl_prfrcs.debug_mf:
        to_write_a=print_chunk_list_for_debug(memory_block.active_chunk_list)
        to_write_b=print_chunk_list_for_debug(memory_block.inactive_chunk_list)
        to_write_a+=' + M(%d)[%s, %s] => '%(chunk_size, hex(fake_chunk_addr), hex(fake_chunk_addr+chunk_size))
        to_write_b+=' - M(%d)[%s, %s] => '%(chunk_size, hex(fake_chunk_addr), hex(fake_chunk_addr+chunk_size))
    memory_block.en_activable(fake_chunk_addr, fake_chunk_addr+chunk_size)
    # check_active_insert(memory_block.active_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
    # check_inactive_remove(memory_block.inactive_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
    if ctl_prfrcs.debug_mf:
        check_active_insert(memory_block.active_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
        check_inactive_remove(memory_block.inactive_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
        to_write_a+=print_chunk_list_for_debug(memory_block.active_chunk_list)+'\n'
        to_write_b+=print_chunk_list_for_debug(memory_block.inactive_chunk_list)+'\n\n'
        statis_prfrcs.fn.write(to_write_a+to_write_b)
    return

def rr_binary_check(env: panda_instance.ffi.CData, pc: int, addr: int, size: int, mode: bool):
    global panda_instance, memory_block, ctl_prfrcs, statis_prfrcs, argv
    if mode and addr < panda_instance.current_sp(env): # heap space
        err_no = memory_block.check(addr, addr+size, ctl_prfrcs.SIZE_SZ)
        if err_no & 0x1:
            if ctl_prfrcs.debug_check:
                to_write=print_chunk_list_for_debug(memory_block.active_chunk_list)+'\n'
                to_write+=print_chunk_list_for_debug(memory_block.inactive_chunk_list)+'\n'
                to_write+='Heap_Overflow : pc(%s) address(%s) size(%d)\n'%(hex(pc), hex(addr), size)
                statis_prfrcs.fn.write(to_write)
            else:
                statis_prfrcs.info += 'Heap_Overflow : pc(%s) address(%s) size(%d)\n'%(hex(pc), hex(addr), size)
    elif mode: # stack space
        err_no=0
        if argv[2]=='i386':
            saved_ret=panda_instance.arch.get_reg(env, 'ebp')+4
        elif argv[2]=='x86_64':
            saved_ret=panda_instance.arch.get_reg(env, 'rbp')+8
        if addr==saved_ret:
            err_no |= 0x8
        if err_no & 0x8:
            if ctl_prfrcs.debug_check:
                statis_prfrcs.fn.write('Stack_Overflow : pc(%s) address(%s) size(%d)\n'%(hex(pc), hex(addr), size))
            else:
                statis_prfrcs.info += 'Stack_Overflow : pc(%s) address(%s) size(%d)\n'%(hex(pc), hex(addr), size)
    return

# glibc/malloc/malloc.c
#define cALLOc          calloc
#define fREe            free
#define mALLOc          malloc
#define mEMALIGn        memalign
#define rEALLOc         realloc
#define vALLOc          valloc
#define pvALLOc         pvalloc
#define mALLINFo        mallinfo
#define mALLOPt         mallopt
#define mALLOC_STATs    malloc_stats
#define mALLOC_USABLE_SIZe malloc_usable_size
#define mALLOC_TRIm     malloc_trim
#define mALLOC_GET_STATe malloc_get_state
#define mALLOC_SET_STATe malloc_set_state
def add_hooks_if_necessary(env: panda_instance.ffi.CData):
    global panda_instance, ctl_prfrcs, statis_prfrcs, HOOK_MF_OFFSET
    libc_found=False
    libc_name, malloc_offset, calloc_offset, realloc_offset, memalign_offset, free_offset = HOOK_MF_OFFSET[ctl_prfrcs.tgt_idx]
    for mapping in panda_instance.get_mappings(env):
        if mapping.file != panda_instance.ffi.NULL and panda_instance.ffi.string(mapping.file).decode('utf8', 'ignore')==libc_name:
            libc_found=True
            break
    if libc_found and mapping.base != statis_prfrcs.libc_mapping_base:
        statis_prfrcs.libc_mapping_base = mapping.base
        print('libc: %s : %s'%(libc_name, hex(mapping.base)))
        malloc_enter_addr=mapping.base+malloc_offset
        calloc_enter_addr=mapping.base+calloc_offset
        realloc_enter_addr=mapping.base+realloc_offset
        memalign_enter_addr=mapping.base+memalign_offset
        free_enter_addr=mapping.base+free_offset

        @panda_instance.hook(malloc_enter_addr, asid=ctl_prfrcs.hook_asid, kernel=False)
        def on_malloc_enter(env: panda_instance.ffi.CData, tb, h):
            global ctl_prfrcs, statis_prfrcs
            malloc_return_addr=get_return_addr_on_call(env)
            if ctl_prfrcs.debug_check:
                statis_prfrcs.fn.write('malloc(%d) enter(%d)\n'%(get_arg0_intval_on_call(env), statis_prfrcs.malloc_times))
            ctl_prfrcs.check_on=False
            
            @panda_instance.hook(malloc_return_addr, asid=ctl_prfrcs.hook_asid, kernel=False)
            def on_malloc_return(env, tb, h):
                global ctl_prfrcs, statis_prfrcs
                h.enabled = False # make on_malloc_return at malloc_return_addr only run once
                ctl_prfrcs.check_on=True
                buf=panda_instance.arch.get_retval(env)
                if ctl_prfrcs.debug_check:
                    statis_prfrcs.fn.write('malloc return(%d) => <%s, %d>\n'%(statis_prfrcs.malloc_times, hex(buf), \
                    get_chunk_size(env, buf-ctl_prfrcs.SIZE_SZ)))
                if buf>0: on_xalloc_return(env)
                return

            return
        
        @panda_instance.hook(calloc_enter_addr, asid=ctl_prfrcs.hook_asid, kernel=False)
        def on_calloc_enter(env: panda_instance.ffi.CData, tb, h):
            global ctl_prfrcs, statis_prfrcs
            calloc_return_addr=get_return_addr_on_call(env)
            if ctl_prfrcs.debug_check:
                data=panda_instance.virtual_memory_read(env, panda_instance.arch.get_reg(env, 'esp')+4, 8, fmt='bytearray')
                statis_prfrcs.fn.write('calloc(%d, %d) enter(%d)\n'%(\
                int.from_bytes(data[:4], byteorder='little', signed=False),\
                int.from_bytes(data[4:], byteorder='little', signed=False),\
                statis_prfrcs.malloc_times))
            ctl_prfrcs.check_on=False
            
            @panda_instance.hook(calloc_return_addr, asid=ctl_prfrcs.hook_asid, kernel=False)
            def on_calloc_return(env, tb, h):
                global ctl_prfrcs, statis_prfrcs
                h.enabled = False # make on_calloc_return at calloc_return_addr only run once
                ctl_prfrcs.check_on=True
                buf=panda_instance.arch.get_retval(env)
                if ctl_prfrcs.debug_check:
                    statis_prfrcs.fn.write('calloc return(%d) => <%s, %d>\n'%(statis_prfrcs.malloc_times, hex(buf), \
                    get_chunk_size(env, buf-ctl_prfrcs.SIZE_SZ)))
                if buf>0: on_xalloc_return(env)
                return

            return
        
        @panda_instance.hook(realloc_enter_addr, asid=ctl_prfrcs.hook_asid, kernel=False)
        def on_realloc_enter(env: panda_instance.ffi.CData, tb, h):
            global ctl_prfrcs, statis_prfrcs, old_buf
            realloc_return_addr=get_return_addr_on_call(env)
            buf=get_arg0_intval_on_call(env)
            size=get_arg1_intval_on_call(env)
            if ctl_prfrcs.debug_check:
                statis_prfrcs.fn.write('realloc(%s, %d) enter(%d)\n'%(hex(buf), size, statis_prfrcs.malloc_times))
            if buf>0:
                fake_chunk_addr=buf-ctl_prfrcs.SIZE_SZ
                chunk_size=get_chunk_size(env, fake_chunk_addr)
                old_buf[realloc_return_addr]=(buf, fake_chunk_addr, chunk_size)
            ctl_prfrcs.check_on=False
            
            @panda_instance.hook(realloc_return_addr, asid=ctl_prfrcs.hook_asid, kernel=False)
            def on_realloc_return(env, tb, h):
                global ctl_prfrcs, statis_prfrcs, old_buf
                h.enabled = False # make on_realloc_return at realloc_return_addr only run once
                ctl_prfrcs.check_on=True
                newbuf=panda_instance.arch.get_retval(env)
                if ctl_prfrcs.debug_check:
                    statis_prfrcs.fn.write('realloc return(%d) => <%s, %d>\n'%(statis_prfrcs.malloc_times, hex(newbuf), \
                    get_chunk_size(env, newbuf-ctl_prfrcs.SIZE_SZ)))
                if newbuf>0:
                    if h.addr in old_buf:
                        buf, fake_chunk_addr, chunk_size = old_buf[h.addr]
                        if newbuf != buf:
                            memory_block.dis_activable(fake_chunk_addr, fake_chunk_addr+chunk_size)
                            del old_buf[h.addr]
                    on_xalloc_return(env)
                return

            return
        
        @panda_instance.hook(memalign_enter_addr, asid=ctl_prfrcs.hook_asid, kernel=False)
        def on_memalign_enter(env: panda_instance.ffi.CData, tb, h):
            global ctl_prfrcs, statis_prfrcs
            memalign_return_addr=get_return_addr_on_call(env)
            if ctl_prfrcs.debug_check:
                alignment=get_arg0_intval_on_call(env)
                size=get_arg1_intval_on_call(env)
                statis_prfrcs.fn.write('memalign(%d, %d) enter(%d)\n'%(alignment, size, statis_prfrcs.malloc_times))
            ctl_prfrcs.check_on=False
            
            @panda_instance.hook(memalign_return_addr, asid=ctl_prfrcs.hook_asid, kernel=False)
            def on_memalign_return(env, tb, h):
                global ctl_prfrcs, statis_prfrcs
                h.enabled = False # make on_memalign_return at memalign_return_addr only run once
                buf=panda_instance.arch.get_retval(env)
                if ctl_prfrcs.debug_check:
                    statis_prfrcs.fn.write('memalign return(%d) => <%s, %d>\n'%(statis_prfrcs.malloc_times, hex(buf), \
                    get_chunk_size(env, buf-ctl_prfrcs.SIZE_SZ)))
                ctl_prfrcs.check_on=True
                if buf>0: on_xalloc_return(env)
                return

            return

        @panda_instance.hook(free_enter_addr, asid=ctl_prfrcs.hook_asid, kernel=False)
        def free_enter(env: panda_instance.ffi.CData, tb, h):
            global ctl_prfrcs, statis_prfrcs, old_buf
            buf=get_arg0_intval_on_call(env)
            if buf>0:
                statis_prfrcs.free_times+=1
                free_return_addr=get_return_addr_on_call(env)
                fake_chunk_addr=buf-ctl_prfrcs.SIZE_SZ
                chunk_size=get_chunk_size(env, fake_chunk_addr)
                old_buf[free_return_addr]=(buf, fake_chunk_addr, chunk_size)
                if ctl_prfrcs.debug_check:
                    statis_prfrcs.fn.write('free(%s) enter(%d)\n'%(hex(buf), statis_prfrcs.free_times))
                ctl_prfrcs.check_on=h.asid == ctl_prfrcs.tgt_asid

                @panda_instance.hook(free_return_addr, asid=ctl_prfrcs.hook_asid, kernel=False)
                def on_free_return(env, tb, h):
                    global ctl_prfrcs, statis_prfrcs, memory_block, old_buf
                    h.enabled = False # make on_free_return at free_return_addr only run once
                    ctl_prfrcs.check_on=True
                    assert h.addr in old_buf
                    buf, fake_chunk_addr, chunk_size = old_buf[h.addr]
                    if ctl_prfrcs.debug_check or ctl_prfrcs.debug_mf:
                        to_write=print_chunk_list_for_debug(memory_block.inactive_chunk_list)
                        to_write+=' + F(%d)[%s, %s] => '%(chunk_size, hex(fake_chunk_addr), hex(fake_chunk_addr+chunk_size))
                    if memory_block.dis_activable(fake_chunk_addr, fake_chunk_addr+chunk_size):
                        if ctl_prfrcs.debug_check:
                            to_write+=print_chunk_list_for_debug(memory_block.inactive_chunk_list)+'\n'
                            to_write+='Double_Free : pc(%s) address(%s)\n\n'%(hex(h.addr), hex(buf))
                            statis_prfrcs.fn.write(to_write)
                        elif ctl_prfrcs.debug_mf is False:
                            statis_prfrcs.info += 'Double_Free : pc(%s) address(%s)\n'%(hex(h.addr), hex(buf))
                    elif ctl_prfrcs.debug_mf:
                        check_inactive_insert(memory_block.inactive_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
                        to_write+=print_chunk_list_for_debug(memory_block.inactive_chunk_list)+'\n\n'
                        statis_prfrcs.fn.write(to_write)
                    # check_inactive_insert(memory_block.inactive_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
                    if ctl_prfrcs.debug_check and h.asid != ctl_prfrcs.tgt_asid: statis_prfrcs.fn.write('free return(%d)\n'%(statis_prfrcs.free_times))
                    # del old_buf[h.addr]
                    return
            
            return

    return

mapping_set=set()

@panda_instance.ppp("osi", "on_task_change")
def on_task_change(env: panda_instance.ffi.CData):
    global ctl_prfrcs, statis_prfrcs, mapping_set
    rr_count=panda_instance.rr_get_guest_instr_count()
    if panda_instance.current_asid(env)==ctl_prfrcs.hook_asid:
        add_hooks_if_necessary(env)
        if ctl_prfrcs.enable_memcb and rr_count>=ctl_prfrcs.rr_start and ctl_prfrcs.memcb_on is False:
            panda_instance.enable_precise_pc()
            panda_instance.enable_memcb()
            print('open memory callback at rr_count: %d'%(rr_count))
            if ctl_prfrcs.debug_check: statis_prfrcs.fn.write('open memory callback at rr_count: %d\n'%(rr_count))
            ctl_prfrcs.memcb_on=True
        for mapping in panda_instance.get_mappings(env):
            if mapping.file != panda_instance.ffi.NULL:
                mapping_set.add('<%s : %s>'%(\
                panda_instance.ffi.string(mapping.file).decode('utf8', 'ignore'), hex(mapping.base)))
    if ctl_prfrcs.memcb_on and rr_count>ctl_prfrcs.rr_end:
        panda_instance.disable_memcb()
        panda_instance.disable_precise_pc()
        print('close memory callback at rr_count: %d'%(rr_count))
        if ctl_prfrcs.debug_check: statis_prfrcs.fn.write('close memory callback at rr_count: %d\n'%(rr_count))
        ctl_prfrcs.enable_memcb=False
        ctl_prfrcs.memcb_on=False
    return

@panda_instance.ppp("syscalls2", "on_sys_brk_return")
def on_sys_brk(env, *unused):
    global ctl_prfrcs
    if panda_instance.current_asid(env)==ctl_prfrcs.hook_asid:
        add_hooks_if_necessary(env)
    return

if argv[2]=='i386':
    @panda_instance.ppp("syscalls2", "on_sys_old_mmap_return")
    def on_sys_old_mmap(env, *unused):
        global ctl_prfrcs
        if panda_instance.current_asid(env)==ctl_prfrcs.hook_asid:
            add_hooks_if_necessary(env)
        return

    @panda_instance.ppp("syscalls2", "on_sys_mmap_pgoff_return")
    def on_sys_mmap_pgoff(env, *unused):
        global ctl_prfrcs
        if panda_instance.current_asid(env)==ctl_prfrcs.hook_asid:
            add_hooks_if_necessary(env)
        return
elif argv[2]=='x86_64':
    @panda_instance.ppp('syscalls2', 'on_sys_mmap_return')
    def on_sys_mmap_return(env, *unused):
        global ctl_prfrcs
        if panda_instance.current_asid(env)==ctl_prfrcs.hook_asid:
            add_hooks_if_necessary(env)
        return

@panda_instance.cb_virt_mem_after_read()
def virt_mem_after_read(env: panda_instance.ffi.CData, pc: int, addr: int, size: int, buf):
    global ctl_prfrcs, statis_prfrcs
    if panda_instance.current_asid(env)==ctl_prfrcs.hook_asid and ctl_prfrcs.check_on and \
    addr < ctl_prfrcs.demarcation: # only check user space
        statis_prfrcs.read_times+=1
        # if ctl_prfrcs.debug_check:
        #     statis_prfrcs.fn.write('read %d bytes from %s then %s\n'%(size, hex(addr), hex(pc)))
        # rr_binary_check(env, pc, addr, size, False)
    return

@panda_instance.cb_virt_mem_before_write()
def virt_mem_before_write(env: panda_instance.ffi.CData, pc: int, addr: int, size: int, buf: int):
    global ctl_prfrcs, statis_prfrcs
    if panda_instance.current_asid(env)==ctl_prfrcs.hook_asid and ctl_prfrcs.check_on and \
    addr < ctl_prfrcs.demarcation: # only check user space
        statis_prfrcs.write_times+=1
        rr_count=panda_instance.rr_get_guest_instr_count()
        if ctl_prfrcs.debug_check:
            statis_prfrcs.fn.write('%d: pc: %s addr: %s size: %d buf: %s\n'%(rr_count, \
            hex(pc), hex(addr), size, panda_instance.ffi.string(buf).decode('utf8', 'ignore')))
        rr_binary_check(env, pc, addr, size, True)
    return

statis_prfrcs.t_start=time.process_time_ns()

panda_instance.run_replay(argv[1])

statis_prfrcs.t_end=time.process_time_ns()

print('malloc_times: %d  free_times: %d  read_times: %d  write_times: %d'%(\
statis_prfrcs.malloc_times, statis_prfrcs.free_times, statis_prfrcs.read_times, statis_prfrcs.write_times))

print('running time cost: %fs'%((statis_prfrcs.t_end-statis_prfrcs.t_start)/1000000000))

if ctl_prfrcs.debug_mf is False and ctl_prfrcs.debug_check is False:
    print(statis_prfrcs.info)
else:
    statis_prfrcs.fn.close()

# for x in mapping_set:
#     print(x)
# if False:
#     to_write='D[%s]\n'%(hex(buf))
#     to_write+=print_chunk_list_for_debug(memory_block.active_chunk_list)+'\n'
#     to_write+=print_chunk_list_for_debug(memory_block.inactive_chunk_list)+'\n\n'
#     statis_prfrcs.fn.write(to_write)
# elif False:
#     to_write='F[%s]\n'%(hex(buf))
#     to_write+=print_chunk_list_for_debug(memory_block.active_chunk_list)+'\n'
#     to_write+=print_chunk_list_for_debug(memory_block.inactive_chunk_list)+'\n\n'
#     statis_prfrcs.fn.write(to_write)
