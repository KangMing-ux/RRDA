import time
from sys import argv
from rr_config import *
from pandare import Panda
from rr_memory_block import *

class STRUCT(dict):
    def __getattr__(self, key):
        return self[key]
    
    def __setattr__(self, key, value):
        self[key]=value

####################################################################################################
#                                                                                                  #
####################################### PANDA INITIALIZATION #######################################
#                                                                                                  #
####################################################################################################

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

####################################################################################################
#                                                                                                  #
################################## GLOBAL VARIABLE INITIALIZATION ##################################
#                                                                                                  #
####################################################################################################

ctl_config=STRUCT([
    ('debug_mf',     False),
    ('debug_check',  True),
    ('enable_memcb', True),
    ('memcb_on',     False),
    ('check_on',     False),
    ('hook_asid',    ANALYSIS_RANGE[argv[1]][0]),
    ('rr_start',     ANALYSIS_RANGE[argv[1]][1]),
    ('rr_end',       ANALYSIS_RANGE[argv[1]][2])
])
assert (ctl_config.debug_mf and ctl_config.enable_memcb) is False
ctl_config.tgt_idx=int(argv[6][argv[6].rfind('_')+1 : argv[6].rfind('.')])
if argv[2]=='i386':
    ctl_config.SIZE_SZ=4
    ctl_config.kernel_space=0xC0000000
else:
    ctl_config.SIZE_SZ=8
    ctl_config.kernel_space=0x800000000000

static_config=STRUCT([
    ('malloc_times', 0), 
    ('free_times', 0), 
    ('read_times', 0), 
    ('write_times', 0), 
    ('libc_mapping_base', 0)
])
if ctl_config.debug_mf is False and ctl_config.debug_check is False:
    static_config.log=''
else:
    static_config.log=open('output/mainfo', 'w')

VULN_TYPE=('', 'stack overflow: ', 'heap overflow: ', 'double free: ', 'UAF: ')

####################################################################################################
#                                                                                                  #
#################################### CODE BEGINNING (HOOK PART) ####################################
#                                                                                                  #
####################################################################################################

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
    global panda_instance, ctl_config
    data=panda_instance.virtual_memory_read(env, fake_chunk_addr, ctl_config.SIZE_SZ, fmt='bytearray')
    chunk_size=int.from_bytes(data, byteorder='little', signed=False)
    chunk_size=(chunk_size>>3)<<3 # eliminate the impact of the lower 3 bits of this field
    return chunk_size

def on_xalloc_return(env: panda_instance.ffi.CData):
    global panda_instance, mb, ctl_config, static_config
    static_config.malloc_times+=1
    fake_chunk_addr=panda_instance.arch.get_retval(env)-ctl_config.SIZE_SZ
    chunk_size=get_chunk_size(env, fake_chunk_addr)
    if ctl_config.debug_mf:
        to_write_a=print_chunk_list_for_debug(mb.active_chunk_list)
        to_write_b=print_chunk_list_for_debug(mb.inactive_chunk_list)
        to_write_a+=' + M(%d)[%s, %s] => '%(chunk_size, hex(fake_chunk_addr), hex(fake_chunk_addr+chunk_size))
        to_write_b+=' - M(%d)[%s, %s] => '%(chunk_size, hex(fake_chunk_addr), hex(fake_chunk_addr+chunk_size))
    mb.on_alloc(fake_chunk_addr, fake_chunk_addr+chunk_size)
    check_active_insert(mb.active_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
    check_inactive_remove(mb.inactive_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
    if ctl_config.debug_mf:
        check_active_insert(mb.active_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
        check_inactive_remove(mb.inactive_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
        to_write_a+=print_chunk_list_for_debug(mb.active_chunk_list)+'\n'
        to_write_b+=print_chunk_list_for_debug(mb.inactive_chunk_list)+'\n\n'
        static_config.log.write(to_write_a+to_write_b)
    return

####################################################################################################
#                                                                                                  #
#################################### ADD HOOK AT alloc and free ####################################
#                malloc | calloc | realloc | valloc | pvalloc | memalign | free                    #
####################################################################################################

def add_hooks_if_necessary(env: panda_instance.ffi.CData):
    global panda_instance, ctl_config, static_config, HOOK_MF_OFFSET
    libc_found=False
    libc_name, malloc_offset, calloc_offset, realloc_offset, memalign_offset, free_offset = HOOK_MF_OFFSET[ctl_config.tgt_idx]
    for mapping in panda_instance.get_mappings(env):
        if mapping.file != panda_instance.ffi.NULL and panda_instance.ffi.string(mapping.file).decode('utf8', 'ignore')==libc_name:
            libc_found=True
            break
    if libc_found and mapping.base != static_config.libc_mapping_base:
        static_config.libc_mapping_base = mapping.base
        print('libc: %s : %s'%(libc_name, hex(mapping.base)))
        malloc_enter_addr=mapping.base+malloc_offset
        calloc_enter_addr=mapping.base+calloc_offset
        realloc_enter_addr=mapping.base+realloc_offset
        memalign_enter_addr=mapping.base+memalign_offset
        free_enter_addr=mapping.base+free_offset

        @panda_instance.hook(malloc_enter_addr, asid=ctl_config.hook_asid, kernel=False)
        def on_malloc_enter(env: panda_instance.ffi.CData, tb, h):
            ######## void *malloc(size_t size); ########
            global panda_instance, ctl_config, static_config
            malloc_return_addr=get_return_addr_on_call(env)
            if ctl_config.debug_check:
                static_config.log.write('malloc(%d) enter(%d)\n'%(get_arg0_intval_on_call(env), static_config.malloc_times))
            ctl_config.check_on=False
            
            @panda_instance.hook(malloc_return_addr, asid=ctl_config.hook_asid, kernel=False)
            def on_malloc_return(env: panda_instance.ffi.CData, tb, h):
                global ctl_config, static_config
                h.enabled = False # make on_malloc_return at malloc_return_addr only run once
                ctl_config.check_on=True
                buf=panda_instance.arch.get_retval(env)
                if ctl_config.debug_check:
                    static_config.log.write('malloc return(%d) => <%s, %d>\n'%(static_config.malloc_times, hex(buf), \
                    get_chunk_size(env, buf-ctl_config.SIZE_SZ)))
                if buf>0: on_xalloc_return(env)
                return

            return
        
        @panda_instance.hook(calloc_enter_addr, asid=ctl_config.hook_asid, kernel=False)
        def on_calloc_enter(env: panda_instance.ffi.CData, tb, h):
            ######## void *calloc(size_t nmemb, size_t size); ########
            global panda_instance, ctl_config, static_config
            calloc_return_addr=get_return_addr_on_call(env)
            if ctl_config.debug_check:
                static_config.log.write('calloc(%d, %d) enter(%d)\n'%(\
                get_arg0_intval_on_call(env), get_arg1_intval_on_call(env), static_config.malloc_times))
            ctl_config.check_on=False
            
            @panda_instance.hook(calloc_return_addr, asid=ctl_config.hook_asid, kernel=False)
            def on_calloc_return(env: panda_instance.ffi.CData, tb, h):
                global panda_instance, ctl_config, static_config
                h.enabled = False # make on_calloc_return at calloc_return_addr only run once
                ctl_config.check_on=True
                buf=panda_instance.arch.get_retval(env)
                if ctl_config.debug_check:
                    static_config.log.write('calloc return(%d) => <%s, %d>\n'%(static_config.malloc_times, hex(buf), \
                    get_chunk_size(env, buf-ctl_config.SIZE_SZ)))
                if buf>0: on_xalloc_return(env)
                return

            return
        
        @panda_instance.hook(realloc_enter_addr, asid=ctl_config.hook_asid, kernel=False)
        def on_realloc_enter(env: panda_instance.ffi.CData, tb, h):
            ######## void *realloc(void *ptr, size_t size); ########
            global panda_instance, ctl_config, static_config, old_chunk
            realloc_return_addr=get_return_addr_on_call(env)
            buf=get_arg0_intval_on_call(env)
            if ctl_config.debug_check:
                static_config.log.write('realloc(%s, %d) enter(%d)\n'%(\
                hex(buf), get_arg1_intval_on_call(env), static_config.malloc_times))
            if buf>0:
                fake_chunk_addr=buf-ctl_config.SIZE_SZ
                chunk_size=get_chunk_size(env, fake_chunk_addr)
                old_chunk[realloc_return_addr]=(buf, fake_chunk_addr, chunk_size)
            ctl_config.check_on=False
            
            @panda_instance.hook(realloc_return_addr, asid=ctl_config.hook_asid, kernel=False)
            def on_realloc_return(env: panda_instance.ffi.CData, tb, h):
                global panda_instance, ctl_config, static_config, old_chunk
                h.enabled = False # make on_realloc_return at realloc_return_addr only run once
                ctl_config.check_on=True
                newbuf=panda_instance.arch.get_retval(env)
                if ctl_config.debug_check:
                    static_config.log.write('realloc return(%d) => <%s, %d>\n'%(\
                    static_config.malloc_times, hex(newbuf), get_chunk_size(env, newbuf-ctl_config.SIZE_SZ)))
                if newbuf>0:
                    if h.addr in old_chunk:
                        buf, fake_chunk_addr, chunk_size = old_chunk[h.addr]
                        if newbuf != buf:
                            mb.on_free(fake_chunk_addr, fake_chunk_addr+chunk_size)
                    on_xalloc_return(env)
                return

            return
        
        @panda_instance.hook(memalign_enter_addr, asid=ctl_config.hook_asid, kernel=False)
        def on_memalign_enter(env: panda_instance.ffi.CData, tb, h):
            ######## void *memalign(size_t alignment, size_t size); ########
            global panda_instance, ctl_config, static_config
            memalign_return_addr=get_return_addr_on_call(env)
            if ctl_config.debug_check:
                static_config.log.write('memalign(%d, %d) enter(%d)\n'%(\
                get_arg0_intval_on_call(env), get_arg1_intval_on_call(env), static_config.malloc_times))
            ctl_config.check_on=False
            
            @panda_instance.hook(memalign_return_addr, asid=ctl_config.hook_asid, kernel=False)
            def on_memalign_return(env: panda_instance.ffi.CData, tb, h):
                global panda_instance, ctl_config, static_config
                h.enabled = False # make on_memalign_return at memalign_return_addr only run once
                buf=panda_instance.arch.get_retval(env)
                if ctl_config.debug_check:
                    static_config.log.write('memalign return(%d) => <%s, %d>\n'%(static_config.malloc_times, \
                    hex(buf), get_chunk_size(env, buf-ctl_config.SIZE_SZ)))
                ctl_config.check_on=True
                if buf>0: on_xalloc_return(env)
                return

            return

        @panda_instance.hook(free_enter_addr, asid=ctl_config.hook_asid, kernel=False)
        def free_enter(env: panda_instance.ffi.CData, tb, h):
            ######## void free(void *ptr); ########
            global panda_instance, ctl_config, static_config, old_chunk
            buf=get_arg0_intval_on_call(env)
            if buf>0:
                static_config.free_times+=1
                free_return_addr=get_return_addr_on_call(env)
                fake_chunk_addr=buf-ctl_config.SIZE_SZ
                chunk_size=get_chunk_size(env, fake_chunk_addr)
                old_chunk[free_return_addr]=(buf, fake_chunk_addr, chunk_size)
                if ctl_config.debug_check:
                    static_config.log.write('free(%s) enter(%d)\n'%(hex(buf), static_config.free_times))
                ctl_config.check_on=False

                @panda_instance.hook(free_return_addr, asid=ctl_config.hook_asid, kernel=False)
                def on_free_return(env: panda_instance.ffi.CData, tb, h):
                    global ctl_config, static_config, mb, old_chunk
                    h.enabled = False # make on_free_return at free_return_addr only run once
                    ctl_config.check_on=True
                    assert h.addr in old_chunk
                    buf, fake_chunk_addr, chunk_size = old_chunk[h.addr]
                    if ctl_config.debug_check or ctl_config.debug_mf:
                        to_write=print_chunk_list_for_debug(mb.inactive_chunk_list)
                    if ctl_config.debug_mf:
                        to_write+=' + F(%d)[%s, %s] => '%(chunk_size, hex(fake_chunk_addr), hex(fake_chunk_addr+chunk_size))
                    if mb.on_free(fake_chunk_addr, fake_chunk_addr+chunk_size):
                        if ctl_config.debug_check:
                            to_write+='\ndouble free: pc=%s address=%s\n\n'%(hex(h.addr), hex(buf))
                            static_config.log.write(to_write)
                        elif ctl_config.debug_mf is False:
                            static_config.log += 'double free: pc=%s address=%s\n'%(hex(h.addr), hex(buf))
                    check_inactive_insert(mb.inactive_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
                    if ctl_config.debug_mf:
                        check_inactive_insert(mb.inactive_chunk_list, fake_chunk_addr, fake_chunk_addr+chunk_size)
                        to_write+=print_chunk_list_for_debug(mb.inactive_chunk_list)+'\n\n'
                        static_config.log.write(to_write)
                    if ctl_config.debug_check:
                        static_config.log.write('free return(%d)\n'%(static_config.free_times))
                    return
            
            return

    return

@panda_instance.ppp("osi", "on_task_change")
def on_task_change(env: panda_instance.ffi.CData):
    global ctl_config, static_config
    rr_count=panda_instance.rr_get_guest_instr_count()
    if panda_instance.current_asid(env)==ctl_config.hook_asid:
        add_hooks_if_necessary(env)
        if ctl_config.enable_memcb and rr_count>=ctl_config.rr_start and ctl_config.memcb_on is False:
            panda_instance.enable_precise_pc()
            panda_instance.enable_memcb()
            print('open memory callback at rr_count: %d'%(rr_count))
            if ctl_config.debug_check:
                static_config.log.write('open memory callback at rr_count: %d\n'%(rr_count))
            ctl_config.memcb_on=True
    if ctl_config.memcb_on and rr_count>ctl_config.rr_end:
        panda_instance.disable_memcb()
        panda_instance.disable_precise_pc()
        print('close memory callback at rr_count: %d'%(rr_count))
        if ctl_config.debug_check: 
            static_config.log.write('close memory callback at rr_count: %d\n'%(rr_count))
        ctl_config.enable_memcb=False
        ctl_config.memcb_on=False
    return

@panda_instance.ppp("syscalls2", "on_sys_brk_return")
def on_sys_brk(env, *unused):
    global ctl_config
    if panda_instance.current_asid(env)==ctl_config.hook_asid:
        add_hooks_if_necessary(env)
    return

if argv[2]=='i386':
    @panda_instance.ppp("syscalls2", "on_sys_old_mmap_return")
    def on_sys_old_mmap(env, *unused):
        global ctl_config
        if panda_instance.current_asid(env)==ctl_config.hook_asid:
            add_hooks_if_necessary(env)
        return

    @panda_instance.ppp("syscalls2", "on_sys_mmap_pgoff_return")
    def on_sys_mmap_pgoff(env, *unused):
        global ctl_config
        if panda_instance.current_asid(env)==ctl_config.hook_asid:
            add_hooks_if_necessary(env)
        return
elif argv[2]=='x86_64':
    @panda_instance.ppp('syscalls2', 'on_sys_mmap_return')
    def on_sys_mmap_return(env, *unused):
        global ctl_config
        if panda_instance.current_asid(env)==ctl_config.hook_asid:
            add_hooks_if_necessary(env)
        return

####################################################################################################
#                                                                                                  #
########################################### CHECK PART #############################################
#                                                                                                  #
####################################################################################################

def stack_check(env: panda_instance.ffi.CData, pc: int, addr: int, size: int):
    return 0

@panda_instance.cb_virt_mem_after_read()
def virt_mem_after_read(env: panda_instance.ffi.CData, pc: int, addr: int, size: int, buf: panda_instance.ffi.CData):
    global ctl_config, static_config
    if panda_instance.current_asid(env)==ctl_config.hook_asid and ctl_config.check_on and addr < ctl_config.kernel_space:
        static_config.read_times+=1
    return

@panda_instance.cb_virt_mem_before_write()
def virt_mem_before_write(env: panda_instance.ffi.CData, pc: int, addr: int, size: int, buf: panda_instance.ffi.CData):
    global ctl_config, static_config, mb
    if panda_instance.current_asid(env)==ctl_config.hook_asid and ctl_config.check_on and addr < ctl_config.kernel_space:
        static_config.write_times+=1
        if addr > panda_instance.current_sp(env):
            err_no=stack_check(env, pc, addr, size)
        else:
            err_no=0 # mb.check(addr, addr+size, ctl_config.SIZE_SZ)
            if err_no and ctl_config.debug_check:
                to_write=print_chunk_list_for_debug(mb.active_chunk_list)+'\n'
                to_write+=print_chunk_list_for_debug(mb.inactive_chunk_list)+'\n'
                static_config.log.write(to_write)
        check_info='%srr_count=%d pc=%s address=%s size=%dbyte buf=%s\n'%(\
        VULN_TYPE[int(err_no).bit_length()], panda_instance.rr_get_guest_instr_count(), \
        hex(pc), hex(addr), size, panda_instance.ffi.string(buf).hex())
        if ctl_config.debug_check:
            static_config.log.write(check_info)
        elif err_no:
            static_config.log+=check_info
    return

if __name__=='__main__':
    old_chunk=dict()
    mb=MemoryBlock(ctl_config.SIZE_SZ)
    static_config.t_start=time.process_time()
    panda_instance.run_replay(argv[1])
    static_config.t_end=time.process_time()
    print('malloc_times: %d  free_times: %d  read_times: %d  write_times: %d'%(\
    static_config.malloc_times, static_config.free_times, static_config.read_times, static_config.write_times))
    print('running time cost: %.1fs'%(static_config.t_end-static_config.t_start))
    if ctl_config.debug_mf is False and ctl_config.debug_check is False:
        print(static_config.log)
    else:
        static_config.log.close()
