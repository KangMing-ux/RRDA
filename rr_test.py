from sys import argv
from rr_config import *
from pandare import Panda

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

mapping_set=set()

class STRUCT(dict):
    def __getattr__(self, key):
        return self[key]
    
    def __setattr__(self, key, value):
        self[key]=value

analysis_range=ANALYSIS_RANGE[argv[1]]

ctl_prfrcs=STRUCT([
    ('tgt_idx', int(argv[6][argv[6].rfind('_')+1 : argv[6].rfind('.')]))
])

statis_prfrcs=STRUCT()
statis_prfrcs.fn=open('debug/mainfo', 'w')

def get_return_addr_on_call(env: panda_instance.ffi.CData):
    global panda_instance, argv
    if argv[2]=='i386':
        data=panda_instance.virtual_memory_read(env, panda_instance.arch.get_reg(env, 'esp'), 4, fmt='bytearray')
    elif argv[2]=='x86_64':
        data=panda_instance.virtual_memory_read(env, panda_instance.arch.get_reg(env, 'rsp'), 8, fmt='bytearray')
    return int.from_bytes(data, byteorder='little', signed=False)

# Generally, addr is a address of bytearray
def rr_get_data(env: panda_instance.ffi.CData, addr: int, k: int=8):
    data=b''
    # Because I don't konw data's length
    while True:
        data += panda_instance.virtual_memory_read(env, addr, k, fmt='bytearray')
        d_len=data.find(b'\x00', -k)
        if d_len >= 0: # I got data's length
            break
        addr += k
    # To avoid that addr[0] is \x00
    if d_len > 0:
        data=data[:d_len]
    else:
        data=b''
    return data

mapping_base_set=set()

def add_hooks_if_necessary(env: panda_instance.ffi.CData):
    global panda_instance, ctl_prfrcs, statis_prfrcs, HOOK_MF_OFFSET
    libc_found=False
    libc_name, strcat_offset = HOOK_MF_OFFSET[ctl_prfrcs.tgt_idx]
    for mapping in panda_instance.get_mappings(env):
        if mapping.file != panda_instance.ffi.NULL and panda_instance.ffi.string(mapping.file).decode('utf8', 'ignore')==libc_name:
            libc_found=True
            break
    current=panda_instance.plugins['osi'].get_current_process(env)
    if libc_found and mapping.base>0 and (current.asid, mapping.base) not in mapping_base_set:
        mapping_base_set.add((current.asid, mapping.base))
        print('libc: %s : %s'%(libc_name, hex(mapping.base)))
        print(type(mapping.base))
        strcat_enter_addr=mapping.base+strcat_offset

        @panda_instance.hook(strcat_enter_addr, asid=current.asid, kernel=False)
        def on_strcat_enter(env: panda_instance.ffi.CData, tb, h):
            global statis_prfrcs
            strcat_return_addr=get_return_addr_on_call(env)

            @panda_instance.hook(strcat_return_addr, asid=h.asid, kernel=False)
            def on_strcat_return(env, tb, h):
                h.enabled = False
                buf=panda_instance.arch.get_retval(env)
                if buf>0:
                    data=rr_get_data(env, buf)
                    statis_prfrcs.fn.write('%d: %s\n'%(h.asid, data.decode('utf8', 'ignore')))
                return
            
            return

squid_set={921116672, 899493888, 921350144, 921227264, 899559424, 921120768, 899489792, 921391104, 899452928, \
921346048, 921341952, 899538944, 921210880, 921309184, 921276416, 921292800, 921260032}

@panda_instance.ppp("osi", "on_task_change")
def on_task_change(env: panda_instance.ffi.CData):
    global squid_set
    current=panda_instance.plugins['osi'].get_current_process(env)
    if current.asid in squid_set:
        add_hooks_if_necessary(env)
    return

@panda_instance.ppp("syscalls2", "on_sys_brk_return")
def on_sys_brk(env, *unused):
    global squid_set
    current=panda_instance.plugins['osi'].get_current_process(env)
    if current.asid in squid_set:
        add_hooks_if_necessary(env)
    return

if argv[2]=='i386':
    @panda_instance.ppp("syscalls2", "on_sys_old_mmap_return")
    def on_sys_old_mmap(env, *unused):
        global squid_set
        current=panda_instance.plugins['osi'].get_current_process(env)
        if current.asid in squid_set:
            add_hooks_if_necessary(env)
        return

    @panda_instance.ppp("syscalls2", "on_sys_mmap_pgoff_return")
    def on_sys_mmap_pgoff(env, *unused):
        global squid_set
        current=panda_instance.plugins['osi'].get_current_process(env)
        if current.asid in squid_set:
            add_hooks_if_necessary(env)
        return
elif argv[2]=='x86_64':
    @panda_instance.ppp('syscalls2', 'on_sys_mmap_return')
    def on_sys_mmap_return(env, *unused):
        global squid_set
        current=panda_instance.plugins['osi'].get_current_process(env)
        if current.asid in squid_set:
            add_hooks_if_necessary(env)
        return

panda_instance.run_replay(argv[1])

# fn.close()

# <PROC service 921387008> => <PROC env 921391104> => <PROC squid 921391104>

# <PROC squid 921391104> => <PROC squid 921276416>

# <PROC squid 921276416> => <PROC squid 921227264>

# <PROC squid 921227264> => <PROC squid 921210880>

# <PROC squid 921210880> => <PROC squid 921116672>

# <PROC squid 921391104> => <PROC squid 921276416>

# 3608012853: <SOCKET 192.168.141.134> => <PROC squid 921210880>

# 3705366944: <PROC squid 921120768> => <PROC squid 899493888>

# 3705440468: <PROC squid 899493888> => <PROC squid 899489792>

# <PROC squid 921227264> => <PROC squid 921120768>

# 3687312973: <SOCKET 192.168.141.134> => <PROC squid 921120768>

# <PROC squid 921120768> => <PROC squid 899493888>

# 3705872226: <FILE /bin/sh> => <PROC squid 899493888>

# <PROC squid 921391104>
#           |
#           V
# <PROC squid 921350144>   <PROC squid 921341952>
#           |                       |                       |
#           V                       V                       V
# <PROC squid 921346048>   <PROC squid 921309184>  <PROC squid 921292800>
# <FILE /sbin/consoletype> <FILE /bin/sed>

# <PROC bash 921583616> => <PROC bash 900730880>
