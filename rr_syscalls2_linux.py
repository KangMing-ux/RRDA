import time
from sys import argv
from rr_graph import *
from rr_config import *
from pandare import Panda
from rr_syscalls2 import *

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

prov_graph=ProvenanceGraph(argv[1])

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

# handle with read/write file syscall event
def on_rw_syscall(env: panda_instance.ffi.CData, syscall_name: str, fd: int):
    global panda_instance, prov_graph, last_syscall_event, sockfdinfo
    current=panda_instance.plugins['osi'].get_current_process(env)
    master=PROC_NODE(current.asid)
    procname=panda_instance.ffi.string(current.name).decode('utf8', 'ignore')
    slave_ptr=panda_instance.plugins['osi_linux'].osi_linux_fd_to_filename(env, current, fd)
    slave_name=panda_instance.ffi.string(slave_ptr).decode('utf8', 'ignore')
    success=True
    if len(slave_name)==0: # everything is possible
        success=False
    elif slave_name.startswith('socket:socket'): # This make me very confused, why does the socket operation not call socketcall
        # The below behavior solve most socket:socket/[xxxx]
        if (current.asid, fd) in sockfdinfo:
            slave=sockfdinfo[(current.asid, fd)]
        else: # treat this socket as trusted, which means this syscall event won't used by prov_graph analysis
            success=False
    elif slave_name.startswith('pipe:pipe'):
        slave=PIPE_NODE(int(slave_name[12:-2]))
    else:
        slave=FILE_NODE(slave_name)
    if success: # which means successfully parsed file descriptor fd
        master.idx=prov_graph.review_node_idx(master)
        slave.idx=prov_graph.review_node_idx(slave)
        if last_syscall_event!=(syscall_name, slave.idx, master.idx) and 'read' in syscall_name: # read related
            prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, syscall_name, slave.idx, master.idx))
            last_syscall_event=(syscall_name, slave.idx, master.idx)
        elif last_syscall_event!=(syscall_name, master.idx, slave.idx) and 'write' in syscall_name or syscall_name=='fchmod': # write related | fchmod
            prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, syscall_name, master.idx, slave.idx))
            last_syscall_event=(syscall_name, master.idx, slave.idx)
    return

def on_pp_call(env: panda_instance.ffi.CData, syscall_name: str, r_pid: int):
    global panda_instance, prov_graph, last_syscall_event
    current=panda_instance.plugins['osi'].get_current_process(env)
    master=PROC_NODE(current.asid)
    procname=panda_instance.ffi.string(current.name).decode('utf8', 'ignore')
    for proc in panda_instance.get_processes(env):
        if proc.pid==r_pid:
            slave=PROC_NODE(proc.asid)
            break
    master.idx=prov_graph.review_node_idx(master)
    # I believe panda_instance.get_processes's ability
    slave.idx=prov_graph.review_node_idx(slave)
    last_syscall_event=None
    if 'read' in syscall_name: # read related
        prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, syscall_name, slave.idx, master.idx))
    elif 'fork' in syscall_name or 'write' in syscall_name: # write related | fork related
        prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, syscall_name, master.idx, slave.idx))
    return

def on_memory_call(env: panda_instance.ffi.CData, syscall_name: str, start: int, size: int):
    global panda_instance, prov_graph, last_syscall_event
    current=panda_instance.plugins['osi'].get_current_process(env)
    master=PROC_NODE(current.asid)
    procname=panda_instance.ffi.string(current.name).decode('utf8', 'ignore')
    slave=MEM_NODE(current.asid, start, size)
    master.idx=prov_graph.review_node_idx(master)
    slave.idx=prov_graph.review_node_idx(slave)
    prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, syscall_name, master.idx, slave.idx))
    last_syscall_event=None
    return

def fix_path(path: str, pwd: str):
    while path[0] != '/':
        if path[0:2] == '..':
            path=path[3:]
            pwd=pwd[:pwd.rfind('/')]
        elif path[0] == '.':
            return path.replace('.', pwd)
        else:
            return pwd+'/'+path

def on_file_call(env: panda_instance.ffi.CData, syscall_name: str, fileptr: int):
    global panda_instance, prov_graph, last_syscall_event, pwdinfo
    current=panda_instance.plugins['osi'].get_current_process(env)
    master=PROC_NODE(current.asid)
    procname=panda_instance.ffi.string(current.name).decode('utf8', 'ignore')
    slave_name=rr_get_data(env, fileptr).decode('utf8', 'ignore')
    if slave_name[0]=='/' or current.asid not in pwdinfo:
        slave=FILE_NODE(slave_name)
    else:
        slave=FILE_NODE(fix_path(slave_name, pwdinfo[current.asid]))
    master.idx=prov_graph.review_node_idx(master)
    slave.idx=prov_graph.review_node_idx(slave)
    last_syscall_event=None
    if syscall_name == 'readlink' or syscall_name=='execve': # readlink | execve
        prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, syscall_name, slave.idx, master.idx))
    elif syscall_name=='chmod' or syscall_name=='unlink': # chmod | unlink
        prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, syscall_name, master.idx, slave.idx))
    return

def on_mmap(env: panda_instance.ffi.CData, fd: int, prot: int):
    global panda_instance, prov_graph, last_syscall_event
    current=panda_instance.plugins['osi'].get_current_process(env)
    master=PROC_NODE(current.asid)
    procname=panda_instance.ffi.string(current.name).decode('utf8', 'ignore')
    slave_ptr=panda_instance.plugins['osi_linux'].osi_linux_fd_to_filename(env, current, fd)
    slave_name=panda_instance.ffi.string(slave_ptr).decode('utf8', 'ignore')
    slave=FILE_NODE(slave_name)
    addr=panda_instance.plugins['syscalls2'].get_syscall_retval(env)
    shminfo[(current.asid, addr)]=slave_name
    master.idx=prov_graph.review_node_idx(master)
    slave.idx=prov_graph.review_node_idx(slave)
    last_syscall_event=None
    if prot & 0x1: # PROC_READ
        prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, 'mmap', slave.idx, master.idx))
    if prot & 0x2: # PROC_WRITE
        prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, 'mmap', master.idx, slave.idx))
    return

def on_shmat(env: panda_instance.ffi.CData, shmid: int, shmflg: int):
    global panda_instance, prov_graph, last_syscall_event
    last_syscall_event=None
    current=panda_instance.plugins['osi'].get_current_process(env)
    master=PROC_NODE(current.asid)
    procname=panda_instance.ffi.string(current.name).decode('utf8', 'ignore')
    slave=SHM_NODE(shmid)
    master.idx=prov_graph.review_node_idx(master)
    slave.idx=prov_graph.review_node_idx(slave)
    prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, 'shmat', slave.idx, master.idx))
    if not shmflg & 10000: # NO SHM_RDONLY
        prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, 'shmat', master.idx, slave.idx))
    return

def on_shmdt(env: panda_instance.ffi.CData, shmid: int):
    global panda_instance, prov_graph, last_syscall_event
    current=panda_instance.plugins['osi'].get_current_process(env)
    master=PROC_NODE(current.asid)
    procname=panda_instance.ffi.string(current.name).decode('utf8', 'ignore')
    slave=SHM_NODE(shmid)
    master.idx=prov_graph.review_node_idx(master)
    slave.idx=prov_graph.review_node_idx(slave)
    prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, 'shmdt', master.idx, slave.idx))
    last_syscall_event=None
    return

##############################################################################################
# read  readv  pread64  preadv  preadv2  process_vm_readv  readahead  readlink  readlinkat
##############################################################################################

@panda_instance.ppp('syscalls2', 'on_sys_read_return')
def on_sys_read_return(env: panda_instance.ffi.CData, pc: int, fd: int, buf: int, count: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'read', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_readv_return')
def on_sys_readv_return(env: panda_instance.ffi.CData, pc: int, fd: int, vec: int, vlen: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'readv', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_pread64_return')
def on_sys_pread64_return(env: panda_instance.ffi.CData, pc: int, fd: int, buf: int, count: int, pos: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'pread64', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_preadv_return')
def on_sys_preadv_return(env: panda_instance.ffi.CData, pc: int, fd: int, vec: int, vlen: int, pos_l: int, pos_h: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'preadv', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_preadv2_return')
def on_sys_preadv2_return(env: panda_instance.ffi.CData, pc: int, fd: int, vec: int, vlen: int, pos_l: int, pos_h: int, flags: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'preadv2', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_process_vm_readv_return')
def on_sys_process_vm_readv_return(env: panda_instance.ffi.CData, pc: int, pid: int, lvec: int, liovcnt: int, rvec: int, riovcnt: int, flags: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_pp_call(env, 'process_vm_readv', pid)
    return

@panda_instance.ppp('syscalls2', 'on_sys_readahead_return')
def on_sys_readahead_return(env: panda_instance.ffi.CData, pc: int, fd: int, offset: int, count: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'readahead', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_readlink_return')
def on_sys_readlink_return(env: panda_instance.ffi.CData, pc: int, pathptr: int, buf: int, bufsiz: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_file_call(env, 'readlink', pathptr)
    return

if argv[2]=='i386':
##############################################################################################
#  mmap  shmat  shmdt  munmap
##############################################################################################

    @panda_instance.ppp('syscalls2', 'on_sys_old_mmap_return')
    def on_sys_old_mmap_return(env: panda_instance.ffi.CData, pc: int, args: int):
        if panda_instance.plugins['syscalls2'].get_syscall_retval(env) > 0:
            data=panda_instance.virtual_memory_read(env, args+8, 12, fmt='bytearray')
            prot=int.from_bytes(data[:4], byteorder='little', signed=False)
            flags=int.from_bytes(data[4:8], byteorder='little', signed=False)
            fd=int.from_bytes(data[8:], byteorder='little', signed=True)
            if fd > 0 and flags & 0x1: # file mapping with MAP_SHARED flag
                on_mmap(env, fd, prot)
        return

    @panda_instance.ppp('syscalls2', 'on_sys_mmap_pgoff_return')
    def on_sys_mmap_pgoff_return(env: panda_instance.ffi.CData, pc: int, addr: int, len: int, prot: int, flags: int, fd: int, pgoff: int):
        if panda_instance.plugins['syscalls2'].get_syscall_retval(env) > 0:
            if fd > 0 and flags & 0x1: # file mapping with MAP_SHARED flag
                on_mmap(env, fd, prot)
        return
    
    qcow=argv[6]

    libc_name, shmat_offset, shmdt_offset = HOOK_SHM_OFFSET[int(qcow[qcow.rfind('_')+1 : qcow.rfind('.')])]

    @panda_instance.hook_symbol(libc_name, shmat_offset, kernel=False)
    def on_shmat_enter(env, tb, h):
        global shminfo
        shmid=panda_instance.arch.get_arg(env, 0)
        data=panda_instance.virtual_memory_read(env, panda_instance.arch.get_reg(env, 'rsp'), 16, fmt='bytearray')
        shmat_return_addr=int.from_bytes(data[:4], byteorder='little', signed=False)
        shmflg=int.from_bytes(data[-4:], byteorder='little', signed=False)
        current=panda_instance.plugins['osi'].get_current_process(env)
        shminfo[(current.asid, shmat_return_addr)]=(shmid, shmflg) # help me remmber shmid and shmflg

        @panda_instance.hook(shmat_return_addr, asid=current.asid, kernel=False)
        def on_shmat_return(env, tb, h):
            global shminfo
            h.enabled = False # make on_shmat_return at shmat_return_addr only run once
            shmaddr=panda_instance.arch.get_retval(env)
            if shmaddr>0 and (h.asid, h.addr) in shminfo:
                shminfo[(h.asid, shmaddr)]=shminfo[(h.asid, h.addr)][0]
                on_shmat(env, shminfo[(h.asid, h.addr)][0], shminfo[(h.asid, h.addr)][1])
                del shminfo[(h.asid, h.addr)]
            return

        return

    @panda_instance.hook_symbol(libc_name, shmdt_offset, kernel=False)
    def on_shmdt_enter(env, tb, h):
        global shminfo
        shmaddr=panda_instance.arch.get_arg(env, 0)
        data=panda_instance.virtual_memory_read(env, panda_instance.arch.get_reg(env, 'rsp'), 4, fmt='bytearray')
        shmdt_return_addr=int.from_bytes(data, byteorder='little', signed=False)
        current=panda_instance.plugins['osi'].get_current_process(env)
        if (current.asid, shmaddr) in shminfo:
            shminfo[(current.asid, shmdt_return_addr)]=shminfo[(current.asid, shmaddr)] # help me remmber shmid

            @panda_instance.hook(shmdt_return_addr, asid=current.asid, kernel=False)
            def on_shmdt_return(env, tb, h):
                global shminfo
                h.enabled = False # make on_shmdt_return at shmdt_return_addr only run once
                if panda_instance.arch.get_retval(env)==0:
                    on_shmdt(env, shminfo[(h.asid, h.addr)])
                    del shminfo[(h.asid, h.addr)]
                return

        return
else:
##############################################################################################
#  mmap  shmat  shmdt  munmap
##############################################################################################

    @panda_instance.ppp('syscalls2', 'on_sys_mmap_return')
    def on_sys_mmap_return(env: panda_instance.ffi.CData, pc: int, addr: int, len: int, prot: int, flags: int, fd: int, pgoff: int):
        if panda_instance.plugins['syscalls2'].get_syscall_retval(env) > 0:
            if fd > 0 and flags & 0x1: # file mapping with MAP_SHARED flag
                on_mmap(env, fd, prot)
        return

    @panda_instance.ppp('syscalls2', 'on_sys_shmat_return')
    def on_sys_shmat_return(env: panda_instance.ffi.CData, pc: int, shmid: int, shmaddr: int, shmflg: int):
        global shminfo
        r_shmaddr=panda_instance.plugins['syscalls2'].get_syscall_retval(env)
        if r_shmaddr > 0:
            current=panda_instance.plugins['osi'].get_current_process(env)
            shminfo[(current.asid, r_shmaddr)]=shmid
            on_shmat(env, shmid, shmflg)
        return
    
    @panda_instance.ppp('syscalls2', 'on_sys_shmdt_return')
    def on_sys_shmdt_return(env: panda_instance.ffi.CData, pc: int, shmaddr: int):
        global shminfo
        if panda_instance.plugins['syscalls2'].get_syscall_retval(env) == 0:
            current=panda_instance.plugins['osi'].get_current_process(env)
            if (current.asid, shmaddr) in shminfo:
                on_shmdt(env, shminfo[(current.asid, shmaddr)])
        return

@panda_instance.ppp('syscalls2', 'on_sys_munmap_return')
def on_sys_munmap_return(env: panda_instance.ffi.CData, pc: int, addr: int, length: int):
    global shminfo, prov_graph, last_syscall_event
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) == 0:
        current=panda_instance.plugins['osi'].get_current_process(env)
        last_syscall_event=None
        if (current.asid, addr) in shminfo:
            master=PROC_NODE(current.asid)
            procname=panda_instance.ffi.string(current.name).decode('utf8', 'ignore')
            slave=FILE_NODE(shminfo[(current.asid, addr)])
            master.idx=prov_graph.review_node_idx(master)
            slave.idx=prov_graph.review_node_idx(slave)
            prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, 'munmap', master.idx, slave.idx))
    return

##############################################################################################
#  write  writev  pwrite64  pwritev  pwritev2  process_vm_writev
##############################################################################################

@panda_instance.ppp('syscalls2', 'on_sys_write_return')
def on_sys_write_return(env: panda_instance.ffi.CData, pc: int, fd: int, buf: int, count: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'write', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_writev_return')
def on_sys_writev_return(env: panda_instance.ffi.CData, pc: int, fd: int, vec: int, vlen: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'writev', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_pwrite64_return')
def on_sys_pwrite64_return(env: panda_instance.ffi.CData, pc: int, fd: int, buf: int, count: int, pos: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'pwrite64', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_pwritev_return')
def on_sys_pwritev_return(env: panda_instance.ffi.CData, pc: int, fd: int, vec: int, vlen: int, pos_l: int, pos_h: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'pwritev', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_pwritev2_return')
def on_sys_pwritev2_return(env: panda_instance.ffi.CData, pc: int, fd: int, vec: int, vlen: int, pos_l: int, pos_h: int, flags: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_rw_syscall(env, 'pwritev2', fd)
    return

@panda_instance.ppp('syscalls2', 'on_sys_process_vm_writev_return')
def on_sys_process_vm_writev_return(env: panda_instance.ffi.CData, pc: int, pid: int, lvec: int, liovcnt: int, rvec: int, riovcnt: int, flags: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0:
        on_pp_call(env, 'process_vm_writev', pid)
    return

##############################################################################################
#  fork  vfork
##############################################################################################

@panda_instance.ppp('syscalls2', 'on_sys_fork_return')
def on_sys_fork_return(env: panda_instance.ffi.CData, pc: int):
    child=panda_instance.plugins['syscalls2'].get_syscall_retval(env)
    if child > 0:
        on_pp_call(env, 'fork', child)
    return

@panda_instance.ppp('syscalls2', 'on_sys_vfork_return')
def on_sys_vfork_return(env: panda_instance.ffi.CData, pc: int):
    child=panda_instance.plugins['syscalls2'].get_syscall_retval(env)
    if child > 0:
        on_pp_call(env, 'vfork', child)
    return

##############################################################################################
#  mprotect pkey_mprotect
##############################################################################################

@panda_instance.ppp('syscalls2', 'on_sys_mprotect_return')
def on_sys_mprotect_return(env: panda_instance.ffi.CData, pc: int, start: int, size: int, prot: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0 and prot & 0x4: # PROT_EXEC
        on_memory_call(env, 'mprotect', start, size)
    return

@panda_instance.ppp('syscalls2', 'on_sys_pkey_mprotect_return')
def on_sys_pkey_mprotect_return(env: panda_instance.ffi.CData, pc: int, start: int, size: int, prot: int, pkey: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) >= 0 and prot & 0x4: # PROT_EXEC
        on_memory_call(env, 'pkey_mprotect', start, size)
    return

##############################################################################################
#  chmod fchmod
##############################################################################################

@panda_instance.ppp('syscalls2', 'on_sys_chmod_return')
def on_sys_chmod_return(env: panda_instance.ffi.CData, pc: int, fileptr: int, mode: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) == 0:
        if mode & 111:# PROT_EXEC
            on_file_call(env, 'chmod', fileptr)
    return

@panda_instance.ppp('syscalls2', 'on_sys_fchmod_return')
def on_sys_fchmod_return(env: panda_instance.ffi.CData, pc: int, fd: int, mode: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) == 0:
        if mode & 111:# PROT_EXEC
            on_rw_syscall(env, 'fchmod', fd)
    return

##############################################################################################
#  execve
##############################################################################################

# Considering that the execve syscall never returns when it success
@panda_instance.ppp('syscalls2', 'on_sys_execve_enter')
def on_sys_execve_enter(env: panda_instance.ffi.CData, pc: int, fileptr: int, argv: int, envp: int):
    global pwdinfo
    offset=0
    pwd=''
    while envp>0:
        data=panda_instance.virtual_memory_read(env, envp+offset, 4, fmt='bytearray')
        addr=int.from_bytes(data, byteorder='little')
        if addr>0:
            info=rr_get_data(env, addr).decode()
            if 'PWD' == info[:3]:
                pwd+=info.split('=')[1]
                break
            offset+=4
        else:
            break
    current=panda_instance.plugins['osi'].get_current_process(env)
    if len(pwd)>0:
        pwdinfo[current.asid]=pwd
    on_file_call(env, 'execve', fileptr)
    return

# Considering that the execve syscall never returns when it success
@panda_instance.ppp('syscalls2', 'on_sys_execve_return')
def on_sys_execve_return(env: panda_instance.ffi.CData, pc: int, fileptr: int, argv: int, envp: int):
    print('failed execve event: ')
    return

##############################################################################################
#  unlink
##############################################################################################

@panda_instance.ppp('syscalls2', 'on_sys_unlink_return')
def on_sys_unlink_return(env: panda_instance.ffi.CData, pc: int, pathptr: int):
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) == 0:
        on_file_call(env, 'unlink', pathptr)
    return

##############################################################################################
# setuid
##############################################################################################

@panda_instance.ppp('syscalls2', 'on_sys_setuid_return')
def on_sys_setuid_return(env: panda_instance.ffi.CData, pc: int, uid: int):
    global prov_graph, last_syscall_event
    if panda_instance.plugins['syscalls2'].get_syscall_retval(env) == 0:
        current=panda_instance.plugins['osi'].get_current_process(env)
        master=PROC_NODE(current.asid)
        procname=panda_instance.ffi.string(current.name).decode('utf8', 'ignore')
        last_syscall_event=None
        if uid == 0:
            slave=USER_NODE(0, 'root')
            master.idx=prov_graph.review_node_idx(master)
            slave.idx=prov_graph.review_node_idx(slave)
            prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, 'setuid', slave.idx, master.idx))
    return

##############################################################################################
#  connect  accept  recv  recvfrom  recvmsg  send  sendto  sendmsg
##############################################################################################

# net/socket.c asmlinkage long sys_socketcall(int call, unsigned long *args)
@panda_instance.ppp('syscalls2', 'on_sys_socketcall_return')
def on_sys_socketcall_return(env: panda_instance.ffi.CData, pc: int, callno: int, args: int):
    global prov_graph, last_syscall_event, sockfdinfo, SOCKET_CALL, ADDRESS_FAMILY
    retval=panda_instance.plugins['syscalls2'].get_syscall_retval(env)
    if retval < 0:
        return
    if SOCKET_CALL[callno] is None:
        return
    data=panda_instance.virtual_memory_read(env, args, 8, fmt='bytearray')
    sockfd=int.from_bytes(data[:4], byteorder='little', signed=False)
    current=panda_instance.plugins['osi'].get_current_process(env)
    if SOCKET_CALL[callno] == 'connect' or SOCKET_CALL[callno] == 'accept':
        if SOCKET_CALL[callno] == 'accept':
            sockfd=retval
        sock_addr=int.from_bytes(data[4:], byteorder='little', signed=False)
        if sock_addr==0:
            return
        data=panda_instance.virtual_memory_read(env, sock_addr, 8, fmt='bytearray')
        sa_family=int.from_bytes(data[:2], byteorder='little', signed=False)
        if sa_family == ADDRESS_FAMILY.AF_INET.value:
            sockfdinfo[(current.asid, sockfd)]=SOCKET_NODE(data[4:8], data[2:4])
        elif sa_family == ADDRESS_FAMILY.AF_UNIX.value:
            un_path=rr_get_data(env, sock_addr+2).decode('utf8', 'ignore')
            sockfdinfo[(current.asid, sockfd)]=FILE_NODE(un_path)
    else:
        if (current.asid, sockfd) in sockfdinfo:
            master=PROC_NODE(current.asid)
            procname=panda_instance.ffi.string(current.name).decode('utf8', 'ignore')
            slave=sockfdinfo[(current.asid, sockfd)]
            master.idx=prov_graph.review_node_idx(master)
            slave.idx=prov_graph.review_node_idx(slave)
            syscall_name=SOCKET_CALL[callno]
            if last_syscall_event!=(syscall_name, master.idx, slave.idx) and syscall_name[:4]=='send': # send related
                prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, syscall_name, master.idx, slave.idx))
                last_syscall_event=(syscall_name, master.idx, slave.idx)
            elif last_syscall_event!=(syscall_name, slave.idx, master.idx) and syscall_name[:4]=='recv': # recv related:
                prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), procname, syscall_name, slave.idx, master.idx))
                last_syscall_event=(syscall_name, slave.idx, master.idx)
    return

t_start=time.process_time_ns()

panda_instance.run_replay(argv[1])

t_end=time.process_time_ns()

print('running time cost: %fs'%((t_end-t_start)/1000000000))

prov_graph.save(argv[1])
