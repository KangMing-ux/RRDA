from rr_syscalls2 import *
from sys import argv
from pandare import Panda

if len(argv)==7:
    panda_instance=Panda(arch=argv[2], mem=argv[3], expect_prompt=None, serial_kwargs=None, os_version=argv[4], os=argv[5], qcow=argv[6], generic=None, raw_monitor=False, extra_args=['-netdev', 'user,id=nd0', '-device', 'rtl8139,netdev=nd0', '-nographic'], catch_exceptions=True, libpanda_path=None)
elif len(argv)==8:
    panda_instance=Panda(arch=argv[2], mem=argv[3], expect_prompt=None, serial_kwargs=None, os_version=argv[4], os=argv[5], qcow=argv[6], generic=None, raw_monitor=False, extra_args=['-netdev', 'user,id=nd0', '-device', '%s,netdev=nd0'%(argv[7]), '-nographic'], catch_exceptions=True, libpanda_path=None)
else:
    panda_instance=Panda(arch=argv[2], mem=argv[3], expect_prompt=None, serial_kwargs=None, os_version=argv[4], os=argv[5], qcow=None, generic=None, raw_monitor=False, extra_args=['-drive', 'file=%s,if=%s'%(argv[6], argv[8]), '-netdev', 'user,id=nd0', '-device', '%s,netdev=nd0'%(argv[7]), '-nographic'], catch_exceptions=True, libpanda_path=None)

panda_instance.load_plugin(name='syscalls2', args={'load-info' : 'true'})
panda_instance.load_plugin(name='osi')

def on_rw_syscall(env: panda_instance.ffi.CData, syscall_name: str, Handle: int, rw: bool):
    global panda_instance, prov_graph, last_syscall_event, sockfdinfo
    current=panda_instance.plugins['osi'].get_current_process(env)
    master=PROC_NODE(panda_instance.ffi.string(current.name).decode('utf8', 'ignore'), current.asid)
    slave_ptr=panda_instance.plugins['wintrospection'].get_handle_name(env, Handle)
    slave_name=panda_instance.ffi.string(slave_ptr).decode('utf8', 'ignore')
    if len(slave_name)==0:
        slave=FILE_NODE('windows_unknown')
    elif slave_name.startswith('socket:socket'):
        #This make me very confused, why does the socket operation not call socketcall
        #The below behavior solve most socket:socket/[xxxx]
        if (current.asid, fd) in sockfdinfo:
            slave=sockfdinfo[(current.asid, fd)]
        else:
            #treat this socket as trusted, which means this syscall event no need appear in prov_graph
            return
    elif slave_name.startswith('pipe:pipe'):
        #pipe used by parent-child process
        slave=PIPE_NODE(int(slave_name[12:-2]))
    else:
        slave=FILE_NODE(slave_name)
    if master not in prov_graph.node_set:
        # record the order
        master.idx=len(prov_graph.node_set)
        prov_graph.node_set[master]=master.idx
    if slave not in prov_graph.node_set:
        # record the order
        slave.idx=len(prov_graph.node_set)
        prov_graph.node_set[slave]=slave.idx
    if last_syscall_event!=(syscall_name, current.asid, Handle):
        if rw:#read related
            prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), syscall_name, prov_graph.node_set[slave], prov_graph.node_set[master]))
        else:#write related
            prov_graph.edge_list.join((panda_instance.rr_get_guest_instr_count(), syscall_name, prov_graph.node_set[master], prov_graph.node_set[slave]))
        last_syscall_event=(syscall_name, current.asid, Handle)
    return

# https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile   #
# https://undocumented-ntinternals.github.io/                                                #
# https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
# https://learn.microsoft.com/en-us/windows/win32/memory/file-mapping                        #

##############################################################################################
# NtReadFile  NtReadVirtualMemory
##############################################################################################

@panda_instance.ppp('syscalls2', 'on_NtReadFile_return')
def on_NtReadFile_return(env: panda_instance.ffi.CData, pc: int, FileHandle: int, Event: int, ApcRoutine: int, ApcContext: int, IoStatusBlock: int, Buffer: int, Length: int, ByteOffset: int, Key: int):
    on_rw_syscall(env, 'NtReadFile', FileHandle, True)
    return

@panda_instance.ppp('syscalls2', 'on_NtReadFileScatter_return')
def on_NtReadFileScatter_return(env: panda_instance.ffi.CData, pc: int, FileHandle: int, Event: int, ApcRoutine: int, ApcContext: int, IoStatusBlock: int, SegmentArray: int, Length: int, ByteOffset: int, Key: int):
    on_rw_syscall(env, 'NtReadFileScatter', FileHandle, True)
    return

@panda_instance.ppp('syscalls2', 'on_NtReadVirtualMemory_return')
def on_NtReadVirtualMemory_return(env: panda_instance.ffi.CData, pc: int, ProcessHandle: int, BaseAddress: int, Buffer: int, BufferSize: int, NumberOfBytesRead: int):
    on_rw_syscall(env, 'NtReadVirtualMemory', ProcessHandle, True)
    return

##############################################################################################
#  NtWriteFile  NtWriteFileGather  NtWriteVirtualMemory
##############################################################################################

@panda_instance.ppp('syscalls2', 'on_NtWriteFile_return')
def on_NtWriteFile_return(env: panda_instance.ffi.CData, pc: int, FileHandle: int, Event: int, ApcRoutine: int, ApcContext: int, IoStatusBlock: int, Buffer: int, Length: int, ByteOffset: int, Key: int):
    on_rw_syscall(env, 'NtWriteFile', FileHandle, False)
    return

@panda_instance.ppp('syscalls2', 'on_NtWriteFileGather_return')
def on_NtWriteFileGather_return(env: panda_instance.ffi.CData, pc: int, FileHandle: int, Event: int, ApcRoutine: int, ApcContext: int, IoStatusBlock: int, SegmentArray: int, Length: int, ByteOffset: int, Key: int):
    on_rw_syscall(env, 'NtWriteFileGather', FileHandle, False)
    return

@panda_instance.ppp('syscalls2', 'on_NtWriteVirtualMemory_return')
def on_NtWriteVirtualMemory_return(env: panda_instance.ffi.CData, pc: int, ProcessHandle: int, BaseAddress: int, Buffer: int, BufferSize: int, NumberOfBytesRead: int):
    on_rw_syscall(env, 'NtWriteVirtualMemory', ProcessHandle, False)
    return

##############################################################################################
#  NtReadRequestData  NtWriteRequestData
##############################################################################################

@panda_instance.ppp('syscalls2', 'on_NtReadRequestData_return')
def on_NtReadRequestData_return(env: panda_instance.ffi.CData, pc: int, PortHandle: int, Message: int, DataEntryIndex: int, Buffer: int, BufferSize: int, NumberOfBytesRead: int):
    on_rw_syscall(env, 'NtReadRequestData', PortHandle, True)
    return

@panda_instance.ppp('syscalls2', 'on_NtWriteRequestData_return')
def on_NtWriteRequestData_return(env: panda_instance.ffi.CData, pc: int, PortHandle: int, Message: int, DataEntryIndex: int, Buffer: int, BufferSize: int, NumberOfBytesRead: int):
    on_rw_syscall(env, 'NtWriteRequestData', PortHandle, False)
    return

panda_instance.run_replay(argv[1])

save_graph(node_set, edge_list, argv[1])
