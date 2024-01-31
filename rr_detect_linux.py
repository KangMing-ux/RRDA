# class TTP_TYPE(Enum):
# initial_compromise  0x_
#                                Untrusted_Recv       0x1 .
#                                Make_Mem_Exec        0x2
#                                Make_File_Exec       0x4
#                                Untrusted_File_Exec  0x8 x
# establish_foothold  0x_0
#                                Shell_Exec           0x10 x
#                                CnC                  0x20
# escalate_privileges 0x_00
#                                Sudo_Exec            0x100 x
#                                Switch_SU            0x200 x
# internal_Recon      0x_000
#                                Sensitive_Read       0x1000 .
#                                Sensitive_Command    0x2000 x
# move_laterally      0x_0000
#                                Send_Data            0x10000
# complete_mission    0x_00000
#                                Sensitive_Leak       0x100000
#                                Destroy_System       0x200000
# cleanup_tracks      0x_000000
#                                Clear_Logs           0x1000000
#                                Sensitive_Temp_RM    0x2000000
#                                Untrusted_File_RM    0x4000000

TTP_TYPE=[
    ('Untrusted_Recv', 'Make_Mem_Exec', 'Make_File_Exec', 'Untrusted_File_Exec'),
    ('Shell_Exec', 'CnC'),
    ('Sudo_Exec', 'Switch_SU'),
    ('Sensitive_Read', 'Sensitive_Command'),
    ('Send_Data', '%'),
    ('Sensitive_Leak', 'Destroy_System'),
    ('Clear_Logs', 'Sensitive_Temp_RM', 'Untrusted_File_RM')
]

get_TTP_TYPE_name = lambda h_type: TTP_TYPE[(h_type.bit_length()-1)//4][(h_type.bit_length()-1)%4]

class CONFIG():
    def __init__(self, rr_name: str):
        _idx=rr_name.rfind('tgt')+4
        with open('tgtinfo/%s.info'%(rr_name[3:_idx]), 'r') as fn:
            line=fn.readline().strip('\n')
            if len(line)==0:
                print('invalid tgt config')
                exit(0)
            self.gateway=b''.join([int(x).to_bytes(1, byteorder='little') for x in line.split('.')])
            line=fn.readline().strip('\n')
            if len(line)==0:
                print('invalid tgt config')
                exit(0)
            self.mask=b''.join([int(x).to_bytes(1, byteorder='little') for x in line.split('.')])
            line=fn.readline().strip('\n')
            if len(line)==0:
                print('invalid tgt config')
                exit(0)
            self.white_list=set([b''.join([int(x).to_bytes(1, byteorder='little') for x in word.split('.')]) for word in line.split(' ')])
            line=fn.readline().strip('\n')
            if len(line)==0:
                print('invalid tgt config')
                exit(0)
            self.Sudo_Files=set(line.split(' '))
            line=fn.readline().strip('\n')
            if len(line)==0:
                print('invalid tgt config')
                exit(0)
            self.Sensitive_Commands=set(line.split(' '))
            line=fn.readline().strip('\n')
            if len(line)==0:
                print('invalid tgt config')
                exit(0)
            self.Sensitive_Files=set(line.split(' '))
        return
    
    def is_internal(self, ip):
        return all([x & y == y & z for x, y, z in zip(self.gateway, self.mask, ip)])
    
    def is_untrusted(self, ip):
        return ip != b'\x7f\x00\x00\x01' and ip != self.gateway and ip not in self.white_list

class STRUCT(dict):
    def __getattr__(self, key):
        return self[key]
    
    def __setattr__(self, key, value):
        self[key]=value

class Detector():
    def __init__(self, rr_name: str, node_set: list):
        self.config=CONFIG(rr_name)
        self.node_set=node_set
        # edge_idx => (rr_count, procname, proc_idx)
        self.edge_info=dict()
        # write_proc => mmap_files | shm | proc
        self.to_sync=dict()
        # read_procs <= mmap_files | shm
        self.from_sync=dict()
        # True: positive | False: negative
        self.sync_mode=True
        self.funcs=None
        self.exp_location=''
    
    def realproc(self, proc_idx: int):
        proc_idx=self.node_set[proc_idx].bind_ttps
        assert not isinstance(self.node_set[proc_idx].bind_ttps, int)
        return proc_idx
    
    def do_from_sync(self, proc_idx: int):
        to_update=dict()
        if proc_idx in self.from_sync:
            for slave_idx in self.from_sync[proc_idx]:
                d=self.node_set[slave_idx].bind_ttps
                assert not isinstance(d, int)
                if d is not None:
                    to_update.update([(x, d[x]) for x in d if d[x] & (0x1 | 0x1000)])
        if len(to_update)>0:
            if self.node_set[proc_idx].bind_ttps is not None:
                self.node_set[proc_idx].bind_ttps.update(to_update)
            else:
                self.node_set[proc_idx].bind_ttps=to_update.copy()
            if len(self.node_set[proc_idx].untrust_src)==0:
                for slave_idx in self.from_sync[proc_idx]:
                    if self.node_set[slave_idx].untrust_src is not None:
                        if len(self.node_set[proc_idx].untrust_src)==0 or self.node_set[slave_idx].untrust_src[0]<self.node_set[proc_idx].untrust_src[0][0]:
                            self.node_set[proc_idx].untrust_src=[self.node_set[slave_idx].untrust_src]
        return
    
    def do_to_sync(self, proc_idx: int, to_update: dict, edge_idx: int, rr_count: int):
        if proc_idx in self.to_sync:
            for slave_idx in self.to_sync[proc_idx]:
                if self.node_set[slave_idx].bind_ttps is None:
                    self.node_set[slave_idx].bind_ttps=to_update.copy()
                else:
                    self.node_set[slave_idx].bind_ttps.update(to_update)
                if self.node_set[slave_idx].untrust_src is None:
                    self.node_set[slave_idx].untrust_src=(edge_idx, rr_count)
                elif len(self.node_set[slave_idx].untrust_src)==0:
                    self.node_set[slave_idx].untrust_src.append((edge_idx, rr_count))
        return

    def review_proc2file(self, edge_idx: int, edge: dict) -> dict:
        proc_idx, file_idx=edge.ldx, edge.rdx
        if isinstance(self.node_set[proc_idx].bind_ttps, int):
            proc_idx=self.realproc(edge.ldx)
        self.do_from_sync(proc_idx)
        h_node=STRUCT()
        if edge.syscall[-5:]=='chmod':
            if len(self.node_set[proc_idx].untrust_src)>0 and self.node_set[file_idx].untrust_src is not None: # Make_File_Exec
                assert self.node_set[proc_idx].bind_ttps is not None
                assert self.node_set[file_idx].bind_ttps is not None
                h_node.update({'type': 0x4, 'dep_ttps': list(set(self.node_set[proc_idx].bind_ttps.keys()).union(set(self.node_set[file_idx].bind_ttps.keys())))})
                self.node_set[file_idx].bind_ttps[edge_idx]=0x4
        elif edge.syscall=='unlink':
            if len(self.node_set[proc_idx].untrust_src)>0 and self.node_set[file_idx].untrust_src is not None: # Untrusted_File_RM
                assert self.node_set[proc_idx].bind_ttps is not None
                assert self.node_set[file_idx].bind_ttps is not None
                h_node.update({'type': 0x4000000, 'dep_ttps': list(set(self.node_set[proc_idx].bind_ttps.keys()).union(set(self.node_set[file_idx].bind_ttps.keys())))})
                self.node_set[file_idx].untrust_src=None
                self.node_set[file_idx].bind_ttps=None
        elif edge.syscall=='munmap':
            if proc_idx in self.to_sync and file_idx in self.to_sync[proc_idx]:
                self.to_sync[proc_idx].remove(file_idx)
            if proc_idx in self.from_sync and file_idx in self.from_sync[proc_idx]:
                self.from_sync[proc_idx].remove(file_idx)
        else: # write related | mmap
            if len(self.node_set[proc_idx].untrust_src)>0:
                self.node_set[file_idx].untrust_src=(edge_idx, edge.rr_count)
                assert self.node_set[proc_idx].bind_ttps is not None
                if self.node_set[file_idx].bind_ttps is not None:
                    self.node_set[file_idx].bind_ttps.update(self.node_set[proc_idx].bind_ttps)
                else:
                    self.node_set[file_idx].bind_ttps=self.node_set[proc_idx].bind_ttps.copy()
            if edge.syscall=='mmap':
                if proc_idx in self.to_sync:
                    self.to_sync[proc_idx].add(file_idx)
                else:
                    self.to_sync[proc_idx]={file_idx}
        return h_node
    
    def review_proc2pipe(self, edge_idx: int, edge: dict):
        proc_idx, pipe_idx=edge.ldx, edge.rdx
        if isinstance(self.node_set[proc_idx].bind_ttps, int):
            proc_idx=self.realproc(edge.ldx)
        self.do_from_sync(proc_idx)
        if len(self.node_set[proc_idx].untrust_src)>0:
            self.node_set[pipe_idx].untrust_src=(edge_idx, edge.rr_count)
            d=self.node_set[proc_idx].bind_ttps
            assert d is not None
            self.node_set[pipe_idx].bind_ttps=dict([(x, d[x]) for x in d if d[x] & (0x1 | 0x1000)])
        return None
    
    def review_proc2socket(self, edge_idx: int, edge: dict) -> dict:
        proc_idx, socket_idx=edge.ldx, edge.rdx
        if isinstance(self.node_set[proc_idx].bind_ttps, int):
            proc_idx=self.realproc(edge.ldx)
        self.do_from_sync(proc_idx)
        socket_ip=self.node_set[socket_idx].ip
        h_node=STRUCT()
        if len(self.node_set[proc_idx].untrust_src)>0:
            if self.config.is_untrusted(socket_ip):
                assert self.node_set[proc_idx].bind_ttps is not None
                if self.config.is_internal(socket_ip): # move_laterally
                    h_node.update({'type': 0x10000, 'dep_ttps': list(self.node_set[proc_idx].bind_ttps.keys())})
                    self.node_set[proc_idx].bind_ttps[edge_idx]=0x10000
                else: # CnC
                    h_node.update({'type': 0x20, 'dep_ttps': list(self.node_set[proc_idx].bind_ttps.keys())})
                    self.node_set[proc_idx].bind_ttps[edge_idx]=0x20
        return h_node
    
    def review_proc2memory(self, edge_idx: int, edge: dict) -> dict:
        proc_idx=edge.ldx
        if isinstance(self.node_set[proc_idx].bind_ttps, int):
            proc_idx=self.realproc(edge.ldx)
        self.do_from_sync(proc_idx)
        h_node=STRUCT()
        if len(self.node_set[proc_idx].untrust_src)>0: # Make_Mem_Exec
            assert self.node_set[proc_idx].bind_ttps is not None
            h_node.update({'type': 0x2, 'dep_ttps': list(self.node_set[proc_idx].bind_ttps.keys())})
            self.node_set[proc_idx].bind_ttps[edge_idx]=0x2
        return h_node
    
    def review_proc2shm(self, edge_idx: int, edge: dict):
        proc_idx, shm_idx=edge.ldx, edge.rdx
        if isinstance(self.node_set[proc_idx].bind_ttps, int):
            proc_idx=self.realproc(edge.ldx)
        self.do_from_sync(proc_idx)
        if edge.syscall=='shmat':
            if len(self.node_set[proc_idx].untrust_src)>0:
                if self.node_set[shm_idx].untrust_src is None:
                    self.node_set[shm_idx].untrust_src=(edge_idx, edge.rr_count)
                d=self.node_set[proc_idx].bind_ttps
                assert d is not None
                if self.node_set[shm_idx].bind_ttps is not None:
                    self.node_set[shm_idx].bind_ttps.update(dict([(x, d[x]) for x in d if d[x] & (0x1 | 0x1000)]))
                else:
                    self.node_set[shm_idx].bind_ttps=dict([(x, d[x]) for x in d if d[x] & (0x1 | 0x1000)])
            if proc_idx in self.to_sync:
                self.to_sync[proc_idx].add(shm_idx)
            else:
                self.to_sync[proc_idx]={shm_idx}
        elif edge.syscall=='shmdt':
            if proc_idx in self.to_sync and shm_idx in self.to_sync[proc_idx]:
                self.to_sync[proc_idx].remove(shm_idx)
            if proc_idx in self.from_sync and shm_idx in self.from_sync[proc_idx]:
                self.from_sync[proc_idx].remove(shm_idx)
        return
    
    def review_file2proc(self, edge_idx: int, edge: dict) -> dict:
        file_idx, proc_idx=edge.ldx, edge.rdx
        if isinstance(self.node_set[proc_idx].bind_ttps, int):
            proc_idx=self.realproc(edge.rdx)
        self.do_from_sync(proc_idx)
        h_node=STRUCT()
        to_update=dict()
        if edge.syscall=='execve':
            if self.node_set[file_idx].untrust_src is not None: # Untrusted_File_Exec
                assert self.node_set[file_idx].bind_ttps is not None
                if self.node_set[proc_idx].bind_ttps is not None:
                    h_node.update({'type': 0x8, 'dep_ttps': list(set(self.node_set[proc_idx].bind_ttps.keys()).union(set(self.node_set[file_idx].bind_ttps.keys())))})
                else:
                    h_node.update({'type': 0x8, 'dep_ttps': list(self.node_set[file_idx].bind_ttps.keys())})
                if self.node_set[edge.rdx].untrust_src is None:
                    self.node_set[edge.rdx].untrust_src=(edge_idx, edge.rr_count)
                else:
                    if all([val & (0x10 | 0x300 | 0x8) == 0 for val in self.node_set[edge.rdx].bind_ttps.values()]):
                        self.exp_location+=self.print_location(0x8, edge)
                self.node_set[edge.rdx].bind_ttps=self.node_set[file_idx].bind_ttps.copy()
                self.node_set[edge.rdx].bind_ttps[edge_idx]=0x8
            elif len(self.node_set[proc_idx].untrust_src)>0:
                if self.node_set[file_idx].name in self.config.Sudo_Files: # Sudo_Exec
                    h_node.update({'type': 0x100, 'dep_ttps': list(self.node_set[proc_idx].bind_ttps.keys())})
                    self.node_set[edge.rdx].bind_ttps={edge_idx: 0x100}
                    self.exp_location+=self.print_location(0x100, edge)
                elif edge.proc in self.config.Sensitive_Commands: # Sensitive_Command
                    h_node.update({'type': 0x2000, 'dep_ttps': list(self.node_set[proc_idx].bind_ttps.keys())})
                    if all([val & (0x10 | 0x300 | 0x8) == 0 for val in self.node_set[edge.rdx].bind_ttps.values()]):
                        self.exp_location+=self.print_location(0x2000, edge)
                    self.node_set[edge.rdx].bind_ttps={edge_idx: 0x2000}
                else: # Shell_Exec
                    h_node.update({'type': 0x10, 'dep_ttps': list(self.node_set[proc_idx].bind_ttps.keys())})
                    if all([val & (0x10 | 0x300 | 0x8) == 0 for val in self.node_set[edge.rdx].bind_ttps.values()]):
                        self.exp_location+=self.print_location(0x10, edge)
                    self.node_set[edge.rdx].bind_ttps={edge_idx: 0x10}
            if proc_idx in self.to_sync:
                self.to_sync.pop(proc_idx)
            if proc_idx in self.from_sync:
                self.from_sync.pop(proc_idx)
        elif edge.syscall=='mmap':
            if self.node_set[file_idx].untrust_src is not None:
                if len(self.node_set[proc_idx].untrust_src)==0:
                    self.node_set[proc_idx].untrust_src.append((edge_idx, edge.rr_count))
                d=self.node_set[file_idx].bind_ttps
                assert d is not None
                to_update.update(dict([(x, d[x]) for x in d if d[x] & (0x1 | 0x1000)]))
                if self.node_set[proc_idx].bind_ttps is not None:
                    self.node_set[proc_idx].bind_ttps.update(to_update)
                else:
                    self.node_set[proc_idx].bind_ttps=to_update.copy()
            if proc_idx in self.from_sync:
                self.from_sync[proc_idx].add(file_idx)
            else:
                self.from_sync[proc_idx]={file_idx}
        else: # read related
            if len(self.node_set[proc_idx].untrust_src)>0 and self.node_set[file_idx].name in self.config.Sensitive_Files: # Sensitive_Read
                h_node.update({'type': 0x1000, 'dep_ttps': list(self.node_set[proc_idx].bind_ttps.keys())})
                self.node_set[proc_idx].bind_ttps[edge_idx]=0x1000
                to_update[edge_idx]=0x1000
        if len(to_update)>0:
            self.do_to_sync(proc_idx, to_update, edge_idx, edge.rr_count)
        return h_node
    
    def review_pipe2proc(self, edge_idx: int, edge: dict):
        pipe_idx, proc_idx=edge.ldx, edge.rdx
        if isinstance(self.node_set[proc_idx].bind_ttps, int):
            proc_idx=self.realproc(edge.rdx)
        self.do_from_sync(proc_idx)
        if self.node_set[pipe_idx].untrust_src is not None:
            if len(self.node_set[proc_idx].untrust_src)==0:
                self.node_set[proc_idx].untrust_src.append((edge_idx, edge.rr_count))
            self.node_set[pipe_idx].untrust_src=None
            assert self.node_set[pipe_idx].bind_ttps is not None
            self.do_to_sync(proc_idx, self.node_set[pipe_idx].bind_ttps, edge_idx, edge.rr_count)
            if self.node_set[proc_idx].bind_ttps is not None:
                self.node_set[proc_idx].bind_ttps.update(self.node_set[pipe_idx].bind_ttps)
            else:
                self.node_set[proc_idx].bind_ttps=self.node_set[pipe_idx].bind_ttps
            self.node_set[pipe_idx].bind_ttps=None
        return
    
    def review_socket2proc(self, edge_idx: int, edge: dict) -> dict:
        socket_idx, proc_idx=edge.ldx, edge.rdx
        if isinstance(self.node_set[proc_idx].bind_ttps, int):
            proc_idx=self.realproc(edge.rdx)
        self.do_from_sync(proc_idx)
        h_node=STRUCT()
        socket_ip=self.node_set[socket_idx].ip
        if self.config.is_untrusted(socket_ip):
            # the only untrusted tag source
            self.node_set[socket_idx].untrust_src=(edge_idx, edge.rr_count)
            if len(self.node_set[proc_idx].untrust_src)==0:
                self.node_set[proc_idx].untrust_src.append((edge_idx, edge.rr_count))
            elif self.node_set[proc_idx].untrust_src[-1][0] in self.edge_info:
                self.node_set[proc_idx].untrust_src.clear()
                self.node_set[proc_idx].untrust_src.append((edge_idx, edge.rr_count))
            # Untrusted_Recv
            h_node.update({'type': 0x1, 'dep_ttps': []})
            if self.node_set[proc_idx].bind_ttps is not None:
                self.node_set[proc_idx].bind_ttps[edge_idx]=0x1
            else:
                self.node_set[proc_idx].bind_ttps={edge_idx : 0x1}
            self.do_to_sync(proc_idx, {edge_idx : 0x1}, edge_idx, edge.rr_count)
        return h_node
    
    def review_shm2proc(self, edge_idx: int, edge: dict):
        shm_idx, proc_idx=edge.ldx, edge.rdx
        if isinstance(self.node_set[proc_idx].bind_ttps, int):
            proc_idx=self.realproc(edge.rdx)
        self.do_from_sync(proc_idx)
        if self.node_set[shm_idx].untrust_src is not None:
            if len(self.node_set[proc_idx].untrust_src)==0:
                self.node_set[proc_idx].untrust_src.append((edge_idx, edge.rr_count))
            assert self.node_set[shm_idx].bind_ttps is not None
            if self.node_set[proc_idx].bind_ttps is not None:
                # if nothing unexpected happens, bind_ttps[shm_idx] only includes data interaction events
                self.node_set[proc_idx].bind_ttps.update(self.node_set[shm_idx].bind_ttps)
            else:
                self.node_set[proc_idx].bind_ttps=self.node_set[shm_idx].bind_ttps.copy()
            self.do_to_sync(proc_idx, self.node_set[shm_idx].bind_ttps, edge_idx, edge.rr_count)
        if proc_idx in self.from_sync:
            self.from_sync[proc_idx].add(shm_idx)
        else:
            self.from_sync[proc_idx]={shm_idx}
        return
    
    def review_user2proc(self, edge_idx: int, edge: dict) -> dict:
        proc_idx=edge.rdx
        if isinstance(self.node_set[proc_idx].bind_ttps, int):
            proc_idx=self.realproc(edge.rdx)
        self.do_from_sync(proc_idx)
        h_node=STRUCT()
        if len(self.node_set[proc_idx].untrust_src)>0: # Switch_SU
            assert self.node_set[proc_idx].bind_ttps is not None
            h_node.update({'type': 0x200, 'dep_ttps': list(self.node_set[proc_idx].bind_ttps.keys())})
            self.node_set[proc_idx].bind_ttps[edge_idx]=0x200
            self.exp_location+=self.print_location(0x200, edge)
        return h_node
    
    def review_proc2proc(self, edge_idx: int, edge: dict):
        master_idx, slave_idx=edge.ldx, edge.rdx
        proc_idx=master_idx
        if isinstance(self.node_set[master_idx].bind_ttps, int):
            proc_idx=self.realproc(master_idx)
        self.do_from_sync(proc_idx)
        if edge.syscall=='vfork':
            if len(self.node_set[proc_idx].untrust_src)>0:
                self.node_set[slave_idx].untrust_src=self.node_set[proc_idx].untrust_src.copy()
                self.node_set[slave_idx].untrust_src.append((edge_idx, edge.rr_count)) # how to handle Cro-process exploit
                self.edge_info[edge_idx]=STRUCT([('rr_count', edge.rr_count), ('procname', edge.proc), ('proc_idx', master_idx)])
            self.node_set[slave_idx].bind_ttps=master_idx # the simplest solution, but too much work to do later
        elif edge.syscall=='fork':
            if len(self.node_set[proc_idx].untrust_src)>0:
                self.node_set[slave_idx].untrust_src=self.node_set[proc_idx].untrust_src.copy()
                self.node_set[slave_idx].untrust_src.append((edge_idx, edge.rr_count)) # how to handle Cro-process exploit
                self.edge_info[edge_idx]=STRUCT([('rr_count', edge.rr_count), ('procname', edge.proc), ('proc_idx', master_idx)])
                self.node_set[slave_idx].bind_ttps=self.node_set[proc_idx].bind_ttps.copy()
            if proc_idx in self.to_sync:
                self.to_sync[slave_idx]=self.to_sync[proc_idx].copy()
            if proc_idx in self.from_sync:
                self.from_sync[slave_idx]=self.from_sync[proc_idx].copy()
            if self.sync_mode:
                # two-way positive sync
                if proc_idx in self.to_sync:
                    self.to_sync[proc_idx].add(slave_idx)
                    self.to_sync[slave_idx].add(proc_idx)
                else:
                    self.to_sync[proc_idx]={slave_idx}
                    self.to_sync[slave_idx]={proc_idx}
            else:
                # two-way negative sync
                if proc_idx in self.from_sync:
                    self.from_sync[proc_idx].add(slave_idx)
                    self.from_sync[slave_idx].add(proc_idx)
                else:
                    self.from_sync[proc_idx]={slave_idx}
                    self.from_sync[slave_idx]={proc_idx}
        else: # process_vm_readv | process_vm_writev
            if isinstance(self.node_set[edge.ldx].bind_ttps, int):
                master_idx=self.realproc(edge.ldx)
            if isinstance(self.node_set[edge.rdx].bind_ttps, int):
                slave_idx=self.realproc(edge.rdx)
            self.do_from_sync(master_idx)
            self.do_from_sync(slave_idx)
            if self.node_set[master_idx].untrust_src is not None:
                d=self.node_set[master_idx].bind_ttps
                assert d is not None
                to_update=dict([(x, d[x]) for x in d if d[x] & (0x1 | 0x1000)])
                if self.node_set[slave_idx].untrust_src is None:
                    self.node_set[slave_idx].untrust_src=(edge_idx, edge.rr_count)
                if self.node_set[slave_idx].bind_ttps is not None:
                    self.node_set[slave_idx].bind_ttps.update(to_update)
                else:
                    self.node_set[slave_idx].bind_ttps=to_update.copy()
                self.do_to_sync(slave_idx, to_update, edge_idx, edge.rr_count)
        return
    
    def fill_detector(self):
        self.funcs=(
            None,
            self.review_file2proc,
            self.review_pipe2proc,
            self.review_socket2proc,
            None,
            self.review_shm2proc,
            self.review_user2proc,
            None,
            self.review_proc2proc,
            self.review_proc2file,
            self.review_proc2pipe,
            self.review_proc2socket,
            self.review_proc2memory,
            self.review_proc2shm
        )
        return
    
    def run(self,  edge_idx: int, edge: dict):
        offset = self.node_set[edge.ldx].type + self.node_set[edge.rdx].type
        if self.node_set[edge.ldx].type==0:
            offset += 8
        return self.funcs[offset](edge_idx, edge)
    
    def print_location(self, h_type: int, edge: dict):
        einfo=STRUCT([('rr_count', edge.rr_count), ('procname', edge.proc), ('proc_idx', edge.rdx)])
        if len(self.node_set[einfo.proc_idx].untrust_src)>1:
            untrust_src=self.node_set[einfo.proc_idx].untrust_src[1]
            assert untrust_src[0] in self.edge_info
            einfo.update(self.edge_info[untrust_src[0]])
        return 'TTP: %s  vuln_process: %s  vuln_asid: %d  rr_begin: %d  rr_end: %d\n'%(
            get_TTP_TYPE_name(h_type),                       # TTP
            einfo.procname,                                  # vuln_process
            self.node_set[einfo.proc_idx].asid,              # vuln_asid
            self.node_set[einfo.proc_idx].untrust_src[0][1], # rr_begin
            edge.rr_count                                    # rr_end
            )
