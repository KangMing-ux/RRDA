from enum import Enum
from json import dumps

LIST_SIZE=1<<12

class NODE_TYPE(Enum):
    PROC=0
    FILE=1
    PIPE=2
    SOCKET=3
    MEMORY=4
    SHM=5
    USER=6

class NODE():
    def __init__(self, set_type: int):
        self.type=set_type
        if __name__ == '__main__':
            # record the edge_idx(rr_count) when node get untrusted
            self.untrust_src=None
            # binding ttp's edge_idx(ttp_type) in hgraph
            self.bind_ttps=None
        else:
            self.idx=0

class PROC_NODE(NODE):
    def __init__(self, asid: int):
        super().__init__(NODE_TYPE.PROC.value)
        self.asid=asid
        self.untrust_src=list()
    
    def __eq__(self, node):
        return self.type==node.type and self.asid==node.asid # only asid
    
    def __hash__(self):
        r=int(1<<self.type).to_bytes(1,'little')+int(self.asid).to_bytes(8, 'little')
        return hash(r)
    
    def encode(self, realname: str=''):
        if len(realname)==0:
            return 'PROC %d'%(self.asid)
        else:
            return 'PROC %s %d'%(realname, self.asid)

class FILE_NODE(NODE):
    def __init__(self, name: str):
        super().__init__(NODE_TYPE.FILE.value)
        self.name=name
    
    def __eq__(self, node):
        return self.type==node.type and self.name==node.name
    
    def __hash__(self):
        r=int(1<<self.type).to_bytes(1,'little')+self.name.encode()
        return hash(r)
    
    def encode(self):
        return 'FILE %s'%(self.name)

class PIPE_NODE(NODE):
    def __init__(self, id: int):
        super().__init__(NODE_TYPE.PIPE.value)
        self.id=id
    
    def __eq__(self, node):
        return self.type==node.type and self.id==node.id
    
    def __hash__(self):
        r=int(1<<self.type).to_bytes(1,'little')+int(self.id).to_bytes(4, 'little')
        return hash(r)
    
    def encode(self):
        return 'PIPE %d'%(self.id)

class SOCKET_NODE(NODE):
    def __init__(self, ip: bytes, port: bytes):
        super().__init__(NODE_TYPE.SOCKET.value)
        self.ip=ip
        self.port=port
    
    def __eq__(self, node):
        return self.type==node.type and self.ip==node.ip #  and self.port==node.port
    
    def __hash__(self):
        r=int(1<<self.type).to_bytes(1,'little')+self.ip # +self.port
        return hash(r)
    
    def encode(self):
        return 'SOCKET %d.%d.%d.%d'%(self.ip[0], self.ip[1], self.ip[2], self.ip[3]) # int.from_bytes(self.port, 'little')

class MEM_NODE(NODE):
    def __init__(self, asid: int, addr: int, _size: int):
        super().__init__(NODE_TYPE.MEMORY.value)
        self.asid=asid
        self.addr=addr
        self.size=_size
    
    def __eq__(self, node):
        return self.type==node.type and self.asid==node.asid and self.addr==node.addr
    
    def __hash__(self):
        r=int(1<<self.type).to_bytes(1,'little')+int(self.asid).to_bytes(8, 'little')+\
        int(self.addr).to_bytes(8, 'little')
        return hash(r)
    
    def encode(self):
        return 'MEMORY %d %d %d'%(self.asid, self.addr, self.size)

class SHM_NODE(NODE):
    def __init__(self, id: int):
        super().__init__(NODE_TYPE.SHM.value)
        self.id=id
    
    def __eq__(self, node):
        return self.type==node.type and self.id==node.id
    
    def __hash__(self):
        r=int(1<<self.type).to_bytes(1,'little')+int(self.id).to_bytes(8, 'little')
        return hash(r)
    
    def encode(self):
        return 'SHM %d'%(self.id)

class USER_NODE(NODE):
    def __init__(self, uid: int, name: str):
        super().__init__(NODE_TYPE.USER.value)
        self.uid=uid
        self.name=name
    
    def __eq__(self, node):
        return self.type==node.type and self.uid==node.uid and self.name==node.name
    
    def __hash__(self):
        r=int(1<<self.type).to_bytes(1,'little')+int(self.uid).to_bytes(8, 'little')+self.name.encode()
        return hash(r)
    
    def encode(self):
        return 'USER %d %s'%(self.uid, self.name)

class EDGE_LIST():
    def __init__(self, rr_name: str):
        self.list=list() # <rr_count, procname, syscall_name, node_index, node_index>
        self.fn=open(rr_name+'_edge.list', 'w')
    
    def join(self, edge: tuple):
        global LIST_SIZE
        self.list.append(edge)
        if len(self.list)==LIST_SIZE:
            to_write=''
            for edge in self.list:
                to_write+=dumps(edge)+'\n'
            self.fn.write(to_write)
            self.list.clear()
        return
    
    def finish(self):
        if len(self.list)>0:
            to_write=''
            for edge in self.list:
                to_write+=dumps(edge)+'\n'
            self.fn.write(to_write)
            self.list.clear()
        self.fn.close()
        return

class ProvenanceGraph():
    def __init__(self, rr_name: str):
        if __name__ == '__main__':
            self.node_set=list()
            self.edge_list=list()
            with open('output/%s_node.set'%(rr_name), 'r') as fn:
                while True:
                    line=fn.readline().strip('\n')
                    if len(line)==0:
                        break
                    line=line.split(' ')
                    if line[0]=='PROC':
                        self.node_set.append(PROC_NODE(int(line[1])))
                    elif line[0]=='MEMORY':
                        self.node_set.append(MEM_NODE(int(line[1]), int(line[2]), int(line[3])))
                    elif line[0]=='FILE':
                        self.node_set.append(FILE_NODE(line[1]))
                    elif line[0]=='SOCKET':
                        ip=b''.join([int(x).to_bytes(1, 'little') for x in line[1].split('.')])
                        self.node_set.append(SOCKET_NODE(ip, 0)) # int(line[2]).to_bytes(2, 'little')
                    elif line[0]=='PIPE':
                        self.node_set.append(PIPE_NODE(int(line[1])))
                    elif line[0]=='USER':
                        self.node_set.append(USER_NODE(int(line[1]), line[2]))
                    elif line[0]=='SHM':
                        self.node_set.append(SHM_NODE(int(line[1])))
            print('==============================import node done...==============================')
            self.edge_fn=open('output/%s_edge.list'%(rr_name), 'r')
            self.still=True
        else:
            self.node_set=dict()
            self.edge_list=EDGE_LIST(rr_name)
        return
    
    def review_node_idx(self, node: NODE):
        if node not in self.node_set:
            # record the order
            node.idx=len(self.node_set)
            # I call it a rebound gun
            self.node_set[node]=node.idx
        return self.node_set[node]
    
    def save(self, rr_name: str):
        node_list=list(self.node_set.keys())
        node_list.sort(key=lambda node: node.idx)
        to_write=''
        for node in node_list:
            to_write+=node.encode()
            to_write+='\n'
        with open(rr_name+'_node.set', 'w') as fn:
            fn.write(to_write)
        self.edge_list.finish()
        return
    
    def import_edge(self):
        assert(self.still)
        global LIST_SIZE
        self.edge_list.clear()
        for inum in range(LIST_SIZE):
            line=self.edge_fn.readline().strip('\n')
            if len(line)==0:
                self.still=False
                self.edge_fn.close()
                break
            einfo=loads(line)
            edge=STRUCT()
            edge.update({'rr_count': einfo[0], 'proc': einfo[1], 'syscall': einfo[2], 'ldx': einfo[3], 'rdx': einfo[4]})
            # check one of edge's node's type is process
            assert(self.node_set[edge.ldx].type==0 or self.node_set[edge.rdx].type==0)
            self.edge_list.append(edge)
        return
    
    def analysis(self, rr_name: str):
        global LIST_SIZE
        idx_base=0
        detector=Detector(rr_name, self.node_set)
        detector.fill_detector()
        hgraph_context=''
        t_start=time.process_time_ns()
        while self.still:
            self.import_edge()
            for edge_idx, edge in enumerate(self.edge_list):
                h_node=detector.run(edge_idx + idx_base, edge)
                if h_node is not None and len(h_node)>0:
                    hgraph_context += '%s: %d <= %s\n'%(get_TTP_TYPE_name(h_node.type), edge_idx + idx_base, \
                    dumps(h_node.dep_ttps).replace('[', '{').replace(']', '}'))
            idx_base += LIST_SIZE
        t_end=time.process_time_ns()
        print('=======================APT detection done...time cost: %dms======================='%((t_end-t_start)//10**6))
        print('==============================locate exp of APT...===============================')
        print(detector.exp_location)
        print('===========================save hgraph to hgraph...===============================')
        with open('output/hgraph', 'w') as fn:
            fn.write(hgraph_context)
        return
    
    def construct(self):
        with open('output/syscall.log.c', 'w') as fn:
            squid_set=set()
            while self.still:
                self.import_edge()
                to_write=''
                for edge in self.edge_list:
                    if self.node_set[edge.ldx].type==NODE_TYPE.PROC.value:
                        if self.node_set[edge.rdx].type==NODE_TYPE.PROC.value:
                            to_write+='%s <%s> <%s>\n'%(edge.syscall, self.node_set[edge.ldx].encode(edge.proc), self.node_set[edge.rdx].encode(edge.proc))
                        else:
                            to_write+='%s <%s> <%s>\n'%(edge.syscall, self.node_set[edge.ldx].encode(edge.proc), self.node_set[edge.rdx].encode())
                        if edge.proc=='squid':
                            squid_set.add(self.node_set[edge.ldx].encode(edge.proc))
                    else:
                        to_write+='%s <%s> <%s>\n'%(edge.syscall, self.node_set[edge.ldx].encode(), self.node_set[edge.rdx].encode(edge.proc))
                        if edge.proc=='squid':
                            squid_set.add(self.node_set[edge.rdx].encode(edge.proc))
                fn.write(to_write)
            # for x in squid_set: print(x)
        return

if __name__ == '__main__':
    import time
    from sys import argv
    from json import loads
    if len(argv)==3:
        prov_graph=ProvenanceGraph(argv[1])
        if argv[2]=='linux':
            from rr_detect_linux import *
        elif argv[2]=='windows':
            from rr_detect_windows import *
        prov_graph.analysis(argv[1])
        # prov_graph.construct()
    else:
        print('usage: python3 %s <rr_name> <os>'%(argv[0]))

# python3 rr_graph.py rr_tgt2_apt1 linux
